use std::collections::BTreeMap;

use hasp_crypto::SecretKey;
use hasp_proto::payload::{DeviceRecord, DeviceStatus, Hidden};
use hasp_proto::wire::{AccountGet, DeviceInfo, Prelogin, SessionToken};
use hasp_proto::{
    AccountRecord, AccountSeen, DeviceId, ItemId, Keyset, PinState, SecretAscii, Signed, VaultId,
    VaultKind, fingerprint, parse_secret_key, payload, verify_account_record,
};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use super::auth::{LoginOutcome, Subject, check_server_key, opaque_login, uniform};
use super::{Client, ctx};
use crate::CoreError;
use crate::keys::{copy_key, derive_account_secrets, kdf_params};
use crate::session::{Cancel, Identity, Session};
use crate::store::{AccountLocal, Batch, Marks, Records, Store, UnlockClass, VaultLocal};
use crate::sync::{Edit, flush_vault, queue_put, sync_all};
use crate::text::normalise_login;
use crate::transport::Transport;

pub struct SignIn<'a> {
    pub origin: &'a str,
    pub login: &'a str,
    pub secret_key: &'a str,
    pub password: &'a SecretString,
    pub kit_server_fp: Option<[u8; 15]>,
}

impl std::fmt::Debug for SignIn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIn")
            .field("origin", &self.origin)
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

pub(crate) struct SnapshotVault {
    pub vault_id: VaultId,
    pub kind: VaultKind,
    pub role: hasp_proto::Role,
    pub marks: Marks,
}

pub(crate) struct Adoption {
    pub origin: String,
    pub login: String,
    pub device_id: DeviceId,
    pub server_fp: [u8; 15],
    pub token: SessionToken,
    pub ak: SecretKey,
    pub password: Option<SecretString>,
    pub opk: Option<SecretKey>,
    pub confirmed: bool,
    pub snapshot: Vec<SnapshotVault>,
    pub expected_fp: Option<[u8; 15]>,
    pub account_seq_floor: u64,
    pub keyset_gen_floor: u64,
    pub class: Option<UnlockClass>,
}

pub(crate) fn verify_record_chain(
    records: &[Signed<AccountRecord>],
) -> Result<(Signed<AccountRecord>, AccountRecord), CoreError> {
    let mut seen: Option<AccountSeen> = None;
    let mut last = None;
    for rec in records {
        let record = verify_account_record(rec, seen.as_ref(), &PinState::new())?;
        seen = Some(AccountSeen {
            seq: record.seq,
            hash: rec.hash(),
        });
        last = Some((rec.clone(), record));
    }
    let (signed, record) = last.ok_or(CoreError::NotFound("account record"))?;
    if record.status != hasp_proto::AccountStatus::Active {
        return Err(CoreError::Refused("the account is deleted"));
    }
    Ok((signed, record))
}

pub(crate) fn open_account_keys(
    record: &AccountRecord,
    keyset: &Keyset,
    ak: &SecretKey,
) -> Result<hasp_proto::KeysetKeys, CoreError> {
    let k_keyset = crate::keys::ak_keys(ak)?.keyset;
    keyset
        .keys
        .open(
            &k_keyset,
            &hasp_proto::Aad::keyset_keys(record.account_id, keyset.generation),
        )
        .map_err(|_| CoreError::Credentials)
}

fn check_adoption(
    adoption: &Adoption,
    record: &AccountRecord,
    keyset: &Keyset,
) -> Result<(), CoreError> {
    if record.seq.get() < adoption.account_seq_floor
        || keyset.generation.get() < adoption.keyset_gen_floor
    {
        return Err(hasp_proto::ProtoError::Rollback.into());
    }
    if adoption
        .expected_fp
        .is_some_and(|fp| fp != fingerprint(&record.ik_pk, &record.kem_pk))
    {
        return Err(hasp_proto::ProtoError::Pin.into());
    }
    Ok(())
}

fn open_ak(
    account: &hasp_proto::wire::AccountGetResponse,
    auk: &SecretKey,
) -> Result<SecretKey, CoreError> {
    let (_, record) = verify_record_chain(&account.records)?;
    let ak = account
        .keyset
        .ak_wrap
        .open(
            auk,
            &hasp_proto::Aad::ak_wrap(record.account_id, &record.kdf, account.keyset.generation),
        )
        .map_err(|_| CoreError::Credentials)?;
    crate::keys::secret_from_slice(&ak)
}

impl<T: Transport, S: Store> Client<T, S> {
    pub async fn sign_in(
        &mut self,
        request: &SignIn<'_>,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        if self.cache.account()?.is_some() {
            return Err(CoreError::Refused("this device already holds an account"));
        }
        let (kind, sk) = parse_secret_key(request.secret_key)?;
        if kind != hasp_proto::SecretKind::SecretKey {
            return Err(hasp_proto::ProtoError::Format.into());
        }
        if let Some(expected) = &request.kit_server_fp {
            check_server_key(&self.transport, &cancel, request.origin, expected).await?;
        }
        let login = normalise_login(request.login)?;
        let hint = self
            .transport
            .call(
                None,
                &Prelogin {
                    login: login.clone(),
                },
            )
            .await?;
        cancel.check()?;
        let params = kdf_params(&hint.kdf, self.config.max_kdf_m_kib)?;
        let secrets = derive_account_secrets(
            request.password.expose_secret(),
            &sk,
            &hint.account_id,
            &params,
        )?;
        let (device_id, done, account) = self
            .login_new_device(request, &hint, &secrets.opk, &cancel)
            .await?;
        let ak = open_ak(&account, &secrets.auk)?;
        self.adopt(
            Adoption {
                origin: request.origin.to_owned(),
                login,
                device_id,
                server_fp: done.server_fp,
                token: done.token,
                ak,
                password: Some(SecretString::from(request.password.expose_secret())),
                opk: Some(secrets.opk),
                confirmed: false,
                snapshot: Vec::new(),
                expected_fp: None,
                account_seq_floor: 0,
                keyset_gen_floor: 0,
                class: None,
            },
            &account.records,
            account.keyset,
            &cancel,
        )
        .await
    }

    async fn login_new_device(
        &self,
        request: &SignIn<'_>,
        hint: &hasp_proto::wire::PreloginResponse,
        opk: &SecretKey,
        cancel: &Cancel,
    ) -> Result<(DeviceId, LoginOutcome, hasp_proto::wire::AccountGetResponse), CoreError> {
        let device_id = DeviceId::from_bytes(self.platform.array()?);
        let subject = Subject {
            origin: request.origin,
            account: hint.account_id,
            kdf: &hint.kdf,
        };
        let done = opaque_login(
            &self.transport,
            cancel,
            &subject,
            opk,
            DeviceInfo {
                device_id,
                platform: self.config.platform_name.clone(),
                label: None,
            },
        )
        .await?;
        if request.kit_server_fp.is_some_and(|fp| fp != done.server_fp) {
            return Err(CoreError::ServerKey);
        }
        let account = self
            .transport
            .call(Some(&done.token), &AccountGet {})
            .await
            .map_err(CoreError::from)
            .map_err(uniform)?;
        Ok((device_id, done, account))
    }

    pub(crate) async fn adopt(
        &mut self,
        adoption: Adoption,
        records: &[Signed<AccountRecord>],
        keyset: Keyset,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        let (signed, record) = verify_record_chain(records)?;
        check_adoption(&adoption, &record, &keyset)?;
        let keys = open_account_keys(&record, &keyset, &adoption.ak)?;
        let sk = SecretAscii::from_ascii(keys.sk_ascii.expose())?;
        let identity = Identity::from_keys(&record, copy_key(&adoption.ak), &keys)?;
        let local = self.adopted_account(&adoption, signed, keyset, &record)?;
        self.persist_adoption(&adoption, local, &sk)?;
        self.session = Some(Session {
            identity,
            token: adoption.token,
            opk: adoption.opk,
            vks: BTreeMap::new(),
            pins: PinState::new(),
        });
        {
            let mut cx = ctx!(self, cancel);
            sync_all(&mut cx).await?;
        }
        self.write_device_item(cancel).await
    }

    fn adopted_account(
        &self,
        adoption: &Adoption,
        record: Signed<AccountRecord>,
        keyset: Keyset,
        verified: &AccountRecord,
    ) -> Result<AccountLocal, CoreError> {
        let class = adoption
            .class
            .unwrap_or(if self.platform.secure.hardware_gated() {
                UnlockClass::Hardware
            } else {
                UnlockClass::PasswordOnly
            });
        Ok(AccountLocal {
            origin: adoption.origin.clone(),
            login: adoption.login.clone(),
            account_id: verified.account_id,
            device_id: adoption.device_id,
            server_fp: adoption.server_fp,
            record,
            keyset,
            max_seen_v: 1,
            min_v: verified.min_v.get(),
            class,
            local_salt: self.platform.array()?,
            local_gen: 0,
            notices_after: 0,
            platform: self.config.platform_name.clone(),
        })
    }

    fn persist_adoption(
        &mut self,
        adoption: &Adoption,
        mut local: AccountLocal,
        sk: &SecretAscii,
    ) -> Result<(), CoreError> {
        let mut batch = Batch::new();
        if adoption.confirmed {
            Records::put_meta(&mut batch, "device-confirmed", b"1");
        }
        if local.class != UnlockClass::Extension {
            let material = super::unlock::Material::create(
                &self.platform,
                &self.config,
                &local,
                adoption.password.as_ref().map(ExposeSecret::expose_secret),
            )?;
            material.write(
                &mut batch,
                &mut local,
                &super::unlock::LocalSecrets {
                    ak: &adoption.ak,
                    sk,
                    token: &adoption.token,
                },
            )?;
        }
        for entry in &adoption.snapshot {
            let mut vault = VaultLocal::new(entry.vault_id, entry.kind, entry.role);
            vault.marks = Some(entry.marks);
            vault.confirmed = true;
            Records::put_vault(&mut batch, &vault)?;
        }
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub(crate) async fn write_device_item(&mut self, cancel: &Cancel) -> Result<(), CoreError> {
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let Some(private) = self
            .cache
            .vaults()?
            .into_iter()
            .find(|v| v.kind == VaultKind::Private)
        else {
            return Ok(());
        };
        let item_id = ItemId::from_bytes(*local.device_id.as_bytes());
        if private
            .state()?
            .is_some_and(|state| state.leafset.get(&item_id).is_some())
        {
            return Ok(());
        }
        let now = self.platform.clock.now();
        let hidden = Hidden::Device(DeviceRecord {
            label: local.platform.clone(),
            platform: local.platform.clone(),
            first_seen: now,
            status: DeviceStatus::Active,
        });
        let overview = payload::encode_overview(&hidden.overview(now))?;
        let details = payload::encode_hidden(&hidden)?;
        let mut cx = ctx!(self, cancel);
        queue_put(
            &mut cx,
            &private,
            &Edit {
                item_id,
                overview: &overview,
                details: &details,
                att_ids: Vec::new(),
            },
        )?;
        let mut kinds = Vec::new();
        flush_vault(&mut cx, private.vault_id, &mut kinds).await?;
        Ok(())
    }
}
