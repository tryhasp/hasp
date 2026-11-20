use hasp_crypto::{KemSecretKey, OpaqueClientRegistration, SecretBytes, SecretKey, SigningKey};
use hasp_proto::payload::{self, DeviceRecord, DeviceStatus, Hidden, VaultMeta};
use hasp_proto::wire::{CommitBundle, DeviceInfo, RegisterFinish, RegisterStart, SignupToken};
use hasp_proto::{
    Aad, AccountId, AccountRecord, AccountStatus, DeviceId, Epoch, ItemId, ItemOp, ItemParams,
    KdfWire, Keyset, KeysetKeys, Manifest, Member, OwnKeys, PinState, Reader, Role, Roster, Rver,
    Sealed, SealedRaw, SecretAscii, SecretKind, SecretText, Seq, SigLabel, Signed, Uint53, VaultId,
    VaultKind, Version, Wire, Writer, encode_secret_key, format_fingerprint, leafset_root,
    seal_item, verify_genesis, vk_commit,
};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use super::auth::{Subject, opaque_login, register_finish};
use super::{Client, ctx};
use crate::CoreError;
use crate::keys::{ak_keys, copy_key, derive_account_secrets, kdf_params};
use crate::session::{Cancel, Identity, Session};
use crate::store::{AccountLocal, Batch, Records, Store, UnlockClass};
use crate::sync::sync_all;
use crate::text::normalise_login;
use crate::transport::Transport;

const KIT_VERSION: u64 = 1;

pub struct SignUp<'a> {
    pub origin: &'a str,
    pub token: &'a str,
    pub login: &'a str,
    pub password: &'a SecretString,
}

impl std::fmt::Debug for SignUp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignUp")
            .field("origin", &self.origin)
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

pub struct EmergencyKit {
    pub origin: String,
    pub login: String,
    pub server_fingerprint: String,
    pub(crate) secret_key: SecretText,
    pub(crate) server_fp: [u8; 15],
}

impl std::fmt::Debug for EmergencyKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmergencyKit(..)")
    }
}

#[derive(Debug)]
pub struct KitContents {
    pub origin: String,
    pub login: String,
    pub secret_key: SecretString,
    pub server_fp: [u8; 15],
}

impl EmergencyKit {
    pub(crate) fn new(
        origin: &str,
        login: &str,
        sk: &SecretAscii,
        server_fp: [u8; 15],
    ) -> Result<Self, CoreError> {
        Ok(Self {
            origin: origin.to_owned(),
            login: login.to_owned(),
            server_fingerprint: format_fingerprint(&server_fp),
            secret_key: encode_secret_key(SecretKind::SecretKey, sk)?,
            server_fp,
        })
    }

    pub fn server_fingerprint_bytes(&self) -> [u8; 15] {
        self.server_fp
    }

    pub fn secret_key(&self) -> &str {
        self.secret_key.expose()
    }

    /// The kit asks the user to re-enter the last Secret Key group before it is shown as done
    /// (protocol 4.4).
    pub fn confirm_last_group(&self, group: &str) -> bool {
        let text = self.secret_key.expose();
        let last = text.rsplit('-').next().unwrap_or_default();
        hasp_crypto::ct_eq(
            last.as_bytes(),
            group.trim().to_ascii_uppercase().as_bytes(),
        )
    }

    pub fn qr_blob(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, CoreError> {
        let mut w = Writer::new();
        w.map(5)?;
        w.key(0)?;
        w.uint(KIT_VERSION)?;
        w.key(1)?;
        w.text(&self.origin)?;
        w.key(2)?;
        w.text(&self.login)?;
        w.key(3)?;
        w.text(self.secret_key.expose())?;
        w.key(4)?;
        w.bytes(&self.server_fp)?;
        Ok(zeroize::Zeroizing::new(w.into_bytes()))
    }

    pub fn parse_qr(blob: &[u8]) -> Result<KitContents, CoreError> {
        let mut r = Reader::new(blob);
        let contents = r.map(|r, n| {
            if n != 5 {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(0)?;
            if r.uint()?.get() != KIT_VERSION {
                return Err(hasp_proto::ProtoError::Version);
            }
            r.key(1)?;
            let origin = r.text()?.to_owned();
            r.key(2)?;
            let login = r.text()?.to_owned();
            r.key(3)?;
            let secret_key = SecretString::from(r.text()?);
            r.key(4)?;
            let server_fp = r.fixed()?;
            Ok(KitContents {
                origin,
                login,
                secret_key,
                server_fp,
            })
        })?;
        r.finish()?;
        Ok(contents)
    }
}

pub(crate) fn now_uint(now: u64) -> Result<Uint53, CoreError> {
    Ok(Uint53::new(now.min(Uint53::MAX))?)
}

pub(crate) struct Genesis {
    pub bundle: CommitBundle,
}

pub(crate) struct GenesisInput<'a> {
    pub signing: &'a SigningKey,
    pub record: &'a AccountRecord,
    pub vk: &'a SecretKey,
    pub device: DeviceId,
    pub platform: &'a str,
    pub label: &'a str,
    pub now: u64,
}

pub(crate) fn hidden_overview(hidden: &Hidden, now: u64) -> payload::Overview {
    hidden.overview(now)
}

pub(crate) fn seal_hidden(
    vk: &SecretKey,
    vault: VaultId,
    item: ItemId,
    hidden: &Hidden,
    now: u64,
) -> Result<hasp_proto::ItemWire, CoreError> {
    let overview = payload::encode_overview(&hidden_overview(hidden, now))?;
    let details = payload::encode_hidden(hidden)?;
    Ok(seal_item(
        vk,
        &ItemParams {
            vault_id: vault,
            item_id: item,
            ver: Version::new(1)?,
            epoch: Epoch::ZERO,
            overview: &overview,
            details: &details,
            att_ids: Vec::new(),
            prev_h: None,
        },
    )?)
}

pub(crate) fn private_genesis(
    input: &GenesisInput<'_>,
    vault_id: VaultId,
) -> Result<Genesis, CoreError> {
    let record = input.record;
    let member = Member {
        account_id: record.account_id,
        ik_pk: record.ik_pk,
        kem_pk: record.kem_pk.clone(),
        role: Role::Owner,
        added_rver: Rver::new(1)?,
    };
    let roster = Roster {
        vault_id,
        rver: Rver::new(1)?,
        epoch: Epoch::ZERO,
        prev: None,
        kind: VaultKind::Private,
        members: vec![member],
        vk_commit: vk_commit(input.vk, &vault_id, Epoch::ZERO)?,
    };
    let signed_roster = Signed::sign(SigLabel::Roster, &roster, input.signing)?;
    let settings = seal_hidden(
        input.vk,
        vault_id,
        ItemId::VAULT_SETTINGS,
        &Hidden::Settings(VaultMeta {
            name: "Private".to_owned(),
            icon: String::new(),
            description: String::new(),
        }),
        input.now,
    )?;
    let device = seal_hidden(
        input.vk,
        vault_id,
        ItemId::from_bytes(*input.device.as_bytes()),
        &Hidden::Device(DeviceRecord {
            label: input.label.to_owned(),
            platform: input.platform.to_owned(),
            first_seen: input.now,
            status: DeviceStatus::Active,
        }),
        input.now,
    )?;
    let mut leafset = hasp_proto::LeafSet::new();
    for wire in [&settings, &device] {
        leafset.apply(&ItemOp::from_wire_bytes(&wire.to_cbor()?)?)?;
    }
    let manifest = Manifest {
        vault_id,
        seq: Seq::new(1)?,
        prev: None,
        epoch: Epoch::ZERO,
        rver: Rver::new(1)?,
        roster_hash: signed_roster.hash(),
        root: leafset_root(&leafset)?,
        author: record.account_id,
        repair: false,
    };
    let manifest = Signed::sign(SigLabel::Manifest, &manifest, input.signing)?;
    Ok(Genesis {
        bundle: CommitBundle {
            manifest,
            roster: Some(signed_roster),
            shares: Vec::new(),
            ops: vec![settings, device],
        },
    })
}

pub(crate) fn account_record(
    account_id: AccountId,
    signing: &SigningKey,
    kem: &KemSecretKey,
    kdf: KdfWire,
    now: u64,
) -> Result<(AccountRecord, Signed<AccountRecord>), CoreError> {
    let record = AccountRecord {
        account_id,
        seq: Seq::new(1)?,
        prev: None,
        ik_pk: signing.verifying_key(),
        kem_pk: kem.public_key(),
        kdf,
        status: AccountStatus::Active,
        rc_gen: Uint53::ZERO,
        min_v: Uint53::new(1)?,
        created: now_uint(now)?,
    };
    let signed = Signed::sign(SigLabel::Account, &record, signing)?;
    Ok((record, signed))
}

pub(crate) fn build_keyset(
    account_id: AccountId,
    kdf: &KdfWire,
    auk: &SecretKey,
    ak: &SecretKey,
    keys: &KeysetKeys,
) -> Result<Keyset, CoreError> {
    let generation = Uint53::new(1)?;
    let k_keyset = ak_keys(ak)?.keyset;
    Ok(Keyset {
        account_id,
        generation,
        ak_wrap: SealedRaw::seal(auk, ak.expose(), &Aad::ak_wrap(account_id, kdf, generation))?,
        keys: Sealed::seal(&k_keyset, keys, &Aad::keyset_keys(account_id, generation))?,
    })
}

pub(crate) fn keyset_keys(
    ik_seed: &SecretKey,
    kem_seed: &SecretKey,
    sk: &SecretAscii,
) -> KeysetKeys {
    KeysetKeys {
        ik_seed: copy_key(ik_seed),
        kem_seed: copy_key(kem_seed),
        sk_ascii: SecretBytes::from_vec(sk.expose().to_vec()),
        retired: Vec::new(),
    }
}

struct Established {
    token: hasp_proto::wire::SessionToken,
    server_fp: [u8; 15],
}

struct Prepared {
    token: SignupToken,
    login: String,
    account_id: AccountId,
    device_id: DeviceId,
    ak: SecretKey,
    sk: SecretAscii,
    kdf: KdfWire,
    secrets: crate::keys::AccountSecrets,
    record: AccountRecord,
    signed_record: Signed<AccountRecord>,
    keys: KeysetKeys,
    keyset: Keyset,
    genesis: CommitBundle,
    self_wrap: SealedRaw,
}

impl<T: Transport, S: Store> Client<T, S> {
    fn prepare_sign_up(&self, request: &SignUp<'_>) -> Result<Prepared, CoreError> {
        let now = self.platform.clock.now();
        let account_id = AccountId::from_bytes(self.platform.array()?);
        let device_id = DeviceId::from_bytes(self.platform.array()?);
        let vault_id = VaultId::from_bytes(self.platform.array()?);
        let ak = SecretKey::random()?;
        let ik_seed = SecretKey::random()?;
        let kem_seed = SecretKey::random()?;
        let vk = SecretKey::random()?;
        let sk = SecretAscii::generate()?;
        let kdf = self.config.account_kdf;
        let params = kdf_params(&kdf, self.config.max_kdf_m_kib)?;
        let secrets =
            derive_account_secrets(request.password.expose_secret(), &sk, &account_id, &params)?;
        let signing = SigningKey::from_seed(&ik_seed);
        let kem = KemSecretKey::from_seed(&kem_seed)?;
        let (record, signed_record) = account_record(account_id, &signing, &kem, kdf, now)?;
        let keys = keyset_keys(&ik_seed, &kem_seed, &sk);
        let keyset = build_keyset(account_id, &kdf, &secrets.auk, &ak, &keys)?;
        let genesis = private_genesis(
            &GenesisInput {
                signing: &signing,
                record: &record,
                vk: &vk,
                device: device_id,
                platform: &self.config.platform_name,
                label: "this device",
                now,
            },
            vault_id,
        )?;
        let self_wrap = SealedRaw::seal(
            &ak_keys(&ak)?.self_wrap,
            vk.expose(),
            &Aad::self_wrap(account_id, vault_id, Epoch::ZERO),
        )?;
        Ok(Prepared {
            token: SignupToken::parse(request.token)?,
            login: normalise_login(request.login)?,
            account_id,
            device_id,
            ak,
            sk,
            kdf,
            secrets,
            record,
            signed_record,
            keys,
            keyset,
            genesis: genesis.bundle,
            self_wrap,
        })
    }

    async fn register_account(
        &self,
        request: &SignUp<'_>,
        prepared: &Prepared,
        cancel: &Cancel,
    ) -> Result<[u8; 15], CoreError> {
        let (state, reg_request) = OpaqueClientRegistration::start(&prepared.secrets.opk)?;
        cancel.check()?;
        let response = self
            .transport
            .call(
                None,
                &RegisterStart {
                    token: prepared.token.clone(),
                    login: prepared.login.clone(),
                    account_id: prepared.account_id,
                    request: reg_request.into(),
                },
            )
            .await?;
        let reg_key = OpaqueClientRegistration::response_server_key(response.response.as_slice())?;
        let opaque_record = register_finish(
            state,
            response.response.as_slice(),
            request.origin,
            &prepared.account_id,
        )?;
        cancel.check()?;
        self.transport
            .call(
                None,
                &RegisterFinish {
                    token: prepared.token.clone(),
                    login: prepared.login.clone(),
                    account_id: prepared.account_id,
                    record: opaque_record.into(),
                    account: prepared.signed_record.clone(),
                    keyset: prepared.keyset.clone(),
                    vault: prepared.genesis.clone(),
                    self_wrap: prepared.self_wrap.clone(),
                },
            )
            .await?;
        Ok(super::auth::server_fingerprint(&reg_key))
    }

    /// Protocol 7.1. Returns the Emergency Kit; the caller shows it and requires the user to
    /// confirm it before moving on.
    pub async fn sign_up(
        &mut self,
        request: &SignUp<'_>,
        call: &CancellationToken,
    ) -> Result<EmergencyKit, CoreError> {
        self.sign_up_pinned(request, None, call).await
    }

    /// The fingerprint of the key the server at the origin presents, for the user to compare with
    /// the one `haspd init` printed before `sign_up_pinned` registers anything.
    pub async fn server_fingerprint(
        &self,
        origin: &str,
        call: &CancellationToken,
    ) -> Result<[u8; 15], CoreError> {
        let cancel = self.begin(call);
        cancel.check()?;
        let reply = self
            .transport
            .call(None, &hasp_proto::wire::ServerKey {})
            .await?;
        cancel.check()?;
        let key: [u8; 32] = reply
            .public_key
            .0
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::ServerKey)?;
        if reply.origin != origin {
            return Err(CoreError::ServerKey);
        }
        Ok(super::auth::server_fingerprint(&key))
    }

    /// Like `sign_up`, but when `expected` is set the server key is compared with it before any
    /// registration call, and a mismatch is `ServerKey` with nothing sent.
    pub async fn sign_up_pinned(
        &mut self,
        request: &SignUp<'_>,
        expected: Option<[u8; 15]>,
        call: &CancellationToken,
    ) -> Result<EmergencyKit, CoreError> {
        let cancel = self.begin(call);
        if self.cache.account()?.is_some() {
            return Err(CoreError::Refused("this device already holds an account"));
        }
        if let Some(expected) = &expected {
            super::auth::check_server_key(&self.transport, &cancel, request.origin, expected)
                .await?;
        }
        let prepared = self.prepare_sign_up(request)?;
        let server_fp = Box::pin(self.register_account(request, &prepared, &cancel)).await?;
        let own = OwnKeys {
            account_id: prepared.account_id,
            ik_pk: prepared.record.ik_pk,
            kem_pk: prepared.record.kem_pk.clone(),
            retired_kem_pk_hashes: Vec::new(),
        };
        verify_genesis(
            &crate::sync::proto_commit(&prepared.genesis)?,
            &own,
            &PinState::new(),
        )?;
        let subject = Subject {
            origin: request.origin,
            account: prepared.account_id,
            kdf: &prepared.kdf,
        };
        let device = DeviceInfo {
            device_id: prepared.device_id,
            platform: self.config.platform_name.clone(),
            label: None,
        };
        let done = opaque_login(
            &self.transport,
            &cancel,
            &subject,
            &prepared.secrets.opk,
            device,
        )
        .await?;
        if done.server_fp != server_fp || expected.is_some_and(|fp| fp != server_fp) {
            return Err(CoreError::ServerKey);
        }
        let established = Established {
            token: done.token,
            server_fp,
        };
        Box::pin(self.settle_sign_up(request, prepared, established, &cancel)).await
    }

    async fn settle_sign_up(
        &mut self,
        request: &SignUp<'_>,
        prepared: Prepared,
        established: Established,
        cancel: &Cancel,
    ) -> Result<EmergencyKit, CoreError> {
        let Established { token, server_fp } = established;
        let identity =
            Identity::from_keys(&prepared.record, copy_key(&prepared.ak), &prepared.keys)?;
        let mut local = AccountLocal {
            origin: request.origin.to_owned(),
            login: prepared.login.clone(),
            account_id: prepared.account_id,
            device_id: prepared.device_id,
            server_fp,
            record: prepared.signed_record,
            keyset: prepared.keyset,
            max_seen_v: 1,
            min_v: 1,
            class: if self.platform.secure.hardware_gated() {
                UnlockClass::Hardware
            } else {
                UnlockClass::PasswordOnly
            },
            local_salt: self.platform.array()?,
            local_gen: 0,
            notices_after: 0,
            platform: self.config.platform_name.clone(),
        };
        let mut batch = Batch::new();
        Records::put_meta(&mut batch, "device-confirmed", b"1");
        let material = super::unlock::Material::create(
            &self.platform,
            &self.config,
            &local,
            Some(request.password.expose_secret()),
        )?;
        material.write(
            &mut batch,
            &mut local,
            &super::unlock::LocalSecrets {
                ak: &identity.ak,
                sk: &prepared.sk,
                token: &token,
            },
        )?;
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        self.session = Some(Session {
            identity,
            token,
            opk: Some(copy_key(&prepared.secrets.opk)),
            vks: std::collections::BTreeMap::new(),
            pins: PinState::new(),
        });
        let mut cx = ctx!(self, cancel);
        sync_all(&mut cx).await?;
        EmergencyKit::new(request.origin, &prepared.login, &prepared.sk, server_fp)
    }
}
