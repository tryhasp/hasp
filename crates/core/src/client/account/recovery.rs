use hasp_crypto::{Argon2idParams, OpaqueClientRegistration, SecretKey};
use hasp_proto::payload::{self};
use hasp_proto::wire::{
    AccountGet, DeviceInfo, ErrorCode, RcAuthKey, RcSet, RecoverComplete, RecoverFetch,
    RecoverPrelogin, RecoverRegisterStart, RecoverStart, RecoveryId,
};
use hasp_proto::{
    Aad, AccountId, AccountRecord, AccountStatus, DeviceId, Hash32, ItemId, Reader,
    RecoveryEnrolment, SealedRaw, SecretAscii, SecretKind, SecretText, SigLabel, Signed, Uint53,
    Wire, Writer, encode_secret_key, parse_secret_key,
};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::auth::{Subject, opaque_login, register_finish, uniform};
use crate::client::signin::{Adoption, open_account_keys, verify_record_chain};
use crate::client::signup::{EmergencyKit, build_keyset, keyset_keys};
use crate::client::{Client, ctx};
use crate::keys::{
    copy_key, derive_account_secrets, kdf_params, local_key, recovery_keys, secret_from_slice,
};
use crate::model::id::Id;
use crate::model::item::Item;
use crate::store::{Batch, Records, Store};
use crate::transport::{Transport, TransportError};

pub struct RecoveryTicket {
    pub recovery_id: RecoveryId,
    pub release_at: u64,
    account_id: AccountId,
    login: String,
    origin: String,
    rc: SecretAscii,
}

impl std::fmt::Debug for RecoveryTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryTicket(..)")
    }
}

const TICKET_META: &str = "recovery-ticket";
const TICKET_AAD: &[u8] = b"hasp/v1/local/recovery-ticket";
const TICKET_VERSION: u64 = 1;

impl RecoveryTicket {
    fn plain(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, CoreError> {
        let mut w = Writer::new();
        w.array(6)?;
        w.bytes(self.recovery_id.as_bytes())?;
        w.uint(self.release_at)?;
        w.bytes(self.account_id.as_bytes())?;
        w.text(&self.login)?;
        w.text(&self.origin)?;
        w.text(std::str::from_utf8(self.rc.expose()).map_err(|_| hasp_proto::ProtoError::Format)?)?;
        Ok(w.into_zeroizing())
    }

    fn from_plain(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut r = Reader::new(bytes);
        let ticket = r.array(|r, n| {
            if n != 6 {
                return Err(hasp_proto::ProtoError::Format);
            }
            let recovery_id = RecoveryId::from_bytes(r.fixed()?);
            let release_at = r.uint()?.get();
            let account_id = AccountId::from_bytes(r.fixed()?);
            let login = r.text()?.to_owned();
            let origin = r.text()?.to_owned();
            let rc = SecretAscii::from_ascii(r.text()?.as_bytes())?;
            Ok(Self {
                recovery_id,
                release_at,
                account_id,
                login,
                origin,
                rc,
            })
        })?;
        r.finish()?;
        Ok(ticket)
    }
}

pub struct RecoveryOutcome {
    pub kit: EmergencyKit,
    pub recovery_code: SecretText,
}

impl std::fmt::Debug for RecoveryOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryOutcome(..)")
    }
}

struct Replacement {
    ak: SecretKey,
    sk: SecretAscii,
    secrets: crate::keys::AccountSecrets,
    keyset: hasp_proto::Keyset,
    rc: RcMaterial,
    account: Signed<AccountRecord>,
    kdf: hasp_proto::KdfWire,
}

struct RcMaterial {
    set: RcSet,
    text: SecretText,
}

fn rc_material(
    ak: &SecretKey,
    account_id: AccountId,
    signing: &hasp_crypto::SigningKey,
    latest: &Signed<AccountRecord>,
    status: AccountStatus,
) -> Result<(RcMaterial, Signed<AccountRecord>, SecretAscii), CoreError> {
    let rc = SecretAscii::generate()?;
    let record = latest.unverified()?;
    let rgen = record.rc_gen.checked_next()?;
    let keys = recovery_keys(&rc, &account_id)?;
    let rc_wrap = SealedRaw::seal(
        &keys.wrap,
        ak.expose(),
        &Aad::recovery_wrap(account_id, rgen),
    )?;
    let body = RecoveryEnrolment {
        account_id,
        rgen,
        h_wrap: Hash32::digest(&[&rc_wrap.to_cbor()?]),
    };
    let signed_rc = Signed::sign(SigLabel::Recovery, &body, signing)?;
    let next = AccountRecord {
        seq: record.seq.checked_next()?,
        prev: Some(latest.hash()),
        rc_gen: rgen,
        status,
        ..record
    };
    let account = Signed::sign(SigLabel::Account, &next, signing)?;
    let auth = RcAuthKey::from_bytes(*keys.auth.expose());
    let text = encode_secret_key(SecretKind::RecoveryCode, &rc)?;
    Ok((
        RcMaterial {
            set: RcSet {
                rc: signed_rc,
                rc_wrap,
                h_auth: auth.hash(),
                account: account.clone(),
            },
            text,
        },
        account,
        rc,
    ))
}

impl<T: Transport, S: Store> Client<T, S> {
    /// Protocol 7.11 create: a fresh Recovery Code, shown once. Replaces any earlier one.
    pub async fn create_recovery_code(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<SecretText, CoreError> {
        let cancel = self.begin(call);
        self.reauth(password, &cancel).await?;
        let mut local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let (material, account, _) = {
            let session = self.unlocked()?;
            rc_material(
                &session.identity.ak,
                local.account_id,
                &session.identity.signing,
                &local.record,
                AccountStatus::Active,
            )?
        };
        {
            let cx = ctx!(self, &cancel);
            cx.call(&material.set).await?;
        }
        local.record = account;
        let mut batch = Batch::new();
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(material.text)
    }

    /// Protocol 7.11 use, step 1 to 2: prove possession of the code to the server and start the
    /// delay. Notices go to the account's other devices; any normal sign-in aborts the recovery.
    pub async fn recover_start(
        &mut self,
        origin: &str,
        login: &str,
        recovery_code: &str,
    ) -> Result<RecoveryTicket, CoreError> {
        let (kind, rc) = parse_secret_key(recovery_code)?;
        if kind != SecretKind::RecoveryCode {
            return Err(hasp_proto::ProtoError::Format.into());
        }
        let login = crate::normalise_login(login)?;
        let pre = self
            .transport
            .call(
                None,
                &RecoverPrelogin {
                    login: login.clone(),
                },
            )
            .await?;
        let keys = recovery_keys(&rc, &pre.account_id)?;
        let started = self
            .transport
            .call(
                None,
                &RecoverStart {
                    account_id: pre.account_id,
                    k_rc_auth: RcAuthKey::from_bytes(*keys.auth.expose()),
                },
            )
            .await
            .map_err(CoreError::from)
            .map_err(uniform)?;
        Ok(RecoveryTicket {
            recovery_id: started.recovery_id,
            release_at: started.release_at.get(),
            account_id: pre.account_id,
            login,
            origin: origin.to_owned(),
            rc,
        })
    }

    /// Keeps a started recovery across process exits. The ticket holds the Recovery Code, so it
    /// is sealed under a key stretched from `password`, the new password the user will set when
    /// the recovery finishes. Nothing in the store opens without it.
    pub fn save_recovery_ticket(
        &mut self,
        ticket: &RecoveryTicket,
        password: &SecretString,
    ) -> Result<(), CoreError> {
        let params = Argon2idParams::local(
            self.config.local_kdf.m,
            self.config.local_kdf.t,
            self.config.local_kdf.p,
        )?;
        let salt: [u8; 16] = self.platform.array()?;
        let key = local_key(password.expose_secret(), &salt, &params)?;
        let sealed = hasp_crypto::seal(&key, &ticket.plain()?, TICKET_AAD)?;
        let mut w = Writer::new();
        w.array(7)?;
        w.uint(TICKET_VERSION)?;
        w.uint(u64::from(self.config.local_kdf.m))?;
        w.uint(u64::from(self.config.local_kdf.t))?;
        w.uint(u64::from(self.config.local_kdf.p))?;
        w.bytes(&salt)?;
        w.bytes(&sealed.nonce)?;
        w.bytes(&sealed.ct)?;
        let mut batch = Batch::new();
        Records::put_meta(&mut batch, TICKET_META, &w.into_bytes());
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub fn has_recovery_ticket(&self) -> Result<bool, CoreError> {
        Ok(self.cache.meta(TICKET_META)?.is_some())
    }

    /// `Credentials` when `password` is not the one the ticket was saved under.
    pub fn load_recovery_ticket(
        &self,
        password: &SecretString,
    ) -> Result<Option<RecoveryTicket>, CoreError> {
        let Some(stored) = self.cache.meta(TICKET_META)? else {
            return Ok(None);
        };
        let mut r = Reader::new(&stored);
        let (m, t, p, salt, nonce, ct) = r.array(|r, n| {
            if n != 7 {
                return Err(hasp_proto::ProtoError::Format);
            }
            if r.uint()?.get() != TICKET_VERSION {
                return Err(hasp_proto::ProtoError::Version);
            }
            let m = u32::try_from(r.uint()?.get()).map_err(|_| hasp_proto::ProtoError::Format)?;
            let t = u32::try_from(r.uint()?.get()).map_err(|_| hasp_proto::ProtoError::Format)?;
            let p = u32::try_from(r.uint()?.get()).map_err(|_| hasp_proto::ProtoError::Format)?;
            let salt: [u8; 16] = r.fixed()?;
            let nonce: [u8; 24] = r.fixed()?;
            Ok((m, t, p, salt, nonce, r.bytes()?.to_vec()))
        })?;
        r.finish()?;
        let params = Argon2idParams::local(m, t, p)?;
        params.within_capability(self.config.max_kdf_m_kib)?;
        let key = local_key(password.expose_secret(), &salt, &params)?;
        let plain =
            hasp_crypto::open(&key, &nonce, &ct, TICKET_AAD).map_err(|_| CoreError::Credentials)?;
        RecoveryTicket::from_plain(plain.expose()).map(Some)
    }

    pub fn discard_recovery_ticket(&mut self) -> Result<(), CoreError> {
        let mut batch = Batch::new();
        Records::delete_meta(&mut batch, TICKET_META);
        self.cache.commit(&batch)?;
        Ok(())
    }

    async fn fetch_recovery(
        &self,
        ticket: &RecoveryTicket,
    ) -> Result<hasp_proto::wire::RecoverFetchResponse, CoreError> {
        let keys = recovery_keys(&ticket.rc, &ticket.account_id)?;
        let fetched = self
            .transport
            .call(
                None,
                &RecoverFetch {
                    recovery_id: ticket.recovery_id,
                    k_rc_auth: RcAuthKey::from_bytes(*keys.auth.expose()),
                },
            )
            .await;
        match fetched {
            Ok(fetched) => Ok(fetched),
            Err(TransportError::Server(wire)) if wire.code == ErrorCode::Pending => {
                Err(CoreError::Pending {
                    retry_after: wire.retry_after.map_or(0, Uint53::get),
                })
            }
            Err(other) => Err(uniform(other.into())),
        }
    }

    fn open_recovery(
        &self,
        ticket: &RecoveryTicket,
        fetched: &hasp_proto::wire::RecoverFetchResponse,
        new_password: &SecretString,
    ) -> Result<Replacement, CoreError> {
        let keys = recovery_keys(&ticket.rc, &ticket.account_id)?;
        let (latest, record) = verify_record_chain(&fetched.records)?;
        let enrolment = fetched
            .enrolment
            .verify(SigLabel::Recovery, &record.ik_pk)?;
        if enrolment.rgen != record.rc_gen
            || enrolment.account_id != ticket.account_id
            || enrolment.h_wrap != Hash32::digest(&[&fetched.rc_wrap.to_cbor()?])
        {
            return Err(hasp_proto::ProtoError::Rollback.into());
        }
        let ak = fetched
            .rc_wrap
            .open(
                &keys.wrap,
                &Aad::recovery_wrap(ticket.account_id, enrolment.rgen),
            )
            .map_err(|_| CoreError::Credentials)?;
        let ak = secret_from_slice(&ak)?;
        let old_keys = open_account_keys(&record, &fetched.keyset, &ak)?;
        let identity = crate::session::Identity::from_keys(&record, copy_key(&ak), &old_keys)?;
        let sk = SecretAscii::generate()?;
        let params = kdf_params(&record.kdf, self.config.max_kdf_m_kib)?;
        let secrets = derive_account_secrets(
            new_password.expose_secret(),
            &sk,
            &ticket.account_id,
            &params,
        )?;
        let new_keys = keyset_keys(&old_keys.ik_seed, &old_keys.kem_seed, &sk);
        let keyset = build_keyset(ticket.account_id, &record.kdf, &secrets.auk, &ak, &new_keys)?;
        let (rc, account, _) = rc_material(
            &ak,
            ticket.account_id,
            &identity.signing,
            &latest,
            AccountStatus::Active,
        )?;
        Ok(Replacement {
            ak,
            sk,
            secrets,
            keyset,
            rc,
            account,
            kdf: record.kdf,
        })
    }

    /// Protocol 7.11 steps 3 and 4. Before the delay ends this returns `Pending`. The device that
    /// completes it is unconfirmed (protocol 7.3).
    pub async fn recover_finish(
        &mut self,
        ticket: &RecoveryTicket,
        new_password: &SecretString,
        call: &CancellationToken,
    ) -> Result<RecoveryOutcome, CoreError> {
        let cancel = self.begin(call);
        if self.cache.account()?.is_some() {
            return Err(CoreError::Refused("this device already holds an account"));
        }
        let fetched = self.fetch_recovery(ticket).await?;
        let replacement = self.open_recovery(ticket, &fetched, new_password)?;
        let opaque_record = self
            .register_replacement(ticket, &fetched.token, &replacement)
            .await?;
        let device_id = DeviceId::from_bytes(self.platform.array()?);
        let device = DeviceInfo {
            device_id,
            platform: self.config.platform_name.clone(),
            label: None,
        };
        self.transport
            .call(
                Some(&fetched.token),
                &RecoverComplete {
                    recovery_id: ticket.recovery_id,
                    record: opaque_record.into(),
                    keyset: replacement.keyset.clone(),
                    account: replacement.account.clone(),
                    rc: replacement.rc.set.rc.clone(),
                    rc_wrap: replacement.rc.set.rc_wrap.clone(),
                    h_auth: replacement.rc.set.h_auth,
                    device: device.clone(),
                },
            )
            .await?;
        let subject = Subject {
            origin: &ticket.origin,
            account: ticket.account_id,
            kdf: &replacement.kdf,
        };
        let logged_in = opaque_login(
            &self.transport,
            &cancel,
            &subject,
            &replacement.secrets.opk,
            device,
        )
        .await?;
        let account = self
            .transport
            .call(Some(&logged_in.token), &AccountGet {})
            .await?;
        let kit = EmergencyKit::new(
            &ticket.origin,
            &ticket.login,
            &replacement.sk,
            logged_in.server_fp,
        )?;
        let recovery_code = replacement.rc.text;
        self.adopt(
            Adoption {
                origin: ticket.origin.clone(),
                login: ticket.login.clone(),
                device_id,
                server_fp: logged_in.server_fp,
                token: logged_in.token,
                ak: replacement.ak,
                password: Some(SecretString::from(new_password.expose_secret())),
                opk: Some(replacement.secrets.opk),
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
        .await?;
        self.discard_recovery_ticket()?;
        Ok(RecoveryOutcome { kit, recovery_code })
    }

    async fn register_replacement(
        &self,
        ticket: &RecoveryTicket,
        token: &hasp_proto::wire::SessionToken,
        replacement: &Replacement,
    ) -> Result<Vec<u8>, CoreError> {
        let (state, request) = OpaqueClientRegistration::start(&replacement.secrets.opk)?;
        let response = self
            .transport
            .call(
                Some(token),
                &RecoverRegisterStart {
                    recovery_id: ticket.recovery_id,
                    request: request.into(),
                },
            )
            .await?;
        register_finish(
            state,
            response.response.as_slice(),
            &ticket.origin,
            &ticket.account_id,
        )
    }

    /// Protocol 7.12: a shared vault `Recovery` holding the current code, for the family organizer
    /// to be invited into as a viewer. Opt-in; the UI states the trade-offs first.
    pub async fn family_recovery_setup(
        &mut self,
        recovery_code: &str,
        call: &CancellationToken,
    ) -> Result<(hasp_proto::VaultId, ItemId), CoreError> {
        let vault = self.create_vault("Recovery", call).await?;
        let item = self.store_recovery_item(&vault, None, recovery_code)?;
        self.flush(&vault, call).await?;
        Ok((vault, item))
    }

    pub async fn family_recovery_update(
        &mut self,
        vault: &hasp_proto::VaultId,
        item: &ItemId,
        recovery_code: &str,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        self.store_recovery_item(vault, Some(*item), recovery_code)?;
        self.flush(vault, call).await?;
        Ok(())
    }

    fn store_recovery_item(
        &mut self,
        vault: &hasp_proto::VaultId,
        item: Option<ItemId>,
        recovery_code: &str,
    ) -> Result<ItemId, CoreError> {
        use crate::model::field::{Field, FieldValue, Section};
        use crate::model::item::{ItemParts, ItemState};
        let now = self.platform.clock.now();
        let field = Field::new(
            Id::from_bytes(self.platform.array()?),
            "Recovery code",
            FieldValue::Concealed(SecretString::from(recovery_code)),
        )?
        .with_concealed(true);
        let section = Section::new(Id::from_bytes(self.platform.array()?), "", vec![field])?;
        let parts = ItemParts {
            kind: payload::KIND_RECOVERY.to_owned(),
            title: "Recovery code".to_owned(),
            subtitle: String::new(),
            tags: Vec::new(),
            favourite: None,
            state: ItemState::Active,
            sections: vec![section],
            notes: None,
            urls: Vec::new(),
            apps: Vec::new(),
            passkeys: Vec::new(),
            attachments: Vec::new(),
            password_history: Vec::new(),
            client_modified: now,
            created: now,
            expires_at: None,
        };
        let item_value = Item::new(parts)?;
        match item {
            Some(id) => {
                self.edit_item(vault, &id, &item_value)?;
                Ok(id)
            }
            None => self.create_item(vault, &item_value),
        }
    }
}
