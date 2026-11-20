mod backup;
mod devices;
mod recovery;
mod reregister;

pub use backup::RestoreReport;
pub use devices::DeviceEntry;
pub use recovery::{RecoveryOutcome, RecoveryTicket};

use hasp_crypto::OpaqueClientRegistration;
use hasp_proto::wire::{AccountGet, ChangeCredentialFinish, ChangeCredentialStart};
use hasp_proto::{AccountSeen, PinState, SecretAscii, verify_account_record};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::auth::{Subject, opaque_reauth, register_finish};
use crate::client::signin::open_account_keys;
use crate::client::signup::{EmergencyKit, build_keyset, keyset_keys};
use crate::client::{Client, ctx};
use crate::keys::{copy_key, derive_account_secrets, kdf_params};
use crate::session::Cancel;
use crate::store::{Batch, Records, Store};
use crate::transport::Transport;

impl<T: Transport, S: Store> Client<T, S> {
    pub(crate) async fn reauth(
        &mut self,
        password: &SecretString,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let record = local.record.unverified()?;
        let (ak, token) = {
            let session = self.unlocked()?;
            (copy_key(&session.identity.ak), session.token.clone())
        };
        let keys = Self::open_keys(&local, &ak)?;
        let sk = SecretAscii::from_ascii(keys.sk_ascii.expose())?;
        let params = kdf_params(&record.kdf, self.config.max_kdf_m_kib)?;
        let secrets =
            derive_account_secrets(password.expose_secret(), &sk, &local.account_id, &params)?;
        opaque_reauth(
            &self.transport,
            cancel,
            &token,
            &Subject {
                origin: &local.origin,
                account: local.account_id,
                kdf: &record.kdf,
            },
            &secrets.opk,
        )
        .await
    }

    /// Protocol 4.4: the Emergency Kit of an unlocked account, as text and as a printable PDF.
    /// Asks for the last Secret Key group, so a kit is never produced for someone who only holds
    /// an unlocked session.
    pub fn emergency_kit(&self, last_group: &str) -> Result<super::KitDocument, CoreError> {
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let ak = copy_key(&self.unlocked()?.identity.ak);
        let keys = Self::open_keys(&local, &ak)?;
        let sk = SecretAscii::from_ascii(keys.sk_ascii.expose())?;
        let kit = EmergencyKit::new(&local.origin, &local.login, &sk, local.server_fp)?;
        if !kit.confirm_last_group(last_group) {
            return Err(CoreError::Refused(
                "the last group of the Secret Key does not match",
            ));
        }
        kit.document(self.platform.clock.now())
    }

    pub async fn admin_create_token(
        &mut self,
        call: &CancellationToken,
    ) -> Result<String, CoreError> {
        let cancel = self.begin(call);
        let cx = ctx!(self, &cancel);
        let reply = cx
            .call(&hasp_proto::wire::AdminTokenCreate {
                kind: hasp_proto::wire::TokenKind::Signup,
            })
            .await?;
        Ok(reply.token.to_text())
    }

    /// Protocol 7.4. Re-wraps AK under the new password (and optionally a new Secret Key) and
    /// uploads the new OPAQUE record atomically; the server revokes every other session.
    pub async fn change_password(
        &mut self,
        current: &SecretString,
        new: &SecretString,
        new_secret_key: bool,
        call: &CancellationToken,
    ) -> Result<Option<EmergencyKit>, CoreError> {
        let cancel = self.begin(call);
        self.reauth(current, &cancel).await?;
        let mut local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let record = local.record.unverified()?;
        let ak = copy_key(&self.unlocked()?.identity.ak);
        let old_keys = Self::open_keys(&local, &ak)?;
        let sk = if new_secret_key {
            SecretAscii::generate()?
        } else {
            SecretAscii::from_ascii(old_keys.sk_ascii.expose())?
        };
        let params = kdf_params(&record.kdf, self.config.max_kdf_m_kib)?;
        let secrets = derive_account_secrets(new.expose_secret(), &sk, &local.account_id, &params)?;
        let keys = keyset_keys(&old_keys.ik_seed, &old_keys.kem_seed, &sk);
        let keyset = build_keyset(local.account_id, &record.kdf, &secrets.auk, &ak, &keys)?;
        let (state, request) = OpaqueClientRegistration::start(&secrets.opk)?;
        let response = {
            let cx = ctx!(self, &cancel);
            cx.call(&ChangeCredentialStart {
                request: request.into(),
            })
            .await?
        };
        let opaque_record = register_finish(
            state,
            response.response.as_slice(),
            &local.origin,
            &local.account_id,
        )?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&ChangeCredentialFinish {
                record: opaque_record.into(),
                keyset: keyset.clone(),
                account: None,
            })
            .await?;
        }
        local.keyset = keyset;
        let token = self.unlocked()?.token.clone();
        let mut batch = Batch::new();
        let material = super::unlock::Material::create_existing(
            &self.platform,
            &self.config,
            &local,
            new.expose_secret(),
        )?;
        material.write(
            &mut batch,
            &mut local,
            &super::unlock::LocalSecrets {
                ak: &ak,
                sk: &sk,
                token: &token,
            },
        )?;
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        if let Some(session) = self.session.as_mut() {
            session.opk = Some(secrets.opk);
        }
        if new_secret_key {
            let server_fp = local.server_fp;
            return EmergencyKit::new(&local.origin, &local.login, &sk, server_fp).map(Some);
        }
        Ok(None)
    }

    /// Protocol 5.1 and 5.2: fetch the account record chain and keyset again and refuse any that
    /// is older than, or forks from, what this device already verified. A newer record is adopted
    /// only if its identity keys are unchanged and the keyset still opens under this device's key.
    pub(super) async fn refresh_account(&mut self, cancel: &Cancel) -> Result<(), CoreError> {
        let mut local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let reply = {
            let cx = ctx!(self, cancel);
            cx.call(&AccountGet {}).await?
        };
        let held = local.record.unverified()?;
        let mut seen = Some(AccountSeen {
            seq: held.seq,
            hash: local.record.hash(),
        });
        let mut newest = None;
        for rec in &reply.records {
            if rec.unverified()?.seq < held.seq {
                continue;
            }
            let record = verify_account_record(rec, seen.as_ref(), &PinState::new())?;
            seen = Some(AccountSeen {
                seq: record.seq,
                hash: rec.hash(),
            });
            newest = Some((rec.clone(), record));
        }
        let (signed, record) = newest.ok_or(hasp_proto::ProtoError::Rollback)?;
        if record.account_id != held.account_id
            || record.ik_pk != held.ik_pk
            || record.kem_pk != held.kem_pk
        {
            return Err(hasp_proto::ProtoError::Pin.into());
        }
        if record.seq < held.seq || reply.keyset.generation < local.keyset.generation {
            return Err(hasp_proto::ProtoError::Rollback.into());
        }
        let ak = copy_key(&self.unlocked()?.identity.ak);
        open_account_keys(&record, &reply.keyset, &ak)?;
        if signed.hash() == local.record.hash() && reply.keyset == local.keyset {
            return Ok(());
        }
        local.record = signed;
        local.keyset = reply.keyset;
        local.min_v = record.min_v.get();
        let mut batch = Batch::new();
        Records::put_account(&mut batch, &local)?;
        self.cache.commit(&batch)?;
        Ok(())
    }
}
