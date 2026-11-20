use hasp_proto::payload::{self, DeviceRecord, DeviceStatus, Hidden};
use hasp_proto::wire::{AccountDelete, SessionId, SessionList, SessionRevoke};
use hasp_proto::{
    AccountRecord, AccountStatus, DeviceId, ItemId, Role, SigLabel, Signed, VaultKind,
};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::{Client, ctx};
use crate::store::{Batch, LocalVaultStatus, Store};
use crate::sync::{Edit, flush_vault, queue_put};
use crate::transport::Transport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub platform: String,
    pub current: bool,
    pub recognised: bool,
    pub label: Option<String>,
    pub revoked: bool,
}

impl<T: Transport, S: Store> Client<T, S> {
    pub async fn devices(
        &mut self,
        call: &CancellationToken,
    ) -> Result<Vec<DeviceEntry>, CoreError> {
        let cancel = self.begin(call);
        let listed = {
            let cx = ctx!(self, &cancel);
            cx.call(&SessionList {}).await?
        };
        let private = self.private_vault()?;
        let local = self.local_vault(&private)?;
        let mut out = Vec::new();
        for info in listed.sessions {
            let item_id = ItemId::from_bytes(*info.device_id.as_bytes());
            let record = match self.open_current(&local, &item_id) {
                Ok(Some(opened)) => match payload::decode_hidden(opened.details.expose()) {
                    Ok(Hidden::Device(record)) => Some(record),
                    _ => None,
                },
                _ => None,
            };
            out.push(DeviceEntry {
                session_id: info.session_id,
                device_id: info.device_id,
                platform: info.platform,
                current: info.current,
                recognised: record.is_some(),
                revoked: record
                    .as_ref()
                    .is_some_and(|r| r.status == DeviceStatus::Revoked),
                label: record.map(|r| r.label),
            });
        }
        Ok(out)
    }

    pub(in crate::client) fn own_device_revoked(&self) -> Result<bool, CoreError> {
        let Some(account) = self.cache.account()? else {
            return Ok(false);
        };
        let private = self.private_vault()?;
        let local = self.local_vault(&private)?;
        let item_id = ItemId::from_bytes(*account.device_id.as_bytes());
        let Some(opened) = self.open_current(&local, &item_id)? else {
            return Ok(false);
        };
        Ok(matches!(
            payload::decode_hidden(opened.details.expose()),
            Ok(Hidden::Device(record)) if record.status == DeviceStatus::Revoked
        ))
    }

    pub async fn revoke_device(
        &mut self,
        session_id: &SessionId,
        device_id: &DeviceId,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        {
            let cx = ctx!(self, &cancel);
            cx.call(&SessionRevoke {
                session_id: *session_id,
            })
            .await?;
        }
        let private = self.private_vault()?;
        let local = self.local_vault(&private)?;
        let item_id = ItemId::from_bytes(*device_id.as_bytes());
        let now = self.platform.clock.now();
        let existing = match self.open_current(&local, &item_id)? {
            Some(opened) => match payload::decode_hidden(opened.details.expose())? {
                Hidden::Device(record) => record,
                _ => return Err(CoreError::NotFound("device item")),
            },
            None => DeviceRecord {
                label: "unrecognised".to_owned(),
                platform: String::new(),
                first_seen: now,
                status: DeviceStatus::Active,
            },
        };
        let hidden = Hidden::Device(DeviceRecord {
            status: DeviceStatus::Revoked,
            ..existing
        });
        let overview = payload::encode_overview(&hidden.overview(now))?;
        let details = payload::encode_hidden(&hidden)?;
        let mut kinds = Vec::new();
        {
            let mut cx = ctx!(self, &cancel);
            queue_put(
                &mut cx,
                &local,
                &Edit {
                    item_id,
                    overview: &overview,
                    details: &details,
                    att_ids: Vec::new(),
                },
            )?;
            flush_vault(&mut cx, private, &mut kinds).await?;
        }
        self.store_events(&cancel, kinds)
    }

    pub async fn delete_account(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        for summary in self.vaults()? {
            if summary.kind != VaultKind::Shared || summary.status != LocalVaultStatus::Active {
                continue;
            }
            if summary.role == Role::Owner {
                self.dissolve_vault(&summary.vault_id, &summary.name, password, call)
                    .await?;
            } else {
                self.leave_vault(&summary.vault_id, call).await?;
            }
        }
        self.reauth(password, &cancel).await?;
        let local = self.cache.account()?.ok_or(CoreError::Locked)?;
        let record = local.record.unverified()?;
        let next = AccountRecord {
            seq: record.seq.checked_next()?,
            prev: Some(local.record.hash()),
            status: AccountStatus::Deleted,
            ..record
        };
        let signed = Signed::sign(SigLabel::Account, &next, &self.unlocked()?.identity.signing)?;
        {
            let cx = ctx!(self, &cancel);
            cx.call(&AccountDelete { account: signed }).await?;
        }
        self.wipe_local()
    }

    pub(in crate::client) fn wipe_local(&mut self) -> Result<(), CoreError> {
        let mut batch = Batch::new();
        for tag in *b"ABVIWPQEJM" {
            batch.delete_prefix(vec![tag]);
        }
        self.cache.commit(&batch)?;
        self.platform
            .secure
            .delete(crate::client::unlock::DUK_LABEL)?;
        self.platform.secure.delete(super::backup::BACKUP_LABEL)?;
        self.session = None;
        Ok(())
    }
}
