use hasp_proto::{ItemId, VaultKind, Wire};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::client::Client;
use crate::client::signup::EmergencyKit;
use crate::export::{self, ExportContent, ExportItem, ExportVault, Protection, Unlock};
use crate::keys::secret_from_slice;
use crate::model::id::Id;
use crate::model::item::Item;
use crate::store::{Batch, LocalVaultStatus, Records, Store};
use crate::transport::Transport;

pub(super) const BACKUP_LABEL: &str = "hasp.backup-key";

#[derive(Debug, PartialEq, Eq)]
pub struct RestoreReport {
    pub vaults: usize,
    pub items: usize,
    pub attachments: usize,
}

impl<T: Transport, S: Store> Client<T, S> {
    fn exported_history(
        &self,
        vault: &hasp_proto::VaultId,
        item: &ItemId,
    ) -> Result<Vec<Item>, CoreError> {
        let session = self.unlocked()?;
        let mut out = Vec::new();
        for (_, epoch, bytes) in self
            .authenticated_versions(vault, item)?
            .into_iter()
            .skip(1)
        {
            let wire = hasp_proto::ItemWire::from_cbor(&bytes)?;
            let Some(vk) = session.vk(vault, epoch) else {
                continue;
            };
            let Ok((overview, details)) = hasp_proto::open_item_unverified(&wire, vk) else {
                continue;
            };
            let Ok(old) = crate::model::wire::decode_item(overview.expose(), details.expose())
            else {
                continue;
            };
            let mut parts = old.into_parts();
            parts.attachments.clear();
            out.push(Item::new(parts)?);
        }
        Ok(out)
    }

    /// Every live item of every active vault with its attachments, from this device's verified
    /// copy. Plain content: the caller seals it (export) or replays it (rehost, restore).
    pub async fn export_content(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<ExportContent, CoreError> {
        let cancel = self.begin(call);
        self.reauth(password, &cancel).await?;
        let mut content = ExportContent {
            vaults: Vec::new(),
            items: Vec::new(),
        };
        for summary in self.vaults()? {
            if summary.status != LocalVaultStatus::Active {
                continue;
            }
            content.vaults.push(ExportVault {
                id: Id::from_bytes(*summary.vault_id.as_bytes()),
                name: summary.name.clone(),
                kind: summary.kind,
            });
            for entry in self.items(&summary.vault_id)? {
                let item = self.item(&summary.vault_id, &entry.item_id)?;
                let mut files = Vec::new();
                for desc in &item.details().attachments {
                    let att = hasp_proto::AttId::from_bytes(*desc.att_id.as_bytes());
                    let data = self
                        .download_attachment(&summary.vault_id, &entry.item_id, &att, call)
                        .await?;
                    files.push(crate::import::AttachedFile {
                        id: desc.att_id,
                        name: desc.name.clone(),
                        mime: desc.mime.clone(),
                        data: secrecy::SecretSlice::from(data.to_vec()),
                    });
                }
                let mut parts = item.into_parts();
                parts.attachments.clear();
                let history = self.exported_history(&summary.vault_id, &entry.item_id)?;
                content.items.push(ExportItem {
                    vault_id: Id::from_bytes(*summary.vault_id.as_bytes()),
                    item_id: Id::from_bytes(*entry.item_id.as_bytes()),
                    item: Item::new(parts)?,
                    history,
                    files,
                });
            }
        }
        Ok(content)
    }

    pub async fn export(
        &mut self,
        password: &SecretString,
        passphrase: &SecretString,
        params: hasp_crypto::Argon2idParams,
        call: &CancellationToken,
    ) -> Result<Vec<u8>, CoreError> {
        let content = self.export_content(password, call).await?;
        let mut out = Vec::new();
        export::write(
            &mut out,
            &content,
            &Protection::Passphrase { passphrase, params },
            self.platform.clock.now(),
        )?;
        Ok(out)
    }

    pub fn enable_backup(
        &mut self,
        passphrase: &SecretString,
        params: hasp_crypto::Argon2idParams,
    ) -> Result<(), CoreError> {
        if !self.platform.secure.hardware_gated() {
            return Err(CoreError::Refused(
                "unattended backup needs a hardware-gated platform",
            ));
        }
        let salt: [u8; 16] = self.platform.array()?;
        let normalised = crate::normalise_password(passphrase.expose_secret());
        let key = hasp_crypto::argon2id(normalised.as_bytes(), &salt, &params)?;
        self.platform.secure.put(BACKUP_LABEL, key.expose())?;
        let mut batch = Batch::new();
        let mut meta = Vec::with_capacity(28);
        meta.extend_from_slice(&salt);
        meta.extend_from_slice(&params.m_kib().to_be_bytes());
        meta.extend_from_slice(&params.t().to_be_bytes());
        meta.extend_from_slice(&params.p().to_be_bytes());
        Records::put_meta(&mut batch, "backup", &meta);
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub async fn backup(
        &mut self,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<Vec<u8>, CoreError> {
        let meta = self
            .cache
            .meta("backup")?
            .ok_or(CoreError::Refused("backups are not enabled"))?;
        let key = secret_from_slice(&self.platform.secure.get(BACKUP_LABEL)?)?;
        let salt: [u8; 16] = meta
            .get(..16)
            .and_then(|b| b.try_into().ok())
            .ok_or(CoreError::Internal("backup meta"))?;
        let number = |at: usize| -> Result<u32, CoreError> {
            meta.get(at..at.saturating_add(4))
                .and_then(|b| b.try_into().ok())
                .map(u32::from_be_bytes)
                .ok_or(CoreError::Internal("backup meta"))
        };
        let params = hasp_crypto::Argon2idParams::local(number(16)?, number(20)?, number(24)?)?;
        let content = self.export_content(password, call).await?;
        let mut out = Vec::new();
        export::write(
            &mut out,
            &content,
            &Protection::BackupKey {
                key: &key,
                params,
                salt,
            },
            self.platform.clock.now(),
        )?;
        Ok(out)
    }

    pub async fn restore(
        &mut self,
        bytes: &[u8],
        unlock: &Unlock<'_>,
        call: &CancellationToken,
    ) -> Result<RestoreReport, CoreError> {
        let content = export::read(bytes, unlock)?;
        self.import_content(content, call).await
    }

    pub async fn import_content(
        &mut self,
        content: ExportContent,
        call: &CancellationToken,
    ) -> Result<RestoreReport, CoreError> {
        let mut map = std::collections::BTreeMap::new();
        let mut report = RestoreReport {
            vaults: 0,
            items: 0,
            attachments: 0,
        };
        for vault in &content.vaults {
            let target = match vault.kind {
                VaultKind::Private => self.private_vault()?,
                VaultKind::Shared => self.create_vault(&vault.name, call).await?,
            };
            map.insert(vault.id, target);
            report.vaults += 1;
        }
        for entry in content.items {
            let target = *map
                .get(&entry.vault_id)
                .ok_or(CoreError::NotFound("export vault"))?;
            let new_id = ItemId::from_bytes(self.platform.array()?);
            let mut parts = entry.item.into_parts();
            for file in &entry.files {
                use secrecy::ExposeSecret as _;
                let desc = self
                    .upload_blob(
                        &target,
                        &new_id,
                        &crate::client::NewAttachment {
                            name: &file.name,
                            mime: &file.mime,
                            data: file.data.expose_secret(),
                        },
                        call,
                    )
                    .await?;
                parts.attachments.push(desc);
                report.attachments += 1;
            }
            let item = Item::new(parts)?;
            self.write_item(&target, new_id, &item)?;
            report.items += 1;
        }
        for target in map.values() {
            self.flush(target, call).await?;
        }
        Ok(report)
    }

    /// Moves this account to a new server by replaying the verified local copy into a new
    /// account there. The chain heads do not carry over: the server's register path starts every
    /// account and vault at sequence 1.
    pub async fn rehost_to<T2: Transport, S2: Store>(
        &mut self,
        target: &mut Client<T2, S2>,
        signup: &crate::client::SignUp<'_>,
        password: &SecretString,
        call: &CancellationToken,
    ) -> Result<EmergencyKit, CoreError> {
        let content = self.export_content(password, call).await?;
        let kit = target.sign_up(signup, call).await?;
        target.import_content(content, call).await?;
        Ok(kit)
    }
}
