use hasp_proto::{Role, VaultKind};

use super::convert::{detail_of, parts_from_draft, row_of_summary, secret_text, state_of};
use super::engine::Engine;
use super::{
    AttachmentUpload, AttachmentView, Category, EventKind, FieldDraft, HistoryRow, ItemDetail,
    ItemDraft, ItemRef, ItemRow, ItemStatus, SearchQuery, Secret, SectionDraft, TotpCode,
    VaultInfo,
};
use super::{ids, search};
use crate::CoreError;
use crate::client::NewAttachment;
use crate::model::field::{FieldKind, FieldValue, Purpose, Section};
use crate::model::item::{Item, ItemParts};
use crate::otp::OtpKind;
use crate::store::{LocalVaultStatus, Store};
use crate::transport::Transport;

fn vault_info(summary: crate::client::VaultSummary) -> VaultInfo {
    VaultInfo {
        id: ids::hex(summary.vault_id.as_bytes()),
        name: summary.name,
        kind: match summary.kind {
            VaultKind::Private => "private",
            VaultKind::Shared => "shared",
        }
        .to_owned(),
        role: match summary.role {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Owner => "owner",
        }
        .to_owned(),
        confirmed: summary.confirmed,
        quarantined: summary.quarantined,
        repair_pending: summary.repair_pending,
        members: u32::try_from(summary.members).unwrap_or(u32::MAX),
        writable: summary.role.can_write()
            && summary.status == LocalVaultStatus::Active
            && !summary.quarantined,
    }
}

impl<T: Transport, S: Store> Engine<T, S> {
    pub async fn vaults(&self) -> Result<Vec<VaultInfo>, CoreError> {
        let client = self.client.lock().await;
        Ok(client
            .vaults()?
            .into_iter()
            .filter(|v| v.status == LocalVaultStatus::Active)
            .map(vault_info)
            .collect())
    }

    pub async fn items(&self, vault: &str) -> Result<Vec<ItemRow>, CoreError> {
        let id = ids::vault(vault)?;
        let client = self.client.lock().await;
        Ok(Self::loaded_items(&client, &id)?
            .iter()
            .map(|(summary, item)| row_of_summary(summary, item))
            .collect())
    }

    pub(super) fn loaded_items(
        client: &crate::client::Client<T, S>,
        vault: &hasp_proto::VaultId,
    ) -> Result<Vec<(crate::client::ItemSummary, Item)>, CoreError> {
        Ok(client
            .items(vault)?
            .into_iter()
            .filter_map(|summary| {
                let item = client.item(&summary.vault_id, &summary.item_id).ok()?;
                Some((summary, item))
            })
            .collect())
    }

    pub async fn search(&self, query: SearchQuery) -> Result<Vec<ItemRow>, CoreError> {
        let client = self.client.lock().await;
        let mut rows = Vec::new();
        for vault in client.vaults()? {
            if vault.status != LocalVaultStatus::Active || vault.quarantined {
                continue;
            }
            let wanted = match &query.vault {
                Some(text) => ids::vault(text)? == vault.vault_id,
                None => true,
            };
            if wanted {
                rows.extend(
                    Self::loaded_items(&client, &vault.vault_id)?
                        .iter()
                        .map(|(summary, item)| row_of_summary(summary, item)),
                );
            }
        }
        Ok(search::run(&self.matcher, rows, &query))
    }

    pub async fn item_detail(&self, vault: &str, item: &str) -> Result<ItemDetail, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let client = self.client.lock().await;
        let loaded = client.item(&vault_id, &item_id)?;
        let (version, pending) = client.item_version(&vault_id, &item_id)?;
        Ok(detail_of(&vault_id, &item_id, &loaded, version, pending))
    }

    /// The raw value of one field, for reveal, copy or fill. This and `totp` are the only
    /// calls that hand out a stored secret besides `fill_payload`.
    pub async fn reveal_field(
        &self,
        vault: &str,
        item: &str,
        field: &str,
    ) -> Result<Secret, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let wanted = ids::item(field)?;
        let client = self.client.lock().await;
        let loaded = client.item(&vault_id, &item_id)?;
        loaded
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .find(|f| f.id().as_bytes() == wanted.as_bytes())
            .map(secret_text)
            .ok_or(CoreError::NotFound("field"))
    }

    pub async fn create_item(&self, vault: &str, draft: ItemDraft) -> Result<ItemRef, CoreError> {
        let vault_id = ids::vault(vault)?;
        let mut client = self.client.lock().await;
        let parts = parts_from_draft(draft, None, client.now())?;
        let item = self.finish(parts)?;
        let id = client.create_item(&vault_id, &item)?;
        self.emit(EventKind::VaultChanged);
        Ok(ItemRef {
            vault: vault.to_owned(),
            item: ids::hex(id.as_bytes()),
        })
    }

    pub async fn edit_item(
        &self,
        vault: &str,
        item: &str,
        draft: ItemDraft,
    ) -> Result<(), CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let mut client = self.client.lock().await;
        let previous = client.item(&vault_id, &item_id)?.into_parts();
        let parts = parts_from_draft(draft, Some(previous), client.now())?;
        let updated = self.finish(parts)?;
        client.edit_item(&vault_id, &item_id, &updated)?;
        self.emit(EventKind::VaultChanged);
        Ok(())
    }

    pub async fn set_status(
        &self,
        vault: &str,
        item: &str,
        status: ItemStatus,
    ) -> Result<(), CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let mut client = self.client.lock().await;
        let now = client.now();
        let updated = client
            .item(&vault_id, &item_id)?
            .with_state(state_of(status, now), now);
        client.edit_item(&vault_id, &item_id, &updated)?;
        self.emit(EventKind::VaultChanged);
        Ok(())
    }

    pub async fn set_favourite(
        &self,
        vault: &str,
        item: &str,
        favourite: bool,
    ) -> Result<(), CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let mut client = self.client.lock().await;
        let now = client.now();
        let updated = client
            .item(&vault_id, &item_id)?
            .with_favourite(favourite.then_some(0), now);
        client.edit_item(&vault_id, &item_id, &updated)?;
        self.emit(EventKind::VaultChanged);
        Ok(())
    }

    pub async fn delete_item(&self, vault: &str, item: &str) -> Result<(), CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let mut client = self.client.lock().await;
        client.delete_item(&vault_id, &item_id)?;
        self.emit(EventKind::VaultChanged);
        Ok(())
    }

    pub async fn history(&self, vault: &str, item: &str) -> Result<Vec<HistoryRow>, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let client = self.client.lock().await;
        Ok(client
            .history(&vault_id, &item_id)?
            .into_iter()
            .map(|h| HistoryRow {
                version: h.version,
                epoch: h.epoch,
                title: h.title,
                modified: h.client_modified,
            })
            .collect())
    }

    pub async fn restore_version(
        &self,
        vault: &str,
        item: &str,
        version: u64,
    ) -> Result<(), CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let mut client = self.client.lock().await;
        client.restore_version(&vault_id, &item_id, version)?;
        self.emit(EventKind::VaultChanged);
        Ok(())
    }

    pub async fn totp(
        &self,
        vault: &str,
        item: &str,
        field: Option<String>,
    ) -> Result<TotpCode, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let wanted = field.as_deref().map(ids::item).transpose()?;
        let client = self.client.lock().await;
        let loaded = client.item(&vault_id, &item_id)?;
        let params = loaded
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .filter(|f| match &wanted {
                Some(id) => f.id().as_bytes() == id.as_bytes(),
                None => f.kind() == FieldKind::Otp || f.purpose() == Some(Purpose::Totp),
            })
            .find_map(|f| match f.value() {
                FieldValue::Otp(params) => Some(params),
                _ => None,
            })
            .ok_or(CoreError::NotFound("otp field"))?;
        let now = client.now();
        let OtpKind::Totp { period_s } = params.kind() else {
            return Err(CoreError::Refused("counter based code"));
        };
        Ok(TotpCode {
            code: Secret::new(
                secrecy::ExposeSecret::expose_secret(&params.code_at(now)?)
                    .as_bytes()
                    .to_vec(),
            ),
            remaining: params.seconds_remaining(now)?,
            period: period_s,
            digits: u32::from(params.digits()),
        })
    }

    pub async fn attach_file(
        &self,
        vault: &str,
        item: &str,
        upload: AttachmentUpload,
    ) -> Result<AttachmentView, CoreError> {
        let (vault_id, item_id) = (ids::vault(vault)?, ids::item(item)?);
        let mut client = self.client.lock().await;
        let info = client
            .attach_file(
                &vault_id,
                &item_id,
                &NewAttachment {
                    name: &upload.name,
                    mime: &upload.mime,
                    data: upload.data.as_bytes(),
                },
                &Self::token(),
            )
            .await?;
        self.emit(EventKind::VaultChanged);
        Ok(AttachmentView {
            id: ids::hex(info.att_id.as_bytes()),
            name: info.name,
            mime: info.mime,
            size: info.size,
        })
    }

    pub async fn download_attachment(
        &self,
        vault: &str,
        item: &str,
        attachment: &str,
    ) -> Result<Secret, CoreError> {
        let (vault_id, item_id, att) = (
            ids::vault(vault)?,
            ids::item(item)?,
            ids::attachment(attachment)?,
        );
        let mut client = self.client.lock().await;
        let bytes = client
            .download_attachment(&vault_id, &item_id, &att, &Self::token())
            .await?;
        Ok(Secret::from_slice(&bytes))
    }

    pub async fn remove_attachment(
        &self,
        vault: &str,
        item: &str,
        attachment: &str,
    ) -> Result<(), CoreError> {
        let (vault_id, item_id, att) = (
            ids::vault(vault)?,
            ids::item(item)?,
            ids::attachment(attachment)?,
        );
        let mut client = self.client.lock().await;
        let now = client.now();
        let mut parts = client.item(&vault_id, &item_id)?.into_parts();
        parts
            .attachments
            .retain(|a| a.att_id.as_bytes() != att.as_bytes());
        parts.client_modified = now;
        let updated = Item::new(parts)?;
        client.edit_item(&vault_id, &item_id, &updated)?;
        self.emit(EventKind::VaultChanged);
        Ok(())
    }

    pub fn categories(&self) -> Vec<Category> {
        self.templates
            .iter()
            .map(|t| Category {
                id: t.id.clone(),
                name_en: t.name.en.clone(),
                name_ko: t.name.ko.clone(),
                icon: t.icon.clone(),
                autofill: format!("{:?}", t.capabilities.autofill).to_lowercase(),
            })
            .collect()
    }

    pub fn blank_draft(&self, kind: &str) -> Result<ItemDraft, CoreError> {
        let template = self.templates.resolve(kind)?;
        let sections = template
            .sections
            .iter()
            .map(|section| SectionDraft {
                id: None,
                title: section
                    .title
                    .as_ref()
                    .map(|t| t.en.clone())
                    .unwrap_or_default(),
                fields: section
                    .fields
                    .iter()
                    .map(|field| FieldDraft {
                        id: None,
                        label: field.label.en.clone(),
                        kind: super::convert::kind_name(field.kind).to_owned(),
                        purpose: field
                            .purpose
                            .map(|p| super::convert::purpose_name(p).to_owned()),
                        concealed: field.concealed
                            || matches!(
                                field.kind,
                                FieldKind::Concealed | FieldKind::Otp | FieldKind::SecurityQuestion
                            ),
                        expires_alert: field.expires_alert_default,
                        value: Secret::new(Vec::new()),
                        keep_value: false,
                    })
                    .collect(),
            })
            .collect();
        Ok(ItemDraft {
            kind: template.id.clone(),
            title: String::new(),
            subtitle: String::new(),
            tags: Vec::new(),
            favourite: false,
            notes: None,
            expires_at: None,
            sections,
            urls: Vec::new(),
        })
    }

    pub(super) fn finish(&self, parts: ItemParts) -> Result<Item, CoreError> {
        let item = Item::new(parts)?;
        let kind = self
            .templates
            .kind_after_edit(&item.overview().kind, item.details());
        if kind == item.overview().kind {
            return Ok(item);
        }
        let mut promoted = item.into_parts();
        promoted.kind = kind;
        Ok(Item::new(promoted)?)
    }
}
