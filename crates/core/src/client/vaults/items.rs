use std::collections::BTreeMap;

use hasp_proto::payload::{self};
use hasp_proto::{
    AttId, Epoch, ItemId, ItemWire, VaultId, Version, Wire, chained_history, item_wire_hash,
    open_item_unverified,
};
use tokio_util::sync::CancellationToken;

use super::{HistoryEntry, ItemSummary, is_hidden};
use crate::CoreError;
use crate::client::{Client, NewAttachment, ctx};
use crate::model::item::Item;
use crate::model::wire as item_wire;
use crate::store::Store;
use crate::sync::{Edit, queue_delete, queue_put};
use crate::transport::Transport;

impl<T: Transport, S: Store> Client<T, S> {
    pub fn items(&self, vault: &VaultId) -> Result<Vec<ItemSummary>, CoreError> {
        let local = self.local_vault(vault)?;
        let mut ids: BTreeMap<ItemId, bool> = BTreeMap::new();
        if let Some(state) = local.state()? {
            for leaf in state.leafset.iter() {
                ids.insert(leaf.item_id, false);
            }
        }
        for op in self.cache.pending(vault)? {
            ids.insert(op.item_id, true);
        }
        let mut out = Vec::new();
        for (item_id, pending) in ids {
            if item_id == ItemId::VAULT_SETTINGS {
                continue;
            }
            let Some(opened) = self.open_view(&local, &item_id)? else {
                continue;
            };
            let Ok(overview) = payload::decode_overview(opened.overview.expose()) else {
                continue;
            };
            if is_hidden(&overview.kind) {
                continue;
            }
            out.push(ItemSummary {
                vault_id: *vault,
                item_id,
                overview,
                version: opened.version.get(),
                pending,
            });
        }
        Ok(out)
    }

    pub fn item_version(&self, vault: &VaultId, item: &ItemId) -> Result<(u64, bool), CoreError> {
        let local = self.local_vault(vault)?;
        let opened = self
            .open_view(&local, item)?
            .ok_or(CoreError::NotFound("item"))?;
        let pending = self.cache.pending_item(vault, item)?.is_some();
        Ok((opened.version.get(), pending))
    }

    pub fn item(&self, vault: &VaultId, item: &ItemId) -> Result<Item, CoreError> {
        let local = self.local_vault(vault)?;
        let opened = self
            .open_view(&local, item)?
            .ok_or(CoreError::NotFound("item"))?;
        Ok(item_wire::decode_item(
            opened.overview.expose(),
            opened.details.expose(),
        )?)
    }

    pub fn create_item(&mut self, vault: &VaultId, item: &Item) -> Result<ItemId, CoreError> {
        let item_id = ItemId::from_bytes(self.platform.array()?);
        self.write_item(vault, item_id, item)?;
        Ok(item_id)
    }

    pub fn edit_item(
        &mut self,
        vault: &VaultId,
        item_id: &ItemId,
        item: &Item,
    ) -> Result<(), CoreError> {
        self.item(vault, item_id)?;
        self.write_item(vault, *item_id, item)
    }

    pub(crate) fn write_item(
        &mut self,
        vault: &VaultId,
        item_id: ItemId,
        item: &Item,
    ) -> Result<(), CoreError> {
        let local = self.local_vault(vault)?;
        let (overview, details) = item_wire::encode_item(item)?;
        let att_ids = item
            .details()
            .attachments
            .iter()
            .map(|a| AttId::from_bytes(*a.att_id.as_bytes()))
            .collect();
        let cancel = self.begin(&CancellationToken::new());
        let mut cx = ctx!(self, &cancel);
        queue_put(
            &mut cx,
            &local,
            &Edit {
                item_id,
                overview: &overview,
                details: &details,
                att_ids,
            },
        )
    }

    pub fn delete_item(&mut self, vault: &VaultId, item_id: &ItemId) -> Result<(), CoreError> {
        let local = self.local_vault(vault)?;
        self.item(vault, item_id)?;
        let cancel = self.begin(&CancellationToken::new());
        let mut cx = ctx!(self, &cancel);
        queue_delete(&mut cx, &local, *item_id)
    }

    /// The versions that chain back from the current leaf by `prev_h`, newest first. A version
    /// the chain does not reach is never returned, so another holder of the vault key cannot add
    /// to the history (protocol 5.7).
    pub(crate) fn authenticated_versions(
        &self,
        vault: &VaultId,
        item: &ItemId,
    ) -> Result<Vec<(Version, Epoch, Vec<u8>)>, CoreError> {
        let local = self.local_vault(vault)?;
        let Some(leaf) = local
            .state()?
            .and_then(|state| state.leafset.get(item).cloned())
        else {
            return Ok(Vec::new());
        };
        let stored = self.cache.item_versions(vault, item)?;
        let Some((_, _, head_bytes)) = stored.iter().find(|(ver, epoch, bytes)| {
            *ver == leaf.ver && *epoch == leaf.epoch && item_wire_hash(bytes) == leaf.h_item
        }) else {
            return Ok(Vec::new());
        };
        let head = ItemWire::from_cbor(head_bytes)?;
        let mut keep: Vec<(Version, Epoch)> = vec![(leaf.ver, leaf.epoch)];
        keep.extend(chained_history(&head, &stored));
        Ok(keep
            .into_iter()
            .filter_map(|(ver, epoch)| {
                stored
                    .iter()
                    .find(|(v, e, _)| *v == ver && *e == epoch)
                    .cloned()
            })
            .collect())
    }

    pub fn history(&self, vault: &VaultId, item: &ItemId) -> Result<Vec<HistoryEntry>, CoreError> {
        let session = self.unlocked()?;
        let mut out = Vec::new();
        for (ver, epoch, bytes) in self.authenticated_versions(vault, item)? {
            let wire = ItemWire::from_cbor(&bytes)?;
            let Some(vk) = session.vk(vault, epoch) else {
                continue;
            };
            let Ok((overview, _)) = open_item_unverified(&wire, vk) else {
                continue;
            };
            let Ok(overview) = payload::decode_overview(overview.expose()) else {
                continue;
            };
            out.push(HistoryEntry {
                version: ver.get(),
                epoch: epoch.get(),
                title: overview.title,
                client_modified: overview.client_modified,
            });
        }
        Ok(out)
    }

    pub fn restore_version(
        &mut self,
        vault: &VaultId,
        item_id: &ItemId,
        version: u64,
    ) -> Result<(), CoreError> {
        let session = self.unlocked()?;
        let (_, epoch, bytes) = self
            .authenticated_versions(vault, item_id)?
            .into_iter()
            .find(|(ver, _, _)| ver.get() == version)
            .ok_or(CoreError::NotFound("version"))?;
        let wire = ItemWire::from_cbor(&bytes)?;
        let vk = session.vk(vault, epoch).ok_or(CoreError::Locked)?;
        let (overview, details) = open_item_unverified(&wire, vk)?;
        let local = self.local_vault(vault)?;
        let att_ids = wire.att_ids.clone();
        let cancel = self.begin(&CancellationToken::new());
        let mut cx = ctx!(self, &cancel);
        queue_put(
            &mut cx,
            &local,
            &Edit {
                item_id: *item_id,
                overview: overview.expose(),
                details: details.expose(),
                att_ids,
            },
        )
    }

    pub async fn move_item(
        &mut self,
        from: &VaultId,
        item_id: &ItemId,
        to: &VaultId,
        call: &CancellationToken,
    ) -> Result<ItemId, CoreError> {
        let item = self.item(from, item_id)?;
        let new_id = ItemId::from_bytes(self.platform.array()?);
        let mut parts = item.into_parts();
        let old = std::mem::take(&mut parts.attachments);
        let mut copies = Vec::with_capacity(old.len());
        for desc in &old {
            let data = self
                .download_attachment(
                    from,
                    item_id,
                    &AttId::from_bytes(*desc.att_id.as_bytes()),
                    call,
                )
                .await?;
            let copy = self
                .upload_blob(
                    to,
                    &new_id,
                    &NewAttachment {
                        name: &desc.name,
                        mime: &desc.mime,
                        data: &data,
                    },
                    call,
                )
                .await?;
            copies.push(copy);
        }
        parts.attachments = copies;
        let moved = Item::new(parts)?;
        self.write_item(to, new_id, &moved)?;
        self.delete_item(from, item_id)?;
        Ok(new_id)
    }
}
