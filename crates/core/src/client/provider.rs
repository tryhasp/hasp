use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use hasp_proto::payload::{self};
use hasp_proto::{
    ItemBody, ItemId, ItemWire, OpenedItem, VaultId, Wire, open_item, open_item_unverified,
};

use super::Client;
use super::vaults::is_hidden;
use crate::CoreError;
use crate::model::wire as item_wire;
use crate::provider::{Index, IndexEntry, entry_of};
use crate::store::{LocalVaultStatus, Store};
use crate::transport::Transport;

const NOTE: &str = "provider-index";
const STAMP_PENDING: &str = "pending";

fn hex(raw: &[u8]) -> String {
    hasp_crypto::to_hex(raw)
}

fn entry_from(ids: (&VaultId, &ItemId), stamp: &str, sealed: (&[u8], &[u8])) -> Option<IndexEntry> {
    let (vault, item) = ids;
    let (overview, details) = sealed;
    let head = payload::decode_overview(overview).ok()?;
    if is_hidden(&head.kind) {
        return Some(IndexEntry::hidden(
            &hex(vault.as_bytes()),
            &hex(item.as_bytes()),
            stamp,
            &head.kind,
        ));
    }
    let decoded = item_wire::decode_item(overview, details).ok()?;
    Some(entry_of(
        &hex(vault.as_bytes()),
        &hex(item.as_bytes()),
        stamp,
        &decoded,
    ))
}

impl<T: Transport, S: Store> Client<T, S> {
    fn stored_index(&self) -> Index {
        self.local_note_get(NOTE)
            .ok()
            .flatten()
            .and_then(|raw| Index::decode(raw.expose()))
            .unwrap_or_default()
    }

    /// The metadata of every live item, read from the sealed index and brought up to date by
    /// opening only the items whose version changed since it was written, plus the local edits
    /// that are not synced yet. A device that never built an index opens each item once, one at
    /// a time, and keeps none of them.
    pub fn provider_index(&mut self) -> Result<Index, CoreError> {
        self.unlocked()?;
        let stored = self.stored_index();
        let mut previous: BTreeMap<(String, String), IndexEntry> = stored
            .entries
            .into_iter()
            .map(|entry| ((entry.vault.clone(), entry.item.clone()), entry))
            .collect();
        let mut fresh = Vec::new();
        let mut changed = false;
        let mut overlay = Vec::new();
        for local in self.cache.vaults()? {
            if local.status != LocalVaultStatus::Active
                || self.cache.quarantine(&local.vault_id)?.is_some()
            {
                continue;
            }
            let vault_hex = hex(local.vault_id.as_bytes());
            if let Some(state) = local.state()? {
                for leaf in state.leafset.iter() {
                    if leaf.item_id == ItemId::VAULT_SETTINGS
                        || leaf.flag == hasp_proto::LeafFlag::Tombstone
                    {
                        continue;
                    }
                    let item_hex = hex(leaf.item_id.as_bytes());
                    let stamp = format!(
                        "{}.{}.{}",
                        leaf.ver.get(),
                        leaf.epoch.get(),
                        hex(&leaf.h_item.as_bytes()[..8])
                    );
                    if let Some(known) = previous.remove(&(vault_hex.clone(), item_hex.clone()))
                        && known.stamp == stamp
                    {
                        fresh.push(known);
                        continue;
                    }
                    changed = true;
                    let Some(bytes) = self.cache.item_wire(
                        &local.vault_id,
                        &leaf.item_id,
                        leaf.ver,
                        leaf.epoch,
                    )?
                    else {
                        continue;
                    };
                    let wire = ItemWire::from_cbor(&bytes)?;
                    let Some(vk) = self.unlocked()?.vk(&local.vault_id, wire.epoch) else {
                        continue;
                    };
                    self.opened.fetch_add(1, Ordering::Relaxed);
                    if let OpenedItem::Live {
                        overview, details, ..
                    } = open_item(&wire, &bytes, &state, vk)?
                        && let Some(entry) = entry_from(
                            (&local.vault_id, &leaf.item_id),
                            &stamp,
                            (overview.expose(), details.expose()),
                        )
                    {
                        fresh.push(entry);
                    }
                }
            }
            for op in self.cache.pending(&local.vault_id)? {
                overlay.push((local.vault_id, op));
            }
        }
        let rebuilt = Index::new(fresh);
        if changed || !previous.is_empty() {
            self.local_note_put(NOTE, &rebuilt.encode()?)?;
        }
        let mut entries = rebuilt.entries;
        entries.retain(|entry| !is_hidden(&entry.kind));
        for (vault, op) in overlay {
            let key = (hex(vault.as_bytes()), hex(op.item_id.as_bytes()));
            entries.retain(|entry| (entry.vault.clone(), entry.item.clone()) != key);
            let ItemBody::Live { .. } = op.wire.body else {
                continue;
            };
            let Some(vk) = self.unlocked()?.vk(&vault, op.wire.epoch) else {
                continue;
            };
            self.opened.fetch_add(1, Ordering::Relaxed);
            let (overview, details) = open_item_unverified(&op.wire, vk)?;
            if let Some(entry) = entry_from(
                (&vault, &op.item_id),
                STAMP_PENDING,
                (overview.expose(), details.expose()),
            ) {
                entries.push(entry);
            }
        }
        Ok(Index::new(entries))
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn drop_provider_index_for_tests(&mut self) -> Result<(), CoreError> {
        self.local_note_put(NOTE, b"")
    }
}
