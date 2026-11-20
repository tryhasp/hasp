use std::collections::BTreeMap;

use hasp_proto::wire::CommitBundle;
use hasp_proto::{
    Commit as ProtoCommit, Epoch, ItemId, ItemOp, ProtoError, Signed, VaultState, Version, Wire,
    item_wire_hash,
};

use crate::CoreError;
use crate::store::Records;
use crate::store::{Batch, Cache, Head, Store, VaultLocal};

pub(super) const HISTORY_VERSIONS: usize = 10;

pub(crate) fn proto_commit(bundle: &CommitBundle) -> Result<ProtoCommit, ProtoError> {
    Ok(ProtoCommit {
        manifest: bundle.manifest.clone(),
        roster: bundle.roster.clone(),
        ops: bundle
            .ops
            .iter()
            .map(|wire| ItemOp::from_wire_bytes(&wire.to_cbor()?))
            .collect::<Result<_, _>>()?,
        shares: bundle.shares.clone(),
    })
}

type Versions = Vec<(Version, Epoch, Vec<u8>)>;

pub(crate) fn persist_commits<S: Store>(
    cache: &Cache<S>,
    batch: &mut Batch,
    local: &mut VaultLocal,
    state: &VaultState,
    bundles: &[CommitBundle],
) -> Result<Vec<ItemId>, CoreError> {
    let vault = local.vault_id;
    persist_with(
        |item| Ok(cache.item_versions(&vault, item)?),
        batch,
        local,
        state,
        bundles,
    )
}

/// Persists a whole chain with no cached versions: the caller has already cleared the vault's
/// item rows, so only what the chain carries survives.
pub(crate) fn persist_chain(
    batch: &mut Batch,
    local: &mut VaultLocal,
    state: &VaultState,
    bundles: &[CommitBundle],
) -> Result<Vec<ItemId>, CoreError> {
    persist_with(|_| Ok(Vec::new()), batch, local, state, bundles)
}

fn persist_with(
    existing: impl Fn(&ItemId) -> Result<Versions, CoreError>,
    batch: &mut Batch,
    local: &mut VaultLocal,
    state: &VaultState,
    bundles: &[CommitBundle],
) -> Result<Vec<ItemId>, CoreError> {
    let last = bundles
        .last()
        .ok_or(CoreError::Internal("no commits to persist"))?;
    let roster: Signed<hasp_proto::Roster> =
        match bundles.iter().rev().find_map(|b| b.roster.clone()) {
            Some(roster) => roster,
            None => local
                .head
                .as_ref()
                .map(|head| head.roster.clone())
                .ok_or(CoreError::Internal("no roster"))?,
        };
    for bundle in bundles {
        if let Some(rec) = &bundle.roster {
            let body = rec.unverified()?;
            local.vk_commits.insert(body.epoch.get(), body.vk_commit);
        }
    }
    let mut touched: BTreeMap<ItemId, BTreeMap<(Version, Epoch), Vec<u8>>> = BTreeMap::new();
    for bundle in bundles {
        for wire in &bundle.ops {
            let entry = touched.entry(wire.item_id).or_default();
            entry.insert((wire.ver, wire.epoch), wire.to_cbor()?);
        }
    }
    let mut withheld = Vec::new();
    for (item, fresh) in &mut touched {
        for (ver, epoch, bytes) in existing(item)? {
            fresh.entry((ver, epoch)).or_insert(bytes);
        }
        let mut versions: Vec<Version> = fresh.keys().map(|(ver, _)| *ver).collect();
        versions.dedup();
        let keep_from = versions
            .len()
            .checked_sub(HISTORY_VERSIONS)
            .and_then(|at| versions.get(at))
            .copied();
        for ((ver, epoch), bytes) in fresh.iter() {
            if keep_from.is_some_and(|cutoff| *ver < cutoff) {
                Records::delete_item_version(batch, &local.vault_id, item, *ver, *epoch);
            } else {
                Records::put_item(batch, &local.vault_id, (item, *ver, *epoch), bytes);
            }
        }
        if let Some(leaf) = state.leafset.get(item) {
            let present = fresh
                .get(&(leaf.ver, leaf.epoch))
                .is_some_and(|bytes| item_wire_hash(bytes) == leaf.h_item);
            if !present {
                withheld.push(*item);
            }
        }
    }
    local.head = Some(Head::from_state(state, last.manifest.clone(), roster));
    Records::put_vault(batch, local)?;
    Ok(withheld)
}
