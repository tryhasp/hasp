use hasp_crypto::SecretKey;
use hasp_proto::wire::{Commit, CommitBundle, ErrorCode, SelfWrapEntry};
use hasp_proto::{
    AttId, Epoch, Hash32, ItemId, ItemOp, ItemParams, ItemWire, LeafFlag, Manifest, Roster, Share,
    SigLabel, Signed, VaultId, VaultKind, VaultState, Version, Wire, leafset_root,
    open_item_unverified, seal_item, tombstone, verify_batch,
};

use super::pull::pull_vault_ids;
use super::share::seal_self_wrap;
use super::{Ctx, persist_commits, proto_commit, server_code};
use crate::CoreError;
use crate::session::Identity;
use crate::store::Records;
use crate::store::{
    Batch, Cache, EventKind, LocalVaultStatus, PendingKind, PendingOp, Store, VaultLocal,
};
use crate::transport::Transport;

const MAX_COMMIT_OPS: usize = 500;
const MAX_ATTEMPTS: usize = 5;

#[derive(Debug, Default)]
pub(crate) struct CommitDraft {
    pub ops: Vec<ItemWire>,
    pub roster: Option<Signed<Roster>>,
    pub shares: Vec<Signed<Share>>,
    pub self_wraps: Vec<SelfWrapEntry>,
}

pub(crate) fn build_bundle(
    identity: &Identity,
    state: &VaultState,
    draft: &CommitDraft,
) -> Result<CommitBundle, CoreError> {
    let (epoch, rver, roster_hash) = match &draft.roster {
        Some(rec) => {
            let body = rec.unverified()?;
            (body.epoch, body.rver, rec.hash())
        }
        None => (state.epoch, state.rver, state.roster_hash),
    };
    let mut leafset = state.leafset.clone();
    for wire in &draft.ops {
        leafset.apply(&ItemOp::from_wire_bytes(&wire.to_cbor()?)?)?;
    }
    let manifest = Manifest {
        vault_id: state.roster.vault_id,
        seq: state.seq.checked_next()?,
        prev: Some(state.hash),
        epoch,
        rver,
        roster_hash,
        root: leafset_root(&leafset)?,
        author: identity.account_id,
        repair: false,
    };
    Ok(CommitBundle {
        manifest: Signed::sign(SigLabel::Manifest, &manifest, &identity.signing)?,
        roster: draft.roster.clone(),
        shares: draft.shares.clone(),
        ops: draft.ops.clone(),
    })
}

pub(crate) fn ensure_writable<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    local: &VaultLocal,
) -> Result<(), CoreError> {
    if let Some(info) = cx.cache.quarantine(&local.vault_id)? {
        return Err(CoreError::Quarantined {
            vault: local.vault_id,
            check: info.check,
        });
    }
    if cx.cache.pending_repair(&local.vault_id)?.is_some() {
        return Err(CoreError::RepairPending {
            vault: local.vault_id,
        });
    }
    match local.status {
        LocalVaultStatus::Active => {}
        LocalVaultStatus::Left => return Err(CoreError::VaultInactive("left")),
        LocalVaultStatus::Dissolved => return Err(CoreError::VaultInactive("dissolved")),
        LocalVaultStatus::Removed => return Err(CoreError::VaultInactive("removed")),
    }
    if !local.role.can_write() {
        return Err(CoreError::Refused("this role is read-only"));
    }
    if local.kind == VaultKind::Shared && !local.confirmed {
        return Err(CoreError::Unconfirmed);
    }
    Ok(())
}

pub(crate) struct Edit<'a> {
    pub item_id: ItemId,
    pub overview: &'a [u8],
    pub details: &'a [u8],
    pub att_ids: Vec<AttId>,
}

pub(crate) fn queue_put<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    edit: &Edit<'_>,
) -> Result<(), CoreError> {
    ensure_writable(cx, local)?;
    let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
    let base = base_version(cx.cache, local, &state, &edit.item_id)?;
    let vk = cx
        .session
        .vk(&local.vault_id, state.epoch)
        .ok_or(CoreError::Locked)?;
    let wire = seal_item(
        vk,
        &ItemParams {
            vault_id: local.vault_id,
            item_id: edit.item_id,
            ver: base.checked_next()?,
            epoch: state.epoch,
            overview: edit.overview,
            details: edit.details,
            att_ids: edit.att_ids.clone(),
            prev_h: previous_hash(&state, &edit.item_id, base),
        },
    )?;
    let mut batch = Batch::new();
    Records::put_pending(
        &mut batch,
        &PendingOp {
            vault_id: local.vault_id,
            item_id: edit.item_id,
            kind: PendingKind::Put,
            base_ver: base,
            wire,
        },
    )?;
    cx.cache.commit(&batch)?;
    Ok(())
}

pub(crate) fn queue_delete<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    item_id: ItemId,
) -> Result<(), CoreError> {
    ensure_writable(cx, local)?;
    let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
    let base = base_version(cx.cache, local, &state, &item_id)?;
    let wire = tombstone(
        local.vault_id,
        item_id,
        base.checked_next()?,
        state.epoch,
        previous_hash(&state, &item_id, base),
    );
    let mut batch = Batch::new();
    Records::put_pending(
        &mut batch,
        &PendingOp {
            vault_id: local.vault_id,
            item_id,
            kind: PendingKind::Delete,
            base_ver: base,
            wire,
        },
    )?;
    cx.cache.commit(&batch)?;
    Ok(())
}

fn previous_hash(state: &VaultState, item: &ItemId, base: Version) -> Option<Hash32> {
    state
        .leafset
        .get(item)
        .filter(|leaf| leaf.ver == base)
        .map(|leaf| leaf.h_item)
}

fn base_version<S: Store>(
    cache: &Cache<S>,
    local: &VaultLocal,
    state: &VaultState,
    item: &ItemId,
) -> Result<Version, CoreError> {
    if let Some(pending) = cache.pending_item(&local.vault_id, item)? {
        return Ok(pending.base_ver);
    }
    Ok(state
        .leafset
        .get(item)
        .map_or(Version::ZERO, |leaf| leaf.ver))
}

pub(crate) async fn flush_vault<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    vault_id: VaultId,
    kinds: &mut Vec<EventKind>,
) -> Result<usize, CoreError> {
    let mut flushed = 0;
    let mut retries = 0;
    loop {
        let mut local = cx
            .cache
            .vault(&vault_id)?
            .ok_or(CoreError::NotFound("vault"))?;
        if cx.cache.pending(&vault_id)?.is_empty() {
            return Ok(flushed);
        }
        ensure_writable(cx, &local)?;
        let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
        let mut pending = rebase_pending(cx, &local, &state, kinds)?;
        if pending.is_empty() {
            return Ok(flushed);
        }
        pending.truncate(MAX_COMMIT_OPS);
        let count = pending.len();
        let draft = CommitDraft {
            ops: pending.iter().map(|op| op.wire.clone()).collect(),
            ..CommitDraft::default()
        };
        match submit_commit(cx, &mut local, draft, &pending, &[]).await {
            Ok(()) => {
                flushed += count;
                retries = 0;
            }
            Err(error)
                if matches!(
                    server_code(&error),
                    Some(ErrorCode::StaleHead | ErrorCode::EpochStale)
                ) =>
            {
                retries += 1;
                if retries >= MAX_ATTEMPTS {
                    return Err(CoreError::Refused("the vault kept changing; try again"));
                }
                pull_vault_ids(cx, vault_id).await?;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn rebase_pending<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    state: &VaultState,
    kinds: &mut Vec<EventKind>,
) -> Result<Vec<PendingOp>, CoreError> {
    let mut out = Vec::new();
    let mut batch = Batch::new();
    for mut op in cx.cache.pending(&local.vault_id)? {
        let leaf = state.leafset.get(&op.item_id);
        let expected = leaf.map_or(Ok(Version::ZERO), |leaf| Ok::<_, CoreError>(leaf.ver))?;
        let expected = expected.checked_next()?;
        let chained = op.wire.prev_h == leaf.map(|leaf| leaf.h_item);
        let current = op.wire.ver == expected && op.wire.epoch == state.epoch && chained;
        if current {
            out.push(op);
            continue;
        }
        let remote_ver = leaf.map_or(0, |leaf| leaf.ver.get());
        let remote_dead = leaf.is_some_and(|leaf| leaf.flag == LeafFlag::Tombstone);
        match op.kind {
            PendingKind::Delete => {
                if remote_dead || leaf.is_none() {
                    Records::delete_pending(&mut batch, &op.vault_id, &op.item_id);
                    continue;
                }
                op.wire = tombstone(
                    op.vault_id,
                    op.item_id,
                    expected,
                    state.epoch,
                    leaf.map(|leaf| leaf.h_item),
                );
            }
            PendingKind::Put => {
                if remote_ver > op.base_ver.get() {
                    kinds.push(EventKind::Conflict {
                        vault_id: op.vault_id,
                        item_id: op.item_id,
                        replaced_ver: remote_ver,
                        resurrected: remote_dead,
                    });
                }
                let old_vk = cx
                    .session
                    .vk(&op.vault_id, op.wire.epoch)
                    .ok_or(CoreError::Locked)?;
                let (overview, details) = open_item_unverified(&op.wire, old_vk)?;
                let new_vk = cx
                    .session
                    .vk(&op.vault_id, state.epoch)
                    .ok_or(CoreError::Locked)?;
                op.wire = seal_item(
                    new_vk,
                    &ItemParams {
                        vault_id: op.vault_id,
                        item_id: op.item_id,
                        ver: expected,
                        epoch: state.epoch,
                        overview: overview.expose(),
                        details: details.expose(),
                        att_ids: op.wire.att_ids.clone(),
                        prev_h: leaf.map(|leaf| leaf.h_item),
                    },
                )?;
            }
        }
        op.base_ver = leaf.map_or(Version::ZERO, |leaf| leaf.ver);
        Records::put_pending(&mut batch, &op)?;
        out.push(op);
    }
    cx.cache.commit(&batch)?;
    Ok(out)
}

pub(crate) async fn submit_commit<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &mut VaultLocal,
    draft: CommitDraft,
    cleared: &[PendingOp],
    new_keys: &[(Epoch, SecretKey)],
) -> Result<(), CoreError> {
    let state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;
    let bundle = build_bundle(&cx.session.identity, &state, &draft)?;
    cx.call(&Commit {
        vault_id: local.vault_id,
        base_seq: state.seq,
        bundle: bundle.clone(),
        self_wraps: draft.self_wraps.clone(),
    })
    .await?;
    let commit = proto_commit(&bundle)?;
    let next = verify_batch(
        &state,
        &[commit],
        &cx.session.identity.own,
        &cx.session.pins,
    )?;
    if let Some(member) = next.roster.member(&cx.account_id()) {
        local.role = member.role;
    }
    let mut batch = Batch::new();
    persist_commits(
        cx.cache,
        &mut batch,
        local,
        &next,
        std::slice::from_ref(&bundle),
    )?;
    for op in cleared {
        Records::delete_pending_if(&mut batch, op)?;
    }
    for entry in &draft.self_wraps {
        Records::put_self_wrap(&mut batch, &local.vault_id, entry.epoch, &entry.wrap)?;
    }
    for (epoch, vk) in new_keys {
        cx.session.put_vk(local.vault_id, *epoch, vk);
    }
    cx.cache.commit(&batch)?;
    Ok(())
}

pub(crate) fn self_wrap_entry<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    vault: &VaultId,
    epoch: Epoch,
    vk: &SecretKey,
) -> Result<SelfWrapEntry, CoreError> {
    Ok(SelfWrapEntry {
        epoch,
        wrap: seal_self_wrap(cx, vault, epoch, vk)?,
    })
}
