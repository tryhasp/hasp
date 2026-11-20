use std::collections::BTreeMap;

use hasp_proto::wire::VaultStatus;
use hasp_proto::{
    Epoch, Hash32, ItemBody, ItemId, ItemWire, LeafFlag, VaultId, Version, Wire, item_wire_hash,
};

use super::Ctx;
use super::apply::{persist_chain, proto_commit};
use super::page::verify_pulled;
use super::pull::{collect_to_head, pull_request, record_events};
use crate::CoreError;
use crate::store::{
    Batch, EventKind, LocalVaultStatus, PendingKind, PendingOp, Records, Store, VaultLocal,
};
use crate::transport::Transport;

/// What accepting an older server state changed. `queued` local edits wait in the outbox and go
/// to the server through ordinary commits on the next sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackAccepted {
    pub vault_id: VaultId,
    pub from_seq: u64,
    pub to_seq: u64,
    pub queued: usize,
}

type ServerWires = BTreeMap<(ItemId, Version, Epoch), Hash32>;

pub(super) fn record_behind<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    vault: VaultId,
    server_seq: u64,
    forked: bool,
) -> Result<(), CoreError> {
    let Some(local) = cx.cache.vault(&vault)? else {
        return Ok(());
    };
    let watermark = [
        local.head.as_ref().map(|head| head.seq.get()),
        local.marks.as_ref().map(|marks| marks.seq.get()),
    ]
    .into_iter()
    .flatten()
    .max();
    let Some(local_seq) = watermark.filter(|local_seq| forked || server_seq < *local_seq) else {
        return Ok(());
    };
    if cx.cache.server_behind(&vault)? == Some(server_seq) {
        return Ok(());
    }
    let mut batch = Batch::new();
    Records::put_server_behind(&mut batch, &vault, server_seq);
    record_events(
        cx,
        &mut batch,
        vec![EventKind::ServerBehind {
            vault_id: vault,
            server_seq,
            local_seq,
        }],
    )?;
    cx.cache.commit(&batch)?;
    Ok(())
}

pub(super) fn clear_behind<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    vault: VaultId,
) -> Result<(), CoreError> {
    if cx.cache.server_behind(&vault)?.is_none() {
        return Ok(());
    }
    let mut batch = Batch::new();
    Records::clear_server_behind(&mut batch, &vault);
    cx.cache.commit(&batch)?;
    Ok(())
}

/// Re-bases a vault onto the different history the server now holds (an operator restore, P 7.14):
/// older than this device's head, or rewritten at the same height after other devices accepted
/// the restore and wrote on.
///
/// The server's chain is pulled from genesis and verified on its own. The vault must have the
/// same roster as this device's head, so a restore cannot re-admit a removed member or lower the
/// key epoch. Items whose newest local version the server's chain does not contain become outbox
/// operations re-sealed on top of the server's version; nothing local is dropped, and the server's
/// version stays in the item's history through `prev_h`.
pub(crate) async fn accept_older_server_state<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    vault: VaultId,
) -> Result<RollbackAccepted, CoreError> {
    let mut local = cx
        .cache
        .vault(&vault)?
        .ok_or(CoreError::NotFound("vault"))?;
    if local.status != LocalVaultStatus::Active {
        return Err(CoreError::VaultInactive("not active"));
    }
    let Some(head) = &local.head else {
        return Err(CoreError::NotFound("vault state"));
    };
    let from_seq = head.seq.get();
    let head_hash = head.hash;
    if cx.cache.server_behind(&vault)?.is_none() {
        return Err(CoreError::Refused(
            "the server has not reported older state for this vault",
        ));
    }
    if cx.cache.quarantine(&vault)?.is_some() || cx.cache.pending_repair(&vault)?.is_some() {
        return Err(CoreError::Refused(
            "resolve the vault's repair or quarantine first",
        ));
    }
    let local_state = local.state()?.ok_or(CoreError::NotFound("vault state"))?;

    let account = cx.cache.account()?.ok_or(CoreError::Locked)?;
    let first = pull_request(cx, &[(vault, 0)], account.notices_after)
        .await?
        .vaults
        .pop()
        .ok_or(CoreError::NotFound("vault page"))?;
    if first.status != VaultStatus::Ok {
        return Err(CoreError::Refused("the server no longer lists this vault"));
    }
    let blank = VaultLocal::new(vault, local.kind, local.role);
    let page = collect_to_head(cx, &blank, first).await?;
    let forked = page.commits.iter().any(|bundle| {
        bundle
            .manifest
            .unverified()
            .is_ok_and(|manifest| manifest.seq.get() == from_seq)
            && bundle.manifest.hash() != head_hash
    });
    if page.head_seq.get() >= from_seq && !forked {
        return Err(CoreError::Refused(
            "the server's history contains this device's head",
        ));
    }
    let commits = page
        .commits
        .iter()
        .map(proto_commit)
        .collect::<Result<Vec<_>, _>>()?;
    let (server_state, _) = verify_pulled(cx, None, &commits).map_err(|failure| failure.error)?;
    if server_state.roster_hash != local_state.roster_hash {
        return Err(CoreError::Refused(
            "the vault's members or key epoch changed after the restore point",
        ));
    }
    if cx.session.vk(&vault, server_state.epoch).is_none() {
        return Err(CoreError::Locked);
    }

    let mut server_wires = ServerWires::new();
    for wire in page.commits.iter().flat_map(|bundle| &bundle.ops) {
        server_wires.insert(
            (wire.item_id, wire.ver, wire.epoch),
            item_wire_hash(&wire.to_cbor()?),
        );
    }
    let mut batch = Batch::new();
    let compare = Compare {
        local: &local_state,
        server: &server_state,
        server_wires: &server_wires,
    };
    let queued = queue_unsynced(cx, &local, &compare, &mut batch)?;

    Records::clear_items(&mut batch, &vault);
    local.marks = None;
    persist_chain(&mut batch, &mut local, &server_state, &page.commits)?;
    Records::clear_server_behind(&mut batch, &vault);
    let to_seq = server_state.seq.get();
    record_events(
        cx,
        &mut batch,
        vec![EventKind::RollbackAccepted {
            vault_id: vault,
            from_seq,
            to_seq,
        }],
    )?;
    cx.cache.commit_rebase(&batch)?;
    Ok(RollbackAccepted {
        vault_id: vault,
        from_seq,
        to_seq,
        queued,
    })
}

struct Compare<'a> {
    local: &'a hasp_proto::VaultState,
    server: &'a hasp_proto::VaultState,
    server_wires: &'a ServerWires,
}

fn queue_unsynced<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    local: &VaultLocal,
    compare: &Compare<'_>,
    batch: &mut Batch,
) -> Result<usize, CoreError> {
    let mut queued = 0;
    for leaf in compare.local.leafset.iter() {
        let server_leaf = compare.server.leafset.get(&leaf.item_id);
        let on_server = server_leaf.is_some_and(|theirs| theirs.h_item == leaf.h_item)
            || compare
                .server_wires
                .get(&(leaf.item_id, leaf.ver, leaf.epoch))
                == Some(&leaf.h_item);
        if on_server
            || cx
                .cache
                .pending_item(&local.vault_id, &leaf.item_id)?
                .is_some()
        {
            continue;
        }
        let dead_on_server = server_leaf.is_none_or(|theirs| theirs.flag == LeafFlag::Tombstone);
        if leaf.flag == LeafFlag::Tombstone && dead_on_server {
            continue;
        }
        let Some(bytes) =
            cx.cache
                .item_wire(&local.vault_id, &leaf.item_id, leaf.ver, leaf.epoch)?
        else {
            continue;
        };
        let wire = ItemWire::from_cbor(&bytes)?;
        let kind = if matches!(wire.body, ItemBody::Tombstone) {
            PendingKind::Delete
        } else {
            PendingKind::Put
        };
        Records::put_pending(
            batch,
            &PendingOp {
                vault_id: local.vault_id,
                item_id: leaf.item_id,
                kind,
                base_ver: server_leaf.map_or(Version::ZERO, |theirs| theirs.ver),
                wire,
            },
        )?;
        queued += 1;
    }
    Ok(queued)
}
