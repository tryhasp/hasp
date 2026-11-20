use std::collections::{BTreeMap, BTreeSet};

use hasp_proto::wire::{CommitBundle, VaultPull, VaultStatus};
use hasp_proto::{
    ChainError, HeadRoot, ItemBody, ItemId, ItemWire, Pin, PinLevel, ProtoError, VaultKind,
    VaultState, Wire, open_item, verify_batch, verify_chain, verify_dissolve,
};

use super::apply::HISTORY_VERSIONS;
use super::pull::VaultSyncState;
use super::share::{process_shares, refresh_self_wraps, roster_index};
use super::{Ctx, persist_commits, proto_commit};
use crate::CoreError;
use crate::store::{
    Batch, Cache, EventKind, Head, LocalVaultStatus, PendingRepair, QuarantineInfo, Records, Store,
    VaultLocal,
};
use crate::transport::Transport;

const HIDDEN_PIN: &str = hasp_proto::payload::KIND_PIN;

pub(super) struct Page {
    pub(super) commits: usize,
    pub(super) withheld: Vec<ItemId>,
    pub(super) needs_key: bool,
    pub(super) has_more: bool,
    pub(super) state: VaultSyncState,
}

pub(super) async fn apply_page<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &mut VaultLocal,
    mut page: VaultPull,
    kinds: &mut Vec<EventKind>,
) -> Result<Page, CoreError> {
    let finished = |state| Page {
        commits: 0,
        withheld: Vec::new(),
        needs_key: false,
        has_more: false,
        state,
    };
    match page.status {
        VaultStatus::NotMember => {
            mark_removed(cx, local, kinds)?;
            return Ok(finished(VaultSyncState::Removed));
        }
        VaultStatus::Dissolved => return apply_dissolve(cx, local, &page, kinds).map(finished),
        VaultStatus::Ok => {}
    }
    page.has_more = false;
    check_heads(local, &page)?;
    if let Some(parked) = split_at_repair(cx, local, &mut page)? {
        return Ok(finished(parked));
    }
    let state = local.state()?;
    let commits = page
        .commits
        .iter()
        .map(proto_commit)
        .collect::<Result<Vec<_>, _>>()?;
    let mut applied = 0;
    let mut withheld = Vec::new();
    let mut rosters = super::share::RosterIndex::new();
    if !commits.is_empty() {
        let next = verify_or_quarantine(cx, local, state.as_ref(), &page, kinds)?;
        check_marks(local, &commits, &next)?;
        rosters = roster_index(
            state.as_ref(),
            &commits,
            &cx.session.identity.own,
            &cx.session.pins,
        );
        withheld = persist_verified(cx, local, &page, &next)?;
        applied = commits.len();
    }
    apply_side_data(cx, local, &page, &rosters, kinds).await?;
    let needs_key = local
        .head
        .as_ref()
        .map(Head::state)
        .transpose()?
        .is_some_and(|state| cx.session.vk(&local.vault_id, state.epoch).is_none());
    Ok(Page {
        commits: applied,
        withheld,
        needs_key,
        has_more: page.has_more,
        state: VaultSyncState::UpToDate,
    })
}

fn persist_verified<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &mut VaultLocal,
    page: &VaultPull,
    next: &VaultState,
) -> Result<Vec<ItemId>, CoreError> {
    let me = cx.account_id();
    match next.roster.member(&me) {
        Some(member) => local.role = member.role,
        None => local.status = LocalVaultStatus::Removed,
    }
    if local.marks.is_some_and(|marks| next.seq >= marks.seq) {
        local.marks = None;
    }
    let mut batch = Batch::new();
    let withheld = persist_commits(cx.cache, &mut batch, local, next, &page.commits)?;
    cx.cache.commit(&batch)?;
    Ok(withheld)
}

async fn apply_side_data<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &mut VaultLocal,
    page: &VaultPull,
    rosters: &super::share::RosterIndex,
    kinds: &mut Vec<EventKind>,
) -> Result<(), CoreError> {
    let mut batch = Batch::new();
    process_shares(cx, local, &page.shares, rosters, &mut batch).await?;
    refresh_self_wraps(cx, local, &page.self_wraps, &mut batch, kinds)?;
    for request in &page.leave_requests {
        if let Some(state) = local.state()?
            && let Ok(leave) = hasp_proto::verify_leave(request, &state)
        {
            kinds.push(EventKind::LeaveRequested {
                vault_id: local.vault_id,
                account: leave.account_id,
            });
        }
    }
    cx.cache.commit(&batch)?;
    Ok(())
}

pub(super) fn check_heads(local: &VaultLocal, page: &VaultPull) -> Result<(), CoreError> {
    if let Some(head) = &local.head {
        if page.head_seq < head.seq {
            return Err(ProtoError::Rollback.into());
        }
        if page.head_seq == head.seq && page.head_hash != Some(head.hash) {
            return Err(ProtoError::Fork.into());
        }
    }
    if let Some(marks) = &local.marks {
        if page.head_seq < marks.seq {
            return Err(ProtoError::Rollback.into());
        }
        if page.head_seq == marks.seq && page.head_hash != Some(marks.hash) {
            return Err(ProtoError::Fork.into());
        }
    }
    Ok(())
}

fn check_marks(
    local: &VaultLocal,
    commits: &[hasp_proto::Commit],
    next: &VaultState,
) -> Result<(), CoreError> {
    let Some(marks) = &local.marks else {
        return Ok(());
    };
    for commit in commits {
        let manifest = commit.manifest.unverified()?;
        if manifest.seq == marks.seq && commit.manifest.hash() != marks.hash {
            return Err(ProtoError::Fork.into());
        }
    }
    if next.seq < marks.seq {
        return Err(ProtoError::Rollback.into());
    }
    Ok(())
}

fn verify_or_quarantine<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    state: Option<&VaultState>,
    page: &VaultPull,
    kinds: &mut Vec<EventKind>,
) -> Result<VaultState, CoreError> {
    let commits = page
        .commits
        .iter()
        .map(proto_commit)
        .collect::<Result<Vec<_>, _>>()?;
    match verify_pulled(cx, state, &commits) {
        Ok((next, fallback)) => {
            if fallback {
                kinds.push(EventKind::RetentionFallback {
                    vault_id: local.vault_id,
                    from_seq: state.map_or(0, |s| s.seq.get()),
                    to_seq: next.seq.get(),
                });
            }
            Ok(next)
        }
        Err(failure) => Err(quarantine(
            cx,
            local,
            &Rejected {
                page,
                commits: &commits,
                failure: &failure,
            },
            kinds,
        )?),
    }
}

pub(super) fn verify_pulled<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    state: Option<&VaultState>,
    commits: &[hasp_proto::Commit],
) -> Result<(VaultState, bool), ChainError> {
    let own = &cx.session.identity.own;
    let pins = &cx.session.pins;
    let Some(state) = state else {
        return verify_chain(None, commits, own, pins, HeadRoot::Check).map(|next| (next, false));
    };
    let mut current = state.clone();
    for (index, commit) in commits.iter().enumerate() {
        match verify_batch(&current, std::slice::from_ref(commit), own, pins) {
            Ok(next) => current = next,
            Err(error) => {
                if behind_retention(state, commits) {
                    return verify_chain(Some(state), commits, own, pins, HeadRoot::Check)
                        .map(|next| (next, true));
                }
                return Err(ChainError { index, error });
            }
        }
    }
    Ok((current, false))
}

fn behind_retention(state: &VaultState, commits: &[hasp_proto::Commit]) -> bool {
    let mut seen: BTreeMap<ItemId, BTreeSet<u64>> = BTreeMap::new();
    for op in commits.iter().flat_map(|commit| &commit.ops) {
        let wire = op.wire();
        seen.entry(wire.item_id).or_default().insert(wire.ver.get());
    }
    let retention = u64::try_from(HISTORY_VERSIONS).unwrap_or(u64::MAX);
    let mut pruned = false;
    for (item, versions) in seen {
        let Some(top) = versions.last().copied() else {
            continue;
        };
        let base = state.leafset.get(&item).map_or(0, |leaf| leaf.ver.get());
        for missing in base.saturating_add(1)..top {
            if versions.contains(&missing) {
                continue;
            }
            if missing.saturating_add(retention) > top {
                return false;
            }
            pruned = true;
        }
    }
    pruned
}

struct Rejected<'a> {
    page: &'a VaultPull,
    commits: &'a [hasp_proto::Commit],
    failure: &'a ChainError,
}

fn quarantine<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    rejected: &Rejected<'_>,
    kinds: &mut Vec<EventKind>,
) -> Result<CoreError, CoreError> {
    let Rejected {
        page,
        commits,
        failure,
    } = rejected;
    let bundle: Option<&CommitBundle> = page.commits.get(failure.index);
    let manifest = commits
        .get(failure.index)
        .and_then(|c| c.manifest.unverified().ok());
    let info = QuarantineInfo {
        vault_id: local.vault_id,
        check: failure.error.name().to_owned(),
        seq: manifest.as_ref().map_or(0, |m| m.seq.get()),
        author: manifest.as_ref().map(|m| m.author),
        bad_hash: commits.get(failure.index).map(|c| c.manifest.hash()),
        last_good_seq: local.head.as_ref().map_or(0, |h| h.seq.get()),
        last_good_hash: local.head.as_ref().map(|h| h.hash),
        at: cx.platform.clock.now(),
        bad_bundle: bundle.map(Wire::to_cbor).transpose()?.unwrap_or_default(),
    };
    let mut batch = Batch::new();
    Records::put_quarantine(&mut batch, &info)?;
    cx.cache.commit(&batch)?;
    kinds.push(EventKind::Quarantined {
        vault_id: local.vault_id,
        check: info.check.clone(),
    });
    Ok(CoreError::Quarantined {
        vault: local.vault_id,
        check: info.check,
    })
}

fn mark_removed<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &mut VaultLocal,
    kinds: &mut Vec<EventKind>,
) -> Result<(), CoreError> {
    if local.status == LocalVaultStatus::Active {
        local.status = LocalVaultStatus::Removed;
        let mut batch = Batch::new();
        Records::put_vault(&mut batch, local)?;
        cx.cache.commit(&batch)?;
        kinds.push(EventKind::Removed {
            vault_id: local.vault_id,
        });
    }
    Ok(())
}

fn split_at_repair<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    page: &mut VaultPull,
) -> Result<Option<VaultSyncState>, CoreError> {
    if local.head.is_none() {
        return Ok(None);
    }
    let Some(at) = page
        .commits
        .iter()
        .position(|bundle| bundle.manifest.unverified().is_ok_and(|m| m.repair))
    else {
        return Ok(None);
    };
    if at == 0 {
        park_repair(cx, local, page)?;
        return Ok(Some(VaultSyncState::RepairPending));
    }
    page.commits.truncate(at);
    page.has_more = true;
    Ok(None)
}

fn park_repair<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    page: &VaultPull,
) -> Result<(), CoreError> {
    let bundle = page
        .commits
        .first()
        .ok_or(CoreError::Internal("no repair bundle"))?;
    let manifest = bundle.manifest.unverified()?;
    let repair = PendingRepair {
        vault_id: local.vault_id,
        seq: manifest.seq.get(),
        hash: bundle.manifest.hash(),
        author: manifest.author,
        at: cx.platform.clock.now(),
        bundle: bundle.to_cbor()?,
    };
    let mut batch = Batch::new();
    Records::put_pending_repair(&mut batch, &repair)?;
    cx.cache.commit(&batch)?;
    Ok(())
}

fn apply_dissolve<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &mut VaultLocal,
    page: &VaultPull,
    kinds: &mut Vec<EventKind>,
) -> Result<VaultSyncState, CoreError> {
    let (Some(record), Some(state)) = (&page.dissolve, local.state()?) else {
        return Ok(VaultSyncState::Removed);
    };
    verify_dissolve(record, &state)?;
    if local.status != LocalVaultStatus::Dissolved {
        local.status = LocalVaultStatus::Dissolved;
        let mut batch = Batch::new();
        Records::put_vault(&mut batch, local)?;
        cx.cache.commit(&batch)?;
        kinds.push(EventKind::Dissolved {
            vault_id: local.vault_id,
        });
    }
    Ok(VaultSyncState::Dissolved)
}

pub(crate) fn refresh_pins<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
) -> Result<(), CoreError> {
    let Some(private) = cx
        .cache
        .vaults()?
        .into_iter()
        .find(|v| v.kind == VaultKind::Private)
    else {
        return Ok(());
    };
    let Some(state) = private.state()? else {
        return Ok(());
    };
    let confirmed = device_confirmed(cx.cache)?;
    for leaf in state.leafset.iter() {
        let Some(bytes) =
            cx.cache
                .item_wire(&private.vault_id, &leaf.item_id, leaf.ver, leaf.epoch)?
        else {
            continue;
        };
        let Ok(wire) = ItemWire::from_cbor(&bytes) else {
            continue;
        };
        if !matches!(wire.body, ItemBody::Live { .. }) {
            continue;
        }
        let Some(vk) = cx.session.vk(&private.vault_id, wire.epoch) else {
            continue;
        };
        let Ok(hasp_proto::OpenedItem::Live {
            overview, details, ..
        }) = open_item(&wire, &bytes, &state, vk)
        else {
            continue;
        };
        let Ok(parsed) = hasp_proto::payload::decode_overview(overview.expose()) else {
            continue;
        };
        if parsed.kind != HIDDEN_PIN {
            continue;
        }
        if let Ok(hasp_proto::payload::Hidden::Pin(record)) =
            hasp_proto::payload::decode_hidden(details.expose())
            && let Ok(ik_pk) = hasp_crypto::VerifyingKey::from_bytes(record.ik_pk)
        {
            cx.session.pins.insert(
                record.account_id,
                Pin {
                    ik_pk,
                    kem_pk_hash: record.kem_pk_hash,
                    level: match record.level {
                        _ if !confirmed => PinLevel::Unverified,
                        hasp_proto::payload::PinLevelWire::Tofu => PinLevel::Tofu,
                        hasp_proto::payload::PinLevelWire::Verified => PinLevel::Verified,
                    },
                },
            );
        }
    }
    Ok(())
}

pub(crate) fn device_confirmed<S: Store>(cache: &Cache<S>) -> Result<bool, CoreError> {
    Ok(cache.meta("device-confirmed")?.is_some_and(|v| v == b"1"))
}
