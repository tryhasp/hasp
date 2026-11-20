use std::collections::BTreeMap;

use hasp_proto::wire::{
    MemberState, Membership, Pull, PullResponse, VaultCursor, VaultPull, VaultStatus,
};
use hasp_proto::{Hash32, ItemId, ProtoError, Seq, Uint53, VaultKind};

use super::Ctx;
use super::page::{apply_page, check_heads, device_confirmed, refresh_pins};
use crate::CoreError;
use crate::store::{Batch, Event, EventKind, LocalVaultStatus, Records, Store, VaultLocal};
use crate::transport::Transport;

const MAX_CURSORS: usize = 64;
const MAX_PAGES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultSyncState {
    UpToDate,
    Quarantined(String),
    RepairPending,
    Removed,
    Dissolved,
    Left,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSync {
    pub vault_id: hasp_proto::VaultId,
    pub state: VaultSyncState,
    pub commits: usize,
    pub head_seq: u64,
    pub withheld: Vec<ItemId>,
    pub needs_key: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub vaults: Vec<VaultSync>,
    pub events: Vec<Event>,
}

struct Pulled {
    pages: Vec<VaultPull>,
    memberships: Vec<Membership>,
    notices: Vec<hasp_proto::wire::Notice>,
}

pub(crate) async fn sync_all<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
) -> Result<SyncReport, CoreError> {
    let account = cx.cache.account()?.ok_or(CoreError::Locked)?;
    let (known, parked) = classify_vaults(cx)?;
    let requested = known.keys().copied().chain(parked).collect();
    let cursors = known.into_iter().collect();
    let Pulled {
        mut pages,
        memberships,
        notices,
    } = pull_everything(cx, account.notices_after, cursors, requested).await?;
    pages.sort_by_key(|page| {
        let private = memberships
            .iter()
            .any(|m| m.vault_id == page.vault_id && m.kind == VaultKind::Private);
        u8::from(!private)
    });
    let mut kinds: Vec<EventKind> = Vec::new();
    let vaults = sync_pages(cx, pages, &memberships, &mut kinds).await?;
    finish_sync(cx, vaults, &notices, kinds)
}

type Cursors = Vec<(hasp_proto::VaultId, u64)>;

fn classify_vaults<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
) -> Result<(BTreeMap<hasp_proto::VaultId, u64>, Vec<hasp_proto::VaultId>), CoreError> {
    let mut known = BTreeMap::new();
    let mut parked = Vec::new();
    for vault in cx.cache.vaults()? {
        if cx.cache.quarantine(&vault.vault_id)?.is_some()
            || cx.cache.pending_repair(&vault.vault_id)?.is_some()
        {
            parked.push(vault.vault_id);
        } else if vault.status == LocalVaultStatus::Active {
            known.insert(
                vault.vault_id,
                vault.head.as_ref().map_or(0, |h| h.seq.get()),
            );
        }
    }
    Ok((known, parked))
}

async fn pull_everything<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    notices_after: u64,
    mut cursors: Cursors,
    mut requested: Vec<hasp_proto::VaultId>,
) -> Result<Pulled, CoreError> {
    let mut pulled = Pulled {
        pages: Vec::new(),
        memberships: Vec::new(),
        notices: Vec::new(),
    };
    loop {
        let mut discovered = Vec::new();
        let batches: Vec<&[(hasp_proto::VaultId, u64)]> = if cursors.is_empty() {
            vec![&[]]
        } else {
            cursors.chunks(MAX_CURSORS).collect()
        };
        for chunk in batches {
            let response = pull_request(cx, chunk, notices_after).await?;
            discovered.extend(
                response
                    .memberships
                    .iter()
                    .filter(|m| m.state == MemberState::Active && !requested.contains(&m.vault_id))
                    .map(|m| m.vault_id),
            );
            pulled.memberships = response.memberships;
            pulled.notices = response.notices;
            pulled.pages.extend(response.vaults);
        }
        discovered.sort();
        discovered.dedup();
        if discovered.is_empty() {
            return Ok(pulled);
        }
        requested.extend(discovered.iter().copied());
        cursors = discovered.into_iter().map(|id| (id, 0)).collect();
    }
}

async fn sync_pages<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    pages: Vec<VaultPull>,
    memberships: &[Membership],
    kinds: &mut Vec<EventKind>,
) -> Result<Vec<VaultSync>, CoreError> {
    let mut vaults = Vec::with_capacity(pages.len());
    let mut diverged: Option<ProtoError> = None;
    for page in pages {
        let membership = memberships.iter().find(|m| m.vault_id == page.vault_id);
        match sync_vault_pages(cx, page, membership, kinds).await {
            Ok(sync) => vaults.push(sync),
            Err(CoreError::Quarantined { vault, check }) => {
                vaults.push(empty_sync(vault, VaultSyncState::Quarantined(check)));
            }
            Err(CoreError::Proto(error @ (ProtoError::Rollback | ProtoError::Fork))) => {
                diverged.get_or_insert(error);
            }
            Err(other) => return Err(other),
        }
        if membership.is_some_and(|m| m.kind == VaultKind::Private) {
            refresh_pins(cx)?;
        }
    }
    if let Some(error) = diverged {
        return Err(error.into());
    }
    Ok(vaults)
}

fn finish_sync<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    vaults: Vec<VaultSync>,
    notices: &[hasp_proto::wire::Notice],
    mut kinds: Vec<EventKind>,
) -> Result<SyncReport, CoreError> {
    let mut batch = Batch::new();
    let mut account = cx.cache.account()?.ok_or(CoreError::Locked)?;
    for notice in notices {
        account.notices_after = account.notices_after.max(notice.id.get());
        kinds.push(EventKind::Server {
            kind: notice.kind.code(),
            vault_id: notice.vault_id,
            at: notice.at.map(Uint53::get),
        });
    }
    Records::put_account(&mut batch, &account)?;
    let events = record_events(cx, &mut batch, kinds)?;
    cx.cache.commit(&batch)?;
    Ok(SyncReport { vaults, events })
}

pub(crate) fn record_events<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    batch: &mut Batch,
    kinds: Vec<EventKind>,
) -> Result<Vec<Event>, CoreError> {
    let mut id = cx.cache.next_event_id()?;
    let at = cx.platform.clock.now();
    let mut events = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let event = Event { id, at, kind };
        Records::put_event(batch, &event)?;
        id = id.saturating_add(1);
        events.push(event);
    }
    Ok(events)
}

pub(super) async fn pull_request<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    cursors: &[(hasp_proto::VaultId, u64)],
    notices_after: u64,
) -> Result<PullResponse, CoreError> {
    let vaults = cursors
        .iter()
        .map(|(vault_id, seq)| {
            Ok(VaultCursor {
                vault_id: *vault_id,
                seq: Seq::new(*seq)?,
            })
        })
        .collect::<Result<Vec<_>, ProtoError>>()?;
    cx.call(&Pull {
        vaults,
        notices_after: Uint53::new(notices_after)?,
        limit: Uint53::ZERO,
    })
    .await
}

pub(crate) async fn pull_vault_ids<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    vault: hasp_proto::VaultId,
) -> Result<VaultSync, CoreError> {
    let local = cx.cache.vault(&vault)?;
    let seq = local
        .as_ref()
        .and_then(|v| v.head.as_ref())
        .map_or(0, |h| h.seq.get());
    let account = cx.cache.account()?.ok_or(CoreError::Locked)?;
    let mut response = pull_request(cx, &[(vault, seq)], account.notices_after).await?;
    let page = response
        .vaults
        .pop()
        .ok_or(CoreError::NotFound("vault page"))?;
    let membership = response
        .memberships
        .iter()
        .find(|m| m.vault_id == vault)
        .cloned();
    let mut kinds = Vec::new();
    let sync = sync_vault_pages(cx, page, membership.as_ref(), &mut kinds).await?;
    if !kinds.is_empty() {
        let mut batch = Batch::new();
        record_events(cx, &mut batch, kinds)?;
        cx.cache.commit(&batch)?;
    }
    if sync.vault_id == vault
        && cx
            .cache
            .vault(&vault)?
            .is_some_and(|v| v.kind == VaultKind::Private)
    {
        refresh_pins(cx)?;
    }
    Ok(sync)
}

async fn sync_vault_pages<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    first: VaultPull,
    membership: Option<&Membership>,
    kinds: &mut Vec<EventKind>,
) -> Result<VaultSync, CoreError> {
    let vault_id = first.vault_id;
    let server_seq = first.head_seq.get();
    let listed = first.status == VaultStatus::Ok;
    match sync_vault_inner(cx, first, membership, kinds).await {
        Err(CoreError::Proto(ProtoError::Rollback)) if listed => {
            super::rollback::record_behind(cx, vault_id, server_seq, false)?;
            Err(ProtoError::Rollback.into())
        }
        Err(CoreError::Proto(ProtoError::Fork)) if listed => {
            super::rollback::record_behind(cx, vault_id, server_seq, true)?;
            Err(ProtoError::Fork.into())
        }
        Ok(sync) => {
            if sync.state == VaultSyncState::UpToDate {
                super::rollback::clear_behind(cx, vault_id)?;
            }
            Ok(sync)
        }
        other => other,
    }
}

async fn sync_vault_inner<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    first: VaultPull,
    membership: Option<&Membership>,
    kinds: &mut Vec<EventKind>,
) -> Result<VaultSync, CoreError> {
    let vault_id = first.vault_id;
    let mut local = if let Some(mut local) = cx.cache.vault(&vault_id)? {
        let rejoined = membership.is_some_and(|m| m.state == MemberState::Active)
            && matches!(
                local.status,
                LocalVaultStatus::Removed | LocalVaultStatus::Left
            );
        if rejoined {
            local.status = LocalVaultStatus::Active;
            local.head = None;
            local.marks = None;
            local.vk_commits.clear();
            local.confirmed = cx.cache.invite(&vault_id)?.is_some() || device_confirmed(cx.cache)?;
        }
        local
    } else {
        let Some(membership) = membership.filter(|m| m.state == MemberState::Active) else {
            return Ok(empty_sync(vault_id, VaultSyncState::Removed));
        };
        let mut fresh = VaultLocal::new(vault_id, membership.kind, membership.role);
        fresh.confirmed = cx.cache.invite(&vault_id)?.is_some() || device_confirmed(cx.cache)?;
        fresh
    };
    let page = collect_to_head(cx, &local, first).await?;
    let mut outcome = apply_page(cx, &mut local, page, kinds).await?;
    let mut commits = outcome.commits;
    let mut withheld = std::mem::take(&mut outcome.withheld);
    while outcome.has_more && outcome.state == VaultSyncState::UpToDate {
        let seq = local.head.as_ref().map_or(0, |h| h.seq.get());
        let account = cx.cache.account()?.ok_or(CoreError::Locked)?;
        let mut response = pull_request(cx, &[(vault_id, seq)], account.notices_after).await?;
        let page = response
            .vaults
            .pop()
            .ok_or(CoreError::NotFound("vault page"))?;
        let page = collect_to_head(cx, &local, page).await?;
        outcome = apply_page(cx, &mut local, page, kinds).await?;
        commits += outcome.commits;
        withheld.extend(std::mem::take(&mut outcome.withheld));
    }
    Ok(VaultSync {
        vault_id,
        state: outcome.state,
        commits,
        head_seq: local.head.as_ref().map_or(0, |h| h.seq.get()),
        withheld,
        needs_key: outcome.needs_key,
    })
}

fn tip_of(local: &VaultLocal, page: &VaultPull) -> Result<(u64, Option<Hash32>), CoreError> {
    match page.commits.last() {
        Some(bundle) => Ok((
            bundle.manifest.unverified()?.seq.get(),
            Some(bundle.manifest.hash()),
        )),
        None => Ok(local
            .head
            .as_ref()
            .map_or((0, None), |head| (head.seq.get(), Some(head.hash)))),
    }
}

pub(super) async fn collect_to_head<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    local: &VaultLocal,
    first: VaultPull,
) -> Result<VaultPull, CoreError> {
    let mut merged = first;
    for _ in 0..MAX_PAGES {
        if merged.status != VaultStatus::Ok {
            return Ok(merged);
        }
        check_heads(local, &merged)?;
        let (seq, hash) = tip_of(local, &merged)?;
        if merged.head_seq.get() == seq && merged.head_hash == hash {
            return Ok(merged);
        }
        if merged.head_seq.get() <= seq {
            return Err(ProtoError::Fork.into());
        }
        if merged.commits.is_empty() {
            return Err(ProtoError::Format.into());
        }
        let account = cx.cache.account()?.ok_or(CoreError::Locked)?;
        let mut response =
            pull_request(cx, &[(merged.vault_id, seq)], account.notices_after).await?;
        let next = response
            .vaults
            .pop()
            .ok_or(CoreError::NotFound("vault page"))?;
        merged.status = next.status;
        merged.head_seq = next.head_seq;
        merged.head_hash = next.head_hash;
        merged.has_more = next.has_more;
        merged.dissolve = next.dissolve;
        merged.commits.extend(next.commits);
        for share in next.shares {
            if !merged.shares.contains(&share) {
                merged.shares.push(share);
            }
        }
        for wrap in next.self_wraps {
            if !merged.self_wraps.contains(&wrap) {
                merged.self_wraps.push(wrap);
            }
        }
        for request in next.leave_requests {
            if !merged.leave_requests.contains(&request) {
                merged.leave_requests.push(request);
            }
        }
    }
    Err(ProtoError::Format.into())
}

fn empty_sync(vault_id: hasp_proto::VaultId, state: VaultSyncState) -> VaultSync {
    VaultSync {
        vault_id,
        state,
        commits: 0,
        head_seq: 0,
        withheld: Vec::new(),
        needs_key: false,
    }
}
