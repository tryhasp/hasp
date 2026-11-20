use std::collections::BTreeMap;

use hasp_proto::wire::{
    CommitBundle, ErrorCode, Pull, PullResponse, SelfWrapEntry, VaultCursor, VaultPull, VaultStatus,
};
use hasp_proto::{AccountId, Epoch, ItemWire, LeaveRequest, Role, Seq, Share, Signed, VaultId};

use crate::server::{Call, Res, Server, State, notices_after};
use crate::store::{MemberStatus, Store, VaultPhase};

use super::{epoch_max, item_bounds, seq_max};

const DEFAULT_PULL: u64 = 100;
const MAX_PULL: u64 = 200;
const MAX_CURSORS: usize = 64;

impl<S: Store> Server<S> {
    pub(crate) fn pull_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: Pull,
    ) -> Res<PullResponse> {
        let session = self.session(st, call)?;
        let account = session.account_id;
        if req.vaults.len() > MAX_CURSORS {
            return Err(ErrorCode::TooLarge.into());
        }
        let limit = match req.limit.get() {
            0 => DEFAULT_PULL,
            n => n.min(MAX_PULL),
        };
        let limit = usize::try_from(limit).unwrap_or(1);
        let mut vaults = Vec::new();
        for cursor in &req.vaults {
            vaults.push(self.pull_vault(st, &account, cursor, limit)?);
        }
        let notice_limit = usize::try_from(MAX_PULL).unwrap_or(200);
        Ok(PullResponse {
            vaults,
            memberships: self.membership_list(st, &account)?,
            notices: notices_after(st, &account, req.notices_after.get(), notice_limit)?,
        })
    }

    pub(super) fn empty_pull(vault_id: VaultId, status: VaultStatus) -> VaultPull {
        VaultPull {
            vault_id,
            status,
            head_seq: Seq::ZERO,
            head_hash: None,
            has_more: false,
            commits: Vec::new(),
            shares: Vec::new(),
            self_wraps: Vec::new(),
            leave_requests: Vec::new(),
            dissolve: None,
        }
    }

    pub(super) fn pull_vault(
        &self,
        st: &mut State<S>,
        account: &AccountId,
        cursor: &VaultCursor,
        limit: usize,
    ) -> Res<VaultPull> {
        let vault_id = cursor.vault_id;
        let (Some(vault), Some(member)) = (
            st.store.vaults().get(&vault_id)?,
            st.store.members().get(&(vault_id, *account))?,
        ) else {
            return Ok(Self::empty_pull(vault_id, VaultStatus::NotMember));
        };
        if member.state == MemberStatus::Dissolved {
            let mut out = Self::empty_pull(vault_id, VaultStatus::Dissolved);
            out.dissolve = vault.dissolve;
            return Ok(out);
        }
        if member.state != MemberStatus::Active || vault.state != VaultPhase::Active {
            return Ok(Self::empty_pull(vault_id, VaultStatus::NotMember));
        }
        let from = cursor.seq.checked_next()?;
        let manifests = st
            .store
            .manifests()
            .range(&(vault_id, from), &(vault_id, seq_max()))?;
        let has_more = manifests.len() > limit;
        let page: Vec<_> = manifests.into_iter().take(limit).collect();
        let PendingShares {
            by_seq: mut shares_by_seq,
            mine,
        } = pending_shares(st, vault_id, cursor.seq, account)?;
        let mut ops_by_seq = ops_by_seq(st, vault_id)?;
        let mut commits = Vec::new();
        for ((_, seq), row) in page {
            let manifest = row.manifest.unverified()?;
            let roster = st
                .store
                .rosters()
                .get(&(vault_id, manifest.rver))?
                .filter(|roster| roster.seq == seq)
                .map(|roster| roster.roster);
            commits.push(CommitBundle {
                manifest: row.manifest,
                roster,
                shares: shares_by_seq.remove(&seq).unwrap_or_default(),
                ops: ops_by_seq.remove(&seq).unwrap_or_default(),
            });
        }
        let self_wraps = st
            .store
            .self_wraps()
            .range(
                &(*account, vault_id, Epoch::ZERO),
                &(*account, vault_id, epoch_max()),
            )?
            .into_iter()
            .map(|((_, _, epoch), wrap)| SelfWrapEntry { epoch, wrap })
            .collect();
        let leave_requests = if member.role == Role::Owner {
            leave_requests(st, vault_id)?
        } else {
            Vec::new()
        };
        Ok(VaultPull {
            vault_id,
            status: VaultStatus::Ok,
            head_seq: vault.head_seq,
            head_hash: (vault.head_seq != Seq::ZERO).then_some(vault.head_hash),
            has_more,
            commits,
            shares: mine,
            self_wraps,
            leave_requests,
            dissolve: None,
        })
    }
}

struct PendingShares {
    by_seq: BTreeMap<Seq, Vec<Signed<Share>>>,
    mine: Vec<Signed<Share>>,
}

fn pending_shares<S: Store>(
    st: &mut State<S>,
    vault_id: VaultId,
    after: Seq,
    account: &AccountId,
) -> Res<PendingShares> {
    let mut by_seq: BTreeMap<Seq, Vec<_>> = BTreeMap::new();
    let mut mine = Vec::new();
    for (_, row) in st.store.shares().range(
        &(vault_id, Epoch::ZERO, AccountId::from_bytes([0; 16])),
        &(vault_id, epoch_max(), AccountId::from_bytes([0xff; 16])),
    )? {
        if row.seq > after && row.share.unverified()?.to == *account {
            mine.push(row.share.clone());
        }
        by_seq.entry(row.seq).or_default().push(row.share);
    }
    Ok(PendingShares { by_seq, mine })
}

fn ops_by_seq<S: Store>(st: &mut State<S>, vault_id: VaultId) -> Res<BTreeMap<Seq, Vec<ItemWire>>> {
    let (from, to) = item_bounds(vault_id, None);
    let mut by_seq: BTreeMap<Seq, Vec<ItemWire>> = BTreeMap::new();
    for (_, row) in st.store.items().range(&from, &to)? {
        by_seq.entry(row.seq).or_default().push(row.wire);
    }
    Ok(by_seq)
}

fn leave_requests<S: Store>(
    st: &mut State<S>,
    vault_id: VaultId,
) -> Res<Vec<Signed<LeaveRequest>>> {
    let members = st.store.members().range(
        &(vault_id, AccountId::from_bytes([0; 16])),
        &(vault_id, AccountId::from_bytes([0xff; 16])),
    )?;
    Ok(members
        .into_iter()
        .filter(|(_, row)| row.state == MemberStatus::Leaving)
        .filter_map(|(_, row)| row.leave)
        .collect())
}
