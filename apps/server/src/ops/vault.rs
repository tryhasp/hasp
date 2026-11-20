mod attachment_refs;
mod membership;
mod pull;
mod repair;

use hasp_proto::wire::{
    Ack, Commit, CommitBundle, CommitResponse, ErrorCode, SelfWrapEntry, SelfWrapPut,
};
use hasp_proto::{
    AccountId, Commit as ProtoCommit, Epoch, Hash32, ItemBody, ItemId, ItemOp, ItemWire, Leaf,
    LeafFlag, LeafSet, OwnKeys, PinState, Role, Roster, Rver, Seq, Uint53, VaultId,
    VaultState as ProtoState, Version, Wire, item_wire_hash, verify_batch, verify_genesis,
};

use crate::server::{Call, Res, Server, State, latest_record};
use crate::store::{
    ItemKey, ItemRow, ManifestRow, MemberStatus, RosterRow, ShareRow, Store, VaultPhase, VaultRow,
};

fn seq_max() -> Seq {
    Seq::new(Uint53::MAX).unwrap_or(Seq::ZERO)
}

fn rver_max() -> Rver {
    Rver::new(Uint53::MAX).unwrap_or(Rver::ZERO)
}

fn epoch_max() -> Epoch {
    Epoch::new(Uint53::MAX).unwrap_or(Epoch::ZERO)
}

fn item_bounds(vault: VaultId, item: Option<ItemId>) -> (ItemKey, ItemKey) {
    let (lo, hi) = match item {
        Some(id) => (id, id),
        None => (ItemId::from_bytes([0; 16]), ItemId::from_bytes([0xff; 16])),
    };
    let ver_max = Version::new(Uint53::MAX).unwrap_or(Version::ZERO);
    (
        (vault, lo, Version::ZERO, Epoch::ZERO),
        (vault, hi, ver_max, epoch_max()),
    )
}

pub(crate) fn proto_commit(bundle: &CommitBundle) -> Res<ProtoCommit> {
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

fn authorize_commit(
    state: &ProtoState,
    vault: &VaultRow,
    account: &AccountId,
    bundle: &CommitBundle,
) -> Res<()> {
    let manifest = bundle.manifest.unverified()?;
    let role = state
        .roster
        .member(account)
        .map(|member| member.role)
        .ok_or(ErrorCode::NotMember)?;
    if manifest.author != *account {
        return Err(ErrorCode::Authz.into());
    }
    if !role.can_write() {
        return Err(ErrorCode::ReadOnly.into());
    }
    let owner_only = bundle.roster.is_some()
        || !bundle.shares.is_empty()
        || manifest.epoch > vault.epoch
        || manifest.repair;
    if owner_only && role != Role::Owner {
        return Err(ErrorCode::Authz.into());
    }
    if manifest.epoch < vault.epoch || bundle.ops.iter().any(|wire| wire.epoch < vault.epoch) {
        return Err(ErrorCode::EpochStale.into());
    }
    Ok(())
}

fn own_keys(roster: &Roster, account: &AccountId) -> Res<OwnKeys> {
    let member = roster.member(account).ok_or(ErrorCode::NotMember)?;
    Ok(OwnKeys {
        account_id: member.account_id,
        ik_pk: member.ik_pk,
        kem_pk: member.kem_pk.clone(),
        retired_kem_pk_hashes: Vec::new(),
    })
}

impl<S: Store> Server<S> {
    pub(crate) fn vault_state(
        &self,
        st: &mut State<S>,
        vault: &VaultId,
        row: &VaultRow,
    ) -> Res<ProtoState> {
        let (_, stored) = st
            .store
            .rosters()
            .last_in(&(*vault, Rver::ZERO), &(*vault, rver_max()))?
            .ok_or(ErrorCode::Internal)?;
        let roster = stored.roster.unverified()?;
        let (from, to) = item_bounds(*vault, None);
        let leaves = st
            .store
            .items()
            .range(&from, &to)?
            .into_iter()
            .filter(|(_, item)| item.current)
            .map(|(_, item)| Leaf {
                item_id: item.wire.item_id,
                ver: item.wire.ver,
                epoch: item.wire.epoch,
                h_item: item.h_item,
                flag: if item.tomb {
                    LeafFlag::Tombstone
                } else {
                    LeafFlag::Live
                },
            })
            .collect::<Vec<_>>();
        Ok(ProtoState {
            seq: row.head_seq,
            hash: row.head_hash,
            rver: roster.rver,
            roster_hash: stored.roster.hash(),
            epoch: row.epoch,
            roster,
            leafset: LeafSet::from_leaves(leaves),
        })
    }

    pub(crate) fn commit_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: Commit,
    ) -> Res<CommitResponse> {
        let session = self.session(st, call)?;
        let account = session.account_id;
        let bundle = &req.bundle;
        if bundle.ops.len() > self.config.max_ops || bundle.shares.len() > self.config.max_shares {
            return Err(ErrorCode::TooLarge.into());
        }
        let manifest = bundle.manifest.unverified()?;
        if manifest.vault_id != req.vault_id {
            return Err(ErrorCode::Format.into());
        }
        let Some(vault) = st.store.vaults().get(&req.vault_id)? else {
            return self.create_vault(st, call.now, account, &req);
        };
        if vault.state == VaultPhase::Dissolved {
            return Err(ErrorCode::NotMember.into());
        }
        let member = st.store.members().get(&(req.vault_id, account))?;
        if member.is_none_or(|row| row.state != MemberStatus::Active) {
            return Err(ErrorCode::NotMember.into());
        }
        let digest = Hash32::digest(&[&req.to_cbor()?]);
        if let Some(logged) = st.store.commit_log().get(&(req.vault_id, req.base_seq))? {
            return self.replayed_commit(st, &req, logged, digest);
        }
        if req.base_seq != vault.head_seq {
            return Err(ErrorCode::StaleHead.into());
        }
        let state = self.vault_state(st, &req.vault_id, &vault)?;
        authorize_commit(&state, &vault, &account, bundle)?;
        let commit = proto_commit(bundle)?;
        let owner = state.roster.owner().ok_or(ErrorCode::Roster)?;
        let own = own_keys(&state.roster, &owner.account_id)?;
        let next = verify_batch(&state, &[commit], &own, &PinState::new())?;
        if bundle.roster.is_some() {
            self.check_roster_policy(st, &req.vault_id, &state.roster, &next.roster)?;
        }
        self.check_attachments(st, &req.vault_id, &bundle.ops)?;
        let stored = StoredCommit {
            now: call.now,
            account,
            vault_id: req.vault_id,
            base_seq: req.base_seq,
            bundle,
            self_wraps: &req.self_wraps,
            digest,
        };
        self.store_commit(st, &stored, &next, Some(&state))?;
        Ok(CommitResponse {
            head_seq: next.seq,
            head_hash: next.hash,
        })
    }

    fn replayed_commit(
        &self,
        st: &mut State<S>,
        req: &Commit,
        logged: Hash32,
        digest: Hash32,
    ) -> Res<CommitResponse> {
        let seq = Seq::new(req.base_seq.get().saturating_add(1))?;
        let stored = st
            .store
            .manifests()
            .get(&(req.vault_id, seq))?
            .ok_or(ErrorCode::StaleHead)?;
        if logged == digest {
            return Ok(CommitResponse {
                head_seq: seq,
                head_hash: stored.manifest.hash(),
            });
        }
        if stored.manifest.hash() == req.bundle.manifest.hash() {
            return Err(ErrorCode::Sig.into());
        }
        Err(ErrorCode::StaleHead.into())
    }

    fn create_vault(
        &self,
        st: &mut State<S>,
        now: u64,
        account: AccountId,
        req: &Commit,
    ) -> Res<CommitResponse> {
        if req.base_seq != Seq::ZERO {
            return Err(ErrorCode::NotFound.into());
        }
        let (_, record) = latest_record(st, &account)?.ok_or(ErrorCode::Auth)?;
        let own = OwnKeys {
            account_id: record.account_id,
            ik_pk: record.ik_pk,
            kem_pk: record.kem_pk,
            retired_kem_pk_hashes: Vec::new(),
        };
        let commit = proto_commit(&req.bundle)?;
        let state = verify_genesis(&commit, &own, &PinState::new())?;
        if state.roster.members.len() != 1
            || state.roster.owner().map(|member| member.account_id) != Some(account)
            || !req.bundle.shares.is_empty()
            || state.roster.vault_id != req.vault_id
        {
            return Err(ErrorCode::Roster.into());
        }
        if !req
            .self_wraps
            .iter()
            .any(|entry| entry.epoch == state.epoch)
        {
            return Err(ErrorCode::Format.into());
        }
        self.check_attachments(st, &req.vault_id, &req.bundle.ops)?;
        let stored = StoredCommit {
            now,
            account,
            vault_id: req.vault_id,
            base_seq: Seq::ZERO,
            bundle: &req.bundle,
            self_wraps: &req.self_wraps,
            digest: Hash32::digest(&[&req.to_cbor()?]),
        };
        self.insert_vault(st, &stored, &state)?;
        Ok(CommitResponse {
            head_seq: state.seq,
            head_hash: state.hash,
        })
    }

    pub(crate) fn insert_vault(
        &self,
        st: &mut State<S>,
        stored: &StoredCommit<'_>,
        state: &ProtoState,
    ) -> Res<()> {
        st.store.vaults().put(
            stored.vault_id,
            VaultRow {
                kind: state.roster.kind,
                owner: stored.account,
                head_seq: Seq::ZERO,
                head_hash: Hash32::from_bytes([0; 32]),
                rver: state.rver,
                epoch: state.epoch,
                state: VaultPhase::Active,
                dissolve: None,
                created: stored.now,
            },
        )?;
        self.store_commit(st, stored, state, None)
    }

    fn check_roster_policy(
        &self,
        st: &mut State<S>,
        vault: &VaultId,
        old: &Roster,
        new: &Roster,
    ) -> Res<()> {
        for member in &new.members {
            let (_, record) = latest_record(st, &member.account_id)?.ok_or(ErrorCode::Roster)?;
            if record.ik_pk != member.ik_pk || record.kem_pk != member.kem_pk {
                return Err(ErrorCode::Roster.into());
            }
            if old.member(&member.account_id).is_none() {
                let row = st
                    .store
                    .members()
                    .get(&(*vault, member.account_id))?
                    .ok_or(ErrorCode::Invite)?;
                if row.state != MemberStatus::Invited || row.role != member.role {
                    return Err(ErrorCode::Invite.into());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn store_commit(
        &self,
        st: &mut State<S>,
        stored: &StoredCommit<'_>,
        next: &ProtoState,
        old: Option<&ProtoState>,
    ) -> Res<()> {
        let vault_id = stored.vault_id;
        let bundle = stored.bundle;
        let mut vault = st
            .store
            .vaults()
            .get(&vault_id)?
            .ok_or(ErrorCode::Internal)?;
        st.store.manifests().put(
            (vault_id, next.seq),
            ManifestRow {
                manifest: bundle.manifest.clone(),
                author: stored.account,
            },
        )?;
        if let Some(roster) = &bundle.roster {
            st.store.rosters().put(
                (vault_id, next.rver),
                RosterRow {
                    roster: roster.clone(),
                    seq: next.seq,
                },
            )?;
        }
        vault.head_seq = next.seq;
        vault.head_hash = next.hash;
        vault.rver = next.rver;
        vault.epoch = next.epoch;
        st.store.vaults().put(vault_id, vault)?;
        st.store
            .commit_log()
            .put((vault_id, stored.base_seq), stored.digest)?;
        for wire in &bundle.ops {
            self.put_item(st, vault_id, wire, next.seq)?;
        }
        self.sync_members(st, stored, old.map(|state| &state.roster), &next.roster)?;
        for share in &bundle.shares {
            let body = share.unverified()?;
            st.store.shares().put(
                (vault_id, body.epoch, body.to),
                ShareRow {
                    share: share.clone(),
                    seq: next.seq,
                },
            )?;
        }
        for entry in stored.self_wraps {
            if entry.epoch <= next.epoch {
                st.store
                    .self_wraps()
                    .put((stored.account, vault_id, entry.epoch), entry.wrap.clone())?;
            }
        }
        Ok(())
    }

    fn put_item(&self, st: &mut State<S>, vault: VaultId, wire: &ItemWire, seq: Seq) -> Res<()> {
        let (from, to) = item_bounds(vault, Some(wire.item_id));
        for (key, mut row) in st.store.items().range(&from, &to)? {
            if row.current {
                row.current = false;
                st.store.items().put(key, row)?;
            }
        }
        let bytes = wire.to_cbor()?;
        let tomb = matches!(wire.body, ItemBody::Tombstone);
        st.store.items().put(
            (vault, wire.item_id, wire.ver, wire.epoch),
            ItemRow {
                wire: wire.clone(),
                h_item: item_wire_hash(&bytes),
                tomb,
                size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                seq,
                current: true,
            },
        )?;
        for att in &wire.att_ids {
            self.acquire(st, att)?;
        }
        self.prune_item(st, vault, wire.item_id)
    }

    fn prune_item(&self, st: &mut State<S>, vault: VaultId, item: ItemId) -> Res<()> {
        let (from, to) = item_bounds(vault, Some(item));
        let rows = st.store.items().range(&from, &to)?;
        let mut versions: Vec<Version> = rows.iter().map(|(key, _)| key.2).collect();
        versions.sort_unstable();
        versions.dedup();
        let keep = self.config.history_versions;
        if versions.len() <= keep {
            return Ok(());
        }
        let cutoff = versions
            .get(versions.len().saturating_sub(keep))
            .copied()
            .ok_or(ErrorCode::Internal)?;
        for (key, row) in rows {
            if key.2 < cutoff {
                st.store.items().remove(&key)?;
                for att in &row.wire.att_ids {
                    self.release(st, att)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn self_wrap_put_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: SelfWrapPut,
    ) -> Res<Ack> {
        let session = self.session(st, call)?;
        let vault = st
            .store
            .vaults()
            .get(&req.vault_id)?
            .ok_or(ErrorCode::NotMember)?;
        let member = st
            .store
            .members()
            .get(&(req.vault_id, session.account_id))?
            .ok_or(ErrorCode::NotMember)?;
        if member.state != MemberStatus::Active || vault.state != VaultPhase::Active {
            return Err(ErrorCode::NotMember.into());
        }
        if req.entry.epoch > vault.epoch {
            return Err(ErrorCode::Epoch.into());
        }
        st.store.self_wraps().put(
            (session.account_id, req.vault_id, req.entry.epoch),
            req.entry.wrap,
        )?;
        Ok(Ack)
    }
}

pub(crate) struct StoredCommit<'a> {
    pub(crate) now: u64,
    pub(crate) account: AccountId,
    pub(crate) vault_id: VaultId,
    pub(crate) base_seq: Seq,
    pub(crate) bundle: &'a CommitBundle,
    pub(crate) self_wraps: &'a [SelfWrapEntry],
    pub(crate) digest: Hash32,
}
