use hasp_proto::wire::{CommitResponse, ErrorCode, RepairPublish};
use hasp_proto::{AccountId, Epoch, Hash32, Role, Rver, Seq, VaultId, Wire, verify_repair};

use crate::server::{Call, Res, Server, State};
use crate::store::{MemberStatus, Store, VaultPhase};

use super::{StoredCommit, epoch_max, item_bounds, proto_commit, rver_max, seq_max};

impl<S: Store> Server<S> {
    pub(crate) fn repair_publish_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RepairPublish,
    ) -> Res<CommitResponse> {
        let session = self.session(st, call)?;
        let account = session.account_id;
        let bundle = &req.bundle;
        let manifest = bundle.manifest.unverified()?;
        self.check_repair_shape(&req)?;
        let mut vault = st
            .store
            .vaults()
            .get(&req.vault_id)?
            .filter(|row| row.state == VaultPhase::Active)
            .ok_or(ErrorCode::NotMember)?;
        let member = st.store.members().get(&(req.vault_id, account))?;
        let Some(member) = member.filter(|row| row.state == MemberStatus::Active) else {
            return Err(ErrorCode::NotMember.into());
        };
        if manifest.author != account || member.role != Role::Owner {
            return Err(ErrorCode::Authz.into());
        }
        let seq = manifest.seq;
        let last_good = Seq::new(seq.get().saturating_sub(1))?;
        if seq.get() < 2 || seq > vault.head_seq {
            return Err(ErrorCode::Conflict.into());
        }
        let manifest_hash = bundle.manifest.hash();
        let digest = Hash32::digest(&[&req.to_cbor()?]);
        let bad = st
            .store
            .manifests()
            .get(&(req.vault_id, seq))?
            .ok_or(ErrorCode::Conflict)?;
        if bad.manifest.hash() == manifest_hash {
            let logged = st.store.commit_log().get(&(req.vault_id, last_good))?;
            return if logged == Some(digest) {
                Ok(CommitResponse {
                    head_seq: seq,
                    head_hash: manifest_hash,
                })
            } else {
                Err(ErrorCode::Sig.into())
            };
        }
        let good = st
            .store
            .manifests()
            .get(&(req.vault_id, last_good))?
            .ok_or(ErrorCode::Conflict)?;
        self.drop_suffix(st, req.vault_id, seq)?;
        vault.head_seq = last_good;
        vault.head_hash = good.manifest.hash();
        st.store.vaults().put(req.vault_id, vault.clone())?;
        let state = self.vault_state(st, &req.vault_id, &vault)?;
        let commit = proto_commit(bundle)?;
        let next = verify_repair(&state, None, &commit)?;
        self.check_attachments(st, &req.vault_id, &bundle.ops)?;
        let stored = StoredCommit {
            now: call.now,
            account,
            vault_id: req.vault_id,
            base_seq: last_good,
            bundle,
            self_wraps: &[],
            digest: Hash32::digest(&[&req.to_cbor()?]),
        };
        self.store_commit(st, &stored, &next, Some(&state))?;
        Ok(CommitResponse {
            head_seq: next.seq,
            head_hash: next.hash,
        })
    }

    fn check_repair_shape(&self, req: &RepairPublish) -> Res<()> {
        let bundle = &req.bundle;
        let manifest = bundle.manifest.unverified()?;
        if manifest.vault_id != req.vault_id
            || !manifest.repair
            || bundle.roster.is_some()
            || !bundle.shares.is_empty()
        {
            return Err(ErrorCode::Format.into());
        }
        if bundle.ops.len() > self.config.max_ops {
            return Err(ErrorCode::TooLarge.into());
        }
        Ok(())
    }

    pub(super) fn drop_suffix(&self, st: &mut State<S>, vault: VaultId, from: Seq) -> Res<()> {
        let rosters = st
            .store
            .rosters()
            .range(&(vault, Rver::ZERO), &(vault, rver_max()))?;
        let shares = st.store.shares().range(
            &(vault, Epoch::ZERO, AccountId::from_bytes([0; 16])),
            &(vault, epoch_max(), AccountId::from_bytes([0xff; 16])),
        )?;
        if rosters.iter().any(|(_, row)| row.seq >= from)
            || shares.iter().any(|(_, row)| row.seq >= from)
        {
            return Err(ErrorCode::Unsupported.into());
        }
        for (key, _) in st
            .store
            .manifests()
            .range(&(vault, from), &(vault, seq_max()))?
        {
            st.store.manifests().remove(&key)?;
        }
        let base = Seq::new(from.get().saturating_sub(1))?;
        for (key, _) in st
            .store
            .commit_log()
            .range(&(vault, base), &(vault, seq_max()))?
        {
            st.store.commit_log().remove(&key)?;
        }
        let (item_from, item_to) = item_bounds(vault, None);
        let mut touched = Vec::new();
        for (key, row) in st.store.items().range(&item_from, &item_to)? {
            if row.seq >= from {
                st.store.items().remove(&key)?;
                for att in &row.wire.att_ids {
                    self.release(st, att)?;
                }
                touched.push(key.1);
            }
        }
        touched.sort_unstable();
        touched.dedup();
        for item in touched {
            let (lo, hi) = item_bounds(vault, Some(item));
            let rows = st.store.items().range(&lo, &hi)?;
            let newest = rows.iter().map(|(key, _)| *key).max();
            for (key, mut row) in rows {
                row.current = Some(key) == newest;
                st.store.items().put(key, row)?;
            }
        }
        Ok(())
    }
}
