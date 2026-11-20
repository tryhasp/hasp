use hasp_proto::wire::{
    Ack, Blob, ErrorCode, InviteAccept, InviteCreate, InviteCreateResponse, InviteDecline,
    InviteEntry, InviteGet, InviteList, InviteListResponse, InviteState, InviteView, Leave,
    NoticeKind, VaultDissolve,
};
use hasp_proto::{
    AccountId, Epoch, InviteId, Role, Rver, Seq, Uint53, VaultId, VaultKind, verify_dissolve,
    verify_leave,
};

use crate::server::{Call, NoticeDraft, Res, Server, State, latest_record, post_notice, ts};
use crate::store::{InviteRow, MemberRow, MemberStatus, Store, VaultPhase};

const MAX_ACCEPT: usize = 4096;

fn effective(row: &InviteRow, now: u64) -> InviteState {
    if row.state == InviteState::Open && now >= row.expires {
        InviteState::Expired
    } else {
        row.state
    }
}

impl<S: Store> Server<S> {
    fn owner_of(&self, st: &mut State<S>, vault: &VaultId, account: &AccountId) -> Res<()> {
        let member = self.vault_member(st, vault, account)?;
        if member.role != Role::Owner {
            return Err(ErrorCode::Authz.into());
        }
        Ok(())
    }

    pub(crate) fn invite_create_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: InviteCreate,
    ) -> Res<InviteCreateResponse> {
        let session = self.session(st, call)?;
        self.owner_of(st, &req.vault_id, &session.account_id)?;
        let vault = st
            .store
            .vaults()
            .get(&req.vault_id)?
            .ok_or(ErrorCode::NotMember)?;
        if vault.kind != VaultKind::Shared || req.role == Role::Owner {
            return Err(ErrorCode::Format.into());
        }
        let id = InviteId::random()?;
        let expires = call.now.saturating_add(self.config.invite_ttl);
        st.store.invites().put(
            id,
            InviteRow {
                vault_id: req.vault_id,
                inviter: session.account_id,
                role: req.role,
                expires,
                state: InviteState::Open,
                invitee: None,
                accept: None,
            },
        )?;
        Ok(InviteCreateResponse {
            invite_id: id,
            expires: ts(expires),
        })
    }

    pub(crate) fn invite_get_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: InviteGet,
    ) -> Res<InviteView> {
        self.session(st, call)?;
        let row = st
            .store
            .invites()
            .get(&req.invite_id)?
            .ok_or(ErrorCode::NotFound)?;
        let (inviter, _) = latest_record(st, &row.inviter)?.ok_or(ErrorCode::NotFound)?;
        Ok(InviteView {
            invite_id: req.invite_id,
            vault_id: row.vault_id,
            role: row.role,
            state: effective(&row, call.now),
            expires: ts(row.expires),
            inviter,
        })
    }

    pub(crate) fn invite_list_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: InviteList,
    ) -> Res<InviteListResponse> {
        let session = self.session(st, call)?;
        self.owner_of(st, &req.vault_id, &session.account_id)?;
        let rows = st.store.invites().range(
            &InviteId::from_bytes([0; 16]),
            &InviteId::from_bytes([0xff; 16]),
        )?;
        let mut invites = Vec::new();
        for (id, row) in rows {
            if row.vault_id != req.vault_id {
                continue;
            }
            let joined = match row.invitee {
                Some(account) => latest_record(st, &account)?.map(|(signed, _)| signed),
                None => None,
            };
            invites.push(InviteEntry {
                invite_id: id,
                role: row.role,
                state: effective(&row, call.now),
                expires: ts(row.expires),
                invitee: joined,
                accept: row.accept.clone().map(Blob),
            });
        }
        Ok(InviteListResponse { invites })
    }

    pub(crate) fn invite_accept_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: InviteAccept,
    ) -> Res<Ack> {
        let session = self.session(st, call)?;
        let mut row = st
            .store
            .invites()
            .get(&req.invite_id)?
            .ok_or(ErrorCode::NotFound)?;
        if effective(&row, call.now) != InviteState::Open {
            return Err(ErrorCode::Conflict.into());
        }
        if row.inviter == session.account_id || req.accept.0.len() > MAX_ACCEPT {
            return Err(ErrorCode::Conflict.into());
        }
        let vault = st
            .store
            .vaults()
            .get(&row.vault_id)?
            .ok_or(ErrorCode::NotFound)?;
        if vault.state != VaultPhase::Active {
            return Err(ErrorCode::NotFound.into());
        }
        let key = (row.vault_id, session.account_id);
        if st.store.members().get(&key)?.is_some_and(|existing| {
            matches!(existing.state, MemberStatus::Active | MemberStatus::Leaving)
        }) {
            return Err(ErrorCode::Conflict.into());
        }
        st.store.members().put(
            key,
            MemberRow {
                role: row.role,
                state: MemberStatus::Invited,
                rver: Rver::ZERO,
                leave: None,
            },
        )?;
        st.store
            .memberships()
            .put((session.account_id, row.vault_id), ())?;
        row.state = InviteState::Accepted;
        row.invitee = Some(session.account_id);
        row.accept = Some(req.accept.0);
        let inviter = row.inviter;
        let vault_id = row.vault_id;
        st.store.invites().put(req.invite_id, row)?;
        post_notice(
            st,
            &inviter,
            NoticeDraft::new(NoticeKind::InviteAccepted).vault(vault_id),
            call.now,
        )?;
        Ok(Ack)
    }

    pub(crate) fn invite_decline_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: InviteDecline,
    ) -> Res<Ack> {
        let session = self.session(st, call)?;
        let mut row = st
            .store
            .invites()
            .get(&req.invite_id)?
            .ok_or(ErrorCode::NotFound)?;
        match effective(&row, call.now) {
            InviteState::Open => {}
            InviteState::Accepted if row.invitee == Some(session.account_id) => {
                let key = (row.vault_id, session.account_id);
                if st
                    .store
                    .members()
                    .get(&key)?
                    .is_some_and(|member| member.state == MemberStatus::Invited)
                {
                    st.store.members().remove(&key)?;
                    st.store
                        .memberships()
                        .remove(&(session.account_id, row.vault_id))?;
                }
            }
            InviteState::Accepted
            | InviteState::Declined
            | InviteState::Used
            | InviteState::Expired => return Err(ErrorCode::Conflict.into()),
        }
        row.state = InviteState::Declined;
        st.store.invites().put(req.invite_id, row)?;
        Ok(Ack)
    }

    pub(crate) fn leave_op(&self, st: &mut State<S>, call: &Call<'_>, req: Leave) -> Res<Ack> {
        let session = self.session(st, call)?;
        let claimed = req.request.unverified()?;
        if claimed.account_id != session.account_id {
            return Err(ErrorCode::Authz.into());
        }
        let vault_id = claimed.vault_id;
        let vault = st
            .store
            .vaults()
            .get(&vault_id)?
            .ok_or(ErrorCode::NotMember)?;
        let mut member = self.vault_member(st, &vault_id, &session.account_id)?;
        if vault.kind != VaultKind::Shared || member.role == Role::Owner {
            return Err(ErrorCode::Authz.into());
        }
        let state = self.vault_state(st, &vault_id, &vault)?;
        verify_leave(&req.request, &state)?;
        member.state = MemberStatus::Leaving;
        member.leave = Some(req.request);
        st.store
            .members()
            .put((vault_id, session.account_id), member)?;
        self.delete_member_material(st, vault_id, &session.account_id)?;
        post_notice(
            st,
            &vault.owner,
            NoticeDraft::new(NoticeKind::MemberLeaving).vault(vault_id),
            call.now,
        )?;
        Ok(Ack)
    }

    pub(crate) fn vault_dissolve_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: VaultDissolve,
    ) -> Res<Ack> {
        let session = self.reauthed(st, call)?;
        let claimed = req.record.unverified()?;
        let vault_id = claimed.vault_id;
        let mut vault = st
            .store
            .vaults()
            .get(&vault_id)?
            .ok_or(ErrorCode::NotMember)?;
        self.owner_of(st, &vault_id, &session.account_id)?;
        if vault.kind != VaultKind::Shared || vault.owner != session.account_id {
            return Err(ErrorCode::Authz.into());
        }
        if claimed.seq != vault.head_seq || claimed.head != vault.head_hash {
            return Err(ErrorCode::StaleHead.into());
        }
        let state = self.vault_state(st, &vault_id, &vault)?;
        verify_dissolve(&req.record, &state)?;
        let members = st.store.members().range(
            &(vault_id, AccountId::from_bytes([0; 16])),
            &(vault_id, AccountId::from_bytes([0xff; 16])),
        )?;
        self.purge_vault_data(st, &vault_id)?;
        for ((_, account), mut row) in members {
            row.state = MemberStatus::Dissolved;
            row.leave = None;
            st.store.members().put((vault_id, account), row)?;
            if account != session.account_id {
                post_notice(
                    st,
                    &account,
                    NoticeDraft::new(NoticeKind::VaultDissolved).vault(vault_id),
                    call.now,
                )?;
            }
        }
        vault.state = VaultPhase::Dissolved;
        vault.dissolve = Some(req.record);
        st.store.vaults().put(vault_id, vault)?;
        Ok(Ack)
    }

    pub(crate) fn purge_vault_data(&self, st: &mut State<S>, vault: &VaultId) -> Res<()> {
        let seq_max = Seq::new(Uint53::MAX)?;
        for (key, _) in st
            .store
            .manifests()
            .range(&(*vault, Seq::ZERO), &(*vault, seq_max))?
        {
            st.store.manifests().remove(&key)?;
        }
        for (key, _) in st
            .store
            .rosters()
            .range(&(*vault, Rver::ZERO), &(*vault, Rver::new(Uint53::MAX)?))?
        {
            st.store.rosters().remove(&key)?;
        }
        for (key, _) in st
            .store
            .commit_log()
            .range(&(*vault, Seq::ZERO), &(*vault, seq_max))?
        {
            st.store.commit_log().remove(&key)?;
        }
        let epoch_max = Epoch::new(Uint53::MAX)?;
        for (key, _) in st.store.shares().range(
            &(*vault, Epoch::ZERO, AccountId::from_bytes([0; 16])),
            &(*vault, epoch_max, AccountId::from_bytes([0xff; 16])),
        )? {
            st.store.shares().remove(&key)?;
        }
        let members = st.store.members().range(
            &(*vault, AccountId::from_bytes([0; 16])),
            &(*vault, AccountId::from_bytes([0xff; 16])),
        )?;
        for ((_, account), _) in members {
            self.delete_member_material(st, *vault, &account)?;
        }
        let version_max = hasp_proto::Version::new(Uint53::MAX)?;
        for (key, _) in st.store.items().range(
            &(
                *vault,
                hasp_proto::ItemId::from_bytes([0; 16]),
                hasp_proto::Version::ZERO,
                Epoch::ZERO,
            ),
            &(
                *vault,
                hasp_proto::ItemId::from_bytes([0xff; 16]),
                version_max,
                epoch_max,
            ),
        )? {
            st.store.items().remove(&key)?;
        }
        let invites = st.store.invites().range(
            &InviteId::from_bytes([0; 16]),
            &InviteId::from_bytes([0xff; 16]),
        )?;
        for (id, row) in invites {
            if row.vault_id == *vault {
                st.store.invites().remove(&id)?;
            }
        }
        let attachments = st.store.attachments().range(
            &hasp_proto::AttId::from_bytes([0; 16]),
            &hasp_proto::AttId::from_bytes([0xff; 16]),
        )?;
        for (id, row) in attachments {
            if row.vault_id == *vault {
                self.drop_attachment(st, &id)?;
            }
        }
        Ok(())
    }
}
