use hasp_proto::wire::{InviteState, MemberState, Membership, NoticeKind};
use hasp_proto::{AccountId, Epoch, InviteId, Roster, VaultId};

use crate::server::{NoticeDraft, Res, Server, State, post_notice};
use crate::store::{MemberRow, MemberStatus, Store};

use super::{StoredCommit, epoch_max};

impl<S: Store> Server<S> {
    pub(super) fn sync_members(
        &self,
        st: &mut State<S>,
        stored: &StoredCommit<'_>,
        old: Option<&Roster>,
        new: &Roster,
    ) -> Res<()> {
        let vault = stored.vault_id;
        let now = stored.now;
        for member in &new.members {
            let key = (vault, member.account_id);
            match st.store.members().get(&key)? {
                Some(mut row) if row.state == MemberStatus::Invited => {
                    row.state = MemberStatus::Active;
                    row.role = member.role;
                    row.rver = member.added_rver;
                    st.store.members().put(key, row)?;
                    self.close_invite(st, vault, member.account_id)?;
                }
                Some(mut row) if row.state == MemberStatus::Active => {
                    row.role = member.role;
                    st.store.members().put(key, row)?;
                }
                Some(_) => {}
                None => {
                    st.store.members().put(
                        key,
                        MemberRow {
                            role: member.role,
                            state: MemberStatus::Active,
                            rver: member.added_rver,
                            leave: None,
                        },
                    )?;
                }
            }
            st.store.memberships().put((member.account_id, vault), ())?;
        }
        let Some(old) = old else {
            return Ok(());
        };
        for gone in old
            .members
            .iter()
            .filter(|member| new.member(&member.account_id).is_none())
        {
            let key = (vault, gone.account_id);
            if let Some(mut row) = st.store.members().get(&key)? {
                row.state = MemberStatus::Removed;
                row.leave = None;
                st.store.members().put(key, row)?;
            }
            self.delete_member_material(st, vault, &gone.account_id)?;
            post_notice(
                st,
                &gone.account_id,
                NoticeDraft::new(NoticeKind::MemberRemoved).vault(vault),
                now,
            )?;
        }
        Ok(())
    }

    pub(crate) fn delete_member_material(
        &self,
        st: &mut State<S>,
        vault: VaultId,
        account: &AccountId,
    ) -> Res<()> {
        for (key, _) in st.store.shares().range(
            &(vault, Epoch::ZERO, AccountId::from_bytes([0; 16])),
            &(vault, epoch_max(), AccountId::from_bytes([0xff; 16])),
        )? {
            if key.2 == *account {
                st.store.shares().remove(&key)?;
            }
        }
        for (key, _) in st.store.self_wraps().range(
            &(*account, vault, Epoch::ZERO),
            &(*account, vault, epoch_max()),
        )? {
            st.store.self_wraps().remove(&key)?;
        }
        Ok(())
    }

    pub(super) fn close_invite(
        &self,
        st: &mut State<S>,
        vault: VaultId,
        invitee: AccountId,
    ) -> Res<()> {
        let rows = st.store.invites().range(
            &InviteId::from_bytes([0; 16]),
            &InviteId::from_bytes([0xff; 16]),
        )?;
        for (id, mut row) in rows {
            if row.vault_id == vault
                && row.invitee == Some(invitee)
                && row.state == InviteState::Accepted
            {
                row.state = InviteState::Used;
                st.store.invites().put(id, row)?;
            }
        }
        Ok(())
    }

    pub(crate) fn membership_list(
        &self,
        st: &mut State<S>,
        account: &AccountId,
    ) -> Res<Vec<Membership>> {
        let rows = st.store.memberships().range(
            &(*account, VaultId::from_bytes([0; 16])),
            &(*account, VaultId::from_bytes([0xff; 16])),
        )?;
        let mut out = Vec::new();
        for ((_, vault_id), ()) in rows {
            let (Some(member), Some(vault)) = (
                st.store.members().get(&(vault_id, *account))?,
                st.store.vaults().get(&vault_id)?,
            ) else {
                continue;
            };
            out.push(Membership {
                vault_id,
                kind: vault.kind,
                role: member.role,
                state: match member.state {
                    MemberStatus::Invited => MemberState::Invited,
                    MemberStatus::Active => MemberState::Active,
                    MemberStatus::Leaving => MemberState::Leaving,
                    MemberStatus::Removed => MemberState::Removed,
                    MemberStatus::Dissolved => MemberState::Dissolved,
                },
            });
        }
        Ok(out)
    }
}
