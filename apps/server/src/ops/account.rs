use hasp_crypto::{opaque_check_record, opaque_register_response};
use hasp_proto::wire::{
    AccountDelete, AccountGet, AccountGetResponse, AccountLookup, AccountLookupResponse, Ack,
    ChangeCredentialFinish, ChangeCredentialStart, ErrorCode, NoticeKind, OpaqueResponse, RcSet,
    SessionInfo, SessionList, SessionListResponse, SessionRevoke, credential_id,
};
use hasp_proto::{
    AccountId, AccountRecord, AccountSeen, AccountStatus, Hash32, PinState, Seq, Signed, Uint53,
    Wire, verify_account_record,
};

use crate::server::{
    Call, NoticeDraft, Res, Server, State, latest_record, post_notice, remove_session,
    revoke_account_sessions, ts,
};
use crate::store::{AccountState, OpaqueRow, RecoveryRow, Store};
use hasp_proto::VaultKind;
use hasp_proto::wire::MemberState;

#[derive(Clone, Copy)]
pub(crate) struct RecoveryUpload<'a> {
    pub(crate) rc: &'a Signed<hasp_proto::RecoveryEnrolment>,
    pub(crate) rc_wrap: &'a hasp_proto::SealedRaw,
    pub(crate) h_auth: &'a Hash32,
    pub(crate) record: &'a Signed<AccountRecord>,
}

pub(crate) struct Successor {
    pub(crate) record: AccountRecord,
}

impl<S: Store> Server<S> {
    pub(crate) fn account_get_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        _: AccountGet,
    ) -> Res<AccountGetResponse> {
        let session = self.session(st, call)?;
        let account = session.account_id;
        let records = st
            .store
            .account_records()
            .range(&(account, Seq::ZERO), &(account, Seq::new(Uint53::MAX)?))?
            .into_iter()
            .map(|(_, record)| record)
            .collect();
        let keyset = st
            .store
            .keysets()
            .get(&account)?
            .ok_or(ErrorCode::NotFound)?;
        Ok(AccountGetResponse {
            records,
            keyset,
            memberships: self.membership_list(st, &account)?,
        })
    }

    pub(crate) fn account_lookup_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AccountLookup,
    ) -> Res<AccountLookupResponse> {
        self.session(st, call)?;
        let id = st.store.logins().get(&req.login)?;
        let account = match id {
            Some(id) => latest_record(st, &id)?.map(|(signed, _)| signed),
            None => None,
        };
        Ok(AccountLookupResponse { account })
    }

    pub(crate) fn change_credential_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: ChangeCredentialStart,
    ) -> Res<OpaqueResponse> {
        let session = self.reauthed(st, call)?;
        let response = opaque_register_response(
            &self.setup,
            req.request.as_slice(),
            &credential_id(&session.account_id)?,
        )
        .map_err(|_| ErrorCode::Format)?;
        Ok(OpaqueResponse {
            response: response.into(),
        })
    }

    pub(crate) fn next_account_record(
        &self,
        st: &mut State<S>,
        account: &AccountId,
        rec: &Signed<AccountRecord>,
    ) -> Res<Successor> {
        let (latest_signed, latest) = latest_record(st, account)?.ok_or(ErrorCode::NotFound)?;
        let seen = AccountSeen {
            seq: latest.seq,
            hash: latest_signed.hash(),
        };
        let record = verify_account_record(rec, Some(&seen), &PinState::new())?;
        if record.account_id != *account
            || record.seq != latest.seq.checked_next()?
            || record.prev != Some(seen.hash)
            || record.ik_pk != latest.ik_pk
            || record.kem_pk != latest.kem_pk
            || record.created != latest.created
        {
            return Err(ErrorCode::Format.into());
        }
        Ok(Successor { record })
    }

    pub(crate) fn change_credential_finish_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: ChangeCredentialFinish,
    ) -> Res<Ack> {
        let session = self.reauthed(st, call)?;
        let account = session.account_id;
        opaque_check_record(req.record.as_slice()).map_err(|_| ErrorCode::Format)?;
        let stored = st
            .store
            .keysets()
            .get(&account)?
            .ok_or(ErrorCode::NotFound)?;
        if req.keyset.account_id != account {
            return Err(ErrorCode::Format.into());
        }
        if req.keyset.generation < stored.generation {
            return Err(ErrorCode::Rollback.into());
        }
        if let Some(rec) = &req.account {
            let (_, latest) = latest_record(st, &account)?.ok_or(ErrorCode::NotFound)?;
            let next = self.next_account_record(st, &account, rec)?;
            if next.record.status != AccountStatus::Active || next.record.rc_gen != latest.rc_gen {
                return Err(ErrorCode::Format.into());
            }
            st.store
                .account_records()
                .put((account, next.record.seq), rec.clone())?;
        }
        let mut row = st
            .store
            .accounts()
            .get(&account)?
            .ok_or(ErrorCode::NotFound)?;
        row.cred_gen = row.cred_gen.saturating_add(1);
        st.store.opaque_records().put(
            account,
            OpaqueRow {
                record: req.record.0,
                cred_gen: row.cred_gen,
            },
        )?;
        st.store.accounts().put(account, row)?;
        st.store.keysets().put(account, req.keyset)?;
        revoke_account_sessions(st, &account, Some(&session.session_id))?;
        post_notice(
            st,
            &account,
            NoticeDraft::new(NoticeKind::CredentialChanged),
            call.now,
        )?;
        Ok(Ack)
    }

    pub(crate) fn session_list_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        _: SessionList,
    ) -> Res<SessionListResponse> {
        let current = self.session(st, call)?;
        let rows = st.store.sessions().range(
            &hasp_proto::wire::SessionId::from_bytes([0; 16]),
            &hasp_proto::wire::SessionId::from_bytes([0xff; 16]),
        )?;
        let sessions = rows
            .into_iter()
            .filter(|(_, row)| row.account_id == current.account_id)
            .map(|(_, row)| SessionInfo {
                session_id: row.session_id,
                device_id: row.device_id,
                platform: row.platform,
                label: row.label,
                created: ts(row.created),
                last_seen: ts(row.last_seen),
                idle_expires: ts(row.idle_expires),
                abs_expires: ts(row.abs_expires),
                current: row.session_id == current.session_id,
            })
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn session_revoke_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: SessionRevoke,
    ) -> Res<Ack> {
        let current = self.session(st, call)?;
        let row = st
            .store
            .sessions()
            .get(&req.session_id)?
            .filter(|row| row.account_id == current.account_id)
            .ok_or(ErrorCode::NotFound)?;
        remove_session(st, &row)?;
        Ok(Ack)
    }

    pub(crate) fn rc_set_op(&self, st: &mut State<S>, call: &Call<'_>, req: RcSet) -> Res<Ack> {
        let session = self.reauthed(st, call)?;
        let upload = RecoveryUpload {
            rc: &req.rc,
            rc_wrap: &req.rc_wrap,
            h_auth: &req.h_auth,
            record: &req.account,
        };
        self.store_recovery_enrolment(st, &session.account_id, &upload)?;
        Ok(Ack)
    }

    pub(crate) fn store_recovery_enrolment(
        &self,
        st: &mut State<S>,
        account: &AccountId,
        upload: &RecoveryUpload<'_>,
    ) -> Res<()> {
        let RecoveryUpload {
            rc,
            rc_wrap,
            h_auth,
            record: rec,
        } = *upload;
        let (_, latest) = latest_record(st, account)?.ok_or(ErrorCode::NotFound)?;
        let next = self.next_account_record(st, account, rec)?;
        if next.record.status != AccountStatus::Active
            || next.record.rc_gen != latest.rc_gen.checked_next()?
        {
            return Err(ErrorCode::Rollback.into());
        }
        let body = rc.verify(hasp_proto::SigLabel::Recovery, &latest.ik_pk)?;
        if body.account_id != *account
            || body.rgen != next.record.rc_gen
            || body.h_wrap != Hash32::digest(&[&rc_wrap.to_cbor()?])
        {
            return Err(ErrorCode::Rollback.into());
        }
        st.store
            .account_records()
            .put((*account, next.record.seq), rec.clone())?;
        st.store.recovery_enrolments().put(
            (*account, body.rgen.get()),
            RecoveryRow {
                enrolment: rc.clone(),
                rc_wrap: rc_wrap.clone(),
                h_auth: *h_auth,
            },
        )?;
        Ok(())
    }

    pub(crate) fn account_delete_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AccountDelete,
    ) -> Res<Ack> {
        let session = self.reauthed(st, call)?;
        let account = session.account_id;
        let next = self.next_account_record(st, &account, &req.account)?;
        if next.record.status != AccountStatus::Deleted {
            return Err(ErrorCode::Format.into());
        }
        self.guard_deletion(st, &account)?;
        st.store
            .account_records()
            .put((account, next.record.seq), req.account)?;
        self.purge_account(st, &account)?;
        Ok(Ack)
    }

    pub(crate) fn guard_deletion(&self, st: &mut State<S>, account: &AccountId) -> Res<()> {
        for membership in self.membership_list(st, account)? {
            let owner_active = membership.role == hasp_proto::Role::Owner
                && membership.kind == VaultKind::Shared
                && membership.state == MemberState::Active;
            let member_active =
                membership.kind == VaultKind::Shared && membership.state == MemberState::Active;
            if owner_active || member_active {
                return Err(ErrorCode::Conflict.into());
            }
        }
        Ok(())
    }

    pub(crate) fn purge_account(&self, st: &mut State<S>, account: &AccountId) -> Res<()> {
        for membership in self.membership_list(st, account)? {
            if membership.kind == VaultKind::Private {
                let vault = membership.vault_id;
                self.purge_vault_data(st, &vault)?;
                st.store.members().remove(&(vault, *account))?;
                st.store.vaults().remove(&vault)?;
            } else {
                st.store
                    .members()
                    .remove(&(membership.vault_id, *account))?;
                self.delete_member_material(st, membership.vault_id, account)?;
            }
            st.store
                .memberships()
                .remove(&(*account, membership.vault_id))?;
        }
        revoke_account_sessions(st, account, None)?;
        if let Some(row) = st.store.accounts().remove(account)? {
            st.store.logins().remove(&row.login)?;
        }
        st.store.opaque_records().remove(account)?;
        st.store.keysets().remove(account)?;
        let rgens = st
            .store
            .recovery_enrolments()
            .range(&(*account, 0), &(*account, u64::MAX))?;
        for (key, _) in rgens {
            st.store.recovery_enrolments().remove(&key)?;
        }
        let notices = st
            .store
            .notices()
            .range(&(*account, 0), &(*account, u64::MAX))?;
        for (key, _) in notices {
            st.store.notices().remove(&key)?;
        }
        Ok(())
    }

    pub(crate) fn disable_account(
        &self,
        st: &mut State<S>,
        account: &AccountId,
        disabled: bool,
    ) -> Res<()> {
        let mut row = st
            .store
            .accounts()
            .get(account)?
            .ok_or(ErrorCode::NotFound)?;
        row.state = if disabled {
            AccountState::Disabled
        } else {
            AccountState::Active
        };
        st.store.accounts().put(*account, row)?;
        if disabled {
            revoke_account_sessions(st, account, None)?;
        }
        Ok(())
    }
}
