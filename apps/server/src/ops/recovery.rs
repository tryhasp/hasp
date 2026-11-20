use hasp_crypto::{ct_eq, opaque_check_record, opaque_register_response};
use hasp_proto::wire::{
    Ack, ErrorCode, NoticeKind, OpaqueResponse, RcAuthKey, RecoverAbort, RecoverComplete,
    RecoverFetch, RecoverFetchResponse, RecoverRegisterStart, RecoverStart, RecoverStartResponse,
    RecoveryId, SessionGrant, SessionToken, WireError, credential_id,
};
use hasp_proto::{AccountId, Seq, Uint53};

use crate::rate::RateClass;
use crate::server::{
    Call, NoticeDraft, Res, Server, State, latest_record, post_notice, revoke_account_sessions, ts,
};
use crate::store::{OpaqueRow, RecoveryRow, RecoverySessionRow, RecoveryState, Store};

impl<S: Store> Server<S> {
    fn current_enrolment(
        &self,
        st: &mut State<S>,
        account: &AccountId,
    ) -> Res<Option<RecoveryRow>> {
        let Some((_, record)) = latest_record(st, account)? else {
            return Ok(None);
        };
        Ok(st
            .store
            .recovery_enrolments()
            .get(&(*account, record.rc_gen.get()))?
            .filter(|row| {
                row.enrolment
                    .unverified()
                    .is_ok_and(|e| e.rgen == record.rc_gen)
            }))
    }

    pub(crate) fn recover_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RecoverStart,
    ) -> Res<RecoverStartResponse> {
        self.admit(call, RateClass::Recovery, Some(req.account_id.as_bytes()))?;
        let account = st.store.accounts().get(&req.account_id)?;
        let enrolment = self.current_enrolment(st, &req.account_id)?;
        let presented = req.k_rc_auth.hash();
        let matches = enrolment
            .as_ref()
            .is_some_and(|row| ct_eq(presented.as_bytes(), row.h_auth.as_bytes()));
        let active = account
            .as_ref()
            .is_some_and(|row| row.state == crate::store::AccountState::Active);
        if !matches || !active {
            return Err(ErrorCode::Auth.into());
        }
        let rgen = latest_record(st, &req.account_id)?
            .map(|(_, record)| record.rc_gen.get())
            .ok_or(ErrorCode::Auth)?;
        let existing = st.store.recovery_sessions_of(&req.account_id)?;
        if let Some((id, row)) = existing
            .into_iter()
            .find(|(_, row)| row.state == RecoveryState::Pending)
        {
            return Ok(RecoverStartResponse {
                recovery_id: id,
                release_at: ts(row.release_at),
            });
        }
        let id = RecoveryId::random()?;
        let release_at = call.now.saturating_add(self.config.recovery_delay);
        st.store.recovery_sessions().put(
            id,
            RecoverySessionRow {
                account_id: req.account_id,
                rgen,
                started: call.now,
                release_at,
                state: RecoveryState::Pending,
                source: call.caller.peer.map(|peer| peer.to_string()),
                token_hash: None,
            },
        )?;
        post_notice(
            st,
            &req.account_id,
            NoticeDraft::new(NoticeKind::RecoveryStarted).at(release_at),
            call.now,
        )?;
        Ok(RecoverStartResponse {
            recovery_id: id,
            release_at: ts(release_at),
        })
    }

    pub(crate) fn recover_abort_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RecoverAbort,
    ) -> Res<Ack> {
        match (req.recovery_id, req.k_rc_auth) {
            (None, None) => {
                let session = self.session(st, call)?;
                self.abort_recoveries(st, &session.account_id, call.now)?;
            }
            (Some(id), Some(auth)) => self.abort_by_recovery_code(st, call, id, &auth)?,
            _ => return Err(ErrorCode::Format.into()),
        }
        Ok(Ack)
    }

    fn abort_by_recovery_code(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        id: RecoveryId,
        auth: &RcAuthKey,
    ) -> Res<()> {
        self.admit(call, RateClass::Recovery, Some(id.as_bytes()))?;
        let mut row = st
            .store
            .recovery_sessions()
            .get(&id)?
            .ok_or(ErrorCode::Auth)?;
        let enrolment = st
            .store
            .recovery_enrolments()
            .get(&(row.account_id, row.rgen))?
            .ok_or(ErrorCode::Auth)?;
        let presented = auth.hash();
        if !ct_eq(presented.as_bytes(), enrolment.h_auth.as_bytes()) {
            return Err(ErrorCode::Auth.into());
        }
        if !matches!(row.state, RecoveryState::Pending | RecoveryState::Released) {
            return Err(ErrorCode::Auth.into());
        }
        let account = row.account_id;
        row.state = RecoveryState::Aborted;
        row.token_hash = None;
        st.store.recovery_sessions().put(id, row)?;
        post_notice(
            st,
            &account,
            NoticeDraft::new(NoticeKind::RecoveryAborted),
            call.now,
        )
    }

    pub(crate) fn recover_fetch_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RecoverFetch,
    ) -> Res<RecoverFetchResponse> {
        self.admit(call, RateClass::Recovery, Some(req.recovery_id.as_bytes()))?;
        let mut row = st
            .store
            .recovery_sessions()
            .get(&req.recovery_id)?
            .ok_or(ErrorCode::Auth)?;
        let enrolment = st
            .store
            .recovery_enrolments()
            .get(&(row.account_id, row.rgen))?
            .ok_or(ErrorCode::Auth)?;
        let presented = req.k_rc_auth.hash();
        if !ct_eq(presented.as_bytes(), enrolment.h_auth.as_bytes()) {
            return Err(ErrorCode::Auth.into());
        }
        match row.state {
            RecoveryState::Pending | RecoveryState::Released => {}
            RecoveryState::Aborted | RecoveryState::Done => return Err(ErrorCode::Auth.into()),
        }
        if call.now < row.release_at {
            return Err(WireError::retry_after(
                ErrorCode::Pending,
                row.release_at.saturating_sub(call.now),
            ));
        }
        let token = SessionToken::random()?;
        if row.state == RecoveryState::Pending {
            row.started = call.now;
        }
        row.state = RecoveryState::Released;
        row.token_hash = Some(token.hash());
        let account = row.account_id;
        st.store.recovery_sessions().put(req.recovery_id, row)?;
        let keyset = st
            .store
            .keysets()
            .get(&account)?
            .ok_or(ErrorCode::NotFound)?;
        let records = st
            .store
            .account_records()
            .range(&(account, Seq::ZERO), &(account, Seq::new(Uint53::MAX)?))?
            .into_iter()
            .map(|(_, record)| record)
            .collect();
        Ok(RecoverFetchResponse {
            token,
            enrolment: enrolment.enrolment,
            rc_wrap: enrolment.rc_wrap,
            keyset,
            records,
        })
    }

    fn recovery_session(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        recovery_id: &RecoveryId,
    ) -> Res<(RecoveryId, RecoverySessionRow)> {
        let token = call.caller.token.as_ref().ok_or(ErrorCode::Auth)?;
        let hash = token.hash();
        let row = st
            .store
            .recovery_sessions()
            .get(recovery_id)?
            .filter(|row| {
                row.state == RecoveryState::Released
                    && row.token_hash == Some(hash)
                    && call.now < row.started.saturating_add(self.config.recovery_window)
            })
            .ok_or(ErrorCode::Auth)?;
        self.admit(call, RateClass::General, Some(recovery_id.as_bytes()))?;
        Ok((*recovery_id, row))
    }

    pub(crate) fn recover_register_start_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RecoverRegisterStart,
    ) -> Res<OpaqueResponse> {
        let (_, row) = self.recovery_session(st, call, &req.recovery_id)?;
        let response = opaque_register_response(
            &self.setup,
            req.request.as_slice(),
            &credential_id(&row.account_id)?,
        )
        .map_err(|_| ErrorCode::Format)?;
        Ok(OpaqueResponse {
            response: response.into(),
        })
    }

    pub(crate) fn recover_complete_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: RecoverComplete,
    ) -> Res<SessionGrant> {
        let (id, mut row) = self.recovery_session(st, call, &req.recovery_id)?;
        let account = row.account_id;
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
        let upload = super::account::RecoveryUpload {
            rc: &req.rc,
            rc_wrap: &req.rc_wrap,
            h_auth: &req.h_auth,
            record: &req.account,
        };
        self.store_recovery_enrolment(st, &account, &upload)?;
        let mut account_row = st
            .store
            .accounts()
            .get(&account)?
            .ok_or(ErrorCode::NotFound)?;
        account_row.cred_gen = account_row.cred_gen.saturating_add(1);
        st.store.opaque_records().put(
            account,
            OpaqueRow {
                record: req.record.0,
                cred_gen: account_row.cred_gen,
            },
        )?;
        st.store.accounts().put(account, account_row)?;
        st.store.keysets().put(account, req.keyset)?;
        revoke_account_sessions(st, &account, None)?;
        row.state = RecoveryState::Done;
        row.token_hash = None;
        st.store.recovery_sessions().put(id, row)?;
        post_notice(
            st,
            &account,
            NoticeDraft::new(NoticeKind::RecoveryCompleted),
            call.now,
        )?;
        self.grant(st, call.now, account, &req.device)
    }
}
