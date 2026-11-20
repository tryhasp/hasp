use hasp_proto::wire::{
    Ack, EnrolAbort, EnrolApprove, EnrolMsgGet, EnrolMsgGetResponse, EnrolMsgPut, EnrolOpen,
    EnrolOpenResponse, ErrorCode, SessionGrant,
};

use crate::rate::RateClass;
use crate::server::{Call, Res, Server, State, ts};
use crate::store::{EnrolRow, EnrolState, Store};

const MAX_SLOT: usize = 1024 * 1024;
const MAX_MESSAGES: u32 = 16;

impl<S: Store> Server<S> {
    pub(crate) fn enrol_open_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: EnrolOpen,
    ) -> Res<EnrolOpenResponse> {
        let session = self.session(st, call)?;
        if st.store.enrol_channels().get(&req.esid)?.is_some() {
            return Err(ErrorCode::Conflict.into());
        }
        let expires = call.now.saturating_add(self.config.enrol_ttl);
        st.store.enrol_channels().put(
            req.esid,
            EnrolRow {
                account_id: session.account_id,
                session_id: session.session_id,
                expires,
                state: EnrolState::Open,
                slots: Vec::new(),
                attempts: 0,
            },
        )?;
        Ok(EnrolOpenResponse {
            expires: ts(expires),
        })
    }

    fn live_channel(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        esid: &hasp_proto::Esid,
    ) -> Res<EnrolRow> {
        let row = st
            .store
            .enrol_channels()
            .get(esid)?
            .ok_or(ErrorCode::NotFound)?;
        if call.now >= row.expires {
            return Err(ErrorCode::Expired.into());
        }
        if row.state == EnrolState::Aborted {
            return Err(ErrorCode::NotFound.into());
        }
        Ok(row)
    }

    pub(crate) fn enrol_msg_put_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: EnrolMsgPut,
    ) -> Res<Ack> {
        self.admit(call, RateClass::General, Some(req.esid.as_bytes()))?;
        let mut row = self.live_channel(st, call, &req.esid)?;
        let slot = req.slot.code();
        if req.data.0.len() > MAX_SLOT {
            return Err(ErrorCode::TooLarge.into());
        }
        if let Some((_, stored)) = row.slots.iter().find(|(code, _)| *code == slot) {
            return if *stored == req.data.0 {
                Ok(Ack)
            } else {
                Err(ErrorCode::Conflict.into())
            };
        }
        let earlier = (1..slot).all(|code| row.slots.iter().any(|(filled, _)| *filled == code));
        if !earlier {
            return Err(ErrorCode::Conflict.into());
        }
        if row.attempts >= MAX_MESSAGES {
            return Err(ErrorCode::TooLarge.into());
        }
        row.attempts = row.attempts.saturating_add(1);
        row.slots.push((slot, req.data.0));
        st.store.enrol_channels().put(req.esid, row)?;
        Ok(Ack)
    }

    pub(crate) fn enrol_msg_get_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: EnrolMsgGet,
    ) -> Res<EnrolMsgGetResponse> {
        self.admit(call, RateClass::General, Some(req.esid.as_bytes()))?;
        let row = self.live_channel(st, call, &req.esid)?;
        let slot = req.slot.code();
        Ok(EnrolMsgGetResponse {
            data: row
                .slots
                .into_iter()
                .find(|(code, _)| *code == slot)
                .map(|(_, data)| data.into()),
        })
    }

    pub(crate) fn enrol_approve_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: EnrolApprove,
    ) -> Res<SessionGrant> {
        let session = self.session(st, call)?;
        let mut row = self.live_channel(st, call, &req.esid)?;
        if row.account_id != session.account_id
            || row.session_id != session.session_id
            || row.state != EnrolState::Open
        {
            return Err(ErrorCode::Authz.into());
        }
        let grant = self.grant(st, call.now, session.account_id, &req.device)?;
        row.state = EnrolState::Approved;
        st.store.enrol_channels().put(req.esid, row)?;
        Ok(grant)
    }

    pub(crate) fn enrol_abort_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: EnrolAbort,
    ) -> Res<Ack> {
        self.admit(call, RateClass::General, Some(req.esid.as_bytes()))?;
        let mut row = st
            .store
            .enrol_channels()
            .get(&req.esid)?
            .ok_or(ErrorCode::NotFound)?;
        row.state = EnrolState::Aborted;
        row.slots.clear();
        st.store.enrol_channels().put(req.esid, row)?;
        Ok(Ack)
    }
}
