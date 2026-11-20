use hasp_proto::wire::{InviteState, SessionId};
use hasp_proto::{AttId, InviteId};

use crate::server::{Res, Server, State, remove_session};
use crate::store::{AttachmentState, EnrolState, Store};

pub(crate) fn sweep<S: Store>(srv: &Server<S>, st: &mut State<S>, now: u64) -> Res<()> {
    st.pending.retain(|_, pending| pending.expires > now);
    let sessions = st.store.sessions().range(
        &SessionId::from_bytes([0; 16]),
        &SessionId::from_bytes([0xff; 16]),
    )?;
    for (_, row) in sessions {
        if now >= row.idle_expires || now >= row.abs_expires {
            remove_session(st, &row)?;
        }
    }
    let channels = st.store.enrol_channels().range(
        &hasp_proto::Esid::from_bytes([0; 16]),
        &hasp_proto::Esid::from_bytes([0xff; 16]),
    )?;
    for (id, row) in channels {
        if now >= row.expires || row.state == EnrolState::Aborted {
            st.store.enrol_channels().remove(&id)?;
        }
    }
    let invites = st.store.invites().range(
        &InviteId::from_bytes([0; 16]),
        &InviteId::from_bytes([0xff; 16]),
    )?;
    for (id, mut row) in invites {
        if row.state == InviteState::Open && now >= row.expires {
            row.state = InviteState::Expired;
            st.store.invites().put(id, row)?;
        }
    }
    let attachments = st
        .store
        .attachments()
        .range(&AttId::from_bytes([0; 16]), &AttId::from_bytes([0xff; 16]))?;
    for (id, row) in attachments {
        let stale = now >= row.created.saturating_add(srv.config.upload_ttl);
        let orphan = row.state == AttachmentState::Uploading || row.refs == 0;
        if stale && orphan {
            srv.drop_attachment(st, &id)?;
        }
    }
    Ok(())
}
