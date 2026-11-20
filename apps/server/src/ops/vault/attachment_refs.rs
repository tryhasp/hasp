use hasp_proto::wire::ErrorCode;
use hasp_proto::{AttId, ItemWire, VaultId};

use crate::server::{Res, Server, State};
use crate::store::{AttachmentState, Store};

impl<S: Store> Server<S> {
    pub(super) fn check_attachments(
        &self,
        st: &mut State<S>,
        vault: &VaultId,
        ops: &[ItemWire],
    ) -> Res<()> {
        for wire in ops {
            for att in &wire.att_ids {
                let row = st
                    .store
                    .attachments()
                    .get(att)?
                    .ok_or(ErrorCode::NotFound)?;
                if row.vault_id != *vault || row.state != AttachmentState::Complete {
                    return Err(ErrorCode::NotFound.into());
                }
            }
        }
        Ok(())
    }

    pub(super) fn acquire(&self, st: &mut State<S>, att: &AttId) -> Res<()> {
        if let Some(mut row) = st.store.attachments().get(att)? {
            row.refs = row.refs.saturating_add(1);
            st.store.attachments().put(*att, row)?;
        }
        Ok(())
    }

    pub(crate) fn release(&self, st: &mut State<S>, att: &AttId) -> Res<()> {
        let Some(mut row) = st.store.attachments().get(att)? else {
            return Ok(());
        };
        row.refs = row.refs.saturating_sub(1);
        if row.refs == 0 {
            return self.drop_attachment(st, att);
        }
        st.store.attachments().put(*att, row)?;
        Ok(())
    }

    pub(crate) fn drop_attachment(&self, st: &mut State<S>, att: &AttId) -> Res<()> {
        st.store.attachments().remove(att)?;
        for (key, _) in st
            .store
            .attachment_chunks()
            .range(&(*att, 0), &(*att, u64::MAX))?
        {
            st.store.attachment_chunks().remove(&key)?;
        }
        Ok(())
    }
}
