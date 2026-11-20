use std::sync::Arc;

use hasp_proto::wire::{
    Ack, AttachmentComplete, AttachmentGet, AttachmentGetResponse, AttachmentPut, ErrorCode,
};
use hasp_proto::{AccountId, VaultId};

use crate::server::{Call, Res, Server, State};
use crate::store::{AttachmentRow, AttachmentState, MemberRow, MemberStatus, Store, VaultPhase};

pub(crate) const MAX_CHUNK: usize = (1 << 20) + 16;

impl<S: Store> Server<S> {
    pub(crate) fn vault_member(
        &self,
        st: &mut State<S>,
        vault: &VaultId,
        account: &AccountId,
    ) -> Res<MemberRow> {
        let row = st.store.vaults().get(vault)?.ok_or(ErrorCode::NotMember)?;
        let member = st
            .store
            .members()
            .get(&(*vault, *account))?
            .ok_or(ErrorCode::NotMember)?;
        if row.state != VaultPhase::Active || member.state != MemberStatus::Active {
            return Err(ErrorCode::NotMember.into());
        }
        Ok(member)
    }

    pub(crate) fn attachment_put_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AttachmentPut,
    ) -> Res<Ack> {
        let session = self.session(st, call)?;
        let member = self.vault_member(st, &req.vault_id, &session.account_id)?;
        if !member.role.can_write() {
            return Err(ErrorCode::ReadOnly.into());
        }
        if req.data.0.len() > MAX_CHUNK {
            return Err(ErrorCode::TooLarge.into());
        }
        let mut row = st
            .store
            .attachments()
            .get(&req.att_id)?
            .unwrap_or(AttachmentRow {
                vault_id: req.vault_id,
                size: 0,
                chunks: 0,
                state: AttachmentState::Uploading,
                created: call.now,
                refs: 0,
            });
        if row.vault_id != req.vault_id || row.state == AttachmentState::Complete {
            return Err(ErrorCode::Conflict.into());
        }
        let index = req.index.get();
        if index > row.chunks {
            return Err(ErrorCode::Conflict.into());
        }
        let key = (req.att_id, index);
        if let Some(existing) = st.store.attachment_chunks().get(&key)? {
            if existing.as_slice() != req.data.as_slice() {
                return Err(ErrorCode::Conflict.into());
            }
        } else {
            let len = u64::try_from(req.data.0.len()).map_err(|_| ErrorCode::TooLarge)?;
            row.size = row.size.saturating_add(len);
            if row.size > self.config.max_attachment_bytes {
                return Err(ErrorCode::TooLarge.into());
            }
            row.chunks = row.chunks.saturating_add(1);
            st.store
                .attachment_chunks()
                .put(key, Arc::new(req.data.0))?;
        }
        st.store.attachments().put(req.att_id, row)?;
        Ok(Ack)
    }

    pub(crate) fn attachment_complete_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AttachmentComplete,
    ) -> Res<Ack> {
        let session = self.session(st, call)?;
        let member = self.vault_member(st, &req.vault_id, &session.account_id)?;
        if !member.role.can_write() {
            return Err(ErrorCode::ReadOnly.into());
        }
        let mut row = st
            .store
            .attachments()
            .get(&req.att_id)?
            .filter(|row| row.vault_id == req.vault_id)
            .ok_or(ErrorCode::NotFound)?;
        if req.chunks.get() == 0 || req.chunks.get() != row.chunks {
            return Err(ErrorCode::Conflict.into());
        }
        row.state = AttachmentState::Complete;
        st.store.attachments().put(req.att_id, row)?;
        Ok(Ack)
    }

    pub(crate) fn attachment_get_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AttachmentGet,
    ) -> Res<AttachmentGetResponse> {
        let session = self.session(st, call)?;
        self.vault_member(st, &req.vault_id, &session.account_id)?;
        let row = st
            .store
            .attachments()
            .get(&req.att_id)?
            .filter(|row| row.vault_id == req.vault_id && row.state == AttachmentState::Complete)
            .ok_or(ErrorCode::NotFound)?;
        let index = req.index.get();
        if index >= row.chunks {
            return Err(ErrorCode::NotFound.into());
        }
        let data = st
            .store
            .attachment_chunks()
            .get(&(req.att_id, index))?
            .ok_or(ErrorCode::Internal)?;
        Ok(AttachmentGetResponse {
            data: data.as_ref().clone().into(),
            last: index.saturating_add(1) == row.chunks,
        })
    }
}
