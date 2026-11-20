use crate::server::{Call, Res, Server, State, ts};
use crate::store::{AccountState, Store, TokenRow};
use hasp_proto::wire::{
    Ack, AdminAccount, AdminAccountDelete, AdminAccountList, AdminAccountListResponse,
    AdminAccountUpdate, AdminTokenCreate, AdminTokenResponse, ErrorCode, SignupToken, TokenKind,
};

impl<S: Store> Server<S> {
    pub(crate) fn admin_token_create_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AdminTokenCreate,
    ) -> Res<AdminTokenResponse> {
        let session = self.admin(st, call)?;
        if req.kind != TokenKind::Signup {
            return Err(ErrorCode::Unsupported.into());
        }
        let token = SignupToken::random()?;
        let expires = call.now.saturating_add(self.config.signup_ttl);
        st.store.signup_tokens().put(
            token.hash(),
            TokenRow {
                creator: Some(session.account_id),
                target: None,
                expires,
                used_by: None,
                kind: req.kind,
                makes_admin: false,
            },
        )?;
        Ok(AdminTokenResponse {
            token,
            expires: ts(expires),
        })
    }

    pub(crate) fn admin_account_list_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        _: AdminAccountList,
    ) -> Res<AdminAccountListResponse> {
        self.admin(st, call)?;
        let (lo, hi) = crate::server::account_bounds();
        let accounts = st
            .store
            .accounts()
            .range(&lo, &hi)?
            .into_iter()
            .map(|(_, row)| AdminAccount {
                account_id: row.account_id,
                login: row.login,
                disabled: row.state == AccountState::Disabled,
                is_admin: row.is_admin,
                created: ts(row.created),
            })
            .collect();
        Ok(AdminAccountListResponse { accounts })
    }

    pub(crate) fn admin_account_update_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AdminAccountUpdate,
    ) -> Res<Ack> {
        let session = self.admin(st, call)?;
        let mut row = st
            .store
            .accounts()
            .get(&req.account_id)?
            .ok_or(ErrorCode::NotFound)?;
        if req.account_id == session.account_id && (req.disabled || !req.is_admin) {
            return Err(ErrorCode::Conflict.into());
        }
        row.is_admin = req.is_admin;
        st.store.accounts().put(req.account_id, row)?;
        self.disable_account(st, &req.account_id, req.disabled)?;
        Ok(Ack)
    }

    pub(crate) fn admin_account_delete_op(
        &self,
        st: &mut State<S>,
        call: &Call<'_>,
        req: AdminAccountDelete,
    ) -> Res<Ack> {
        let session = self.admin(st, call)?;
        if req.account_id == session.account_id {
            return Err(ErrorCode::Conflict.into());
        }
        if st.store.accounts().get(&req.account_id)?.is_none() {
            return Err(ErrorCode::NotFound.into());
        }
        self.guard_deletion(st, &req.account_id)?;
        self.purge_account(st, &req.account_id)?;
        Ok(Ack)
    }
}
