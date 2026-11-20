mod account;
mod admin;
mod attachment;
pub(crate) mod auth;
mod enrol;
mod maintenance;
mod member;
mod recovery;
mod vault;

use hasp_proto::wire::{
    AccountDelete, AccountGet, AccountLookup, AdminAccountDelete, AdminAccountList,
    AdminAccountUpdate, AdminTokenCreate, AttachmentComplete, AttachmentGet, AttachmentPut,
    ChangeCredentialFinish, ChangeCredentialStart, Commit, EnrolAbort, EnrolApprove, EnrolMsgGet,
    EnrolMsgPut, EnrolOpen, Health, InviteAccept, InviteCreate, InviteDecline, InviteGet,
    InviteList, Leave, LoginFinish, LoginStart, OpId, Prelogin, Pull, RcSet, ReauthFinish,
    ReauthStart, RecoverAbort, RecoverComplete, RecoverFetch, RecoverPrelogin,
    RecoverRegisterStart, RecoverStart, RegisterFinish, RegisterStart, RepairPublish,
    ReregisterFinish, ReregisterStart, SelfWrapPut, ServerKey, SessionList, SessionRevoke,
    VaultDissolve,
};

pub(crate) use maintenance::sweep;

use crate::server::{Caller, Mode, Route, Server};
use crate::store::Store;

pub(crate) fn dispatch<S: Store>(
    srv: &Server<S>,
    caller: &Caller,
    op: OpId,
    body: &[u8],
) -> Vec<u8> {
    macro_rules! route {
        ($ty:ty, $mode:ident, $method:ident) => {
            srv.invoke::<$ty, _>(
                caller,
                body,
                Route { mode: Mode::$mode },
                |srv, st, call, req| srv.$method(st, call, req),
            )
        };
    }
    match op {
        OpId::Health => route!(Health, Read, health_op),
        OpId::Prelogin => route!(Prelogin, Read, prelogin_op),
        OpId::RecoverPrelogin => route!(RecoverPrelogin, Read, recover_prelogin_op),
        OpId::RegisterStart => route!(RegisterStart, Read, register_start_op),
        OpId::RegisterFinish => route!(RegisterFinish, Write, register_finish_op),
        OpId::LoginStart => route!(LoginStart, Read, login_start_op),
        OpId::LoginFinish => route!(LoginFinish, Write, login_finish_op),
        OpId::ReauthStart => route!(ReauthStart, Read, reauth_start_op),
        OpId::ReauthFinish => route!(ReauthFinish, Write, reauth_finish_op),
        OpId::AccountGet => route!(AccountGet, Read, account_get_op),
        OpId::AccountLookup => route!(AccountLookup, Read, account_lookup_op),
        OpId::ChangeCredentialStart => {
            route!(ChangeCredentialStart, Read, change_credential_start_op)
        }
        OpId::ChangeCredentialFinish => {
            route!(ChangeCredentialFinish, Write, change_credential_finish_op)
        }
        OpId::SessionList => route!(SessionList, Read, session_list_op),
        OpId::SessionRevoke => route!(SessionRevoke, Write, session_revoke_op),
        OpId::EnrolOpen => route!(EnrolOpen, Write, enrol_open_op),
        OpId::EnrolApprove => route!(EnrolApprove, Write, enrol_approve_op),
        OpId::EnrolAbort => route!(EnrolAbort, Write, enrol_abort_op),
        OpId::EnrolMsgPut => route!(EnrolMsgPut, Write, enrol_msg_put_op),
        OpId::EnrolMsgGet => route!(EnrolMsgGet, Read, enrol_msg_get_op),
        OpId::RcSet => route!(RcSet, Write, rc_set_op),
        OpId::RecoverStart => route!(RecoverStart, Write, recover_start_op),
        OpId::RecoverAbort => route!(RecoverAbort, Write, recover_abort_op),
        OpId::RecoverFetch => route!(RecoverFetch, Write, recover_fetch_op),
        OpId::RecoverRegisterStart => {
            route!(RecoverRegisterStart, Read, recover_register_start_op)
        }
        OpId::RecoverComplete => route!(RecoverComplete, Write, recover_complete_op),
        OpId::Pull => route!(Pull, Read, pull_op),
        OpId::Commit => route!(Commit, Write, commit_op),
        OpId::RepairPublish => route!(RepairPublish, Write, repair_publish_op),
        OpId::ReregisterStart => route!(ReregisterStart, Read, reregister_start_op),
        OpId::ReregisterFinish => route!(ReregisterFinish, Write, reregister_finish_op),
        OpId::ServerKey => route!(ServerKey, Read, server_key_op),
        OpId::SelfWrapPut => route!(SelfWrapPut, Write, self_wrap_put_op),
        OpId::InviteCreate => route!(InviteCreate, Write, invite_create_op),
        OpId::InviteGet => route!(InviteGet, Read, invite_get_op),
        OpId::InviteList => route!(InviteList, Read, invite_list_op),
        OpId::InviteAccept => route!(InviteAccept, Write, invite_accept_op),
        OpId::InviteDecline => route!(InviteDecline, Write, invite_decline_op),
        OpId::Leave => route!(Leave, Write, leave_op),
        OpId::VaultDissolve => route!(VaultDissolve, Write, vault_dissolve_op),
        OpId::AttachmentPut => route!(AttachmentPut, Write, attachment_put_op),
        OpId::AttachmentGet => route!(AttachmentGet, Read, attachment_get_op),
        OpId::AttachmentComplete => route!(AttachmentComplete, Write, attachment_complete_op),
        OpId::AccountDelete => route!(AccountDelete, Write, account_delete_op),
        OpId::AdminTokenCreate => route!(AdminTokenCreate, Write, admin_token_create_op),
        OpId::AdminAccountList => route!(AdminAccountList, Read, admin_account_list_op),
        OpId::AdminAccountUpdate => {
            route!(AdminAccountUpdate, Write, admin_account_update_op)
        }
        OpId::AdminAccountDelete => {
            route!(AdminAccountDelete, Write, admin_account_delete_op)
        }
    }
}
