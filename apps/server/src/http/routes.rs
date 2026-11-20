use axum::http::Method;
use hasp_proto::wire::OpId;

pub(crate) const SMALL_BODY: usize = 64 * 1024;
pub(crate) const REGISTER_BODY: usize = 1024 * 1024;
pub(crate) const SLOT_BODY: usize = 1024 * 1024 + 4096;
pub(crate) const CHUNK_BODY: usize = (1 << 20) + 16 + 4096;
pub(crate) const LARGE_BODY: usize = hasp_proto::MAX_RECORD;

#[derive(Debug)]
pub(crate) struct RouteSpec {
    pub(crate) path: &'static str,
    pub(crate) methods: &'static [(Method, OpId)],
}

impl RouteSpec {
    pub(crate) fn op_for(&self, method: &Method) -> Option<OpId> {
        self.methods
            .iter()
            .find(|(candidate, _)| candidate == method)
            .map(|(_, op)| *op)
    }
}

pub(crate) const WS_PATH: &str = "/v1/ws";

pub(crate) const ROUTES: &[RouteSpec] = &[
    RouteSpec {
        path: "/healthz",
        methods: &[(Method::GET, OpId::Health)],
    },
    RouteSpec {
        path: "/.well-known/hasp",
        methods: &[(Method::GET, OpId::Health)],
    },
    RouteSpec {
        path: "/v1/server-key",
        methods: &[(Method::GET, OpId::ServerKey)],
    },
    RouteSpec {
        path: "/v1/prelogin",
        methods: &[(Method::POST, OpId::Prelogin)],
    },
    RouteSpec {
        path: "/v1/recover/prelogin",
        methods: &[(Method::POST, OpId::RecoverPrelogin)],
    },
    RouteSpec {
        path: "/v1/register/start",
        methods: &[(Method::POST, OpId::RegisterStart)],
    },
    RouteSpec {
        path: "/v1/register/finish",
        methods: &[(Method::POST, OpId::RegisterFinish)],
    },
    RouteSpec {
        path: "/v1/reregister/start",
        methods: &[(Method::POST, OpId::ReregisterStart)],
    },
    RouteSpec {
        path: "/v1/reregister/finish",
        methods: &[(Method::POST, OpId::ReregisterFinish)],
    },
    RouteSpec {
        path: "/v1/login/start",
        methods: &[(Method::POST, OpId::LoginStart)],
    },
    RouteSpec {
        path: "/v1/login/finish",
        methods: &[(Method::POST, OpId::LoginFinish)],
    },
    RouteSpec {
        path: "/v1/reauth/start",
        methods: &[(Method::POST, OpId::ReauthStart)],
    },
    RouteSpec {
        path: "/v1/reauth/finish",
        methods: &[(Method::POST, OpId::ReauthFinish)],
    },
    RouteSpec {
        path: "/v1/account",
        methods: &[
            (Method::GET, OpId::AccountGet),
            (Method::DELETE, OpId::AccountDelete),
        ],
    },
    RouteSpec {
        path: "/v1/account/lookup",
        methods: &[(Method::POST, OpId::AccountLookup)],
    },
    RouteSpec {
        path: "/v1/account/credential/start",
        methods: &[(Method::POST, OpId::ChangeCredentialStart)],
    },
    RouteSpec {
        path: "/v1/account/credential/finish",
        methods: &[(Method::POST, OpId::ChangeCredentialFinish)],
    },
    RouteSpec {
        path: "/v1/sessions",
        methods: &[(Method::GET, OpId::SessionList)],
    },
    RouteSpec {
        path: "/v1/sessions/{id}",
        methods: &[(Method::DELETE, OpId::SessionRevoke)],
    },
    RouteSpec {
        path: "/v1/enrol",
        methods: &[(Method::POST, OpId::EnrolOpen)],
    },
    RouteSpec {
        path: "/v1/enrol/{esid}",
        methods: &[(Method::DELETE, OpId::EnrolAbort)],
    },
    RouteSpec {
        path: "/v1/enrol/{esid}/approve",
        methods: &[(Method::POST, OpId::EnrolApprove)],
    },
    RouteSpec {
        path: "/v1/enrol/{esid}/msg",
        methods: &[
            (Method::PUT, OpId::EnrolMsgPut),
            (Method::GET, OpId::EnrolMsgGet),
        ],
    },
    RouteSpec {
        path: "/v1/recovery",
        methods: &[(Method::PUT, OpId::RcSet)],
    },
    RouteSpec {
        path: "/v1/recover/start",
        methods: &[(Method::POST, OpId::RecoverStart)],
    },
    RouteSpec {
        path: "/v1/recover/abort",
        methods: &[(Method::POST, OpId::RecoverAbort)],
    },
    RouteSpec {
        path: "/v1/recover/{id}",
        methods: &[(Method::GET, OpId::RecoverFetch)],
    },
    RouteSpec {
        path: "/v1/recover/{id}/register/start",
        methods: &[(Method::POST, OpId::RecoverRegisterStart)],
    },
    RouteSpec {
        path: "/v1/recover/{id}/complete",
        methods: &[(Method::POST, OpId::RecoverComplete)],
    },
    RouteSpec {
        path: "/v1/pull",
        methods: &[(Method::POST, OpId::Pull)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/commit",
        methods: &[(Method::POST, OpId::Commit)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/repair",
        methods: &[(Method::POST, OpId::RepairPublish)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/self-wraps/{epoch}",
        methods: &[(Method::PUT, OpId::SelfWrapPut)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/invites",
        methods: &[
            (Method::POST, OpId::InviteCreate),
            (Method::GET, OpId::InviteList),
        ],
    },
    RouteSpec {
        path: "/v1/invites/{invite_id}",
        methods: &[(Method::GET, OpId::InviteGet)],
    },
    RouteSpec {
        path: "/v1/invites/{invite_id}/accept",
        methods: &[(Method::POST, OpId::InviteAccept)],
    },
    RouteSpec {
        path: "/v1/invites/{invite_id}/decline",
        methods: &[(Method::POST, OpId::InviteDecline)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/leave",
        methods: &[(Method::POST, OpId::Leave)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/dissolve",
        methods: &[(Method::POST, OpId::VaultDissolve)],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/attachments/{att_id}/chunks/{n}",
        methods: &[
            (Method::PUT, OpId::AttachmentPut),
            (Method::GET, OpId::AttachmentGet),
        ],
    },
    RouteSpec {
        path: "/v1/vaults/{id}/attachments/{att_id}/complete",
        methods: &[(Method::POST, OpId::AttachmentComplete)],
    },
    RouteSpec {
        path: "/v1/admin/tokens",
        methods: &[(Method::POST, OpId::AdminTokenCreate)],
    },
    RouteSpec {
        path: "/v1/admin/accounts",
        methods: &[(Method::GET, OpId::AdminAccountList)],
    },
    RouteSpec {
        path: "/v1/admin/accounts/{id}",
        methods: &[
            (Method::PATCH, OpId::AdminAccountUpdate),
            (Method::DELETE, OpId::AdminAccountDelete),
        ],
    },
];

pub(crate) fn body_limit(op: OpId) -> usize {
    match op {
        OpId::ChangeCredentialFinish
        | OpId::RecoverComplete
        | OpId::Commit
        | OpId::RepairPublish
        | OpId::InviteAccept => LARGE_BODY,
        OpId::RegisterFinish => REGISTER_BODY,
        OpId::EnrolMsgPut => SLOT_BODY,
        OpId::AttachmentPut => CHUNK_BODY,
        OpId::Health
        | OpId::ServerKey
        | OpId::Prelogin
        | OpId::RecoverPrelogin
        | OpId::RegisterStart
        | OpId::ReregisterStart
        | OpId::ReregisterFinish
        | OpId::LoginStart
        | OpId::LoginFinish
        | OpId::ReauthStart
        | OpId::ReauthFinish
        | OpId::AccountGet
        | OpId::AccountDelete
        | OpId::AccountLookup
        | OpId::ChangeCredentialStart
        | OpId::SessionList
        | OpId::SessionRevoke
        | OpId::EnrolOpen
        | OpId::EnrolAbort
        | OpId::EnrolApprove
        | OpId::EnrolMsgGet
        | OpId::RcSet
        | OpId::RecoverStart
        | OpId::RecoverAbort
        | OpId::RecoverFetch
        | OpId::RecoverRegisterStart
        | OpId::Pull
        | OpId::SelfWrapPut
        | OpId::InviteCreate
        | OpId::InviteList
        | OpId::InviteGet
        | OpId::InviteDecline
        | OpId::Leave
        | OpId::VaultDissolve
        | OpId::AttachmentGet
        | OpId::AttachmentComplete
        | OpId::AdminTokenCreate
        | OpId::AdminAccountList
        | OpId::AdminAccountUpdate
        | OpId::AdminAccountDelete => SMALL_BODY,
    }
}

pub(crate) fn early_bearer(op: OpId) -> Option<bool> {
    match op {
        OpId::Commit
        | OpId::RepairPublish
        | OpId::ChangeCredentialFinish
        | OpId::InviteAccept
        | OpId::AttachmentPut => Some(false),
        OpId::RecoverComplete => Some(true),
        _ => None,
    }
}

pub(crate) fn is_long(op: OpId) -> bool {
    matches!(op, OpId::Commit | OpId::RepairPublish | OpId::AttachmentPut)
}

pub(crate) fn is_chunk_transfer(op: OpId) -> bool {
    matches!(op, OpId::AttachmentPut | OpId::AttachmentGet)
}

pub(crate) fn name(op: OpId) -> &'static str {
    match op {
        OpId::Health => "health",
        OpId::ServerKey => "server_key",
        OpId::Prelogin => "prelogin",
        OpId::RecoverPrelogin => "recover_prelogin",
        OpId::RegisterStart => "register_start",
        OpId::RegisterFinish => "register_finish",
        OpId::ReregisterStart => "reregister_start",
        OpId::ReregisterFinish => "reregister_finish",
        OpId::LoginStart => "login_start",
        OpId::LoginFinish => "login_finish",
        OpId::ReauthStart => "reauth_start",
        OpId::ReauthFinish => "reauth_finish",
        OpId::AccountGet => "account_get",
        OpId::AccountDelete => "account_delete",
        OpId::AccountLookup => "account_lookup",
        OpId::ChangeCredentialStart => "change_credential_start",
        OpId::ChangeCredentialFinish => "change_credential_finish",
        OpId::SessionList => "session_list",
        OpId::SessionRevoke => "session_revoke",
        OpId::EnrolOpen => "enrol_open",
        OpId::EnrolAbort => "enrol_abort",
        OpId::EnrolApprove => "enrol_approve",
        OpId::EnrolMsgPut => "enrol_msg_put",
        OpId::EnrolMsgGet => "enrol_msg_get",
        OpId::RcSet => "rc_set",
        OpId::RecoverStart => "recover_start",
        OpId::RecoverAbort => "recover_abort",
        OpId::RecoverFetch => "recover_fetch",
        OpId::RecoverRegisterStart => "recover_register_start",
        OpId::RecoverComplete => "recover_complete",
        OpId::Pull => "pull",
        OpId::Commit => "commit",
        OpId::RepairPublish => "repair_publish",
        OpId::SelfWrapPut => "self_wrap_put",
        OpId::InviteCreate => "invite_create",
        OpId::InviteList => "invite_list",
        OpId::InviteGet => "invite_get",
        OpId::InviteAccept => "invite_accept",
        OpId::InviteDecline => "invite_decline",
        OpId::Leave => "leave",
        OpId::VaultDissolve => "vault_dissolve",
        OpId::AttachmentPut => "attachment_put",
        OpId::AttachmentGet => "attachment_get",
        OpId::AttachmentComplete => "attachment_complete",
        OpId::AdminTokenCreate => "admin_token_create",
        OpId::AdminAccountList => "admin_account_list",
        OpId::AdminAccountUpdate => "admin_account_update",
        OpId::AdminAccountDelete => "admin_account_delete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_has_a_route() {
        for op in OpId::ALL {
            assert!(
                ROUTES
                    .iter()
                    .any(|route| route.methods.iter().any(|(_, routed)| routed == op)),
                "{op:?} has no route"
            );
        }
    }

    #[test]
    fn a_path_names_each_method_once() {
        for route in ROUTES {
            for (i, (method, _)) in route.methods.iter().enumerate() {
                assert!(
                    route
                        .methods
                        .iter()
                        .skip(i + 1)
                        .all(|(other, _)| other != method),
                    "{} repeats {method}",
                    route.path
                );
            }
        }
    }

    #[test]
    fn body_limits_never_exceed_the_record_cap() {
        for op in OpId::ALL {
            assert!(body_limit(*op) <= hasp_proto::MAX_RECORD);
        }
    }
}
