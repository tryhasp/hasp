use hasp_proto::base64url;
use hasp_proto::wire::{
    ErrorCode, OpId, RecoveryId, SelfWrapEntry, SessionId, SessionToken, WireError, decode_reply,
};
use hasp_proto::{
    AccountId, AttId, Dissolve, Esid, InviteId, LeaveRequest, ProtoError, Reader, Signed, Uint53,
    VaultId, Wire,
};
use zeroize::Zeroizing;

use super::TransportError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Verb {
    pub fn override_name(self) -> Option<&'static str> {
        match self {
            Self::Post => None,
            Self::Get => Some("GET"),
            Self::Put => Some("PUT"),
            Self::Patch => Some("PATCH"),
            Self::Delete => Some("DELETE"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub verb: Verb,
    pub path: String,
}

impl Route {
    fn fixed(verb: Verb, path: &str) -> Self {
        Self {
            verb,
            path: path.to_owned(),
        }
    }
}

trait PathId {
    fn segment(&self) -> String;
}

macro_rules! path_id {
    ($($name:ty),*) => {
        $(impl PathId for $name {
            fn segment(&self) -> String {
                base64url::encode(self.as_bytes())
            }
        })*
    };
}

path_id!(
    SessionId, RecoveryId, Esid, InviteId, VaultId, AccountId, AttId
);

fn first<T: Wire>(body: &[u8]) -> Result<T, ProtoError> {
    Reader::new(body).map(|reader, _| reader.field(0))
}

fn keyed<T: Wire + PathId>(
    verb: Verb,
    body: &[u8],
    prefix: &str,
    suffix: &str,
) -> Result<Route, ProtoError> {
    let id: T = first(body)?;
    Ok(Route {
        verb,
        path: format!("{prefix}{}{suffix}", id.segment()),
    })
}

fn attachment(verb: Verb, body: &[u8], tail: &str) -> Result<Route, ProtoError> {
    let (vault, att, index) = Reader::new(body).map(|reader, _| {
        let vault: VaultId = reader.field(0)?;
        let att: AttId = reader.field(1)?;
        let index: Uint53 = reader.field(2)?;
        Ok((vault, att, index))
    })?;
    let tail = if tail.is_empty() {
        format!("chunks/{}", index.get())
    } else {
        tail.to_owned()
    };
    Ok(Route {
        verb,
        path: format!(
            "/v1/vaults/{}/attachments/{}/{tail}",
            vault.segment(),
            att.segment()
        ),
    })
}

fn self_wrap(body: &[u8]) -> Result<Route, ProtoError> {
    let (vault, entry) = Reader::new(body).map(|reader, _| {
        let vault: VaultId = reader.field(0)?;
        let entry: SelfWrapEntry = reader.field(1)?;
        Ok((vault, entry))
    })?;
    Ok(Route {
        verb: Verb::Put,
        path: format!(
            "/v1/vaults/{}/self-wraps/{}",
            vault.segment(),
            entry.epoch.get()
        ),
    })
}

fn vault_of_leave(body: &[u8]) -> Result<Route, ProtoError> {
    let request: Signed<LeaveRequest> = first(body)?;
    let vault = request.unverified()?.vault_id;
    Ok(Route {
        verb: Verb::Post,
        path: format!("/v1/vaults/{}/leave", vault.segment()),
    })
}

fn vault_of_dissolve(body: &[u8]) -> Result<Route, ProtoError> {
    let record: Signed<Dissolve> = first(body)?;
    let vault = record.unverified()?.vault_id;
    Ok(Route {
        verb: Verb::Post,
        path: format!("/v1/vaults/{}/dissolve", vault.segment()),
    })
}

pub fn resolve(op: OpId, body: &[u8]) -> Result<Route, ProtoError> {
    use Verb::{Delete, Get, Patch, Post, Put};
    let vault = |verb, tail| keyed::<VaultId>(verb, body, "/v1/vaults/", tail);
    let fixed = |verb, path| Ok(Route::fixed(verb, path));
    match op {
        OpId::Health => fixed(Get, "/healthz"),
        OpId::ServerKey => fixed(Get, "/v1/server-key"),
        OpId::Prelogin => fixed(Post, "/v1/prelogin"),
        OpId::RecoverPrelogin => fixed(Post, "/v1/recover/prelogin"),
        OpId::RegisterStart => fixed(Post, "/v1/register/start"),
        OpId::RegisterFinish => fixed(Post, "/v1/register/finish"),
        OpId::ReregisterStart => fixed(Post, "/v1/reregister/start"),
        OpId::ReregisterFinish => fixed(Post, "/v1/reregister/finish"),
        OpId::LoginStart => fixed(Post, "/v1/login/start"),
        OpId::LoginFinish => fixed(Post, "/v1/login/finish"),
        OpId::ReauthStart => fixed(Post, "/v1/reauth/start"),
        OpId::ReauthFinish => fixed(Post, "/v1/reauth/finish"),
        OpId::AccountGet => fixed(Get, "/v1/account"),
        OpId::AccountDelete => fixed(Delete, "/v1/account"),
        OpId::AccountLookup => fixed(Post, "/v1/account/lookup"),
        OpId::ChangeCredentialStart => fixed(Post, "/v1/account/credential/start"),
        OpId::ChangeCredentialFinish => fixed(Post, "/v1/account/credential/finish"),
        OpId::SessionList => fixed(Get, "/v1/sessions"),
        OpId::SessionRevoke => keyed::<SessionId>(Delete, body, "/v1/sessions/", ""),
        OpId::EnrolOpen => fixed(Post, "/v1/enrol"),
        OpId::EnrolApprove => keyed::<Esid>(Post, body, "/v1/enrol/", "/approve"),
        OpId::EnrolAbort => keyed::<Esid>(Delete, body, "/v1/enrol/", ""),
        OpId::EnrolMsgPut => keyed::<Esid>(Put, body, "/v1/enrol/", "/msg"),
        OpId::EnrolMsgGet => keyed::<Esid>(Get, body, "/v1/enrol/", "/msg"),
        OpId::RcSet => fixed(Put, "/v1/recovery"),
        OpId::RecoverStart => fixed(Post, "/v1/recover/start"),
        OpId::RecoverAbort => fixed(Post, "/v1/recover/abort"),
        OpId::RecoverFetch => keyed::<RecoveryId>(Get, body, "/v1/recover/", ""),
        OpId::RecoverRegisterStart => {
            keyed::<RecoveryId>(Post, body, "/v1/recover/", "/register/start")
        }
        OpId::RecoverComplete => keyed::<RecoveryId>(Post, body, "/v1/recover/", "/complete"),
        OpId::Pull => fixed(Post, "/v1/pull"),
        OpId::Commit => vault(Post, "/commit"),
        OpId::RepairPublish => vault(Post, "/repair"),
        OpId::SelfWrapPut => self_wrap(body),
        OpId::InviteCreate => vault(Post, "/invites"),
        OpId::InviteList => vault(Get, "/invites"),
        OpId::InviteGet => keyed::<InviteId>(Get, body, "/v1/invites/", ""),
        OpId::InviteAccept => keyed::<InviteId>(Post, body, "/v1/invites/", "/accept"),
        OpId::InviteDecline => keyed::<InviteId>(Post, body, "/v1/invites/", "/decline"),
        OpId::Leave => vault_of_leave(body),
        OpId::VaultDissolve => vault_of_dissolve(body),
        OpId::AttachmentPut => attachment(Put, body, ""),
        OpId::AttachmentGet => attachment(Get, body, ""),
        OpId::AttachmentComplete => attachment(Post, body, "complete"),
        OpId::AdminTokenCreate => fixed(Post, "/v1/admin/tokens"),
        OpId::AdminAccountList => fixed(Get, "/v1/admin/accounts"),
        OpId::AdminAccountUpdate => keyed::<AccountId>(Patch, body, "/v1/admin/accounts/", ""),
        OpId::AdminAccountDelete => keyed::<AccountId>(Delete, body, "/v1/admin/accounts/", ""),
    }
}

pub const CBOR: &str = "application/cbor";
pub const OVERRIDE_HEADER: &str = "x-http-method-override";
pub const PROTOCOL_HEADER: &str = "x-protocol";
pub const MAX_RETRY_AFTER_S: u64 = 3600;
pub const BODY_SLACK: usize = 4096;

pub fn bearer_text(token: &SessionToken) -> Zeroizing<String> {
    Zeroizing::new(format!("Bearer {}", base64url::encode(token.as_bytes())))
}

pub fn is_transient(status: u16, is_cbor: bool) -> bool {
    !is_cbor && matches!(status, 408 | 502..=504)
}

#[derive(Debug)]
pub enum Classified<T> {
    Reply(Result<T, TransportError>),
    Transient,
}

pub fn classify<T: Wire>(status: u16, retry_after: Option<u64>, bytes: &[u8]) -> Classified<T> {
    match decode_reply::<T>(bytes) {
        Ok(Ok(value)) if status == 200 => Classified::Reply(Ok(value)),
        Ok(Ok(_)) => Classified::Reply(Err(TransportError::Codec(ProtoError::Format))),
        Ok(Err(wire)) => Classified::Reply(Err(TransportError::Server(with_retry_after(
            wire,
            retry_after,
        )))),
        Err(error) => without_envelope(status, retry_after, error),
    }
}

fn with_retry_after(wire: WireError, header: Option<u64>) -> WireError {
    match (wire.retry_after, header) {
        (None, Some(seconds)) if wire.code == ErrorCode::RateLimited => {
            WireError::retry_after(wire.code, seconds)
        }
        _ => wire,
    }
}

fn without_envelope<T>(status: u16, retry_after: Option<u64>, error: ProtoError) -> Classified<T> {
    let code = match status {
        408 | 502..=504 => return Classified::Transient,
        401 => ErrorCode::Auth,
        403 => ErrorCode::Authz,
        404 => ErrorCode::NotFound,
        413 => ErrorCode::TooLarge,
        426 => ErrorCode::Unsupported,
        429 => {
            return Classified::Reply(Err(TransportError::Server(WireError::retry_after(
                ErrorCode::RateLimited,
                retry_after.unwrap_or(0),
            ))));
        }
        500 => ErrorCode::Internal,
        _ => return Classified::Reply(Err(TransportError::Codec(error))),
    };
    Classified::Reply(Err(TransportError::Server(WireError::new(code))))
}

/// Operations whose replay cannot change the outcome: reads, and the writes the protocol makes
/// idempotent (commit and repair by `(vault, base_seq, manifest hash)`, ordered attachment chunks,
/// a self-wrap that replaces itself). Every other write is sent once.
pub fn is_idempotent(op: OpId) -> bool {
    match op {
        OpId::Health
        | OpId::ServerKey
        | OpId::Prelogin
        | OpId::RecoverPrelogin
        | OpId::AccountGet
        | OpId::AccountLookup
        | OpId::SessionList
        | OpId::EnrolMsgGet
        | OpId::Pull
        | OpId::InviteGet
        | OpId::InviteList
        | OpId::AttachmentGet
        | OpId::AdminAccountList
        | OpId::Commit
        | OpId::RepairPublish
        | OpId::SelfWrapPut
        | OpId::AttachmentPut => true,
        OpId::RegisterStart
        | OpId::RegisterFinish
        | OpId::ReregisterStart
        | OpId::ReregisterFinish
        | OpId::LoginStart
        | OpId::LoginFinish
        | OpId::ReauthStart
        | OpId::ReauthFinish
        | OpId::ChangeCredentialStart
        | OpId::ChangeCredentialFinish
        | OpId::SessionRevoke
        | OpId::EnrolOpen
        | OpId::EnrolApprove
        | OpId::EnrolAbort
        | OpId::EnrolMsgPut
        | OpId::RcSet
        | OpId::RecoverStart
        | OpId::RecoverAbort
        | OpId::RecoverFetch
        | OpId::RecoverRegisterStart
        | OpId::RecoverComplete
        | OpId::InviteCreate
        | OpId::InviteAccept
        | OpId::InviteDecline
        | OpId::Leave
        | OpId::VaultDissolve
        | OpId::AttachmentComplete
        | OpId::AccountDelete
        | OpId::AdminTokenCreate
        | OpId::AdminAccountUpdate
        | OpId::AdminAccountDelete => false,
    }
}

/// Commits, repairs and attachment chunks carry up to 16 MiB; the server allows them longer.
pub fn is_bulk(op: OpId) -> bool {
    matches!(
        op,
        OpId::Commit
            | OpId::RepairPublish
            | OpId::AttachmentPut
            | OpId::AttachmentGet
            | OpId::RegisterFinish
            | OpId::ChangeCredentialFinish
            | OpId::InviteAccept
    )
}
