use core::fmt;

use hasp_crypto::{Prk, hkdf_expand_key, hkdf_extract};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::DeviceId;
use crate::hexenc::{crockford_decode, crockford_encode};
use crate::label::Kdf;
use crate::{
    AccountId, Hash32, KdfWire, ProtoError, Reader, SealedRaw, Uint53, VaultId, Wire, Writer,
};
use hasp_crypto::to_hex as hex;

pub const PROTOCOL_VERSION: u64 = 1;
pub const SIGNUP_PREFIX: &str = "SGN1-";
pub const SIGNUP_TOKEN_LEN: usize = 20;
pub const SESSION_TOKEN_LEN: usize = 32;
const OPAQUE_SUITE: u64 = 1;
const ACCOUNT_CREDENTIAL: &str = "acct";

pub trait Operation: Wire {
    type Response: Wire;
    const ID: OpId;
}

code_enum!(
    OpId {
        Health = 1,
        Prelogin = 2,
        RecoverPrelogin = 3,
        RegisterStart = 4,
        RegisterFinish = 5,
        LoginStart = 6,
        LoginFinish = 7,
        ReauthStart = 8,
        ReauthFinish = 9,
        AccountGet = 10,
        AccountLookup = 11,
        ChangeCredentialStart = 12,
        ChangeCredentialFinish = 13,
        SessionList = 14,
        SessionRevoke = 15,
        EnrolOpen = 16,
        EnrolApprove = 17,
        EnrolAbort = 18,
        EnrolMsgPut = 19,
        EnrolMsgGet = 20,
        RcSet = 21,
        RecoverStart = 22,
        RecoverAbort = 23,
        RecoverFetch = 24,
        RecoverRegisterStart = 25,
        RecoverComplete = 26,
        Pull = 27,
        Commit = 28,
        SelfWrapPut = 29,
        InviteCreate = 30,
        InviteGet = 31,
        InviteList = 32,
        InviteAccept = 33,
        InviteDecline = 34,
        Leave = 35,
        VaultDissolve = 36,
        AttachmentPut = 37,
        AttachmentGet = 38,
        AttachmentComplete = 39,
        AccountDelete = 40,
        AdminTokenCreate = 41,
        AdminAccountList = 42,
        AdminAccountUpdate = 43,
        AdminAccountDelete = 44,
        ServerKey = 45,
        RepairPublish = 46,
        ReregisterStart = 47,
        ReregisterFinish = 48,
    }
);

code_enum!(
    ErrorCode {
        Format = 1,
        Version = 2,
        Sig = 3,
        Aead = 4,
        Pin = 5,
        Rollback = 6,
        Fork = 7,
        Roster = 8,
        KdfParams = 9,
        Epoch = 10,
        Root = 11,
        Auth = 12,
        ServerKey = 13,
        Authz = 14,
        Invite = 15,
        StaleHead = 16,
        EpochStale = 17,
        NotMember = 18,
        ReadOnly = 19,
        TooLarge = 20,
        RateLimited = 21,
        NotFound = 22,
        Conflict = 23,
        ReauthRequired = 24,
        Expired = 25,
        Pending = 26,
        Unsupported = 27,
        Internal = 28,
    }
);

impl ErrorCode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Format => "E_FORMAT",
            Self::Version => "E_VERSION",
            Self::Sig => "E_SIG",
            Self::Aead => "E_AEAD",
            Self::Pin => "E_PIN",
            Self::Rollback => "E_ROLLBACK",
            Self::Fork => "E_FORK",
            Self::Roster => "E_ROSTER",
            Self::KdfParams => "E_KDF_PARAMS",
            Self::Epoch => "E_EPOCH",
            Self::Root => "E_ROOT",
            Self::Auth => "E_AUTH",
            Self::ServerKey => "E_SERVER_KEY",
            Self::Authz => "E_AUTHZ",
            Self::Invite => "E_INVITE",
            Self::StaleHead => "stale_head",
            Self::EpochStale => "epoch_stale",
            Self::NotMember => "not_member",
            Self::ReadOnly => "read_only",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::ReauthRequired => "reauth_required",
            Self::Expired => "expired",
            Self::Pending => "pending",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::Format
            | Self::Version
            | Self::Sig
            | Self::Aead
            | Self::Pin
            | Self::Rollback
            | Self::Fork
            | Self::Roster
            | Self::KdfParams
            | Self::Epoch
            | Self::Root
            | Self::ServerKey
            | Self::Invite => 400,
            Self::Auth | Self::ReauthRequired | Self::Expired => 401,
            Self::Authz | Self::NotMember | Self::ReadOnly => 403,
            Self::NotFound => 404,
            Self::StaleHead | Self::EpochStale | Self::Conflict | Self::Pending => 409,
            Self::TooLarge => 413,
            Self::Unsupported => 426,
            Self::RateLimited => 429,
            Self::Internal => 500,
        }
    }
}

impl From<&ProtoError> for ErrorCode {
    fn from(error: &ProtoError) -> Self {
        match error {
            ProtoError::Format => Self::Format,
            ProtoError::Version => Self::Version,
            ProtoError::Sig => Self::Sig,
            ProtoError::Aead => Self::Aead,
            ProtoError::Pin => Self::Pin,
            ProtoError::Rollback => Self::Rollback,
            ProtoError::Fork => Self::Fork,
            ProtoError::Roster => Self::Roster,
            ProtoError::KdfParams => Self::KdfParams,
            ProtoError::Epoch => Self::Epoch,
            ProtoError::Root => Self::Root,
            ProtoError::Authz => Self::Authz,
            ProtoError::Invite => Self::Invite,
            ProtoError::Internal(_) => Self::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}", .code.name())]
pub struct WireError {
    pub code: ErrorCode,
    pub retry_after: Option<Uint53>,
}

impl WireError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            retry_after: None,
        }
    }

    pub fn retry_after(code: ErrorCode, seconds: u64) -> Self {
        Self {
            code,
            retry_after: Uint53::new(seconds.min(Uint53::MAX)).ok(),
        }
    }
}

impl From<ErrorCode> for WireError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<ProtoError> for WireError {
    fn from(error: ProtoError) -> Self {
        Self::new(ErrorCode::from(&error))
    }
}

impl From<hasp_crypto::CryptoError> for WireError {
    fn from(error: hasp_crypto::CryptoError) -> Self {
        Self::from(ProtoError::from(error))
    }
}

message!(WireErrorBody {
    0 code: ErrorCode,
    1 retry_after: Option<Uint53>,
});

impl Wire for WireError {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        WireErrorBody {
            code: self.code,
            retry_after: self.retry_after,
        }
        .encode(w)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let body = WireErrorBody::decode(r)?;
        Ok(Self {
            code: body.code,
            retry_after: body.retry_after,
        })
    }
}

const REPLY_OK: u64 = 0;
const REPLY_ERR: u64 = 1;

pub fn encode_reply<T: Wire>(reply: &Result<T, WireError>) -> Result<Vec<u8>, ProtoError> {
    let mut w = Writer::new();
    w.map(2)?;
    w.key(0)?;
    match reply {
        Ok(value) => {
            w.uint(REPLY_OK)?;
            w.field(1, value)?;
        }
        Err(error) => {
            w.uint(REPLY_ERR)?;
            w.field(1, error)?;
        }
    }
    let bytes = w.into_bytes();
    if bytes.len() > crate::MAX_RECORD {
        return Err(ProtoError::Format);
    }
    Ok(bytes)
}

pub fn decode_reply<T: Wire>(bytes: &[u8]) -> Result<Result<T, WireError>, ProtoError> {
    if bytes.len() > crate::MAX_RECORD {
        return Err(ProtoError::Format);
    }
    let mut r = Reader::new(bytes);
    let reply = r.map(|r, n| {
        if n != 2 {
            return Err(ProtoError::Format);
        }
        r.key(0)?;
        match r.uint()?.get() {
            REPLY_OK => Ok(Ok(r.field(1)?)),
            REPLY_ERR => Ok(Err(r.field(1)?)),
            _ => Err(ProtoError::Format),
        }
    })?;
    r.finish()?;
    let canonical = encode_reply(&reply)?;
    if canonical != bytes {
        return Err(ProtoError::Format);
    }
    Ok(reply)
}

pub fn decode_request<O: Operation>(bytes: &[u8]) -> Result<O, WireError> {
    O::from_cbor(bytes).map_err(WireError::from)
}

#[derive(Clone, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);

impl Blob {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob(len={})", self.0.len())
    }
}

impl From<Vec<u8>> for Blob {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Wire for Blob {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(&self.0)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.bytes().map(|bytes| Self(bytes.to_vec()))
    }
}

macro_rules! handle16 {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            pub fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            pub fn random() -> Result<Self, ProtoError> {
                hasp_crypto::random_array::<16>()
                    .map(Self)
                    .map_err(ProtoError::from)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex(&self.0))
            }
        }

        impl Wire for $name {
            fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
                w.bytes(&self.0)
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
                r.fixed().map(Self)
            }
        }
    };
}

handle16!(SessionId);
handle16!(LoginHandle);
handle16!(RecoveryId);

macro_rules! bearer {
    ($name:ident, $len:expr) => {
        pub struct $name(Zeroizing<[u8; $len]>);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            pub fn random() -> Result<Self, ProtoError> {
                hasp_crypto::random_array::<$len>()
                    .map(Self::from_bytes)
                    .map_err(ProtoError::from)
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn hash(&self) -> Hash32 {
                Hash32::digest(&[self.0.as_slice()])
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self::from_bytes(*self.0)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.as_slice().ct_eq(other.0.as_slice()).into()
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(..)", stringify!($name))
            }
        }

        impl Wire for $name {
            fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
                w.bytes(self.0.as_slice())
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
                Ok(Self::from_bytes(r.fixed::<$len>()?))
            }
        }
    };
}

bearer!(SessionToken, SESSION_TOKEN_LEN);
bearer!(RcAuthKey, 32);
bearer!(SignupToken, SIGNUP_TOKEN_LEN);

impl SignupToken {
    pub fn to_text(&self) -> String {
        format!("{SIGNUP_PREFIX}{}", crockford_encode(self.as_bytes()))
    }

    pub fn parse(text: &str) -> Result<Self, ProtoError> {
        let text = text.trim().to_ascii_uppercase();
        let body = text.strip_prefix(SIGNUP_PREFIX).ok_or(ProtoError::Format)?;
        let bytes = crockford_decode(body)?;
        let token = Self::from_bytes(bytes.try_into().map_err(|_| ProtoError::Format)?);
        if token.to_text() != text {
            return Err(ProtoError::Format);
        }
        Ok(token)
    }
}

code_enum!(
    TokenKind {
        Signup = 1,
        Rehost = 2,
        Reregister = 3,
    }
);

code_enum!(
    OpaquePurpose {
        Register = 1,
        Login = 2,
        Reauth = 3,
        Change = 4,
    }
);

code_enum!(
    MemberState {
        Invited = 1,
        Active = 2,
        Leaving = 3,
        Removed = 4,
        Dissolved = 5,
    }
);

code_enum!(
    NoticeKind {
        RecoveryStarted = 1,
        RecoveryAborted = 2,
        RecoveryCompleted = 3,
        CredentialChanged = 4,
        InviteAccepted = 5,
        MemberLeaving = 6,
        MemberRemoved = 7,
        VaultDissolved = 8,
    }
);

message!(Notice {
    0 id: Uint53,
    1 kind: NoticeKind,
    2 created: Uint53,
    3 vault_id: Option<VaultId>,
    4 at: Option<Uint53>,
});

message!(DeviceInfo {
    0 device_id: DeviceId,
    1 platform: String,
    2 label: Option<SealedRaw>,
});

message!(Ack {});

message!(SessionGrant {
    0 session_id: SessionId,
    1 token: SessionToken,
    2 idle_expires: Uint53,
    3 abs_expires: Uint53,
});

pub fn credential_id(account: &AccountId) -> Result<Vec<u8>, ProtoError> {
    let mut w = Writer::new();
    w.array(2)?;
    w.text(ACCOUNT_CREDENTIAL)?;
    account.encode(&mut w)?;
    Ok(w.into_bytes())
}

pub fn opaque_context(
    purpose: OpaquePurpose,
    account: &AccountId,
    kdf: &KdfWire,
) -> Result<Vec<u8>, ProtoError> {
    let mut w = Writer::new();
    w.map(6)?;
    w.key(0)?;
    w.uint(PROTOCOL_VERSION)?;
    w.key(1)?;
    w.uint(OPAQUE_SUITE)?;
    w.field(2, &purpose)?;
    w.field(3, account)?;
    w.key(4)?;
    w.array(3)?;
    w.uint(u64::from(kdf.m))?;
    w.uint(u64::from(kdf.t))?;
    w.uint(u64::from(kdf.p))?;
    w.key(5)?;
    w.uint(PROTOCOL_VERSION)?;
    Ok(w.into_bytes())
}

/// `T = X(session_key, "session-token", sid)`. The OPAQUE session key is 64 bytes, so it enters
/// HKDF-Extract (empty salt) first and the extracted key plays the PRK of `X`.
pub fn session_token(session_key: &[u8], sid: &SessionId) -> Result<SessionToken, ProtoError> {
    let prk: Prk = hkdf_extract(&[], session_key);
    let mut w = Writer::new();
    w.array(2)?;
    w.text(Kdf::SessionToken.name())?;
    sid.encode(&mut w)?;
    let key = hkdf_expand_key(&prk, &w.into_bytes())?;
    Ok(SessionToken::from_bytes(*key.expose()))
}
