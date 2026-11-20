use hasp_core::CoreError;
use hasp_core::platform::PlatformError;
use hasp_core::transport::TransportError;
use hasp_proto::wire::ErrorCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Generic = 1,
    Usage = 2,
    Locked = 3,
    NotFound = 4,
    Conflict = 5,
    Permission = 6,
    Network = 7,
    Auth = 8,
    Integrity = 9,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    pub kind: Kind,
    pub code: Option<String>,
    pub message: String,
    pub candidates: Vec<String>,
    pub retry_after: Option<u64>,
}

impl CliError {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: None,
            message: message.into(),
            candidates: Vec::new(),
            retry_after: None,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Kind::Usage, message)
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(Kind::Generic, message)
    }

    pub fn locked(message: impl Into<String>) -> Self {
        Self::new(Kind::Locked, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Kind::NotFound, message)
    }

    pub fn ambiguous(what: &str, candidates: Vec<String>) -> Self {
        let mut error = Self::new(Kind::NotFound, format!("{what} is ambiguous"));
        error.candidates = candidates;
        error
    }

    pub fn exit_code(&self) -> u8 {
        self.kind as u8
    }

    fn coded(kind: Kind, code: &str, message: String) -> Self {
        let mut error = Self::new(kind, message);
        error.code = Some(code.to_owned());
        error
    }
}

fn wire_kind(code: ErrorCode) -> Kind {
    match code {
        ErrorCode::Rollback
        | ErrorCode::Fork
        | ErrorCode::Root
        | ErrorCode::Roster
        | ErrorCode::Pin
        | ErrorCode::Sig
        | ErrorCode::Epoch
        | ErrorCode::Authz
        | ErrorCode::ServerKey
        | ErrorCode::Invite => Kind::Integrity,
        ErrorCode::Auth | ErrorCode::ReauthRequired | ErrorCode::Expired => Kind::Auth,
        ErrorCode::NotMember | ErrorCode::ReadOnly => Kind::Permission,
        ErrorCode::NotFound => Kind::NotFound,
        ErrorCode::StaleHead | ErrorCode::EpochStale | ErrorCode::Conflict => Kind::Conflict,
        ErrorCode::RateLimited | ErrorCode::Internal | ErrorCode::Unsupported => Kind::Network,
        ErrorCode::Format
        | ErrorCode::Version
        | ErrorCode::Aead
        | ErrorCode::KdfParams
        | ErrorCode::TooLarge
        | ErrorCode::Pending => Kind::Generic,
    }
}

impl From<TransportError> for CliError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Server(wire) => {
                let mut out = Self::coded(
                    wire_kind(wire.code),
                    wire.code.name(),
                    format!("the server answered {}", wire.code.name()),
                );
                out.retry_after = wire.retry_after.map(hasp_proto::Uint53::get);
                out
            }
            TransportError::Codec(inner) => Self::coded(
                Kind::Network,
                "E_FORMAT",
                format!("the server reply did not decode: {inner}"),
            ),
            TransportError::Unreachable => Self::new(Kind::Network, "the server is unreachable"),
        }
    }
}

impl From<CoreError> for CliError {
    fn from(error: CoreError) -> Self {
        let message = error.to_string();
        match error {
            CoreError::Proto(inner) => {
                let code = ErrorCode::from(&inner);
                Self::coded(wire_kind(code), code.name(), message)
            }
            CoreError::Transport(inner) => inner.into(),
            CoreError::ServerKey => Self::coded(Kind::Integrity, "E_SERVER_KEY", message),
            CoreError::Quarantined { check, .. } => {
                let mut out = Self::new(Kind::Integrity, message);
                if check.starts_with("E_") {
                    out.code = Some(check);
                }
                out
            }
            CoreError::Locked | CoreError::SessionExpired | CoreError::DeviceRevoked => {
                Self::new(Kind::Locked, message)
            }
            CoreError::Credentials => Self::coded(Kind::Auth, "E_AUTH", message),
            CoreError::Pending { retry_after } => {
                let mut out = Self::new(Kind::Auth, message);
                out.retry_after = Some(retry_after);
                out
            }
            CoreError::Platform(PlatformError::Denied) => Self::new(Kind::Auth, message),
            CoreError::NotFound(_) => Self::new(Kind::NotFound, message),
            CoreError::Unconfirmed | CoreError::VaultInactive(_) => {
                Self::new(Kind::Permission, message)
            }
            CoreError::Diverged(_) | CoreError::Conflict(_) | CoreError::RepairPending { .. } => {
                Self::new(Kind::Conflict, message)
            }
            CoreError::Crypto(_)
            | CoreError::Model(_)
            | CoreError::Generator(_)
            | CoreError::Otp(_)
            | CoreError::Matcher(_)
            | CoreError::Import(_)
            | CoreError::Export(_)
            | CoreError::Watchtower(_)
            | CoreError::Store(_)
            | CoreError::Platform(_)
            | CoreError::Cancelled
            | CoreError::Refused(_)
            | CoreError::Internal(_) => Self::new(Kind::Generic, message),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::failure(format!("i/o: {}", error.kind()))
    }
}

impl From<serde_json::Error> for CliError {
    fn from(_: serde_json::Error) -> Self {
        Self::failure("json")
    }
}

impl From<hasp_core::model::ModelError> for CliError {
    fn from(error: hasp_core::model::ModelError) -> Self {
        Self::failure(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hasp_proto::wire::WireError;

    fn code_of(error: ErrorCode) -> CliError {
        CliError::from(CoreError::Transport(TransportError::Server(
            WireError::new(error),
        )))
    }

    #[test]
    fn integrity_codes_exit_nine_and_name_the_code() {
        for code in [
            ErrorCode::Rollback,
            ErrorCode::Fork,
            ErrorCode::Root,
            ErrorCode::Roster,
            ErrorCode::Pin,
            ErrorCode::Sig,
            ErrorCode::Epoch,
            ErrorCode::Authz,
            ErrorCode::ServerKey,
            ErrorCode::Invite,
        ] {
            let error = code_of(code);
            assert_eq!(error.exit_code(), 9, "{}", code.name());
            assert_eq!(error.code.as_deref(), Some(code.name()));
        }
    }

    #[test]
    fn server_answers_map_to_their_exit_codes() {
        assert_eq!(code_of(ErrorCode::Auth).exit_code(), 8);
        assert_eq!(code_of(ErrorCode::NotFound).exit_code(), 4);
        assert_eq!(code_of(ErrorCode::Conflict).exit_code(), 5);
        assert_eq!(code_of(ErrorCode::StaleHead).exit_code(), 5);
        assert_eq!(code_of(ErrorCode::ReadOnly).exit_code(), 6);
        assert_eq!(code_of(ErrorCode::NotMember).exit_code(), 6);
        assert_eq!(code_of(ErrorCode::RateLimited).exit_code(), 7);
    }

    #[test]
    fn local_conditions_map_to_their_exit_codes() {
        let exit = |error: CoreError| CliError::from(error).exit_code();
        assert_eq!(exit(CoreError::Locked), 3);
        assert_eq!(exit(CoreError::Credentials), 8);
        assert_eq!(exit(CoreError::NotFound("item")), 4);
        assert_eq!(exit(CoreError::Unconfirmed), 6);
        assert_eq!(exit(CoreError::Diverged("heads")), 5);
        assert_eq!(exit(CoreError::ServerKey), 9);
        assert_eq!(exit(CoreError::Transport(TransportError::Unreachable)), 7);
        assert_eq!(exit(CoreError::Internal("x")), 1);
    }

    #[test]
    fn proto_failures_carry_their_wire_code() {
        let error = CliError::from(CoreError::Proto(hasp_proto::ProtoError::Rollback));
        assert_eq!(error.exit_code(), 9);
        assert_eq!(error.code.as_deref(), Some("E_ROLLBACK"));
    }
}
