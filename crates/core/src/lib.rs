#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("the testing feature must not be enabled in a release build");

pub mod api;
pub mod client;
pub mod export;
pub mod generator;
pub mod import;
mod keys;
pub mod matcher;
pub mod model;
pub mod otp;
pub mod platform;
pub mod provider;
mod session;
pub mod store;
mod stream;
pub mod sync;
#[cfg(feature = "testing")]
pub mod testing;
mod text;
pub mod transport;
pub mod watchtower;
pub mod webauthn;

pub use text::{normalise_login, normalise_password};

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("proto: {0}")]
    Proto(#[from] hasp_proto::ProtoError),
    #[error("crypto: {0}")]
    Crypto(#[from] hasp_crypto::CryptoError),
    #[error("model: {0}")]
    Model(#[from] model::ModelError),
    #[error("generator: {0}")]
    Generator(#[from] generator::GeneratorError),
    #[error("otp: {0}")]
    Otp(#[from] otp::OtpError),
    #[error("matcher: {0}")]
    Matcher(#[from] matcher::MatchError),
    #[error("import: {0}")]
    Import(#[from] import::ImportError),
    #[error("export: {0}")]
    Export(#[from] export::ExportError),
    #[error("transport: {0}")]
    Transport(#[from] transport::TransportError),
    #[error("store: {0}")]
    Store(#[from] store::StoreError),
    #[error("platform: {0}")]
    Platform(#[from] platform::PlatformError),
    #[error("watchtower: {0}")]
    Watchtower(#[from] watchtower::WatchtowerError),
    #[error("cancelled")]
    Cancelled,
    #[error("locked")]
    Locked,
    #[error("wrong password, Secret Key or tampered data")]
    Credentials,
    #[error("the session expired; unlock with the password")]
    SessionExpired,
    #[error("this device was revoked; its local data was erased")]
    DeviceRevoked,
    #[error("the server key differs from the pinned key")]
    ServerKey,
    #[error("shared vaults are read-only until this device confirms their heads")]
    Unconfirmed,
    #[error("the vault is quarantined: {check}")]
    Quarantined {
        vault: hasp_proto::VaultId,
        check: String,
    },
    #[error("the vault has an owner repair waiting for confirmation")]
    RepairPending { vault: hasp_proto::VaultId },
    #[error("the vault is {0}")]
    VaultInactive(&'static str),
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("refused: {0}")]
    Refused(&'static str),
    #[error("not ready, retry in {retry_after} s")]
    Pending { retry_after: u64 },
    #[error("conflicting heads for {0}")]
    Diverged(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("internal: {0}")]
    Internal(&'static str),
}
