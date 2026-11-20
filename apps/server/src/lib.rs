#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]
#![expect(
    clippy::needless_pass_by_value,
    clippy::unused_self,
    clippy::unnecessary_wraps,
    reason = "operation handlers share one routing signature: self, state, call, decoded request"
)]

mod backup;
mod cli;
mod clock;
mod config;
mod http;
mod logging;
mod ops;
mod persist;
mod rate;
mod secret;
mod server;
mod settings;
mod store;

#[cfg(any(test, feature = "testing"))]
#[expect(
    clippy::expect_used,
    reason = "test support aborts on a broken fixture"
)]
pub mod fixture;

#[cfg(test)]
mod tests;

pub use backup::{
    BlobEntry, DEFAULT_KEEP, FileEntry, RestoreOptions, RestoreReport, STALE_AFTER, SnapshotInfo,
    SnapshotManifest, Staleness, VaultHead, create_snapshot, list_snapshots, prune_snapshots,
    restore_snapshot, staleness, verify_snapshot,
};
pub use cli::{Cli, CliError, Context, main_with, run};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::ServerConfig;
pub use http::{Capacity, Cidr, CidrError, Gateway, HttpOptions, SocketOptions};
pub use logging::{RedactingLayer, init as init_logging};
pub use persist::{DataLayout, PersistError, VaultRollback};
pub use rate::{Limits, RateClass, RateKey, RateLimited, RateLimiter, Unlimited, WindowLimiter};
pub use secret::{
    KeyOrigin, ReregisterToken, export_server_key, generate_server_key, import_server_key,
    install_server_key, issue_reregister_tokens, load_or_generate_server_key, load_server_key,
    server_fingerprint,
};
pub use server::{Caller, Server};
pub use settings::{CONFIG_ENV, Settings, SettingsError};
pub use store::{
    AccountRow, AccountState, AttachmentRow, AttachmentState, EnrolRow, EnrolState, InviteRow,
    ItemKey, ItemRow, ManifestRow, MemberRow, MemberStatus, MemoryStore, NoticeRow, OpaqueRow,
    RecoveryRow, RecoverySessionRow, RecoveryState, RosterRow, ServerError, SessionRow, ShareRow,
    Store, StoreResult, Table, TokenRow, VaultPhase, VaultRow,
};
pub use store::{Durability, SchemaStatus, SqliteStore};
