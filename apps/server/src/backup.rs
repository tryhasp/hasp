mod manifest;
mod restore;
mod retention;
mod snapshot;

pub use manifest::{BlobEntry, FileEntry, SnapshotManifest, VaultHead};
pub use restore::{RestoreOptions, RestoreReport, restore_snapshot, verify_snapshot};
pub use retention::{
    DEFAULT_KEEP, STALE_AFTER, Staleness, list_snapshots, prune_snapshots, staleness,
};
pub use snapshot::{SnapshotInfo, create_snapshot};

use tokio::runtime::{Builder, Runtime};

use crate::persist::PersistError;

fn runtime() -> Result<Runtime, PersistError> {
    Ok(Builder::new_current_thread().enable_all().build()?)
}
