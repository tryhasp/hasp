use std::fs;
use std::path::{Path, PathBuf};

use super::manifest::{MANIFEST_NAME, SnapshotManifest};
use crate::persist::{PersistError, remove_dir_durable};

pub const DEFAULT_KEEP: usize = 7;
pub const STALE_AFTER: u64 = 7 * 24 * 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Staleness {
    Never,
    Fresh { age: u64 },
    Stale { age: u64 },
}

/// Oldest first. A directory without a readable manifest, such as a half-written `.partial`, is
/// not a snapshot.
pub fn list_snapshots(root: &Path) -> Result<Vec<(PathBuf, SnapshotManifest)>, PersistError> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        let Ok(bytes) = fs::read(path.join(MANIFEST_NAME)) else {
            continue;
        };
        if let Ok(manifest) = SnapshotManifest::parse(&bytes) {
            out.push((path, manifest));
        }
    }
    out.sort_by_key(|(_, manifest)| manifest.created);
    Ok(out)
}

/// Never removes the last snapshot: `keep` is at least 1.
pub fn prune_snapshots(root: &Path, keep: usize) -> Result<Vec<PathBuf>, PersistError> {
    let keep = keep.max(1);
    let snapshots = list_snapshots(root)?;
    let excess = snapshots.len().saturating_sub(keep);
    let mut removed = Vec::new();
    for (path, _) in snapshots.into_iter().take(excess) {
        remove_dir_durable(&path)?;
        removed.push(path);
    }
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries {
            let path = entry?.path();
            let partial = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.') && n.ends_with(".partial"));
            if partial {
                remove_dir_durable(&path)?;
                removed.push(path);
            }
        }
    }
    Ok(removed)
}

/// Age of the newest snapshot against `now`; `Stale` after 7 days (startup warning).
pub fn staleness(root: &Path, now: u64) -> Result<Staleness, PersistError> {
    let newest = list_snapshots(root)?
        .into_iter()
        .map(|(_, manifest)| manifest.created)
        .max();
    Ok(match newest {
        None => Staleness::Never,
        Some(created) => {
            let age = now.saturating_sub(created);
            if age > STALE_AFTER {
                Staleness::Stale { age }
            } else {
                Staleness::Fresh { age }
            }
        }
    })
}
