use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use hasp_crypto::sha256;
use hasp_proto::{AttId, VaultId};

use super::manifest::{
    DB_NAME, FileEntry, KEY_NAME, MANIFEST_NAME, SnapshotManifest, VaultHead, hex_hash,
};
use super::runtime;
use super::snapshot::read_heads;
use crate::persist::{
    DataLayout, PersistError, VaultRollback, copy_durable, create_dir_durable, sync_dir,
    write_durable,
};
use crate::store::{Durability, connect, connect_read_only};
use sqlx::Connection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreOptions {
    pub acknowledge_rollback: bool,
}

#[derive(Clone, Debug)]
pub struct RestoreReport {
    pub manifest: SnapshotManifest,
    pub rolled_back: Vec<VaultRollback>,
    pub previous: Option<PathBuf>,
}

/// Touches nothing outside `dir`.
pub fn verify_snapshot(dir: &Path) -> Result<SnapshotManifest, PersistError> {
    let manifest = SnapshotManifest::parse(&fs::read(dir.join(MANIFEST_NAME))?)?;
    if manifest.schema_version > crate::store::latest_schema() {
        return Err(PersistError::SchemaNewer {
            found: manifest.schema_version,
            supported: crate::store::latest_schema(),
        });
    }
    check(dir, &manifest.db)?;
    if let Some(key) = &manifest.key {
        check(dir, key)?;
    }
    let layout = DataLayout::new(dir);
    for blob in &manifest.blobs {
        let att = parse_att(&blob.att_id)?;
        let bytes = fs::read(layout.blob_path(&att, blob.idx)).map_err(|_| {
            PersistError::HashMismatch(format!("blob {}/{}", blob.att_id, blob.idx))
        })?;
        let intact = u64::try_from(bytes.len()).is_ok_and(|n| n == blob.bytes)
            && hex_hash(&sha256(&[&bytes])) == blob.sha256;
        if !intact {
            return Err(PersistError::HashMismatch(format!(
                "blob {}/{}",
                blob.att_id, blob.idx
            )));
        }
    }
    Ok(manifest)
}

/// The server must be stopped. A restore that would lower or drop a live vault head is refused
/// unless `acknowledge_rollback` is set; clients then raise `E_ROLLBACK` (protocol 7.3). While
/// `restore.in-progress` exists the server refuses to start and the restore can be run again;
/// what was live moves to `pre-restore-N`.
pub fn restore_snapshot(
    snapshot: &Path,
    layout: &DataLayout,
    options: RestoreOptions,
) -> Result<RestoreReport, PersistError> {
    let manifest = verify_snapshot(snapshot)?;
    let _instance = crate::store::InstanceLock::acquire(layout)?;
    let staging = layout.root().join(".restore-staging");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    let outcome = prepare(snapshot, layout, &staging, &manifest, options);
    let rolled_back = match outcome {
        Ok(rolled_back) => rolled_back,
        Err(error) => {
            if staging.exists() {
                fs::remove_dir_all(&staging)?;
            }
            return Err(error);
        }
    };
    write_durable(
        &layout.restore_marker(),
        snapshot.display().to_string().as_bytes(),
    )?;
    let previous = swap(layout, &staging, &manifest)?;
    fs::remove_file(layout.restore_marker())?;
    sync_dir(layout.root())?;
    Ok(RestoreReport {
        manifest,
        rolled_back,
        previous,
    })
}

fn prepare(
    snapshot: &Path,
    layout: &DataLayout,
    staging: &Path,
    manifest: &SnapshotManifest,
    options: RestoreOptions,
) -> Result<Vec<VaultRollback>, PersistError> {
    let staged = stage(snapshot, staging, manifest)?;
    let mut declared: Vec<(&str, u64)> = manifest
        .vaults
        .iter()
        .map(|head| (head.vault_id.as_str(), head.head_seq))
        .collect();
    declared.sort_unstable();
    let mut actual: Vec<(&str, u64)> = staged
        .iter()
        .map(|head| (head.vault_id.as_str(), head.head_seq))
        .collect();
    actual.sort_unstable();
    if declared != actual {
        return Err(PersistError::Manifest(
            "vault heads in the manifest differ from the snapshot database",
        ));
    }
    let rolled_back = rollbacks(layout, &staged, options)?;
    if !rolled_back.is_empty() && !options.acknowledge_rollback {
        return Err(PersistError::RollbackRefused(rolled_back));
    }
    Ok(rolled_back)
}

fn check(dir: &Path, entry: &FileEntry) -> Result<(), PersistError> {
    let bytes = fs::read(dir.join(&entry.path))
        .map_err(|_| PersistError::HashMismatch(entry.path.clone()))?;
    let intact = u64::try_from(bytes.len()).is_ok_and(|n| n == entry.bytes)
        && hex_hash(&sha256(&[&bytes])) == entry.sha256;
    if intact {
        Ok(())
    } else {
        Err(PersistError::HashMismatch(entry.path.clone()))
    }
}

fn parse_att(text: &str) -> Result<AttId, PersistError> {
    let bytes = hasp_crypto::from_hex(text).ok_or(PersistError::Manifest("attachment id"))?;
    let array: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| PersistError::Manifest("attachment id"))?;
    Ok(AttId::from_bytes(array))
}

fn parse_vault(text: &str) -> Result<VaultId, PersistError> {
    let bytes = hasp_crypto::from_hex(text).ok_or(PersistError::Manifest("vault id"))?;
    let array: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| PersistError::Manifest("vault id"))?;
    Ok(VaultId::from_bytes(array))
}

fn rollbacks(
    layout: &DataLayout,
    restored: &[VaultHead],
    options: RestoreOptions,
) -> Result<Vec<VaultRollback>, PersistError> {
    let db = layout.db_path();
    if !db.exists() {
        return Ok(Vec::new());
    }
    let live = runtime()?.block_on(async {
        let mut conn = connect_read_only(&db).await?;
        read_heads(&mut conn).await
    });
    let live = match live {
        Ok(live) => live,
        Err(_) if options.acknowledge_rollback => return Ok(Vec::new()),
        Err(_) => return Err(PersistError::LiveUnreadable),
    };
    let restored: BTreeMap<&str, u64> = restored
        .iter()
        .map(|head| (head.vault_id.as_str(), head.head_seq))
        .collect();
    let mut out = Vec::new();
    for head in live {
        let after = restored.get(head.vault_id.as_str()).copied();
        if after.is_none_or(|after| after < head.head_seq) {
            out.push(VaultRollback {
                vault_id: parse_vault(&head.vault_id)?,
                seen_seq: head.head_seq,
                restored_seq: after,
            });
        }
    }
    Ok(out)
}

const SANITISE: &str = "BEGIN;
DELETE FROM session_tokens;
DELETE FROM sessions;
DELETE FROM enrol_channels;
DELETE FROM recovery_sessions;
UPDATE signup_tokens SET expires = 0 WHERE used_by IS NULL;
COMMIT;";

async fn check_and_sanitise(db: &Path) -> Result<Vec<VaultHead>, PersistError> {
    let mut conn = connect(db, false, Durability::Full).await?;
    let verdicts: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(&mut conn)
        .await?;
    if verdicts != ["ok"] {
        return Err(PersistError::Corrupt(
            "snapshot database failed its integrity check",
        ));
    }
    let heads = read_heads(&mut conn).await?;
    sqlx::raw_sql(SANITISE).execute(&mut conn).await?;
    conn.close().await?;
    Ok(heads)
}

fn stage(
    snapshot: &Path,
    staging: &Path,
    manifest: &SnapshotManifest,
) -> Result<Vec<VaultHead>, PersistError> {
    create_dir_durable(staging)?;
    let staged_db = staging.join(DB_NAME);
    copy_durable(&snapshot.join(DB_NAME), &staged_db)?;
    let heads = runtime()?.block_on(check_and_sanitise(&staged_db))?;
    for suffix in ["-wal", "-shm"] {
        let mut name = staged_db.clone().into_os_string();
        name.push(suffix);
        let leftover = PathBuf::from(name);
        if leftover.exists() {
            fs::remove_file(leftover)?;
        }
    }
    if manifest.key.is_some() {
        copy_durable(&snapshot.join(KEY_NAME), &staging.join(KEY_NAME))?;
    }
    let from = DataLayout::new(snapshot);
    let to = DataLayout::new(staging);
    create_dir_durable(&to.blobs_dir())?;
    for blob in &manifest.blobs {
        let att = parse_att(&blob.att_id)?;
        copy_durable(
            &from.blob_path(&att, blob.idx),
            &to.blob_path(&att, blob.idx),
        )?;
    }
    sync_dir(staging)?;
    Ok(heads)
}

fn swap(
    layout: &DataLayout,
    staging: &Path,
    manifest: &SnapshotManifest,
) -> Result<Option<PathBuf>, PersistError> {
    let root = layout.root();
    let live: Vec<PathBuf> = ["", "-wal", "-shm"]
        .iter()
        .map(|suffix| {
            let mut name = layout.db_path().into_os_string();
            name.push(suffix);
            PathBuf::from(name)
        })
        .chain([layout.blobs_dir()])
        .chain(
            manifest
                .key
                .is_some()
                .then(|| layout.key_path().to_path_buf()),
        )
        .filter(|path| path.exists())
        .collect();
    let previous = if live.is_empty() {
        None
    } else {
        let dir = next_pre_restore(root)?;
        create_dir_durable(&dir)?;
        for path in &live {
            let name = path.file_name().unwrap_or_default();
            if path == layout.key_path() {
                fs::copy(path, dir.join("server.key"))?;
                continue;
            }
            fs::rename(path, dir.join(name))?;
        }
        sync_dir(&dir)?;
        sync_dir(root)?;
        Some(dir)
    };
    fs::rename(staging.join(DB_NAME), layout.db_path())?;
    let staged_blobs = staging.join("blobs");
    fs::rename(&staged_blobs, layout.blobs_dir())?;
    if manifest.key.is_some() {
        let bytes = fs::read(staging.join(KEY_NAME))?;
        write_durable(layout.key_path(), &bytes)?;
    }
    sync_dir(root)?;
    fs::remove_dir_all(staging)?;
    sync_dir(root)?;
    Ok(previous)
}

fn next_pre_restore(root: &Path) -> Result<PathBuf, PersistError> {
    let mut highest = 0_u64;
    for entry in fs::read_dir(root)? {
        let name = entry?.file_name();
        if let Some(n) = name
            .to_str()
            .and_then(|n| n.strip_prefix("pre-restore-"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            highest = highest.max(n);
        }
    }
    Ok(root.join(format!("pre-restore-{}", highest.saturating_add(1))))
}
