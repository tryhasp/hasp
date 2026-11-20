use std::fs;
use std::path::{Path, PathBuf};

use hasp_crypto::sha256;
use hasp_proto::AttId;
use sqlx::Connection;

use super::manifest::{
    BlobEntry, DB_NAME, FORMAT, FileEntry, KEY_NAME, MANIFEST_NAME, SnapshotManifest, VaultHead,
    hex_hash,
};
use super::runtime;
use crate::persist::{DataLayout, PersistError, create_dir_durable, sync_dir, write_durable};
use crate::store::{Durability, connect, connect_read_only, schema_status, vacuum_into};

#[derive(Clone, Debug)]
pub struct SnapshotInfo {
    pub dir: PathBuf,
    pub manifest: SnapshotManifest,
}

pub(super) fn snapshot_dir_name(created: u64) -> String {
    format!("hasp-backup-{created:020}")
}

/// Safe while the server runs and blocks, so async callers use `spawn_blocking`. The directory
/// appears under its final name only when complete, and holds `server.key` only when
/// `include_key` is set.
pub fn create_snapshot(
    layout: &DataLayout,
    dest_root: &Path,
    created: u64,
    include_key: bool,
) -> Result<SnapshotInfo, PersistError> {
    let name = snapshot_dir_name(created);
    let final_dir = dest_root.join(&name);
    if final_dir.exists() {
        return Err(PersistError::Manifest("snapshot already exists"));
    }
    let partial = dest_root.join(format!(".{name}.partial"));
    if partial.exists() {
        fs::remove_dir_all(&partial)?;
    }
    create_dir_durable(&partial)?;
    let manifest = build(layout, &partial, created, include_key)?;
    write_durable(&partial.join(MANIFEST_NAME), &manifest.to_bytes()?)?;
    sync_dir(&partial)?;
    fs::rename(&partial, &final_dir)?;
    sync_dir(dest_root)?;
    Ok(SnapshotInfo {
        dir: final_dir,
        manifest,
    })
}

fn build(
    layout: &DataLayout,
    partial: &Path,
    created: u64,
    include_key: bool,
) -> Result<SnapshotManifest, PersistError> {
    create_dir_durable(&layout.blobs_dir())?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(layout.blobs_dir().join(".lock"))?;
    lock.lock_shared()?;
    let db_target = partial.join(DB_NAME);
    let rt = runtime()?;
    let (schema_version, vaults, chunks) = rt.block_on(async {
        let mut live = connect(&layout.db_path(), false, Durability::Full).await?;
        vacuum_into(&mut live, &db_target).await?;
        live.close().await?;
        let mut copy = connect_read_only(&db_target).await?;
        let status = schema_status(&mut copy).await?;
        let vaults = read_heads(&mut copy).await?;
        let chunks = read_chunks(&mut copy).await?;
        Ok::<_, PersistError>((status.applied.unwrap_or(0), vaults, chunks))
    })?;
    let snapshot_layout = DataLayout::new(partial);
    let mut blobs = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let from = layout.blob_path(&chunk.att, chunk.idx);
        let bytes = fs::read(&from).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PersistError::Corrupt("attachment chunk file is missing")
            } else {
                PersistError::Io(error)
            }
        })?;
        let digest = sha256(&[&bytes]);
        if digest.as_slice() != chunk.digest.as_slice() {
            return Err(PersistError::HashMismatch(format!(
                "attachment chunk {}",
                hasp_crypto::to_hex(chunk.att.as_bytes())
            )));
        }
        write_durable(&snapshot_layout.blob_path(&chunk.att, chunk.idx), &bytes)?;
        blobs.push(BlobEntry {
            att_id: hasp_crypto::to_hex(chunk.att.as_bytes()),
            idx: chunk.idx,
            bytes: u64::try_from(bytes.len()).map_err(|_| PersistError::Encoding)?,
            sha256: hex_hash(&digest),
        });
    }
    let key = if include_key {
        match fs::read(layout.key_path()) {
            Ok(bytes) => {
                write_durable(&partial.join(KEY_NAME), &bytes)?;
                Some(entry(KEY_NAME, &bytes)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    let db_bytes = fs::read(&db_target)?;
    drop(lock);
    Ok(SnapshotManifest {
        format: FORMAT,
        created,
        schema_version,
        db: entry(DB_NAME, &db_bytes)?,
        key,
        blobs,
        vaults,
    })
}

fn entry(path: &str, bytes: &[u8]) -> Result<FileEntry, PersistError> {
    Ok(FileEntry {
        path: path.to_owned(),
        bytes: u64::try_from(bytes.len()).map_err(|_| PersistError::Encoding)?,
        sha256: hex_hash(&sha256(&[bytes])),
    })
}

struct Chunk {
    att: AttId,
    idx: u64,
    digest: Vec<u8>,
}

async fn read_chunks(conn: &mut sqlx::SqliteConnection) -> Result<Vec<Chunk>, PersistError> {
    let rows =
        sqlx::query!("SELECT att_id, idx, digest FROM attachment_chunks ORDER BY att_id, idx")
            .fetch_all(&mut *conn)
            .await?;
    rows.into_iter()
        .map(|row| {
            let att = AttId::from_bytes(
                row.att_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| PersistError::Corrupt("attachment id"))?,
            );
            let idx = u64::try_from(row.idx).map_err(|_| PersistError::Corrupt("chunk index"))?;
            Ok(Chunk {
                att,
                idx,
                digest: row.digest,
            })
        })
        .collect()
}

pub(crate) async fn read_heads(
    conn: &mut sqlx::SqliteConnection,
) -> Result<Vec<VaultHead>, PersistError> {
    let rows = sqlx::query!("SELECT vault_id, head_seq FROM vaults ORDER BY vault_id")
        .fetch_all(&mut *conn)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(VaultHead {
                vault_id: hasp_crypto::to_hex(&row.vault_id),
                head_seq: u64::try_from(row.head_seq)
                    .map_err(|_| PersistError::Corrupt("head seq"))?,
            })
        })
        .collect()
}
