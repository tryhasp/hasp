use serde::{Deserialize, Serialize};

use crate::persist::PersistError;

pub(super) const FORMAT: u32 = 1;
pub(super) const MANIFEST_NAME: &str = "manifest.json";
pub(super) const DB_NAME: &str = "haspd.sqlite3";
pub(super) const KEY_NAME: &str = "secrets/server.key";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEntry {
    pub att_id: String,
    pub idx: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHead {
    pub vault_id: String,
    pub head_seq: u64,
}

/// `vaults` records each vault head at snapshot time, which a later restore compares against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub format: u32,
    pub created: u64,
    pub schema_version: i64,
    pub db: FileEntry,
    pub key: Option<FileEntry>,
    pub blobs: Vec<BlobEntry>,
    pub vaults: Vec<VaultHead>,
}

impl SnapshotManifest {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, PersistError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if manifest.format != FORMAT {
            return Err(PersistError::Manifest("unsupported format"));
        }
        Ok(manifest)
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, PersistError> {
        Ok(serde_json::to_vec_pretty(self)?)
    }
}

pub(super) fn hex_hash(digest: &[u8; 32]) -> String {
    hasp_crypto::to_hex(digest)
}
