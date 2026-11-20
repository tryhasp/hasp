mod fsio;

use std::path::{Path, PathBuf};

use hasp_proto::{AttId, VaultId};

pub(crate) use fsio::{
    copy_durable, create_dir_durable, remove_dir_durable, restrict, restrict_database, sync_dir,
    write_durable,
};

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("io failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("database failure: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("migration failure: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("schema version {found} is newer than this binary supports ({supported})")]
    SchemaNewer { found: i64, supported: i64 },
    #[error("data is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("backup manifest is invalid: {0}")]
    Manifest(&'static str),
    #[error("{0} does not match its recorded hash")]
    HashMismatch(String),
    #[error("restore would roll back {} vault(s) that clients have seen", .0.len())]
    RollbackRefused(Vec<VaultRollback>),
    #[error("another haspd holds this data directory")]
    Busy,
    #[error("the database schema is not current; start `haspd serve` or run `haspd migrate` first")]
    SchemaStale,
    #[error("a server key already exists")]
    KeyExists,
    #[error("no server key at the configured path")]
    KeyMissing,
    #[error("server key file is readable by other users; run `chmod 600` on it before starting")]
    KeyPermissions,
    #[error(
        "the live database could not be read; restore needs --acknowledge-rollback to replace it"
    )]
    LiveUnreadable,
    #[error(
        "a restore was interrupted ({0}); run `haspd restore --from <snapshot>` again, nothing else may start until it finishes"
    )]
    RestoreInterrupted(PathBuf),
    #[error("server key file is malformed")]
    KeyFormat,
    #[error("wrong passphrase or damaged key export")]
    Passphrase,
    #[error("key derivation parameters are out of range")]
    KdfParams,
    #[error("randomness unavailable")]
    Random,
    #[error("encoding failure")]
    Encoding,
}

impl From<hasp_crypto::CryptoError> for PersistError {
    fn from(error: hasp_crypto::CryptoError) -> Self {
        match error {
            hasp_crypto::CryptoError::Aead => Self::Passphrase,
            hasp_crypto::CryptoError::KdfParams => Self::KdfParams,
            hasp_crypto::CryptoError::Random => Self::Random,
            hasp_crypto::CryptoError::Signature
            | hasp_crypto::CryptoError::Length
            | hasp_crypto::CryptoError::Kem
            | hasp_crypto::CryptoError::Opaque
            | hasp_crypto::CryptoError::Internal(_) => Self::Encoding,
        }
    }
}

impl From<hasp_proto::ProtoError> for PersistError {
    fn from(_: hasp_proto::ProtoError) -> Self {
        Self::Encoding
    }
}

impl From<serde_json::Error> for PersistError {
    fn from(_: serde_json::Error) -> Self {
        Self::Manifest("not valid json")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultRollback {
    pub vault_id: VaultId,
    pub seen_seq: u64,
    pub restored_seq: Option<u64>,
}

pub(crate) fn ensure_no_restore_in_progress(layout: &DataLayout) -> Result<(), PersistError> {
    let marker = layout.restore_marker();
    if marker.exists() {
        Err(PersistError::RestoreInterrupted(marker))
    } else {
        Ok(())
    }
}

/// `server.key` may live outside the data directory through `with_key_path`.
#[derive(Clone, Debug)]
pub struct DataLayout {
    root: PathBuf,
    key_path: PathBuf,
}

impl DataLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let key_path = root.join("secrets").join("server.key");
        Self { root, key_path }
    }

    #[must_use]
    pub fn with_key_path(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.key_path = key_path.into();
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn db_path(&self) -> PathBuf {
        self.root.join("haspd.sqlite3")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn restore_marker(&self) -> PathBuf {
        self.root.join("restore.in-progress")
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.root.join("backups")
    }

    pub fn blob_path(&self, att: &AttId, idx: u64) -> PathBuf {
        let name = hasp_crypto::to_hex(att.as_bytes());
        let (first, rest) = name.split_at(2);
        let second = rest.get(..2).unwrap_or_default();
        self.blobs_dir()
            .join(first)
            .join(second)
            .join(&name)
            .join(idx.to_string())
    }
}
