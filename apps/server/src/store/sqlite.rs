mod blobs;
mod codec;
mod db;
mod migrate;
mod tables;

use std::sync::Arc;

use crate::persist::{DataLayout, PersistError};

use hasp_proto::wire::{RecoveryId, SessionId};
use hasp_proto::{
    AccountId, AccountRecord, AttId, Epoch, Esid, Hash32, InviteId, Keyset, Rver, SealedRaw, Seq,
    Signed, VaultId,
};

use crate::store::{
    AccountRow, AttachmentRow, EnrolRow, InviteRow, ItemKey, ItemRow, ManifestRow, MemberRow,
    NoticeRow, OpaqueRow, RecoveryRow, RecoverySessionRow, RosterRow, SessionRow, ShareRow, Store,
    StoreResult, Table, TokenRow, VaultRow,
};

pub(crate) use db::Db;
pub use db::Durability;
pub(crate) use db::vacuum_into;
pub use migrate::SchemaStatus;
pub(crate) use migrate::latest as latest_schema;
pub(crate) use migrate::{connect, connect_read_only, schema_status};

#[derive(Debug)]
pub struct SqliteStore {
    tables: tables::Tables,
    db: Arc<Db>,
    _instance: Option<InstanceLock>,
}

/// Exclusive lock on `haspd.lock`: one server per data directory, and no restore while it runs.
#[derive(Debug)]
pub(crate) struct InstanceLock(
    #[expect(dead_code, reason = "held for the lock it owns")] std::fs::File,
);

impl InstanceLock {
    pub(crate) fn acquire(layout: &DataLayout) -> Result<Self, PersistError> {
        crate::persist::create_dir_durable(layout.root())?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(layout.root().join("haspd.lock"))?;
        match file.try_lock() {
            Ok(()) => Ok(Self(file)),
            Err(std::fs::TryLockError::WouldBlock) => Err(PersistError::Busy),
            Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

impl SqliteStore {
    /// Refuses a schema newer than this binary; on an older one takes a `VACUUM INTO` copy
    /// first. Blocks, so an async caller uses `spawn_blocking`.
    pub fn open(layout: &DataLayout) -> Result<Self, PersistError> {
        Self::open_with(layout, Durability::Full)
    }

    pub fn open_with(layout: &DataLayout, durability: Durability) -> Result<Self, PersistError> {
        let instance = InstanceLock::acquire(layout)?;
        let db = Arc::new(Db::open(layout, durability)?);
        Ok(Self {
            tables: tables::Tables::new(&db),
            db,
            _instance: Some(instance),
        })
    }

    /// Opens the database of a running server for an operator command. Takes no instance lock
    /// and never migrates; the server and this store serialise on SQLite's write lock.
    pub fn open_shared(layout: &DataLayout) -> Result<Self, PersistError> {
        let db = Arc::new(Db::open_shared(layout)?);
        Ok(Self {
            tables: tables::Tables::new(&db),
            db,
            _instance: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_unlocked(layout: &DataLayout) -> Result<Self, PersistError> {
        let db = Arc::new(Db::open(layout, Durability::Full)?);
        Ok(Self {
            tables: tables::Tables::new(&db),
            db,
            _instance: None,
        })
    }

    /// Deletes attachment chunk files that no row references. Returns `None` when a backup holds
    /// the blob lock; the caller retries on its next sweep. Must not run inside a transaction.
    pub fn sweep_blobs(&mut self) -> Result<Option<usize>, PersistError> {
        self.db.sweep_blobs()
    }
}

macro_rules! accessor {
    ($name:ident, $key:ty, $value:ty) => {
        fn $name(&mut self) -> &mut dyn Table<$key, $value> {
            &mut self.tables.$name
        }
    };
}

impl Store for SqliteStore {
    fn begin(&mut self) -> StoreResult<()> {
        self.db.begin()
    }

    fn commit(&mut self) -> StoreResult<()> {
        self.db.commit()
    }

    fn rollback(&mut self) -> StoreResult<()> {
        self.db.rollback()
    }

    accessor!(accounts, AccountId, AccountRow);
    accessor!(logins, String, AccountId);
    accessor!(account_records, (AccountId, Seq), Signed<AccountRecord>);
    accessor!(opaque_records, AccountId, OpaqueRow);
    accessor!(keysets, AccountId, Keyset);
    accessor!(signup_tokens, Hash32, TokenRow);
    accessor!(sessions, SessionId, SessionRow);
    accessor!(session_tokens, Hash32, SessionId);
    accessor!(enrol_channels, Esid, EnrolRow);
    accessor!(recovery_enrolments, (AccountId, u64), RecoveryRow);
    accessor!(recovery_sessions, RecoveryId, RecoverySessionRow);
    accessor!(notices, (AccountId, u64), NoticeRow);
    accessor!(vaults, VaultId, VaultRow);
    accessor!(rosters, (VaultId, Rver), RosterRow);
    accessor!(manifests, (VaultId, Seq), ManifestRow);
    accessor!(members, (VaultId, AccountId), MemberRow);
    accessor!(memberships, (AccountId, VaultId), ());
    accessor!(shares, (VaultId, Epoch, AccountId), ShareRow);
    accessor!(self_wraps, (AccountId, VaultId, Epoch), SealedRaw);
    accessor!(items, ItemKey, ItemRow);
    accessor!(invites, InviteId, InviteRow);
    accessor!(attachments, AttId, AttachmentRow);
    accessor!(attachment_chunks, (AttId, u64), Arc<Vec<u8>>);
    accessor!(commit_log, (VaultId, Seq), Hash32);

    fn sessions_of(&mut self, account: &AccountId) -> StoreResult<Vec<(SessionId, SessionRow)>> {
        self.tables.sessions.of_account(account)
    }

    fn recovery_sessions_of(
        &mut self,
        account: &AccountId,
    ) -> StoreResult<Vec<(RecoveryId, RecoverySessionRow)>> {
        self.tables.recovery_sessions.of_account(account)
    }
}
