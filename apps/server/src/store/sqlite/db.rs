use std::path::Path;
use std::sync::Mutex;

use sqlx::{Connection, SqliteConnection};
use tokio::runtime::{Builder, Runtime};

use super::blobs::{Blobs, Undo};
use super::migrate;
use crate::persist::{DataLayout, PersistError, create_dir_durable};
use crate::store::{ServerError, StoreResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Full,
    Relaxed,
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(super) conn: SqliteConnection,
    pub(super) undo: Option<Vec<Undo>>,
}

#[derive(Debug)]
pub(crate) struct Db {
    rt: Option<Runtime>,
    inner: Mutex<Option<Inner>>,
    pub(super) blobs: Blobs,
}

impl From<sqlx::Error> for ServerError {
    fn from(_: sqlx::Error) -> Self {
        Self::Store
    }
}

impl From<std::io::Error> for ServerError {
    fn from(_: std::io::Error) -> Self {
        Self::Store
    }
}

pub(crate) async fn vacuum_into(
    conn: &mut SqliteConnection,
    target: &Path,
) -> Result<(), PersistError> {
    if let Some(parent) = target.parent() {
        create_dir_durable(parent)?;
    }
    let path = target
        .to_str()
        .ok_or(PersistError::Corrupt("non-utf8 path"))?;
    sqlx::query!("VACUUM INTO ?", path)
        .execute(&mut *conn)
        .await?;
    crate::persist::restrict(target)?;
    Ok(())
}

impl Db {
    pub(super) fn open(layout: &DataLayout, durability: Durability) -> Result<Self, PersistError> {
        crate::persist::ensure_no_restore_in_progress(layout)?;
        create_dir_durable(layout.root())?;
        crate::persist::restrict(layout.root())?;
        let rt = Builder::new_current_thread().enable_all().build()?;
        let db_path = layout.db_path();
        let backups = layout.backups_dir();
        let conn = rt.block_on(async {
            let mut conn = migrate::connect(&db_path, true, durability).await?;
            migrate::migrate(&mut conn, &backups).await?;
            Ok::<_, PersistError>(conn)
        })?;
        let blobs = Blobs::new(layout.blobs_dir());
        blobs.ensure_root()?;
        Ok(Self {
            rt: Some(rt),
            inner: Mutex::new(Some(Inner { conn, undo: None })),
            blobs,
        })
    }

    /// No instance lock and no migration, so a stale schema is refused.
    pub(super) fn open_shared(layout: &DataLayout) -> Result<Self, PersistError> {
        crate::persist::ensure_no_restore_in_progress(layout)?;
        let rt = Builder::new_current_thread().enable_all().build()?;
        let conn = rt.block_on(async {
            let mut conn = migrate::connect(&layout.db_path(), false, Durability::Full).await?;
            if !migrate::schema_status(&mut conn).await?.is_current() {
                return Err(PersistError::SchemaStale);
            }
            Ok::<_, PersistError>(conn)
        })?;
        Ok(Self {
            rt: Some(rt),
            inner: Mutex::new(Some(Inner { conn, undo: None })),
            blobs: Blobs::new(layout.blobs_dir()),
        })
    }

    pub(super) fn exec<T>(
        &self,
        f: impl AsyncFnOnce(&mut Inner) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let rt = self.rt.as_ref().ok_or(ServerError::Store)?;
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let inner = guard.as_mut().ok_or(ServerError::Store)?;
        rt.block_on(f(inner))
    }

    pub(super) fn begin(&self) -> StoreResult<()> {
        self.exec(async |inner| {
            if inner.undo.is_some() {
                return Err(ServerError::Store);
            }
            sqlx::query!("BEGIN IMMEDIATE")
                .execute(&mut inner.conn)
                .await?;
            inner.undo = Some(Vec::new());
            Ok(())
        })
    }

    pub(super) fn commit(&self) -> StoreResult<()> {
        self.exec(async |inner| {
            if inner.undo.is_none() {
                return Ok(());
            }
            sqlx::query!("COMMIT").execute(&mut inner.conn).await?;
            inner.undo = None;
            Ok(())
        })
    }

    pub(super) fn rollback(&self) -> StoreResult<()> {
        self.exec(async |inner| {
            let Some(undo) = inner.undo.take() else {
                return Ok(());
            };
            sqlx::query!("ROLLBACK").execute(&mut inner.conn).await?;
            for entry in undo.into_iter().rev() {
                Blobs::undo(entry)?;
            }
            Ok(())
        })
    }

    pub(super) fn sweep_blobs(&self) -> Result<Option<usize>, PersistError> {
        super::tables::attachment::sweep_blobs(self)
    }

    pub(super) fn runtime(&self) -> Result<&Runtime, PersistError> {
        self.rt
            .as_ref()
            .ok_or(PersistError::Corrupt("store closed"))
    }

    pub(super) fn with_inner<T>(
        &self,
        f: impl AsyncFnOnce(&mut Inner) -> Result<T, PersistError>,
    ) -> Result<T, PersistError> {
        let rt = self.runtime()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PersistError::Corrupt("store poisoned"))?;
        let inner = guard
            .as_mut()
            .ok_or(PersistError::Corrupt("store closed"))?;
        rt.block_on(f(inner))
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        let Some(rt) = self.rt.take() else {
            return;
        };
        let inner = self.inner.get_mut().ok().and_then(Option::take);
        if let Some(inner) = inner {
            let closed = std::thread::scope(|scope| {
                scope
                    .spawn(|| rt.block_on(inner.conn.close()))
                    .join()
                    .is_ok_and(|result| result.is_ok())
            });
            if !closed {
                tracing::warn!("closing the database connection failed");
            }
        }
        rt.shutdown_background();
    }
}
