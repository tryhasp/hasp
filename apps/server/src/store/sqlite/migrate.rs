use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::{Migrate, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{ConnectOptions, SqliteConnection};

use super::db::Durability;
use crate::persist::PersistError;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaStatus {
    pub applied: Option<i64>,
    pub latest: i64,
}

impl SchemaStatus {
    pub fn is_current(&self) -> bool {
        self.applied == Some(self.latest)
    }

    pub fn is_newer(&self) -> bool {
        self.applied.is_some_and(|applied| applied > self.latest)
    }
}

pub(crate) fn latest() -> i64 {
    MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0)
}

pub(crate) async fn connect(
    path: &Path,
    create: bool,
    durability: Durability,
) -> Result<SqliteConnection, PersistError> {
    let synchronous = match durability {
        Durability::Full => SqliteSynchronous::Full,
        Durability::Relaxed => SqliteSynchronous::Off,
    };
    let options = SqliteConnectOptions::from_str("sqlite://")?
        .filename(path)
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(synchronous)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .log_statements(tracing::log::LevelFilter::Off);
    let conn = options.connect().await?;
    if create {
        crate::persist::restrict_database(path)?;
    }
    Ok(conn)
}

pub(crate) async fn connect_read_only(path: &Path) -> Result<SqliteConnection, PersistError> {
    let options = SqliteConnectOptions::from_str("sqlite://")?
        .filename(path)
        .read_only(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .log_statements(tracing::log::LevelFilter::Off);
    Ok(options.connect().await?)
}

pub(crate) async fn schema_status(
    conn: &mut SqliteConnection,
) -> Result<SchemaStatus, PersistError> {
    conn.ensure_migrations_table(&MIGRATOR.table_name).await?;
    if let Some(version) = conn.dirty_version(&MIGRATOR.table_name).await? {
        return Err(PersistError::Migrate(sqlx::migrate::MigrateError::Dirty(
            version,
        )));
    }
    let applied = conn
        .list_applied_migrations(&MIGRATOR.table_name)
        .await?
        .iter()
        .map(|m| m.version)
        .max();
    Ok(SchemaStatus {
        applied,
        latest: latest(),
    })
}

pub(crate) async fn migrate(
    conn: &mut SqliteConnection,
    backup_dir: &Path,
) -> Result<SchemaStatus, PersistError> {
    let status = schema_status(conn).await?;
    if status.is_newer() {
        return Err(PersistError::SchemaNewer {
            found: status.applied.unwrap_or(0),
            supported: status.latest,
        });
    }
    if status.is_current() {
        return Ok(status);
    }
    if let Some(from) = status.applied {
        let target = backup_dir.join(format!("pre-migrate-v{from}-to-v{}.sqlite3", status.latest));
        super::db::vacuum_into(conn, &target).await?;
    }
    MIGRATOR.run(&mut *conn).await?;
    schema_status(conn).await
}
