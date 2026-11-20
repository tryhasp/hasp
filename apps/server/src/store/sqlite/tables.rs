use std::sync::Arc;

use super::db::Db;

macro_rules! sql_table {
    (
        $name:ident, $key:ty, $value:ty;
        table $table:literal;
        cols $cols:literal;
        key_eq $key_eq:literal;
        key_row $key_row:literal;
        key_holes $key_holes:literal;
        order $order:literal;
        order_desc $order_desc:literal;
        holes $holes:literal;
        conflict $conflict:literal;
        key($k:ident) [$($key_arg:expr),+ $(,)?];
        value($v:ident) [$($val_arg:expr),* $(,)?];
        decode($r:ident) $decode:expr;
    ) => {
        #[derive(Debug)]
        pub(in crate::store::sqlite) struct $name {
            db: Arc<Db>,
        }

        impl $name {
            pub(super) fn new(db: &Arc<Db>) -> Self {
                Self { db: Arc::clone(db) }
            }
        }

        impl Table<$key, $value> for $name {
            fn get(&self, key: &$key) -> StoreResult<Option<$value>> {
                self.db.exec(async |tx| {
                    let row = sqlx::query!(
                        "SELECT " + $cols + " FROM " + $table + " WHERE " + $key_eq,
                        $({ let $k = key; $key_arg }),+
                    )
                    .fetch_optional(&mut tx.conn)
                    .await?;
                    let decoded = row
                        .map(|$r| -> StoreResult<($key, $value)> { $decode })
                        .transpose()?;
                    Ok(decoded.map(|(_, value)| value))
                })
            }

            fn put(&mut self, key: $key, value: $value) -> StoreResult<()> {
                let (key, value) = (&key, &value);
                let _ = &value;
                self.db.exec(async |tx| {
                    sqlx::query!(
                        "INSERT INTO " + $table + " (" + $cols + ") VALUES (" + $holes + ") " + $conflict,
                        $({ let $k = key; $key_arg },)+
                        $({ let $v = value; $val_arg },)*
                    )
                    .execute(&mut tx.conn)
                    .await?;
                    Ok(())
                })
            }

            fn remove(&mut self, key: &$key) -> StoreResult<Option<$value>> {
                self.db.exec(async |tx| {
                    let row = sqlx::query!(
                        "DELETE FROM " + $table + " WHERE " + $key_eq + " RETURNING " + $cols,
                        $({ let $k = key; $key_arg }),+
                    )
                    .fetch_optional(&mut tx.conn)
                    .await?;
                    let decoded = row
                        .map(|$r| -> StoreResult<($key, $value)> { $decode })
                        .transpose()?;
                    Ok(decoded.map(|(_, value)| value))
                })
            }

            fn range(&self, from: &$key, to: &$key) -> StoreResult<Vec<($key, $value)>> {
                if from > to {
                    return Ok(Vec::new());
                }
                self.db.exec(async |tx| {
                    let rows = sqlx::query!(
                        "SELECT " + $cols + " FROM " + $table + " WHERE " + $key_row + " >= " + $key_holes
                            + " AND " + $key_row + " <= " + $key_holes + " ORDER BY " + $order,
                        $({ let $k = from; $key_arg },)+
                        $({ let $k = to; $key_arg }),+
                    )
                    .fetch_all(&mut tx.conn)
                    .await?;
                    rows.into_iter()
                        .map(|$r| -> StoreResult<($key, $value)> { $decode })
                        .collect()
                })
            }

            fn last_in(&self, from: &$key, to: &$key) -> StoreResult<Option<($key, $value)>> {
                if from > to {
                    return Ok(None);
                }
                self.db.exec(async |tx| {
                    let row = sqlx::query!(
                        "SELECT " + $cols + " FROM " + $table + " WHERE " + $key_row + " >= " + $key_holes
                            + " AND " + $key_row + " <= " + $key_holes + " ORDER BY " + $order_desc + " LIMIT 1",
                        $({ let $k = from; $key_arg },)+
                        $({ let $k = to; $key_arg }),+
                    )
                    .fetch_optional(&mut tx.conn)
                    .await?;
                    row.map(|$r| -> StoreResult<($key, $value)> { $decode })
                        .transpose()
                })
            }

            fn len(&self) -> StoreResult<usize> {
                self.db.exec(async |tx| {
                    let row = sqlx::query!("SELECT COUNT(*) AS \"n!: i64\" FROM " + $table)
                        .fetch_one(&mut tx.conn)
                        .await?;
                    usize::try_from(row.n).map_err(|_| ServerError::Store)
                })
            }
        }
    };
}

pub(super) mod account;
pub(super) mod attachment;
mod vault;

use account::{
    AccountRecordsTable, AccountsTable, EnrolChannelsTable, KeysetsTable, LoginsTable,
    NoticesTable, OpaqueRecordsTable, RecoveryEnrolmentsTable, RecoverySessionsTable,
    SessionTokensTable, SessionsTable, SignupTokensTable,
};
use attachment::{AttachmentsTable, ChunksTable};
use vault::{
    CommitLogTable, InvitesTable, ItemsTable, ManifestsTable, MembersTable, MembershipsTable,
    RostersTable, SelfWrapsTable, SharesTable, VaultsTable,
};

#[derive(Debug)]
pub(super) struct Tables {
    pub(super) accounts: AccountsTable,
    pub(super) logins: LoginsTable,
    pub(super) account_records: AccountRecordsTable,
    pub(super) opaque_records: OpaqueRecordsTable,
    pub(super) keysets: KeysetsTable,
    pub(super) signup_tokens: SignupTokensTable,
    pub(super) sessions: SessionsTable,
    pub(super) session_tokens: SessionTokensTable,
    pub(super) enrol_channels: EnrolChannelsTable,
    pub(super) recovery_enrolments: RecoveryEnrolmentsTable,
    pub(super) recovery_sessions: RecoverySessionsTable,
    pub(super) notices: NoticesTable,
    pub(super) vaults: VaultsTable,
    pub(super) rosters: RostersTable,
    pub(super) manifests: ManifestsTable,
    pub(super) members: MembersTable,
    pub(super) memberships: MembershipsTable,
    pub(super) shares: SharesTable,
    pub(super) self_wraps: SelfWrapsTable,
    pub(super) items: ItemsTable,
    pub(super) invites: InvitesTable,
    pub(super) attachments: AttachmentsTable,
    pub(super) attachment_chunks: ChunksTable,
    pub(super) commit_log: CommitLogTable,
}

impl Tables {
    pub(super) fn new(db: &Arc<Db>) -> Self {
        Self {
            accounts: AccountsTable::new(db),
            logins: LoginsTable::new(db),
            account_records: AccountRecordsTable::new(db),
            opaque_records: OpaqueRecordsTable::new(db),
            keysets: KeysetsTable::new(db),
            signup_tokens: SignupTokensTable::new(db),
            sessions: SessionsTable::new(db),
            session_tokens: SessionTokensTable::new(db),
            enrol_channels: EnrolChannelsTable::new(db),
            recovery_enrolments: RecoveryEnrolmentsTable::new(db),
            recovery_sessions: RecoverySessionsTable::new(db),
            notices: NoticesTable::new(db),
            vaults: VaultsTable::new(db),
            rosters: RostersTable::new(db),
            manifests: ManifestsTable::new(db),
            members: MembersTable::new(db),
            memberships: MembershipsTable::new(db),
            shares: SharesTable::new(db),
            self_wraps: SelfWrapsTable::new(db),
            items: ItemsTable::new(db),
            invites: InvitesTable::new(db),
            attachments: AttachmentsTable::new(db),
            attachment_chunks: ChunksTable::new(db),
            commit_log: CommitLogTable::new(db),
        }
    }
}
