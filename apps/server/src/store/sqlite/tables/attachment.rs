use std::sync::Arc;

use hasp_proto::{AttId, VaultId};

use crate::persist::PersistError;
use crate::store::sqlite::blobs::Blobs;
use crate::store::sqlite::codec::{
    array, attachment_state, attachment_state_code, int, key_int, uint,
};
use crate::store::sqlite::db::Db;
use crate::store::{AttachmentRow, ServerError, StoreResult, Table};

sql_table! {
    AttachmentsTable, AttId, AttachmentRow;
    table "attachments";
    cols "att_id, vault_id, size, chunks, state, created, refs";
    key_eq "att_id = ?";
    key_row "(att_id)";
    key_holes "(?)";
    order "att_id";
    order_desc "att_id DESC";
    holes "?, ?, ?, ?, ?, ?, ?";
    conflict "ON CONFLICT (att_id) DO UPDATE SET vault_id = excluded.vault_id, size = excluded.size, chunks = excluded.chunks, state = excluded.state, created = excluded.created, refs = excluded.refs";
    key(k) [k.as_bytes().as_slice()];
    value(v) [
        v.vault_id.as_bytes().as_slice(),
        int(v.size)?,
        int(v.chunks)?,
        attachment_state_code(v.state),
        int(v.created)?,
        int(v.refs)?,
    ];
    decode(r) {
        Ok((AttId::from_bytes(array(&r.att_id)?), AttachmentRow {
            vault_id: VaultId::from_bytes(array(&r.vault_id)?),
            size: uint(r.size)?,
            chunks: uint(r.chunks)?,
            state: attachment_state(r.state)?,
            created: uint(r.created)?,
            refs: uint(r.refs)?,
        }))
    };
}

#[derive(Debug)]
pub(in crate::store::sqlite) struct ChunksTable {
    db: Arc<Db>,
}

impl ChunksTable {
    pub(super) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    fn load(&self, att: &AttId, idx: u64, len: i64, digest: &[u8]) -> StoreResult<Arc<Vec<u8>>> {
        let bytes = self.db.blobs.read(att, idx)?;
        let intact = i64::try_from(bytes.len()).is_ok_and(|n| n == len)
            && Blobs::digest(&bytes).as_slice() == digest;
        if !intact {
            return Err(ServerError::Store);
        }
        Ok(Arc::new(bytes))
    }
}

impl Table<(AttId, u64), Arc<Vec<u8>>> for ChunksTable {
    fn get(&self, key: &(AttId, u64)) -> StoreResult<Option<Arc<Vec<u8>>>> {
        let (att, idx) = key;
        let row = self.db.exec(async |tx| {
            Ok(sqlx::query!(
                "SELECT len, digest FROM attachment_chunks WHERE att_id = ? AND idx = ?",
                att.as_bytes().as_slice(),
                key_int(*idx)
            )
            .fetch_optional(&mut tx.conn)
            .await?)
        })?;
        row.map(|row| self.load(att, *idx, row.len, &row.digest))
            .transpose()
    }

    fn put(&mut self, key: (AttId, u64), value: Arc<Vec<u8>>) -> StoreResult<()> {
        let (att, idx) = key;
        let len = int(u64::try_from(value.len()).map_err(|_| ServerError::Store)?)?;
        let digest = Blobs::digest(&value);
        self.db.exec(async |tx| {
            let undo = self.db.blobs.write(&att, idx, &value)?;
            if let Some(log) = tx.undo.as_mut() {
                log.push(undo);
            }
            sqlx::query!(
                "INSERT INTO attachment_chunks (att_id, idx, len, digest) VALUES (?, ?, ?, ?) ON CONFLICT (att_id, idx) DO UPDATE SET len = excluded.len, digest = excluded.digest",
                att.as_bytes().as_slice(),
                key_int(idx),
                len,
                digest.as_slice()
            )
            .execute(&mut tx.conn)
            .await?;
            Ok(())
        })
    }

    fn remove(&mut self, key: &(AttId, u64)) -> StoreResult<Option<Arc<Vec<u8>>>> {
        let (att, idx) = key;
        let row = self.db.exec(async |tx| {
            Ok(sqlx::query!(
                "DELETE FROM attachment_chunks WHERE att_id = ? AND idx = ? RETURNING len, digest",
                att.as_bytes().as_slice(),
                key_int(*idx)
            )
            .fetch_optional(&mut tx.conn)
            .await?)
        })?;
        row.map(|row| self.load(att, *idx, row.len, &row.digest))
            .transpose()
    }

    fn range(
        &self,
        from: &(AttId, u64),
        to: &(AttId, u64),
    ) -> StoreResult<Vec<((AttId, u64), Arc<Vec<u8>>)>> {
        if from > to {
            return Ok(Vec::new());
        }
        let rows = self.db.exec(async |tx| {
            Ok(sqlx::query!(
                "SELECT att_id, idx, len, digest FROM attachment_chunks WHERE (att_id, idx) >= (?, ?) AND (att_id, idx) <= (?, ?) ORDER BY att_id, idx",
                from.0.as_bytes().as_slice(),
                key_int(from.1),
                to.0.as_bytes().as_slice(),
                key_int(to.1)
            )
            .fetch_all(&mut tx.conn)
            .await?)
        })?;
        rows.into_iter()
            .map(|row| {
                let att = AttId::from_bytes(array(&row.att_id)?);
                let idx = uint(row.idx)?;
                Ok(((att, idx), self.load(&att, idx, row.len, &row.digest)?))
            })
            .collect()
    }

    fn last_in(
        &self,
        from: &(AttId, u64),
        to: &(AttId, u64),
    ) -> StoreResult<Option<((AttId, u64), Arc<Vec<u8>>)>> {
        if from > to {
            return Ok(None);
        }
        let row = self.db.exec(async |tx| {
            Ok(sqlx::query!(
                "SELECT att_id, idx, len, digest FROM attachment_chunks WHERE (att_id, idx) >= (?, ?) AND (att_id, idx) <= (?, ?) ORDER BY att_id DESC, idx DESC LIMIT 1",
                from.0.as_bytes().as_slice(),
                key_int(from.1),
                to.0.as_bytes().as_slice(),
                key_int(to.1)
            )
            .fetch_optional(&mut tx.conn)
            .await?)
        })?;
        row.map(|row| {
            let att = AttId::from_bytes(array(&row.att_id)?);
            let idx = uint(row.idx)?;
            Ok(((att, idx), self.load(&att, idx, row.len, &row.digest)?))
        })
        .transpose()
    }

    fn len(&self) -> StoreResult<usize> {
        self.db.exec(async |tx| {
            let row = sqlx::query!("SELECT COUNT(*) AS \"n!: i64\" FROM attachment_chunks")
                .fetch_one(&mut tx.conn)
                .await?;
            usize::try_from(row.n).map_err(|_| ServerError::Store)
        })
    }
}

pub(in crate::store::sqlite) fn sweep_blobs(db: &Db) -> Result<Option<usize>, PersistError> {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(db.blobs.root().join(".lock"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let removed = db.with_inner(async |inner| {
        if inner.undo.is_some() {
            return Err(PersistError::Busy);
        }
        sqlx::query!("BEGIN IMMEDIATE")
            .execute(&mut inner.conn)
            .await?;
        let outcome = remove_orphans(db, &mut inner.conn).await;
        if outcome.is_ok() {
            sqlx::query!("COMMIT").execute(&mut inner.conn).await?;
        } else {
            sqlx::query!("ROLLBACK").execute(&mut inner.conn).await?;
        }
        outcome
    });
    drop(lock);
    removed.map(Some)
}

async fn remove_orphans(db: &Db, conn: &mut sqlx::SqliteConnection) -> Result<usize, PersistError> {
    let rows = sqlx::query!("SELECT att_id, idx FROM attachment_chunks")
        .fetch_all(&mut *conn)
        .await?;
    let mut live = std::collections::BTreeSet::new();
    for row in rows {
        let att = AttId::from_bytes(
            array(&row.att_id).map_err(|_| PersistError::Corrupt("attachment id"))?,
        );
        let idx = uint(row.idx).map_err(|_| PersistError::Corrupt("chunk index"))?;
        live.insert((att, idx));
    }
    let mut removed = 0_usize;
    for (att, idx, path) in db.blobs.files()? {
        if idx.is_some_and(|idx| live.contains(&(att, idx))) {
            continue;
        }
        std::fs::remove_file(&path)?;
        removed = removed.saturating_add(1);
    }
    db.blobs.prune_empty_dirs()?;
    Ok(removed)
}
