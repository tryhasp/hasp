mod cache;
mod file;
mod memory;

pub use cache::{
    AccountLocal, Cache, Event, EventKind, Head, LocalVaultStatus, Marks, PendingKind, PendingOp,
    PendingRepair, QuarantineInfo, Records, UnlockClass, VaultLocal,
};
pub use file::FileStore;
pub use memory::MemoryStore;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io")]
    Io,
    #[error("the store is damaged: {0}")]
    Corrupt(&'static str),
    #[error("a stored record does not decode")]
    Record,
    #[error("another process holds the store; retry shortly")]
    Locked,
    #[error("the write would move a vault head backwards")]
    Stale,
}

pub type Entry = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    DeletePrefix(Vec<u8>),
    DeleteIf(Vec<u8>, Vec<u8>),
}

/// Writes that become visible together or not at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    ops: Vec<BatchOp>,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(BatchOp::Put(key, value));
    }

    pub fn delete(&mut self, key: Vec<u8>) {
        self.ops.push(BatchOp::Delete(key));
    }

    /// Deletes the key only when it still holds exactly `expected`.
    pub fn delete_if(&mut self, key: Vec<u8>, expected: Vec<u8>) {
        self.ops.push(BatchOp::DeleteIf(key, expected));
    }

    pub fn delete_prefix(&mut self, prefix: Vec<u8>) {
        self.ops.push(BatchOp::DeletePrefix(prefix));
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn ops(&self) -> &[BatchOp] {
        &self.ops
    }

    pub fn extend(&mut self, other: Self) {
        self.ops.extend(other.ops);
    }
}

/// The device-local store. It holds ciphertext as received plus verified state:
/// nothing in it opens without keys the store never sees.
pub trait Store: Send {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StoreError>;
    fn apply(&mut self, batch: &Batch) -> Result<(), StoreError>;
}

pub(crate) fn apply_to_map(map: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>, batch: &Batch) {
    for op in batch.ops() {
        match op {
            BatchOp::Put(key, value) => {
                map.insert(key.clone(), value.clone());
            }
            BatchOp::Delete(key) => {
                map.remove(key);
            }
            BatchOp::DeleteIf(key, expected) => {
                if map.get(key) == Some(expected) {
                    map.remove(key);
                }
            }
            BatchOp::DeletePrefix(prefix) => {
                let doomed: Vec<Vec<u8>> = map
                    .range(prefix.clone()..)
                    .take_while(|(key, _)| key.starts_with(prefix))
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in doomed {
                    map.remove(&key);
                }
            }
        }
    }
}

pub(crate) fn scan_map(
    map: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    prefix: &[u8],
) -> Vec<Entry> {
    map.range(prefix.to_vec()..)
        .take_while(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
