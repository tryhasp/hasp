use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use hasp_core::platform::{Biometric, PlatformError, SecureStore};
use hasp_core::store::{Batch, BatchOp, Entry, Store, StoreError};
use hasp_crypto::SecretBytes;

type Map = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Debug, thiserror::Error)]
#[error("the snapshot is damaged")]
pub struct SnapshotError;

/// The device store of a host that has no file system (the extension service worker): the
/// whole map is exported as ciphertext and restored after the worker is evicted.
#[derive(Clone, Debug, Default)]
pub struct SnapshotStore {
    map: Arc<Mutex<Map>>,
    revision: Arc<AtomicU64>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, SnapshotError> {
        let store = Self::new();
        let mut rest = bytes;
        let mut map = Map::new();
        let count = take_len(&mut rest)?;
        for _ in 0..count {
            let key = take_bytes(&mut rest)?;
            let value = take_bytes(&mut rest)?;
            map.insert(key, value);
        }
        if !rest.is_empty() {
            return Err(SnapshotError);
        }
        *store.map.lock().unwrap_or_else(PoisonError::into_inner) = map;
        Ok(store)
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    pub fn export(&self) -> Vec<u8> {
        let map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = Vec::new();
        put_len(&mut out, map.len());
        for (key, value) in map.iter() {
            put_len(&mut out, key.len());
            out.extend_from_slice(key);
            put_len(&mut out, value.len());
            out.extend_from_slice(value);
        }
        out
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
}

fn take_len(rest: &mut &[u8]) -> Result<usize, SnapshotError> {
    let (head, tail) = rest.split_at_checked(4).ok_or(SnapshotError)?;
    let head: [u8; 4] = head.try_into().map_err(|_| SnapshotError)?;
    *rest = tail;
    usize::try_from(u32::from_be_bytes(head)).map_err(|_| SnapshotError)
}

fn take_bytes(rest: &mut &[u8]) -> Result<Vec<u8>, SnapshotError> {
    let len = take_len(rest)?;
    let (head, tail) = rest.split_at_checked(len).ok_or(SnapshotError)?;
    *rest = tail;
    Ok(head.to_vec())
}

impl Store for SnapshotStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned())
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StoreError> {
        let map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(map
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), StoreError> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
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
                    map.retain(|key, _| !key.starts_with(prefix));
                }
            }
        }
        self.revision.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

/// Holds secrets in memory for one session: the password-only device class has no hardware gate.
#[derive(Debug, Default)]
pub struct SoftSecureStore {
    items: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl SecureStore for SoftSecureStore {
    fn hardware_gated(&self) -> bool {
        false
    }

    fn put(&self, label: &str, secret: &[u8]) -> Result<(), PlatformError> {
        self.items
            .lock()
            .map_err(|_| PlatformError::Store)?
            .insert(label.to_owned(), secret.to_vec());
        Ok(())
    }

    fn get(&self, label: &str) -> Result<SecretBytes, PlatformError> {
        self.items
            .lock()
            .map_err(|_| PlatformError::Store)?
            .get(label)
            .cloned()
            .map(SecretBytes::from_vec)
            .ok_or(PlatformError::Missing)
    }

    fn delete(&self, label: &str) -> Result<(), PlatformError> {
        self.items
            .lock()
            .map_err(|_| PlatformError::Store)?
            .remove(label);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NoBiometric;

impl Biometric for NoBiometric {
    fn available(&self) -> bool {
        false
    }

    fn authenticate(&self, _reason: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_round_trips_and_counts_writes() {
        let mut store = SnapshotStore::new();
        let mut batch = Batch::new();
        batch.put(b"a/1".to_vec(), b"one".to_vec());
        batch.put(b"a/2".to_vec(), b"two".to_vec());
        batch.put(b"b/1".to_vec(), b"three".to_vec());
        store.apply(&batch).unwrap();
        assert_eq!(store.revision(), 1);
        let restored = SnapshotStore::restore(&store.export()).unwrap();
        assert_eq!(restored.get(b"a/2").unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(restored.scan(b"a/").unwrap().len(), 2);
        let mut wipe = Batch::new();
        wipe.delete_prefix(b"a/".to_vec());
        let mut restored = restored;
        restored.apply(&wipe).unwrap();
        assert_eq!(restored.scan(b"").unwrap().len(), 1);
    }

    #[test]
    fn a_damaged_snapshot_is_refused() {
        let store = SnapshotStore::new();
        let mut bytes = store.export();
        bytes.push(1);
        assert!(SnapshotStore::restore(&bytes).is_err());
        assert!(SnapshotStore::restore(&[0, 0, 0, 1]).is_err());
    }
}
