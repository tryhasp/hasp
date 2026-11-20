use std::collections::BTreeMap;

use super::{Batch, Entry, Store, StoreError, apply_to_map, scan_map};

#[derive(Debug, Default)]
pub struct MemoryStore {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.map.get(key).cloned())
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StoreError> {
        Ok(scan_map(&self.map, prefix))
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), StoreError> {
        apply_to_map(&mut self.map, batch);
        Ok(())
    }
}
