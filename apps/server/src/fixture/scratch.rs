use std::path::{Path, PathBuf};

use crate::persist::DataLayout;
use crate::{Durability, SqliteStore};

use super::TestStore;

#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Self {
        let id = hasp_crypto::to_hex(&hasp_crypto::random_array::<8>().expect("os randomness"));
        let path = std::env::temp_dir().join(format!("hasp-scratch-{id}"));
        std::fs::create_dir_all(&path).expect("scratch dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

impl TestStore for SqliteStore {
    fn fresh() -> (Self, Box<dyn std::any::Any + Send>) {
        let scratch = Scratch::new();
        let layout = DataLayout::new(scratch.path());
        let store = Self::open_with(&layout, Durability::Relaxed).expect("sqlite store");
        (store, Box::new(scratch))
    }
}
