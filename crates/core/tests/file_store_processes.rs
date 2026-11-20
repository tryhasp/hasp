use std::path::PathBuf;
use std::process::Command;

use hasp_core::store::{Batch, FileStore, Store};

const CHILD_DIR: &str = "HASP_FILESTORE_CHILD_DIR";
const CHILD_NAME: &str = "HASP_FILESTORE_CHILD_NAME";
const WRITES: usize = 150;
const VALUE: usize = 24 * 1024;

fn shared_dir() -> PathBuf {
    std::env::temp_dir().join(format!("hasp-filestore-processes-{}", std::process::id()))
}

#[test]
fn child_writer() {
    let (Ok(dir), Ok(name)) = (std::env::var(CHILD_DIR), std::env::var(CHILD_NAME)) else {
        return;
    };
    let mut store = FileStore::open(&PathBuf::from(dir)).unwrap();
    for n in 0..WRITES {
        let mut batch = Batch::new();
        batch.put(format!("{name}/{n:04}").into_bytes(), vec![7_u8; VALUE]);
        store.apply(&batch).unwrap();
        let other = if name == "a" { "b" } else { "a" };
        store.scan(format!("{other}/").as_bytes()).unwrap();
    }
}

#[test]
fn two_processes_writing_one_directory_lose_nothing_across_compaction() {
    let dir = shared_dir();
    drop(FileStore::open(&dir).unwrap());
    let exe = std::env::current_exe().unwrap();
    let spawn = |name: &str| {
        Command::new(&exe)
            .args(["child_writer", "--exact", "--nocapture"])
            .env(CHILD_DIR, &dir)
            .env(CHILD_NAME, name)
            .spawn()
            .unwrap()
    };
    let mut first = spawn("a");
    let mut second = spawn("b");
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());

    let store = FileStore::open(&dir).unwrap();
    for name in ["a", "b"] {
        let found = store.scan(format!("{name}/").as_bytes()).unwrap();
        assert_eq!(found.len(), WRITES, "writer {name} lost records");
        assert!(found.iter().all(|(_, value)| value.len() == VALUE));
    }
    assert!(
        std::fs::metadata(dir.join("snapshot")).is_ok(),
        "the run was meant to cross a compaction"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
