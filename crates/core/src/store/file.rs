use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use hasp_crypto::sha256;

use super::{Batch, BatchOp, Entry, Store, StoreError, apply_to_map, scan_map};

const SNAPSHOT: &str = "snapshot";
const SNAPSHOT_TMP: &str = "snapshot.tmp";
const LOG: &str = "log";
const LOCK: &str = "lock";
const MAGIC: &[u8; 8] = b"HASPST01";
const HASH_LEN: usize = 32;
const COMPACT_AT: u64 = 4 << 20;
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
const OP_DELETE_PREFIX: u8 = 3;
const OP_DELETE_IF: u8 = 4;
const MAX_RECORD: usize = 64 << 20;
const LOCK_WAIT: Duration = Duration::from_secs(2);
const LOCK_POLL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
enum Hold {
    Shared,
    Exclusive,
}

#[expect(
    clippy::disallowed_methods,
    reason = "the store is synchronous and a try-lock poll parks the thread for a few milliseconds"
)]
fn acquire(lock: &File, hold: Hold, wait: Duration) -> Result<(), StoreError> {
    let started = Instant::now();
    loop {
        let attempt = match hold {
            Hold::Shared => lock.try_lock_shared(),
            Hold::Exclusive => lock.try_lock(),
        };
        match attempt {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= wait {
                    return Err(StoreError::Locked);
                }
                std::thread::sleep(LOCK_POLL);
            }
            Err(fs::TryLockError::Error(_)) => return Err(StoreError::Io),
        }
    }
}

// Why: the log replays its valid prefix and drops a torn tail; SQLite is not used because the data is a small key space and a C dependency needs maintainer approval.
// Why: the app and the AutoFill extension open the same directory. A `lock` file serialises writers across processes (exclusive) and reloads (shared); every access first catches up with what another process appended or compacted.
#[derive(Debug)]
pub struct FileStore {
    dir: PathBuf,
    lock: File,
    wait: Duration,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    log: File,
    log_len: u64,
    snapshot: Option<Stamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: u64,
}

impl Stamp {
    fn of(path: &Path) -> Result<Option<Self>, StoreError> {
        match fs::metadata(path) {
            Ok(meta) => Ok(Some(Self {
                len: meta.len(),
                modified: meta.modified().ok(),
                #[cfg(unix)]
                inode: std::os::unix::fs::MetadataExt::ino(&meta),
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StoreError::Io),
        }
    }
}

fn private_dir(dir: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).map_err(|_| StoreError::Io)
}

fn private_file(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    options.mode(0o600);
    options
}

impl FileStore {
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        private_dir(dir)?;
        let lock = private_file(OpenOptions::new().read(true).write(true).create(true))
            .open(dir.join(LOCK))
            .map_err(|_| StoreError::Io)?;
        acquire(&lock, Hold::Exclusive, LOCK_WAIT)?;
        let opened = Self::load(dir);
        let released = lock.unlock();
        let inner = opened?;
        released.map_err(|_| StoreError::Io)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            lock,
            wait: LOCK_WAIT,
            inner: Mutex::new(inner),
        })
    }

    fn load(dir: &Path) -> Result<Inner, StoreError> {
        match fs::remove_file(dir.join(SNAPSHOT_TMP)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
        let log = private_file(OpenOptions::new().read(true).append(true).create(true))
            .open(dir.join(LOG))
            .map_err(|_| StoreError::Io)?;
        let mut inner = Inner {
            map: BTreeMap::new(),
            log,
            log_len: 0,
            snapshot: None,
        };
        inner.reload(dir)?;
        inner.drop_torn_tail()?;
        Ok(inner)
    }

    fn lock_inner(&mut self) -> Result<&mut Inner, StoreError> {
        self.inner.get_mut().map_err(|_| StoreError::Io)
    }

    fn current(&self) -> Result<MutexGuard<'_, Inner>, StoreError> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Io)?;
        if inner.is_current(&self.dir)? {
            return Ok(inner);
        }
        acquire(&self.lock, Hold::Shared, self.wait)?;
        let caught_up = inner.catch_up(&self.dir);
        let released = self.lock.unlock();
        caught_up?;
        released.map_err(|_| StoreError::Io)?;
        Ok(inner)
    }
}

impl Inner {
    fn is_current(&self, dir: &Path) -> Result<bool, StoreError> {
        let size = self.log.metadata().map_err(|_| StoreError::Io)?.len();
        Ok(size == self.log_len && Stamp::of(&dir.join(SNAPSHOT))? == self.snapshot)
    }

    fn reload(&mut self, dir: &Path) -> Result<(), StoreError> {
        self.snapshot = Stamp::of(&dir.join(SNAPSHOT))?;
        self.map = match fs::read(dir.join(SNAPSHOT)) {
            Ok(bytes) => read_snapshot(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err(StoreError::Io),
        };
        self.log_len = 0;
        self.replay_tail()
    }

    fn replay_tail(&mut self) -> Result<(), StoreError> {
        let mut bytes = Vec::new();
        self.log
            .seek(SeekFrom::Start(self.log_len))
            .map_err(|_| StoreError::Io)?;
        self.log
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Io)?;
        let valid = replay(&bytes, &mut self.map);
        let valid = u64::try_from(valid).map_err(|_| StoreError::Corrupt("log length"))?;
        self.log_len = self.log_len.saturating_add(valid);
        Ok(())
    }

    fn catch_up(&mut self, dir: &Path) -> Result<(), StoreError> {
        let size = self.log.metadata().map_err(|_| StoreError::Io)?.len();
        if Stamp::of(&dir.join(SNAPSHOT))? != self.snapshot || size < self.log_len {
            return self.reload(dir);
        }
        if size > self.log_len {
            return self.replay_tail();
        }
        Ok(())
    }

    fn drop_torn_tail(&mut self) -> Result<(), StoreError> {
        let size = self.log.metadata().map_err(|_| StoreError::Io)?.len();
        if size != self.log_len {
            self.log.set_len(self.log_len).map_err(|_| StoreError::Io)?;
            self.log.sync_all().map_err(|_| StoreError::Io)?;
        }
        self.log
            .seek(SeekFrom::End(0))
            .map_err(|_| StoreError::Io)?;
        Ok(())
    }

    fn write(&mut self, dir: &Path, batch: &Batch) -> Result<(), StoreError> {
        self.catch_up(dir)?;
        self.drop_torn_tail()?;
        let payload = encode_batch(batch)?;
        if payload.len() > MAX_RECORD {
            return Err(StoreError::Corrupt("batch too large"));
        }
        let length = u32::try_from(payload.len()).map_err(|_| StoreError::Corrupt("batch"))?;
        let mut record = Vec::with_capacity(payload.len().saturating_add(4 + HASH_LEN));
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(&sha256(&[&payload]));
        record.extend_from_slice(&payload);
        self.log.write_all(&record).map_err(|_| StoreError::Io)?;
        self.log.sync_data().map_err(|_| StoreError::Io)?;
        let written = u64::try_from(record.len()).map_err(|_| StoreError::Corrupt("record"))?;
        self.log_len = self.log_len.saturating_add(written);
        apply_to_map(&mut self.map, batch);
        if self.log_len > COMPACT_AT {
            self.compact(dir)?;
        }
        Ok(())
    }

    fn compact(&mut self, dir: &Path) -> Result<(), StoreError> {
        let tmp = dir.join(SNAPSHOT_TMP);
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        for (key, value) in &self.map {
            push_field(&mut body, key)?;
            push_field(&mut body, value)?;
        }
        let digest = sha256(&[&body]);
        body.extend_from_slice(&digest);
        let mut file = private_file(OpenOptions::new().write(true).create(true).truncate(true))
            .open(&tmp)
            .map_err(|_| StoreError::Io)?;
        file.write_all(&body).map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        fs::rename(&tmp, dir.join(SNAPSHOT)).map_err(|_| StoreError::Io)?;
        sync_dir(dir)?;
        self.log.set_len(0).map_err(|_| StoreError::Io)?;
        self.log.sync_all().map_err(|_| StoreError::Io)?;
        self.log_len = 0;
        self.snapshot = Stamp::of(&dir.join(SNAPSHOT))?;
        Ok(())
    }
}

impl Store for FileStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.current()?.map.get(key).cloned())
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StoreError> {
        Ok(scan_map(&self.current()?.map, prefix))
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), StoreError> {
        if batch.is_empty() {
            return Ok(());
        }
        acquire(&self.lock, Hold::Exclusive, self.wait)?;
        let dir = self.dir.clone();
        let written = self.lock_inner().and_then(|inner| inner.write(&dir, batch));
        let released = self.lock.unlock();
        written?;
        released.map_err(|_| StoreError::Io)
    }
}

fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| StoreError::Io)
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), StoreError> {
    let length = u32::try_from(field.len()).map_err(|_| StoreError::Corrupt("field"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn take_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (length, tail) = rest.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    let field = tail.get(..length)?;
    *rest = tail.get(length..)?;
    Some(field)
}

fn encode_batch(batch: &Batch) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    let count = u32::try_from(batch.ops().len()).map_err(|_| StoreError::Corrupt("batch"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for op in batch.ops() {
        match op {
            BatchOp::Put(key, value) => {
                out.push(OP_PUT);
                push_field(&mut out, key)?;
                push_field(&mut out, value)?;
            }
            BatchOp::Delete(key) => {
                out.push(OP_DELETE);
                push_field(&mut out, key)?;
            }
            BatchOp::DeleteIf(key, expected) => {
                out.push(OP_DELETE_IF);
                push_field(&mut out, key)?;
                push_field(&mut out, expected)?;
            }
            BatchOp::DeletePrefix(prefix) => {
                out.push(OP_DELETE_PREFIX);
                push_field(&mut out, prefix)?;
            }
        }
    }
    Ok(out)
}

fn decode_batch(payload: &[u8]) -> Option<Batch> {
    let (count, mut rest) = payload.split_first_chunk::<4>()?;
    let count = usize::try_from(u32::from_be_bytes(*count)).ok()?;
    let mut batch = Batch::new();
    for _ in 0..count {
        let (tag, tail) = rest.split_first()?;
        rest = tail;
        match *tag {
            OP_PUT => {
                let key = take_field(&mut rest)?.to_vec();
                let value = take_field(&mut rest)?.to_vec();
                batch.put(key, value);
            }
            OP_DELETE => batch.delete(take_field(&mut rest)?.to_vec()),
            OP_DELETE_PREFIX => batch.delete_prefix(take_field(&mut rest)?.to_vec()),
            OP_DELETE_IF => {
                let key = take_field(&mut rest)?.to_vec();
                let expected = take_field(&mut rest)?.to_vec();
                batch.delete_if(key, expected);
            }
            _ => return None,
        }
    }
    rest.is_empty().then_some(batch)
}

fn replay(bytes: &[u8], map: &mut BTreeMap<Vec<u8>, Vec<u8>>) -> usize {
    let mut offset = 0_usize;
    loop {
        let Some(rest) = bytes.get(offset..) else {
            return offset;
        };
        let Some((length, tail)) = rest.split_first_chunk::<4>() else {
            return offset;
        };
        let Ok(length) = usize::try_from(u32::from_be_bytes(*length)) else {
            return offset;
        };
        let Some((digest, tail)) = tail.split_at_checked(HASH_LEN) else {
            return offset;
        };
        let Some(payload) = tail.get(..length) else {
            return offset;
        };
        if sha256(&[payload]).as_slice() != digest {
            return offset;
        }
        let Some(batch) = decode_batch(payload) else {
            return offset;
        };
        apply_to_map(map, &batch);
        offset = offset.saturating_add(4 + HASH_LEN).saturating_add(length);
    }
}

fn read_snapshot(bytes: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let corrupt = StoreError::Corrupt("snapshot");
    let split = bytes
        .len()
        .checked_sub(HASH_LEN)
        .ok_or(StoreError::Corrupt("snapshot"))?;
    let (body, digest) = bytes.split_at(split);
    if sha256(&[body]).as_slice() != digest {
        return Err(corrupt);
    }
    let mut rest = body
        .strip_prefix(MAGIC.as_slice())
        .ok_or(StoreError::Corrupt("snapshot"))?;
    let mut map = BTreeMap::new();
    while !rest.is_empty() {
        let key = take_field(&mut rest).ok_or(StoreError::Corrupt("snapshot"))?;
        let value = take_field(&mut rest).ok_or(StoreError::Corrupt("snapshot"))?;
        map.insert(key.to_vec(), value.to_vec());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let suffix = u32::from_be_bytes(hasp_crypto::random_array::<4>().unwrap());
        std::env::temp_dir().join(format!(
            "hasp-filestore-{name}-{}-{suffix:08x}",
            std::process::id()
        ))
    }

    fn held_elsewhere(path: &Path) -> File {
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.join(LOCK))
            .unwrap();
        other.lock().unwrap();
        other
    }

    #[test]
    fn a_write_behind_a_held_lock_fails_retryably_instead_of_blocking() {
        let path = dir("busy-write");
        let mut store = FileStore::open(&path).unwrap();
        store.wait = Duration::from_millis(50);
        let other = held_elsewhere(&path);
        let mut batch = Batch::new();
        batch.put(b"a".to_vec(), b"1".to_vec());
        assert!(matches!(store.apply(&batch), Err(StoreError::Locked)));
        other.unlock().unwrap();
        store.apply(&batch).unwrap();
    }

    #[test]
    fn a_stale_read_behind_a_held_lock_fails_retryably() {
        let path = dir("busy-read");
        let mut first = FileStore::open(&path).unwrap();
        let mut second = FileStore::open(&path).unwrap();
        second.wait = Duration::from_millis(50);
        put(&mut first, "a/1", "x");
        let other = held_elsewhere(&path);
        assert!(matches!(second.get(b"a/1"), Err(StoreError::Locked)));
        other.unlock().unwrap();
        assert_eq!(
            second.get(b"a/1").unwrap().as_deref(),
            Some(b"x".as_slice())
        );
    }

    #[test]
    fn opening_behind_a_held_lock_returns_instead_of_hanging() {
        let path = dir("busy-open");
        drop(FileStore::open(&path).unwrap());
        let other = held_elsewhere(&path);
        let started = Instant::now();
        assert!(matches!(FileStore::open(&path), Err(StoreError::Locked)));
        assert!(started.elapsed() < Duration::from_secs(10));
        other.unlock().unwrap();
        FileStore::open(&path).unwrap();
    }

    #[test]
    fn a_conditional_delete_replays_from_the_log() {
        let path = dir("delete-if");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "k", "old");
        let mut batch = Batch::new();
        batch.delete_if(b"k".to_vec(), b"other".to_vec());
        store.apply(&batch).unwrap();
        assert!(store.get(b"k").unwrap().is_some());
        let mut batch = Batch::new();
        batch.delete_if(b"k".to_vec(), b"old".to_vec());
        store.apply(&batch).unwrap();
        assert!(store.get(b"k").unwrap().is_none());
        let reopened = FileStore::open(&path).unwrap();
        assert!(reopened.get(b"k").unwrap().is_none());
    }

    impl FileStore {
        fn compact_for_test(&mut self) {
            let dir = self.dir.clone();
            self.lock_inner().unwrap().compact(&dir).unwrap();
        }
    }

    fn put(store: &mut FileStore, key: &str, value: &str) {
        let mut batch = Batch::new();
        batch.put(key.as_bytes().to_vec(), value.as_bytes().to_vec());
        store.apply(&batch).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_store_directory_and_files_are_closed_to_other_users() {
        use std::os::unix::fs::PermissionsExt;
        let path = dir("modes").join("nested");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "a/1", "x");
        store.compact_for_test();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o700);
        assert_eq!(mode(&path.join(LOG)), 0o600);
        assert_eq!(mode(&path.join(SNAPSHOT)), 0o600);
    }

    #[test]
    fn committed_batches_survive_reopen_and_prefix_deletes_apply() {
        let path = dir("reopen");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "a/1", "x");
        put(&mut store, "a/2", "y");
        put(&mut store, "b/1", "z");
        let mut batch = Batch::new();
        batch.delete_prefix(b"a/".to_vec());
        batch.put(b"a/3".to_vec(), b"w".to_vec());
        store.apply(&batch).unwrap();
        drop(store);
        let store = FileStore::open(&path).unwrap();
        assert_eq!(store.get(b"a/1").unwrap(), None);
        assert_eq!(store.get(b"a/3").unwrap(), Some(b"w".to_vec()));
        assert_eq!(store.scan(b"b/").unwrap().len(), 1);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_torn_tail_drops_only_the_unfinished_batch() {
        let path = dir("torn");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "k1", "one");
        put(&mut store, "k2", "two");
        drop(store);
        let log = path.join(LOG);
        let full = fs::metadata(&log).unwrap().len();
        let file = OpenOptions::new().write(true).open(&log).unwrap();
        file.set_len(full - 3).unwrap();
        drop(file);
        let mut store = FileStore::open(&path).unwrap();
        assert_eq!(store.get(b"k1").unwrap(), Some(b"one".to_vec()));
        assert_eq!(store.get(b"k2").unwrap(), None);
        put(&mut store, "k3", "three");
        drop(store);
        let store = FileStore::open(&path).unwrap();
        assert_eq!(store.get(b"k3").unwrap(), Some(b"three".to_vec()));
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_flipped_byte_in_the_log_stops_replay_at_that_record() {
        let path = dir("flip");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "k1", "one");
        let first = fs::metadata(path.join(LOG)).unwrap().len();
        put(&mut store, "k2", "two");
        drop(store);
        let mut bytes = fs::read(path.join(LOG)).unwrap();
        let at = usize::try_from(first).unwrap() + 40;
        bytes[at] ^= 1;
        fs::write(path.join(LOG), bytes).unwrap();
        let store = FileStore::open(&path).unwrap();
        assert_eq!(store.get(b"k1").unwrap(), Some(b"one".to_vec()));
        assert_eq!(store.get(b"k2").unwrap(), None);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn compaction_preserves_state_and_a_crash_before_truncation_is_harmless() {
        let path = dir("compact");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "a/1", "x");
        let mut batch = Batch::new();
        batch.delete_prefix(b"a/".to_vec());
        batch.put(b"a/2".to_vec(), b"y".to_vec());
        store.apply(&batch).unwrap();
        let log_before = fs::read(path.join(LOG)).unwrap();
        store.compact_for_test();
        drop(store);
        fs::write(path.join(LOG), &log_before).unwrap();
        let store = FileStore::open(&path).unwrap();
        assert_eq!(store.get(b"a/1").unwrap(), None);
        assert_eq!(store.get(b"a/2").unwrap(), Some(b"y".to_vec()));
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_damaged_snapshot_is_refused_not_ignored() {
        let path = dir("snap");
        let mut store = FileStore::open(&path).unwrap();
        put(&mut store, "k", "v");
        store.compact_for_test();
        drop(store);
        let mut bytes = fs::read(path.join(SNAPSHOT)).unwrap();
        bytes[9] ^= 1;
        fs::write(path.join(SNAPSHOT), bytes).unwrap();
        assert!(matches!(
            FileStore::open(&path),
            Err(StoreError::Corrupt(_))
        ));
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_second_handle_sees_writes_and_compaction_of_the_first_without_reopening() {
        let path = dir("handles");
        let mut first = FileStore::open(&path).unwrap();
        let mut second = FileStore::open(&path).unwrap();
        put(&mut first, "a", "1");
        assert_eq!(second.get(b"a").unwrap(), Some(b"1".to_vec()));
        put(&mut second, "b", "2");
        put(&mut first, "c", "3");
        first.compact_for_test();
        put(&mut second, "d", "4");
        assert_eq!(first.scan(b"").unwrap().len(), 4);
        assert_eq!(second.scan(b"").unwrap().len(), 4);
        drop((first, second));
        assert_eq!(FileStore::open(&path).unwrap().scan(b"").unwrap().len(), 4);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_writer_truncates_the_torn_tail_left_by_a_crashed_process() {
        let path = dir("torn-handles");
        let mut first = FileStore::open(&path).unwrap();
        put(&mut first, "k1", "one");
        let mut crashed = OpenOptions::new()
            .append(true)
            .open(path.join(LOG))
            .unwrap();
        crashed.write_all(&[0, 0, 0, 9, 1, 2, 3]).unwrap();
        drop(crashed);
        assert_eq!(first.get(b"k1").unwrap(), Some(b"one".to_vec()));
        put(&mut first, "k2", "two");
        drop(first);
        let store = FileStore::open(&path).unwrap();
        assert_eq!(store.get(b"k2").unwrap(), Some(b"two".to_vec()));
        fs::remove_dir_all(&path).unwrap();
    }
}
