#[cfg(any(test, feature = "testing"))]
use std::collections::BTreeMap;
use std::sync::Arc;
#[cfg(any(test, feature = "testing"))]
use std::sync::Mutex;
#[cfg(any(test, feature = "testing"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hasp_crypto::SecretBytes;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("user presence was not given")]
    Denied,
    #[error("no such item in the secure store")]
    Missing,
    #[error("secure store failure")]
    Store,
    #[error("randomness unavailable")]
    Random,
}

/// Holds the device unlock key (protocol 4.6 `DUK`) and the unattended backup key. `get` is the
/// gated release: a hardware implementation asks for user presence before it returns.
pub trait SecureStore: Send + Sync {
    fn hardware_gated(&self) -> bool;
    fn put(&self, label: &str, secret: &[u8]) -> Result<(), PlatformError>;
    fn get(&self, label: &str) -> Result<SecretBytes, PlatformError>;
    fn delete(&self, label: &str) -> Result<(), PlatformError>;
}

pub trait Biometric: Send + Sync {
    fn available(&self) -> bool;
    fn authenticate(&self, reason: &str) -> Result<(), PlatformError>;
}

/// Seconds since the Unix epoch. Protocol timestamps are informational and never gate a
/// security decision (protocol 3.1).
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Clone)]
pub struct Platform {
    pub secure: Arc<dyn SecureStore>,
    pub biometric: Arc<dyn Biometric>,
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Platform(..)")
    }
}

impl Platform {
    pub fn array<const N: usize>(&self) -> Result<[u8; N], PlatformError> {
        let mut out = [0_u8; N];
        hasp_crypto::fill_random(&mut out).map_err(|_| PlatformError::Random)?;
        Ok(out)
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

#[cfg(any(test, feature = "testing"))]
impl ManualClock {
    pub fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
    }

    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::Relaxed);
    }

    pub fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "testing"))]
impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct MemorySecureStore {
    gated: bool,
    items: Mutex<BTreeMap<String, Vec<u8>>>,
}

#[cfg(any(test, feature = "testing"))]
impl MemorySecureStore {
    pub fn new(hardware_gated: bool) -> Self {
        Self {
            gated: hardware_gated,
            items: Mutex::new(BTreeMap::new()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl SecureStore for MemorySecureStore {
    fn hardware_gated(&self) -> bool {
        self.gated
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

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct ScriptedBiometric {
    approve: AtomicBool,
    present: bool,
    reasons: Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "testing"))]
impl ScriptedBiometric {
    pub fn new(present: bool, approve: bool) -> Self {
        Self {
            approve: AtomicBool::new(approve),
            present,
            reasons: Mutex::new(Vec::new()),
        }
    }

    pub fn reasons(&self) -> Vec<String> {
        self.reasons
            .lock()
            .map_or_else(|_| Vec::new(), |r| r.clone())
    }

    pub fn set_approve(&self, approve: bool) {
        self.approve.store(approve, Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "testing"))]
impl Biometric for ScriptedBiometric {
    fn available(&self) -> bool {
        self.present
    }

    fn authenticate(&self, reason: &str) -> Result<(), PlatformError> {
        if let Ok(mut reasons) = self.reasons.lock() {
            reasons.push(reason.to_owned());
        }
        if self.present && self.approve.load(Ordering::Relaxed) {
            Ok(())
        } else {
            Err(PlatformError::Denied)
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Platform {
    pub fn for_tests(clock: Arc<ManualClock>) -> Self {
        Self {
            secure: Arc::new(MemorySecureStore::new(true)),
            biometric: Arc::new(ScriptedBiometric::new(true, true)),
            clock,
        }
    }

    pub fn password_only_for_tests(clock: Arc<ManualClock>) -> Self {
        Self {
            secure: Arc::new(MemorySecureStore::new(false)),
            biometric: Arc::new(ScriptedBiometric::new(false, false)),
            clock,
        }
    }
}
