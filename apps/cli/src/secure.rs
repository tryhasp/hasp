use std::sync::Arc;

use hasp_core::platform::{Biometric, PlatformError, SecureStore};
use hasp_crypto::SecretBytes;

#[cfg(target_os = "macos")]
mod keychain;

#[derive(Debug)]
pub struct NoSecureStore;

impl SecureStore for NoSecureStore {
    fn hardware_gated(&self) -> bool {
        false
    }

    fn put(&self, _label: &str, _secret: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Store)
    }

    fn get(&self, _label: &str) -> Result<SecretBytes, PlatformError> {
        Err(PlatformError::Missing)
    }

    fn delete(&self, _label: &str) -> Result<(), PlatformError> {
        Ok(())
    }
}

// Why: the gate is the platform store's own release of the item, so the CLI adds none.
#[derive(Debug)]
pub struct StoreGate {
    present: bool,
}

impl StoreGate {
    pub fn new(store: &dyn SecureStore) -> Self {
        Self {
            present: store.hardware_gated(),
        }
    }
}

impl Biometric for StoreGate {
    fn available(&self) -> bool {
        self.present
    }

    fn authenticate(&self, _reason: &str) -> Result<(), PlatformError> {
        if self.present {
            Ok(())
        } else {
            Err(PlatformError::Denied)
        }
    }
}

// Why: Linux libsecret is open to every process of the user and Windows DPAPI isolates only
// other users, so both are the password-only class (protocol 4.6).
pub fn platform_store() -> Arc<dyn SecureStore> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(keychain::Keychain::probe())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(NoSecureStore)
    }
}

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}
