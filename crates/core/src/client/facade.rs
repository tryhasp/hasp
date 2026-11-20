use std::sync::Arc;

use super::Client;
use crate::CoreError;
use crate::platform::{Biometric, Clock, SecureStore};
use crate::store::{Batch, Records, Store, UnlockClass};
use crate::transport::Transport;

impl<T: Transport, S: Store> Client<T, S> {
    pub fn unlock_class(&self) -> Result<Option<UnlockClass>, CoreError> {
        Ok(self.cache.account()?.map(|account| account.class))
    }

    pub fn origin(&self) -> Result<Option<String>, CoreError> {
        Ok(self.cache.account()?.map(|account| account.origin))
    }

    pub fn lockout_remaining(&self) -> u64 {
        if self.failed_unlocks < super::unlock::FAILURES_BEFORE_DELAY {
            return 0;
        }
        self.locked_until.saturating_sub(self.platform.clock.now())
    }

    pub fn biometric_ready(&self) -> bool {
        self.platform.biometric.available()
            && matches!(self.unlock_class(), Ok(Some(UnlockClass::Hardware)))
    }

    pub fn require_unlocked(&self) -> Result<(), CoreError> {
        self.unlocked().map(|_| ())
    }

    pub fn now(&self) -> u64 {
        self.platform.clock.now()
    }

    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.platform.clock)
    }

    pub fn secure_store(&self) -> Arc<dyn SecureStore> {
        Arc::clone(&self.platform.secure)
    }

    pub fn biometric(&self) -> Arc<dyn Biometric> {
        Arc::clone(&self.platform.biometric)
    }

    /// Device-local plain state that is not secret: timestamps, policy and preferences.
    pub fn meta_get(&self, name: &str) -> Result<Option<Vec<u8>>, CoreError> {
        Ok(self.cache.meta(&format!("app/{name}"))?)
    }

    pub fn meta_put(&mut self, name: &str, value: &[u8]) -> Result<(), CoreError> {
        let mut batch = Batch::new();
        Records::put_meta(&mut batch, &format!("app/{name}"), value);
        self.cache.commit(&batch)?;
        Ok(())
    }
}
