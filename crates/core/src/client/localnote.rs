use hasp_crypto::{SecretBytes, hkdf_expand_key, hkdf_extract};

use super::Client;
use crate::CoreError;
use crate::store::{Batch, Records, Store};
use crate::transport::Transport;

const NONCE_LEN: usize = 24;
const SALT: &[u8] = b"hasp/v1/local-note";

impl<T: Transport, S: Store> Client<T, S> {
    /// Keeps `plain` in the encrypted local store under a key derived from the account key, for
    /// state that must not sit in clear text next to the store. It never leaves the device.
    pub fn local_note_put(&mut self, name: &str, plain: &[u8]) -> Result<(), CoreError> {
        let session = self.unlocked()?;
        let key = hkdf_expand_key(
            &hkdf_extract(SALT, session.identity.ak.expose()),
            name.as_bytes(),
        )?;
        let sealed = hasp_crypto::seal(&key, plain, name.as_bytes())?;
        let mut stored = sealed.nonce.to_vec();
        stored.extend_from_slice(&sealed.ct);
        let mut batch = Batch::new();
        Records::put_meta(&mut batch, &format!("note/{name}"), &stored);
        self.cache.commit(&batch)?;
        Ok(())
    }

    pub fn local_note_get(&self, name: &str) -> Result<Option<SecretBytes>, CoreError> {
        let session = self.unlocked()?;
        let Some(stored) = self.cache.meta(&format!("note/{name}"))? else {
            return Ok(None);
        };
        let (nonce, ct) = stored
            .split_at_checked(NONCE_LEN)
            .ok_or(CoreError::Internal("local note"))?;
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CoreError::Internal("local note"))?;
        let key = hkdf_expand_key(
            &hkdf_extract(SALT, session.identity.ak.expose()),
            name.as_bytes(),
        )?;
        let plain = hasp_crypto::open(&key, &nonce, ct, name.as_bytes())
            .map_err(|_| CoreError::Internal("local note"))?;
        Ok(Some(plain))
    }
}
