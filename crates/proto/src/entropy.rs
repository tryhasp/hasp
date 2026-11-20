use hasp_crypto::{NONCE_LEN, SecretKey, random_array};

use crate::ProtoError;

mod private {
    pub trait Sealed {}
}

/// Source of fresh nonces and keys. Production code uses `OsEntropy`; the trait is sealed so
/// only the OS source (and a seeded source behind the `testing` feature) can implement it.
pub trait Entropy: private::Sealed {
    fn nonce(&mut self) -> Result<[u8; NONCE_LEN], ProtoError>;
    fn key(&mut self) -> Result<SecretKey, ProtoError>;
}

#[derive(Clone, Copy, Debug)]
pub struct OsEntropy;

impl private::Sealed for OsEntropy {}

impl Entropy for OsEntropy {
    fn nonce(&mut self) -> Result<[u8; NONCE_LEN], ProtoError> {
        random_array::<NONCE_LEN>().map_err(ProtoError::from)
    }

    fn key(&mut self) -> Result<SecretKey, ProtoError> {
        SecretKey::random().map_err(ProtoError::from)
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug)]
pub struct SeededEntropy {
    seed: [u8; 32],
    counter: u64,
}

#[cfg(any(test, feature = "testing"))]
impl SeededEntropy {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    fn block(&mut self) -> Result<[u8; 32], ProtoError> {
        let counter = self.counter.to_be_bytes();
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(ProtoError::Internal("entropy"))?;
        Ok(hasp_crypto::sha256(&[&self.seed, &counter]))
    }
}

#[cfg(any(test, feature = "testing"))]
impl private::Sealed for SeededEntropy {}

#[cfg(any(test, feature = "testing"))]
impl Entropy for SeededEntropy {
    fn nonce(&mut self) -> Result<[u8; NONCE_LEN], ProtoError> {
        let block = self.block()?;
        let mut nonce = [0; NONCE_LEN];
        nonce.copy_from_slice(
            block
                .get(..NONCE_LEN)
                .ok_or(ProtoError::Internal("entropy"))?,
        );
        Ok(nonce)
    }

    fn key(&mut self) -> Result<SecretKey, ProtoError> {
        self.block().map(SecretKey::from_bytes)
    }
}
