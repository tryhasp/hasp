use core::fmt;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::{CryptoError, SecretKey, random_array};

pub const X25519_LEN: usize = 32;

/// A short-lived X25519 secret for the enrolment channel. Not for long-term keys.
pub struct X25519Secret(StaticSecret);

impl X25519Secret {
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random_array::<X25519_LEN>()?;
        Ok(Self(StaticSecret::from(bytes)))
    }

    pub fn public_key(&self) -> [u8; X25519_LEN] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// Refuses an all-zero shared secret (a small-order peer key).
    pub fn diffie_hellman(&self, peer: &[u8; X25519_LEN]) -> Result<SecretKey, CryptoError> {
        let shared = self.0.diffie_hellman(&PublicKey::from(*peer));
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(CryptoError::Kem);
        }
        SecretKey::from_slice(shared.as_bytes())
    }
}

impl fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Secret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_secret_and_zero_keys_are_refused() {
        let a = X25519Secret::generate().unwrap();
        let b = X25519Secret::generate().unwrap();
        let ab = a.diffie_hellman(&b.public_key()).unwrap();
        let ba = b.diffie_hellman(&a.public_key()).unwrap();
        assert_eq!(ab.expose(), ba.expose());
        assert!(a.diffie_hellman(&[0; X25519_LEN]).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let secret = X25519Secret::generate().unwrap();
        assert_eq!(format!("{secret:?}"), "X25519Secret(..)");
    }
}
