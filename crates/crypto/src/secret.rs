use std::fmt;

use secrecy::{ExposeSecret, SecretBox, SecretSlice};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, KEY_LEN, random};

pub struct SecretKey(SecretBox<[u8; KEY_LEN]>);

impl SecretKey {
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let key = Self(SecretBox::new(Box::new(bytes)));
        bytes.zeroize();
        key
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::Length);
        }
        let mut boxed = Box::new([0_u8; KEY_LEN]);
        boxed.copy_from_slice(bytes);
        Ok(Self(SecretBox::new(boxed)))
    }

    #[must_use]
    pub fn duplicate(&self) -> Self {
        let mut boxed = Box::new([0_u8; KEY_LEN]);
        boxed.copy_from_slice(self.expose());
        Self(SecretBox::new(boxed))
    }

    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = random::random_array::<KEY_LEN>()?;
        let key = Self::from_bytes(bytes);
        bytes.zeroize();
        Ok(key)
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose().as_slice().ct_eq(other.expose().as_slice())
    }
}

pub struct SecretBytes(SecretSlice<u8>);

impl SecretBytes {
    /// Takes ownership and zeroizes any spare capacity.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        if bytes.capacity() == bytes.len() {
            return Self(SecretSlice::from(bytes));
        }
        let source = Zeroizing::new(bytes);
        let mut exact = Vec::with_capacity(source.len());
        exact.extend_from_slice(&source);
        Self(SecretSlice::from(exact))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub fn len(&self) -> usize {
        self.expose().len()
    }

    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(..)")
    }
}

impl ConstantTimeEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose().ct_eq(other.expose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let key = SecretKey::from_bytes([7; KEY_LEN]);
        let bytes = SecretBytes::from_vec(vec![7; 9]);
        assert_eq!(format!("{key:?}"), "SecretKey(..)");
        assert_eq!(format!("{bytes:?}"), "SecretBytes(..)");
    }

    #[test]
    fn constant_time_equality_compares_contents() {
        let first = SecretKey::from_bytes([1; KEY_LEN]);
        let same = SecretKey::from_bytes([1; KEY_LEN]);
        let other = SecretKey::from_bytes([2; KEY_LEN]);
        assert!(bool::from(first.ct_eq(&same)));
        assert!(!bool::from(first.ct_eq(&other)));
        let long = SecretBytes::from_vec(vec![1, 2, 3]);
        let short = SecretBytes::from_vec(vec![1, 2]);
        assert!(!bool::from(long.ct_eq(&short)));
    }

    #[test]
    fn from_vec_keeps_contents_when_capacity_exceeds_length() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[9, 8, 7]);
        let secret = SecretBytes::from_vec(bytes);
        assert_eq!(secret.expose(), &[9, 8, 7]);
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
    }

    #[test]
    fn random_keys_differ() {
        let first = SecretKey::random().unwrap();
        let second = SecretKey::random().unwrap();
        assert!(!bool::from(first.ct_eq(&second)));
    }
}
