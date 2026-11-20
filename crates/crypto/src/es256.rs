use std::fmt;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use zeroize::Zeroize;

use crate::{CryptoError, SecretBytes, fill_random};

pub const ES256_COORD_LEN: usize = 32;
pub const ES256_SEC1_LEN: usize = 65;

const GENERATE_TRIES: usize = 8;

/// An ECDSA P-256 key for WebAuthn credentials (COSE -7). Randomness comes from the OS CSPRNG;
/// signatures are deterministic (RFC 6979) over SHA-256 and DER encoded, as WebAuthn requires.
pub struct Es256Key(SigningKey);

impl Es256Key {
    pub fn generate() -> Result<Self, CryptoError> {
        for _ in 0..GENERATE_TRIES {
            let mut bytes = [0_u8; ES256_COORD_LEN];
            fill_random(&mut bytes)?;
            let key = SigningKey::from_slice(&bytes);
            bytes.zeroize();
            if let Ok(key) = key {
                return Ok(Self(key));
            }
        }
        Err(CryptoError::Random)
    }

    pub fn from_scalar(bytes: &[u8; ES256_COORD_LEN]) -> Result<Self, CryptoError> {
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Signature)
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| CryptoError::Signature)
    }

    pub fn to_pkcs8(&self) -> Result<SecretBytes, CryptoError> {
        let document = self
            .0
            .to_pkcs8_der()
            .map_err(|_| CryptoError::Internal("pkcs8 encoding"))?;
        Ok(SecretBytes::from_vec(document.as_bytes().to_vec()))
    }

    /// The uncompressed SEC1 point `04 || x || y`.
    pub fn public_sec1(&self) -> [u8; ES256_SEC1_LEN] {
        let point = self.0.verifying_key().to_sec1_point(false);
        let mut out = [0_u8; ES256_SEC1_LEN];
        let bytes = point.as_bytes();
        if bytes.len() == ES256_SEC1_LEN {
            out.copy_from_slice(bytes);
        }
        out
    }

    /// The ASN.1 DER ECDSA signature of SHA-256(message).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.0.sign(message);
        signature.to_der().as_bytes().to_vec()
    }
}

impl fmt::Debug for Es256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Es256Key(..)")
    }
}

/// Verifies a DER ECDSA P-256 signature of SHA-256(message) against an uncompressed SEC1 point.
///
/// ```
/// use hasp_crypto::{Es256Key, verify_es256};
///
/// let key = Es256Key::generate()?;
/// let signature = key.sign(b"message");
/// verify_es256(&key.public_sec1(), b"message", &signature)?;
/// assert!(verify_es256(&key.public_sec1(), b"other", &signature).is_err());
/// # Ok::<(), hasp_crypto::CryptoError>(())
/// ```
pub fn verify_es256(
    public_sec1: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_sec1_bytes(public_sec1).map_err(|_| CryptoError::Signature)?;
    let signature = Signature::from_der(signature_der).map_err(|_| CryptoError::Signature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::from_hex;

    fn hex(text: &str) -> Vec<u8> {
        from_hex(text).unwrap()
    }

    #[test]
    fn matches_rfc6979_p256_sha256_sample() {
        let scalar: [u8; 32] =
            hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
                .try_into()
                .unwrap();
        let key = Es256Key::from_scalar(&scalar).unwrap();
        let public = key.public_sec1();
        assert_eq!(
            public.get(1..33).unwrap(),
            hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
        );
        assert_eq!(
            public.get(33..).unwrap(),
            hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
        );
        let der = key.sign(b"sample");
        let parsed = Signature::from_der(&der).unwrap();
        let (r, s) = parsed.split_bytes();
        assert_eq!(
            r.as_slice(),
            hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
        );
        assert_eq!(
            s.as_slice(),
            hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
        );
        verify_es256(&public, b"sample", &der).unwrap();
    }

    #[test]
    fn pkcs8_round_trips_and_rejects_garbage() {
        let key = Es256Key::generate().unwrap();
        let der = key.to_pkcs8().unwrap();
        let again = Es256Key::from_pkcs8(der.expose()).unwrap();
        assert_eq!(key.public_sec1(), again.public_sec1());
        assert!(Es256Key::from_pkcs8(b"nope").is_err());
        assert!(Es256Key::from_scalar(&[0; 32]).is_err());
    }

    #[test]
    fn verification_rejects_other_keys_messages_and_damage() {
        let key = Es256Key::generate().unwrap();
        let other = Es256Key::generate().unwrap();
        let mut signature = key.sign(b"message");
        assert!(verify_es256(&other.public_sec1(), b"message", &signature).is_err());
        assert!(verify_es256(&key.public_sec1(), b"messagf", &signature).is_err());
        assert!(verify_es256(&key.public_sec1()[1..], b"message", &signature).is_err());
        if let Some(byte) = signature.last_mut() {
            *byte ^= 1;
        }
        assert!(verify_es256(&key.public_sec1(), b"message", &signature).is_err());
    }
}
