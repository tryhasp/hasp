use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::AeadInOut};
use zeroize::Zeroizing;

use crate::{CryptoError, NONCE_LEN, SecretBytes, SecretKey, TAG_LEN, random};

#[derive(Clone, Debug)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ct: Vec<u8>,
}

/// Seals under a fresh random 24-byte nonce. Every failure to open reports `Aead`.
///
/// ```
/// use hasp_crypto::{SecretKey, open, seal};
///
/// let key = SecretKey::random()?;
/// let sealed = seal(&key, b"plaintext", b"aad")?;
/// let opened = open(&key, &sealed.nonce, &sealed.ct, b"aad")?;
/// assert_eq!(opened.expose(), b"plaintext");
/// # Ok::<(), hasp_crypto::CryptoError>(())
/// ```
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    let nonce = random::random_array::<NONCE_LEN>()?;
    let ct = seal_with_nonce(key, &nonce, plaintext, aad)?;
    Ok(Sealed { nonce, ct })
}

/// The caller owns nonce uniqueness for this key.
pub fn seal_with_nonce(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let capacity = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(CryptoError::Length)?;
    let mut buffer = Vec::with_capacity(capacity);
    buffer.extend_from_slice(plaintext);
    cipher(key)
        .encrypt_in_place(nonce.into(), aad, &mut buffer)
        .map_err(|_| CryptoError::Aead)?;
    Ok(buffer)
}

pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ct: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(ct.len()));
    buffer.extend_from_slice(ct);
    cipher(key)
        .decrypt_in_place(nonce.into(), aad, &mut *buffer)
        .map_err(|_| CryptoError::Aead)?;
    Ok(SecretBytes::from_vec(std::mem::take(&mut *buffer)))
}

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.expose().into())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testutil::{array, field, load};
    use crate::to_hex;

    fn key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    #[test]
    fn matches_xchacha_draft_vector() {
        let case = &load("xchacha20poly1305")["cases"][0];
        let key = SecretKey::from_bytes(array(case["key"].as_str().unwrap()));
        let nonce: [u8; NONCE_LEN] = array(case["nonce"].as_str().unwrap());
        let ct =
            seal_with_nonce(&key, &nonce, &field(case, "plaintext"), &field(case, "aad")).unwrap();
        assert_eq!(to_hex(&ct), case["ciphertext"].as_str().unwrap());
        let opened = open(&key, &nonce, &ct, &field(case, "aad")).unwrap();
        assert_eq!(opened.expose(), field(case, "plaintext").as_slice());
    }

    #[test]
    fn round_trips_with_aad() {
        let sealed = seal(&key(), b"secret", b"context").unwrap();
        assert_eq!(sealed.ct.len(), 6 + TAG_LEN);
        let opened = open(&key(), &sealed.nonce, &sealed.ct, b"context").unwrap();
        assert_eq!(opened.expose(), b"secret");
    }

    #[test]
    fn round_trips_empty_plaintext() {
        let sealed = seal(&key(), b"", b"").unwrap();
        assert_eq!(sealed.ct.len(), TAG_LEN);
        assert!(
            open(&key(), &sealed.nonce, &sealed.ct, b"")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn nonces_are_fresh_per_seal() {
        let first = seal(&key(), b"same", b"").unwrap();
        let second = seal(&key(), b"same", b"").unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ct, second.ct);
    }

    #[test]
    fn rejects_tampered_ciphertext_tag_nonce_aad_and_key() {
        let sealed = seal(&key(), b"secret", b"context").unwrap();
        for index in 0..sealed.ct.len() {
            let mut ct = sealed.ct.clone();
            ct[index] ^= 1;
            assert!(matches!(
                open(&key(), &sealed.nonce, &ct, b"context"),
                Err(CryptoError::Aead)
            ));
        }
        let mut nonce = sealed.nonce;
        nonce[0] ^= 1;
        assert!(matches!(
            open(&key(), &nonce, &sealed.ct, b"context"),
            Err(CryptoError::Aead)
        ));
        assert!(matches!(
            open(&key(), &sealed.nonce, &sealed.ct, b"other"),
            Err(CryptoError::Aead)
        ));
        let other = SecretKey::from_bytes([0x43; 32]);
        assert!(matches!(
            open(&other, &sealed.nonce, &sealed.ct, b"context"),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let sealed = seal(&key(), b"secret", b"").unwrap();
        for len in 0..sealed.ct.len() {
            assert!(matches!(
                open(&key(), &sealed.nonce, sealed.ct.get(..len).unwrap(), b""),
                Err(CryptoError::Aead)
            ));
        }
    }

    proptest! {
        #[test]
        fn open_inverts_seal(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
            key_bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let key = SecretKey::from_bytes(key_bytes);
            let sealed = seal(&key, &plaintext, &aad).unwrap();
            let opened = open(&key, &sealed.nonce, &sealed.ct, &aad).unwrap();
            prop_assert_eq!(opened.expose(), plaintext.as_slice());
        }

        #[test]
        fn any_single_bit_flip_is_rejected(
            plaintext in proptest::collection::vec(any::<u8>(), 1..64),
            bit in 0_usize..8,
            position in any::<proptest::sample::Index>(),
        ) {
            let sealed = seal(&key(), &plaintext, b"aad").unwrap();
            let mut ct = sealed.ct.clone();
            let index = position.index(ct.len());
            ct[index] ^= 1 << bit;
            prop_assert!(open(&key(), &sealed.nonce, &ct, b"aad").is_err());
        }
    }
}
