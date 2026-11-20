use std::fmt;

use subtle::ConstantTimeEq;

use ed25519_dalek::{Signer, SigningKey as DalekSigningKey, VerifyingKey as DalekVerifyingKey};

use crate::{CryptoError, SIGNATURE_LEN, SecretKey, VERIFYING_KEY_LEN};

pub struct SigningKey(DalekSigningKey);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyingKey([u8; VERIFYING_KEY_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl SigningKey {
    pub fn from_seed(seed: &SecretKey) -> Self {
        Self(DalekSigningKey::from_bytes(seed.expose()))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl VerifyingKey {
    pub fn from_bytes(bytes: [u8; VERIFYING_KEY_LEN]) -> Result<Self, CryptoError> {
        let key = DalekVerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::Signature)?;
        let canonical = key.to_edwards().compress().to_bytes();
        if key.is_weak() || !bool::from(canonical.ct_eq(&bytes)) {
            return Err(CryptoError::Signature);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.0
    }
}

impl Signature {
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

/// Rejects non-canonical `S` and small-order `A` or `R` in addition to a bad signature.
///
/// ```
/// use hasp_crypto::{SecretKey, SigningKey, verify_strict};
///
/// let signing = SigningKey::from_seed(&SecretKey::random()?);
/// let signature = signing.sign(b"message");
/// verify_strict(&signing.verifying_key(), b"message", &signature)?;
/// assert!(verify_strict(&signing.verifying_key(), b"other", &signature).is_err());
/// # Ok::<(), hasp_crypto::CryptoError>(())
/// ```
pub fn verify_strict(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let dalek_key = DalekVerifyingKey::from_bytes(&key.0).map_err(|_| CryptoError::Signature)?;
    let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature.0);
    dalek_key
        .verify_strict(message, &dalek_signature)
        .map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testutil::{array, field, load};

    fn signer() -> SigningKey {
        SigningKey::from_seed(&SecretKey::from_bytes([5; 32]))
    }

    #[test]
    fn matches_rfc8032_vectors() {
        for case in load("ed25519")["positive"].as_array().unwrap() {
            let signing = SigningKey::from_seed(&SecretKey::from_bytes(array(
                case["seed"].as_str().unwrap(),
            )));
            let message = field(case, "message");
            assert_eq!(
                signing.verifying_key().as_bytes(),
                &array::<32>(case["public"].as_str().unwrap())
            );
            let signature = signing.sign(&message);
            assert_eq!(
                signature.as_bytes(),
                &array::<64>(case["signature"].as_str().unwrap())
            );
            verify_strict(&signing.verifying_key(), &message, &signature).unwrap();
        }
    }

    #[test]
    fn strict_verification_rejects_noncanonical_and_small_order_cases() {
        for case in load("ed25519")["negative"].as_array().unwrap() {
            let public: [u8; 32] = array(case["public"].as_str().unwrap());
            let signature = Signature::from_bytes(array(case["signature"].as_str().unwrap()));
            let name = case["name"].as_str().unwrap();
            let key = VerifyingKey(public);
            assert!(
                matches!(
                    verify_strict(&key, &field(case, "message"), &signature),
                    Err(CryptoError::Signature)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn small_order_keys_are_refused_at_decoding() {
        let identity = {
            let mut bytes = [0_u8; 32];
            bytes[0] = 1;
            bytes
        };
        assert!(matches!(
            VerifyingKey::from_bytes(identity),
            Err(CryptoError::Signature)
        ));
    }

    #[test]
    fn rejects_noncanonical_field_element_encodings() {
        let mut tested = 0;
        for y in 2_u8..19 {
            let mut canonical = [0_u8; 32];
            canonical[0] = y;
            if VerifyingKey::from_bytes(canonical).is_err() {
                continue;
            }
            let mut alias = [0xff_u8; 32];
            alias[0] = 0xed_u8 + y;
            alias[31] = 0x7f;
            assert!(matches!(
                VerifyingKey::from_bytes(alias),
                Err(CryptoError::Signature)
            ));
            tested += 1;
        }
        assert!(tested > 0);
    }

    #[test]
    fn rejects_points_off_the_curve() {
        let mut rejected = 0;
        for y in 2_u8..64 {
            let mut bytes = [0_u8; 32];
            bytes[0] = y;
            if VerifyingKey::from_bytes(bytes).is_err() {
                rejected += 1;
            }
        }
        assert!(rejected > 0);
    }

    #[test]
    fn rejects_wrong_message_key_and_signature() {
        let signature = signer().sign(b"message");
        let key = signer().verifying_key();
        verify_strict(&key, b"message", &signature).unwrap();
        assert!(verify_strict(&key, b"messagf", &signature).is_err());
        let other = SigningKey::from_seed(&SecretKey::from_bytes([6; 32])).verifying_key();
        assert!(verify_strict(&other, b"message", &signature).is_err());
        let mut bytes = *signature.as_bytes();
        bytes[0] ^= 1;
        assert!(verify_strict(&key, b"message", &Signature::from_bytes(bytes)).is_err());
    }

    #[test]
    fn signing_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", signer()), "SigningKey(..)");
    }

    #[test]
    fn verifying_keys_order_by_bytes() {
        let low = signer().verifying_key();
        let high = SigningKey::from_seed(&SecretKey::from_bytes([6; 32])).verifying_key();
        assert_eq!(low.cmp(&high), low.as_bytes().cmp(high.as_bytes()));
    }

    proptest! {
        #[test]
        fn signatures_verify_and_reject_any_flipped_bit(
            seed in proptest::array::uniform32(any::<u8>()),
            message in proptest::collection::vec(any::<u8>(), 0..128),
            bit in 0_usize..8,
            position in any::<proptest::sample::Index>(),
        ) {
            let signing = SigningKey::from_seed(&SecretKey::from_bytes(seed));
            let key = signing.verifying_key();
            let signature = signing.sign(&message);
            prop_assert!(verify_strict(&key, &message, &signature).is_ok());
            let mut bytes = *signature.as_bytes();
            let index = position.index(bytes.len());
            bytes[index] ^= 1 << bit;
            prop_assert!(verify_strict(&key, &message, &Signature::from_bytes(bytes)).is_err());
        }
    }
}
