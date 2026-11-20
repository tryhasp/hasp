use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{CryptoError, SecretBytes, SecretKey};

pub const SHA256_LEN: usize = 32;
pub const SHA1_LEN: usize = 20;
const HMAC_SHA256_BLOCK_LEN: usize = 64;

pub fn sha256(parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// SHA-1 exists only for Have I Been Pwned range lookups; it is never a security
/// primitive here. The digest of a password is as sensitive as the password, so it is wiped on drop.
pub fn sha1_of_secret(message: &[u8]) -> Zeroizing<[u8; SHA1_LEN]> {
    let mut hasher = <Sha1 as Digest>::new();
    hasher.update(message);
    Zeroizing::new(hasher.finalize().into())
}

pub fn hmac_sha256(key: &SecretKey, message: &[u8]) -> [u8; SHA256_LEN] {
    let mut block = Zeroizing::new([0_u8; HMAC_SHA256_BLOCK_LEN]);
    block
        .iter_mut()
        .zip(key.expose())
        .for_each(|(slot, byte)| *slot = *byte);
    let mut mac = <Hmac<Sha256> as KeyInit>::new((&*block).into());
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlg {
    Sha1,
    Sha256,
    Sha512,
}

macro_rules! keyed_hmac {
    ($hash:ty, $key:expr, $message:expr) => {{
        let mut mac =
            <Hmac<$hash> as KeyInit>::new_from_slice($key).map_err(|_| CryptoError::Length)?;
        mac.update($message);
        mac.finalize().into_bytes().to_vec()
    }};
}

pub fn hmac(alg: HmacAlg, key: &[u8], message: &[u8]) -> Result<SecretBytes, CryptoError> {
    let digest = match alg {
        HmacAlg::Sha1 => keyed_hmac!(Sha1, key, message),
        HmacAlg::Sha256 => keyed_hmac!(Sha256, key, message),
        HmacAlg::Sha512 => keyed_hmac!(Sha512, key, message),
    };
    Ok(SecretBytes::from_vec(digest))
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testutil::{field, load, unhex};
    use crate::to_hex;

    fn hmac_with_any_key(key: &[u8], message: &[u8]) -> [u8; SHA256_LEN] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    #[test]
    fn sha256_matches_known_answers() {
        for case in load("sha256")["cases"].as_array().unwrap() {
            let digest = case["digest"].as_str().unwrap();
            if case["repeat"].is_null() {
                let owned: Vec<Vec<u8>> = case["parts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|part| unhex(part.as_str().unwrap()))
                    .collect();
                let parts: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                assert_eq!(to_hex(&sha256(&parts)), digest);
            } else {
                let byte = field(&case["repeat"], "byte")[0];
                let count = case["repeat"]["count"].as_u64().unwrap();
                let input = vec![byte; usize::try_from(count).unwrap()];
                assert_eq!(to_hex(&sha256(&[&input])), digest);
            }
        }
    }

    #[test]
    fn sha256_of_parts_equals_sha256_of_concatenation() {
        assert_eq!(sha256(&[b"ab", b"c"]), sha256(&[b"abc"]));
        assert_eq!(sha256(&[b"", b"abc", b""]), sha256(&[b"abc"]));
    }

    #[test]
    fn hmac_matches_rfc4231() {
        for case in load("hmac-sha256")["rfc4231"].as_array().unwrap() {
            let mac = hmac_with_any_key(&field(case, "key"), &field(case, "data"));
            assert_eq!(to_hex(&mac), case["mac"].as_str().unwrap());
        }
    }

    #[test]
    fn hmac_matches_rfc_4231_and_2202_case_one() {
        let key_sha2 = [0x0b_u8; 20];
        let sha256 = hmac(HmacAlg::Sha256, &key_sha2, b"Hi There").unwrap();
        assert_eq!(
            to_hex(sha256.expose()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let sha512 = hmac(HmacAlg::Sha512, &key_sha2, b"Hi There").unwrap();
        assert_eq!(
            to_hex(sha512.expose()),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        let sha1 = hmac(HmacAlg::Sha1, &key_sha2, b"Hi There").unwrap();
        assert_eq!(
            to_hex(sha1.expose()),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn hmac_accepts_keys_longer_than_the_block() {
        let long = [0xaa_u8; 131];
        let sha256 = hmac(
            HmacAlg::Sha256,
            &long,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        )
        .unwrap();
        assert_eq!(
            to_hex(sha256.expose()),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_with_secret_key_matches_independent_implementation() {
        for case in load("hmac-sha256")["project"].as_array().unwrap() {
            let key = SecretKey::from_bytes(crate::testutil::array(case["key"].as_str().unwrap()));
            let mac = hmac_sha256(&key, &field(case, "data"));
            assert_eq!(to_hex(&mac), case["mac"].as_str().unwrap());
        }
    }

    #[test]
    fn ct_eq_requires_equal_length_and_content() {
        assert!(ct_eq(b"tag", b"tag"));
        assert!(!ct_eq(b"tag", b"tab"));
        assert!(!ct_eq(b"tag", b"tags"));
        assert!(ct_eq(b"", b""));
    }

    proptest! {
        #[test]
        fn hmac_block_padding_matches_variable_key_hmac(
            key in proptest::array::uniform32(any::<u8>()),
            message in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let secret = SecretKey::from_bytes(key);
            prop_assert_eq!(hmac_sha256(&secret, &message), hmac_with_any_key(&key, &message));
        }

        #[test]
        fn ct_eq_agrees_with_slice_equality(
            left in proptest::collection::vec(any::<u8>(), 0..64),
            right in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assert_eq!(ct_eq(&left, &right), left == right);
        }
    }
}
