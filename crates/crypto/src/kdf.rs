use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{CryptoError, KEY_LEN, SHA256_LEN, SecretBytes, SecretKey};

const HKDF_MAX_OUTPUT: usize = 255 * SHA256_LEN;
const ARGON2_TAG_LEN: usize = 32;
const ARGON2_SALT_LEN: usize = 16;
const ACCOUNT_M_KIB: (u32, u32) = (65_536, 524_288);
const ACCOUNT_T: (u32, u32) = (3, 12);
const ACCOUNT_P: u32 = 4;

pub struct Prk(SecretKey);

impl Prk {
    pub fn from_secret(key: SecretKey) -> Self {
        Self(key)
    }

    /// The extracted key, for protocols that use the PRK itself as a key.
    pub fn into_secret(self) -> SecretKey {
        self.0
    }
}

impl std::fmt::Debug for Prk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prk(..)")
    }
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Prk {
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut bytes = [0_u8; KEY_LEN];
    bytes
        .iter_mut()
        .zip(prk.iter())
        .for_each(|(slot, byte)| *slot = *byte);
    prk.zeroize();
    let key = SecretKey::from_bytes(bytes);
    bytes.zeroize();
    Prk(key)
}

/// Refuses empty `info` so every derivation carries a label.
///
/// ```
/// use hasp_crypto::{hkdf_expand_key, hkdf_extract};
///
/// let prk = hkdf_extract(b"salt", b"input keying material");
/// let key = hkdf_expand_key(&prk, b"hasp/v1/example")?;
/// assert_eq!(key.expose().len(), 32);
/// # Ok::<(), hasp_crypto::CryptoError>(())
/// ```
pub fn hkdf_expand_key(prk: &Prk, info: &[u8]) -> Result<SecretKey, CryptoError> {
    let mut okm = [0_u8; KEY_LEN];
    expand_into(prk, info, &mut okm)?;
    let key = SecretKey::from_bytes(okm);
    okm.zeroize();
    Ok(key)
}

pub fn hkdf_expand(prk: &Prk, info: &[u8], len: usize) -> Result<SecretBytes, CryptoError> {
    if len > HKDF_MAX_OUTPUT {
        return Err(CryptoError::Length);
    }
    let mut okm = vec![0_u8; len];
    if let Err(error) = expand_into(prk, info, &mut okm) {
        okm.zeroize();
        return Err(error);
    }
    Ok(SecretBytes::from_vec(okm))
}

fn expand_into(prk: &Prk, info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
    if info.is_empty() {
        return Err(CryptoError::Length);
    }
    expand_raw(prk, info, okm)
}

fn expand_raw(prk: &Prk, info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
    let hkdf =
        Hkdf::<Sha256>::from_prk(prk.0.expose()).map_err(|_| CryptoError::Internal("hkdf prk"))?;
    hkdf.expand(info, okm).map_err(|_| CryptoError::Length)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl Argon2idParams {
    pub const FLOOR: Self = Self {
        m_kib: ACCOUNT_M_KIB.0,
        t: ACCOUNT_T.0,
        p: ACCOUNT_P,
    };

    pub fn account(m_kib: u32, t: u32, p: u32) -> Result<Self, CryptoError> {
        let in_range = (ACCOUNT_M_KIB.0..=ACCOUNT_M_KIB.1).contains(&m_kib)
            && (ACCOUNT_T.0..=ACCOUNT_T.1).contains(&t)
            && p == ACCOUNT_P;
        if !in_range {
            return Err(CryptoError::KdfParams);
        }
        Self::local(m_kib, t, p)
    }

    pub fn local(m_kib: u32, t: u32, p: u32) -> Result<Self, CryptoError> {
        Params::new(m_kib, t, p, Some(ARGON2_TAG_LEN)).map_err(|_| CryptoError::KdfParams)?;
        Ok(Self { m_kib, t, p })
    }

    /// Refuses with `KdfParams` when this device cannot allocate `m_kib`. Never lowers it.
    pub fn within_capability(&self, max_m_kib: u32) -> Result<(), CryptoError> {
        if self.m_kib > max_m_kib {
            return Err(CryptoError::KdfParams);
        }
        Ok(())
    }

    pub fn m_kib(&self) -> u32 {
        self.m_kib
    }

    pub fn t(&self) -> u32 {
        self.t
    }

    pub fn p(&self) -> u32 {
        self.p
    }
}

/// An allocation failure for the requested memory is `KdfParams`.
pub fn argon2id(
    password: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    params: &Argon2idParams,
) -> Result<SecretKey, CryptoError> {
    let inner = Params::new(params.m_kib, params.t, params.p, Some(ARGON2_TAG_LEN))
        .map_err(|_| CryptoError::KdfParams)?;
    let mut tag = [0_u8; ARGON2_TAG_LEN];
    let result = Argon2::new(Algorithm::Argon2id, Version::V0x13, inner)
        .hash_password_into(password, salt, &mut tag);
    if result.is_err() {
        tag.zeroize();
        return Err(CryptoError::KdfParams);
    }
    let key = SecretKey::from_bytes(tag);
    tag.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testutil::{array, field, load};
    use crate::to_hex;

    fn prk_from(bytes: &[u8]) -> Prk {
        Prk::from_secret(SecretKey::from_bytes(array(&to_hex(bytes))))
    }

    #[test]
    fn hkdf_matches_rfc5869() {
        for case in load("hkdf-sha256")["cases"].as_array().unwrap() {
            let prk = hkdf_extract(&field(case, "salt"), &field(case, "ikm"));
            assert_eq!(to_hex(prk.0.expose()), case["prk"].as_str().unwrap());
            let mut okm = vec![0_u8; usize::try_from(case["len"].as_u64().unwrap()).unwrap()];
            expand_raw(&prk, &field(case, "info"), &mut okm).unwrap();
            assert_eq!(to_hex(&okm), case["okm"].as_str().unwrap());
        }
    }

    #[test]
    fn labelled_expand_matches_rfc5869_prefix() {
        let case = &load("hkdf-sha256")["cases"][0];
        let prk = prk_from(&field(case, "prk"));
        let okm = field(case, "okm");
        let key = hkdf_expand_key(&prk, &field(case, "info")).unwrap();
        assert_eq!(key.expose().as_slice(), okm.get(..32).unwrap());
        let long = hkdf_expand(&prk, &field(case, "info"), okm.len()).unwrap();
        assert_eq!(long.expose(), okm.as_slice());
    }

    #[test]
    fn expand_refuses_empty_info_and_oversized_output() {
        let prk = hkdf_extract(b"salt", b"ikm");
        assert!(matches!(
            hkdf_expand_key(&prk, b""),
            Err(CryptoError::Length)
        ));
        assert!(matches!(
            hkdf_expand(&prk, b"", 8),
            Err(CryptoError::Length)
        ));
        assert_eq!(HKDF_MAX_OUTPUT, 8160);
        assert!(hkdf_expand(&prk, b"label", 8160).is_ok());
        assert!(matches!(
            hkdf_expand(&prk, b"label", 8161),
            Err(CryptoError::Length)
        ));
    }

    #[test]
    fn params_report_what_they_were_built_with() {
        let params = Argon2idParams::local(64, 2, 3).unwrap();
        assert_eq!((params.m_kib(), params.t(), params.p()), (64, 2, 3));
    }

    #[test]
    fn different_labels_derive_different_keys() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let first = hkdf_expand_key(&prk, b"hasp/v1/one").unwrap();
        let second = hkdf_expand_key(&prk, b"hasp/v1/two").unwrap();
        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn argon2_crate_matches_rfc9106_with_secret_and_data() {
        let case = &load("argon2id")["rfc9106"];
        let ad = field(case, "ad");
        let params = argon2::ParamsBuilder::new()
            .m_cost(u32::try_from(case["m_kib"].as_u64().unwrap()).unwrap())
            .t_cost(u32::try_from(case["t"].as_u64().unwrap()).unwrap())
            .p_cost(u32::try_from(case["p"].as_u64().unwrap()).unwrap())
            .data(argon2::AssociatedData::new(&ad).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let secret = field(case, "secret");
        let argon =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut tag = [0_u8; 32];
        argon
            .hash_password_into(&field(case, "password"), &field(case, "salt"), &mut tag)
            .unwrap();
        assert_eq!(to_hex(&tag), case["tag"].as_str().unwrap());
    }

    #[test]
    fn argon2id_matches_independent_implementation() {
        for case in load("argon2id")["project"].as_array().unwrap() {
            let params = Argon2idParams::local(
                u32::try_from(case["m_kib"].as_u64().unwrap()).unwrap(),
                u32::try_from(case["t"].as_u64().unwrap()).unwrap(),
                u32::try_from(case["p"].as_u64().unwrap()).unwrap(),
            )
            .unwrap();
            let key = argon2id(
                &field(case, "password"),
                &array(case["salt"].as_str().unwrap()),
                &params,
            )
            .unwrap();
            assert_eq!(to_hex(key.expose()), case["tag"].as_str().unwrap());
        }
    }

    #[test]
    fn account_parameters_enforce_floor_and_ceiling() {
        assert_eq!(
            Argon2idParams::account(65_536, 3, 4).unwrap(),
            Argon2idParams::FLOOR
        );
        assert!(Argon2idParams::account(524_288, 12, 4).is_ok());
        for (m, t, p) in [
            (65_535, 3, 4),
            (524_289, 3, 4),
            (65_536, 2, 4),
            (65_536, 13, 4),
            (65_536, 3, 3),
            (65_536, 3, 5),
            (0, 0, 0),
            (u32::MAX, u32::MAX, u32::MAX),
        ] {
            assert!(
                matches!(
                    Argon2idParams::account(m, t, p),
                    Err(CryptoError::KdfParams)
                ),
                "{m} {t} {p}"
            );
        }
    }

    #[test]
    fn local_parameters_follow_library_limits_only() {
        let params = Argon2idParams::local(64, 1, 1).unwrap();
        assert_eq!((params.m_kib(), params.t(), params.p()), (64, 1, 1));
        assert!(matches!(
            Argon2idParams::local(7, 1, 1),
            Err(CryptoError::KdfParams)
        ));
        assert!(matches!(
            Argon2idParams::local(64, 0, 1),
            Err(CryptoError::KdfParams)
        ));
        assert!(matches!(
            Argon2idParams::local(64, 1, 0),
            Err(CryptoError::KdfParams)
        ));
        assert!(matches!(
            Argon2idParams::local(16, 1, 4),
            Err(CryptoError::KdfParams)
        ));
    }

    #[test]
    fn capability_check_refuses_without_lowering() {
        let params = Argon2idParams::account(131_072, 3, 4).unwrap();
        assert!(params.within_capability(131_072).is_ok());
        assert!(matches!(
            params.within_capability(65_536),
            Err(CryptoError::KdfParams)
        ));
        assert_eq!(params.m_kib(), 131_072);
    }

    #[test]
    fn argon2id_depends_on_every_input() {
        let params = Argon2idParams::local(64, 1, 1).unwrap();
        let base = argon2id(b"password", &[1; 16], &params).unwrap();
        let other_password = argon2id(b"passwore", &[1; 16], &params).unwrap();
        let other_salt = argon2id(b"password", &[2; 16], &params).unwrap();
        let other_cost = argon2id(
            b"password",
            &[1; 16],
            &Argon2idParams::local(64, 2, 1).unwrap(),
        )
        .unwrap();
        for other in [other_password, other_salt, other_cost] {
            assert_ne!(base.expose(), other.expose());
        }
    }

    #[test]
    fn prk_debug_is_redacted() {
        assert_eq!(format!("{:?}", hkdf_extract(b"s", b"k")), "Prk(..)");
    }

    proptest! {
        #[test]
        fn expand_output_is_prefix_consistent(
            ikm in proptest::collection::vec(any::<u8>(), 1..64),
            len in 1_usize..200,
        ) {
            let prk = hkdf_extract(b"salt", &ikm);
            let long = hkdf_expand(&prk, b"hasp/v1/test", 255).unwrap();
            let short = hkdf_expand(&prk, b"hasp/v1/test", len).unwrap();
            prop_assert_eq!(short.expose(), long.expose().get(..len).unwrap());
        }
    }
}
