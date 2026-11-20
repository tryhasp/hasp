use std::fmt;

use hpke::{
    Deserializable, HpkeError, Kem as HpkeKem, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::{TryCryptoRng, TryRng},
    single_shot_open, single_shot_seal_with_rng,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, SecretBytes, SecretKey, XWING_ENCAPSULATED_LEN, XWING_PUBLIC_KEY_LEN, random,
};

type XWingPrivateKey = <XWing as HpkeKem>::PrivateKey;
type XWingPublicKey = <XWing as HpkeKem>::PublicKey;
type XWingEncapped = <XWing as HpkeKem>::EncappedKey;

const ENCAPSULATION_RANDOMNESS_LEN: usize = 64;
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
const MLKEM_Q: u16 = 3329;

pub struct KemSecretKey(XWingPrivateKey);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey([u8; XWING_PUBLIC_KEY_LEN]);

#[derive(Clone, Debug)]
pub struct HpkeSealed {
    pub enc: [u8; XWING_ENCAPSULATED_LEN],
    pub ct: Vec<u8>,
}

struct PrefilledRng {
    buffer: Zeroizing<[u8; ENCAPSULATION_RANDOMNESS_LEN]>,
    offset: usize,
    exhausted: bool,
}

impl KemSecretKey {
    pub fn from_seed(seed: &SecretKey) -> Result<Self, CryptoError> {
        XWingPrivateKey::from_bytes(seed.expose().as_slice())
            .map(Self)
            .map_err(|_| CryptoError::Kem)
    }

    pub fn public_key(&self) -> KemPublicKey {
        let public = <XWing as HpkeKem>::sk_to_pk(&self.0);
        let mut bytes = [0_u8; XWING_PUBLIC_KEY_LEN];
        bytes
            .iter_mut()
            .zip(public.to_bytes().iter())
            .for_each(|(slot, byte)| *slot = *byte);
        KemPublicKey(bytes)
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KemSecretKey(..)")
    }
}

impl KemPublicKey {
    pub fn from_bytes(bytes: [u8; XWING_PUBLIC_KEY_LEN]) -> Result<Self, CryptoError> {
        let (mlkem_part, _) = bytes
            .split_at_checked(MLKEM768_ENCAPSULATION_KEY_LEN)
            .ok_or(CryptoError::Length)?;
        check_mlkem_encapsulation_key(mlkem_part)?;
        XWingPublicKey::from_bytes(&bytes).map_err(|_| CryptoError::Kem)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl TryRng for PrefilledRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.take(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.take(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.take(dest);
        Ok(())
    }
}

impl TryCryptoRng for PrefilledRng {}

impl PrefilledRng {
    fn new(buffer: [u8; ENCAPSULATION_RANDOMNESS_LEN]) -> Self {
        Self {
            buffer: Zeroizing::new(buffer),
            offset: 0,
            exhausted: false,
        }
    }

    fn take(&mut self, dest: &mut [u8]) {
        dest.zeroize();
        let end = self.offset.checked_add(dest.len());
        let source = end.and_then(|end| self.buffer.get(self.offset..end));
        match (source, end) {
            (Some(source), Some(end)) => {
                dest.copy_from_slice(source);
                self.offset = end;
            }
            _ => self.exhausted = true,
        }
    }
}

/// HPKE Base mode over X-Wing with HKDF-SHA256 and ChaCha20-Poly1305. The encapsulation
/// key is checked as FIPS 203 section 7.2 requires.
///
/// ```
/// use hasp_crypto::{KemSecretKey, SecretKey, hpke_open, hpke_seal};
///
/// let secret = KemSecretKey::from_seed(&SecretKey::random()?)?;
/// let sealed = hpke_seal(&secret.public_key(), b"info", b"aad", b"plaintext")?;
/// let opened = hpke_open(&secret, &sealed.enc, b"info", b"aad", &sealed.ct)?;
/// assert_eq!(opened.expose(), b"plaintext");
/// # Ok::<(), hasp_crypto::CryptoError>(())
/// ```
pub fn hpke_seal(
    recipient: &KemPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    let randomness = random::random_array::<ENCAPSULATION_RANDOMNESS_LEN>()?;
    seal_with_randomness(recipient, randomness, info, aad, plaintext)
}

#[cfg(feature = "testing")]
pub fn hpke_seal_with_randomness(
    recipient: &KemPublicKey,
    randomness: [u8; ENCAPSULATION_RANDOMNESS_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    seal_with_randomness(recipient, randomness, info, aad, plaintext)
}

/// Decapsulation failure is `Kem`, a bad tag, info or aad is `Aead`.
pub fn hpke_open(
    recipient: &KemSecretKey,
    enc: &[u8; XWING_ENCAPSULATED_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let encapped = XWingEncapped::from_bytes(enc).map_err(|_| CryptoError::Kem)?;
    single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &recipient.0,
        &encapped,
        info,
        ct,
        aad,
    )
    .map(SecretBytes::from_vec)
    .map_err(|error| match error {
        HpkeError::OpenError => CryptoError::Aead,
        HpkeError::MessageLimitReached
        | HpkeError::SealError
        | HpkeError::KdfOutputTooLong
        | HpkeError::ValidationError
        | HpkeError::EncapError
        | HpkeError::DecapError
        | HpkeError::IncorrectInputLength(..)
        | HpkeError::InvalidPskBundle => CryptoError::Kem,
    })
}

fn seal_with_randomness(
    recipient: &KemPublicKey,
    randomness: [u8; ENCAPSULATION_RANDOMNESS_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    let public = XWingPublicKey::from_bytes(&recipient.0).map_err(|_| CryptoError::Kem)?;
    let mut rng = PrefilledRng::new(randomness);
    let (encapped, ct) = single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &public,
        info,
        plaintext,
        aad,
        &mut rng,
    )
    .map_err(|_| CryptoError::Kem)?;
    if rng.exhausted {
        return Err(CryptoError::Internal("encapsulation randomness"));
    }
    let mut enc = [0_u8; XWING_ENCAPSULATED_LEN];
    let encapped_bytes = encapped.to_bytes();
    if encapped_bytes.len() != enc.len() {
        return Err(CryptoError::Internal("encapsulated key length"));
    }
    enc.copy_from_slice(&encapped_bytes);
    Ok(HpkeSealed { enc, ct })
}

fn check_mlkem_encapsulation_key(bytes: &[u8]) -> Result<(), CryptoError> {
    let (polynomials, _) = bytes
        .split_at_checked(MLKEM768_ENCAPSULATION_KEY_LEN.saturating_sub(32))
        .ok_or(CryptoError::Length)?;
    let (chunks, _) = polynomials.as_chunks::<3>();
    for &[first, second, third] in chunks {
        let low = u16::from(first) | u16::from(second & 0x0f).wrapping_shl(8);
        let high = u16::from(second >> 4) | u16::from(third).wrapping_shl(4);
        if low >= MLKEM_Q || high >= MLKEM_Q {
            return Err(CryptoError::Kem);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, KeyExport};

    use super::*;
    use crate::testutil::{array, field, load};
    use crate::to_hex;

    fn seed(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; 32])
    }

    fn recipient() -> (KemSecretKey, KemPublicKey) {
        let secret = KemSecretKey::from_seed(&seed(3)).unwrap();
        let public = secret.public_key();
        (secret, public)
    }

    #[test]
    fn x_wing_crate_matches_draft_11_vectors() {
        let vectors = load("xwing-draft11");
        let cases = vectors["vectors"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            let decapsulation = DecapsulationKey::from(array::<32>(case["seed"].as_str().unwrap()));
            let encapsulation = decapsulation.encapsulation_key();
            assert_eq!(
                to_hex(&encapsulation.to_bytes()),
                case["pk"].as_str().unwrap()
            );
            let randomness: [u8; 64] = array(case["eseed"].as_str().unwrap());
            let (ct, shared) = encapsulation.encapsulate_deterministic((&randomness).into());
            assert_eq!(to_hex(&ct), case["ct"].as_str().unwrap());
            assert_eq!(to_hex(&shared), case["ss"].as_str().unwrap());
            assert_eq!(
                to_hex(&decapsulation.decapsulate(&ct)),
                case["ss"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn key_generation_from_seed_matches_draft_11_public_keys() {
        for case in load("xwing-draft11")["vectors"].as_array().unwrap() {
            let secret = KemSecretKey::from_seed(&SecretKey::from_bytes(array(
                case["seed"].as_str().unwrap(),
            )))
            .unwrap();
            assert_eq!(
                to_hex(secret.public_key().as_bytes()),
                case["pk"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn hpke_matches_pq_draft_vector() {
        let case = &load("hpke-xwing")["cases"][0];
        let secret = KemSecretKey::from_seed(&SecretKey::from_bytes(array(
            case["seed"].as_str().unwrap(),
        )))
        .unwrap();
        let public = secret.public_key();
        assert_eq!(
            to_hex(public.as_bytes()),
            case["public_key"].as_str().unwrap()
        );
        let public = KemPublicKey::from_bytes(array(case["public_key"].as_str().unwrap())).unwrap();
        let sealed = seal_with_randomness(
            &public,
            array(case["randomness"].as_str().unwrap()),
            &field(case, "info"),
            &field(case, "aad"),
            &field(case, "plaintext"),
        )
        .unwrap();
        assert_eq!(to_hex(&sealed.enc), case["enc"].as_str().unwrap());
        assert_eq!(to_hex(&sealed.ct), case["ciphertext"].as_str().unwrap());
        let opened = hpke_open(
            &secret,
            &array(case["enc"].as_str().unwrap()),
            &field(case, "info"),
            &field(case, "aad"),
            &field(case, "ciphertext"),
        )
        .unwrap();
        assert_eq!(opened.expose(), field(case, "plaintext").as_slice());
    }

    #[test]
    fn round_trips_and_binds_info_and_aad() {
        let (secret, public) = recipient();
        let sealed = hpke_seal(
            &public,
            b"hasp/v1/share",
            b"hasp/v1/share-aad",
            b"vault key",
        )
        .unwrap();
        let opened = hpke_open(
            &secret,
            &sealed.enc,
            b"hasp/v1/share",
            b"hasp/v1/share-aad",
            &sealed.ct,
        )
        .unwrap();
        assert_eq!(opened.expose(), b"vault key");
        assert!(matches!(
            hpke_open(
                &secret,
                &sealed.enc,
                b"other",
                b"hasp/v1/share-aad",
                &sealed.ct
            ),
            Err(CryptoError::Aead)
        ));
        assert!(matches!(
            hpke_open(&secret, &sealed.enc, b"hasp/v1/share", b"other", &sealed.ct),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn seals_are_randomised() {
        let (_, public) = recipient();
        let first = hpke_seal(&public, b"i", b"a", b"m").unwrap();
        let second = hpke_seal(&public, b"i", b"a", b"m").unwrap();
        assert_ne!(first.enc, second.enc);
    }

    #[test]
    fn rejects_tampered_encapsulation_and_ciphertext() {
        let (secret, public) = recipient();
        let sealed = hpke_seal(&public, b"i", b"a", b"message").unwrap();
        for index in [0, 500, 1087, 1088, 1119] {
            let mut enc = sealed.enc;
            enc[index] ^= 1;
            assert!(
                hpke_open(&secret, &enc, b"i", b"a", &sealed.ct).is_err(),
                "enc byte {index}"
            );
        }
        for index in 0..sealed.ct.len() {
            let mut ct = sealed.ct.clone();
            ct[index] ^= 1;
            assert!(matches!(
                hpke_open(&secret, &sealed.enc, b"i", b"a", &ct),
                Err(CryptoError::Aead)
            ));
        }
    }

    #[test]
    fn other_recipient_cannot_open() {
        let (_, public) = recipient();
        let stranger = KemSecretKey::from_seed(&seed(4)).unwrap();
        let sealed = hpke_seal(&public, b"i", b"a", b"message").unwrap();
        assert!(hpke_open(&stranger, &sealed.enc, b"i", b"a", &sealed.ct).is_err());
    }

    #[test]
    fn rejects_encapsulation_keys_failing_the_modulus_check() {
        let vectors = load("xwing-invalid-ek");
        for case in vectors["cases"].as_array().unwrap() {
            let bytes: [u8; XWING_PUBLIC_KEY_LEN] = array(case["public_key"].as_str().unwrap());
            assert!(
                matches!(KemPublicKey::from_bytes(bytes), Err(CryptoError::Kem)),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn modulus_check_does_not_depend_on_the_hpke_crate() {
        let vectors = load("xwing-invalid-ek");
        for case in vectors["cases"].as_array().unwrap() {
            let bytes = field(case, "public_key");
            assert!(check_mlkem_encapsulation_key(bytes.get(..1184).unwrap()).is_err());
        }
        let valid = load("xwing-draft11");
        let pk = field(&valid["vectors"][0], "pk");
        check_mlkem_encapsulation_key(pk.get(..1184).unwrap()).unwrap();
    }

    #[test]
    fn accepts_valid_public_key_and_round_trips_bytes() {
        let (_, public) = recipient();
        let parsed = KemPublicKey::from_bytes(*public.as_bytes()).unwrap();
        assert_eq!(parsed, public);
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", recipient().0), "KemSecretKey(..)");
    }

    #[test]
    fn exhausted_randomness_is_reported() {
        let mut rng = PrefilledRng::new([1; 64]);
        let mut sink = [0_u8; 65];
        rng.take(&mut sink);
        assert!(rng.exhausted);
        assert_eq!(sink, [0; 65]);
    }

    #[test]
    fn prefilled_rng_serves_its_buffer_in_order() {
        let buffer: [u8; 64] = std::array::from_fn(|index| u8::try_from(index).unwrap() + 2);
        let mut rng = PrefilledRng::new(buffer);
        assert_eq!(
            rng.try_next_u32().unwrap(),
            u32::from_le_bytes([2, 3, 4, 5])
        );
        assert_eq!(
            rng.try_next_u64().unwrap(),
            u64::from_le_bytes([6, 7, 8, 9, 10, 11, 12, 13])
        );
        let mut rest = [0_u8; 4];
        rng.try_fill_bytes(&mut rest).unwrap();
        assert_eq!(rest, [14, 15, 16, 17]);
        assert!(!rng.exhausted);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn public_seal_with_randomness_is_the_deterministic_seal() {
        let case = &load("hpke-xwing")["cases"][0];
        let public = KemPublicKey::from_bytes(array(case["public_key"].as_str().unwrap())).unwrap();
        let sealed = hpke_seal_with_randomness(
            &public,
            array(case["randomness"].as_str().unwrap()),
            &field(case, "info"),
            &field(case, "aad"),
            &field(case, "plaintext"),
        )
        .unwrap();
        assert_eq!(to_hex(&sealed.enc), case["enc"].as_str().unwrap());
        assert_eq!(to_hex(&sealed.ct), case["ciphertext"].as_str().unwrap());
    }

    #[test]
    fn modulus_check_covers_every_coefficient_position() {
        let mut key = [0_u8; MLKEM768_ENCAPSULATION_KEY_LEN];
        check_mlkem_encapsulation_key(&key).unwrap();
        for index in 0..768_usize {
            for (value, valid) in [(MLKEM_Q - 1, true), (MLKEM_Q, false), (0xfff, false)] {
                let mut candidate = key;
                let byte = index / 2 * 3;
                let [low, high] = value.to_le_bytes();
                if index % 2 == 0 {
                    candidate[byte] = low;
                    candidate[byte + 1] = high & 0x0f;
                } else {
                    candidate[byte + 1] = low << 4;
                    candidate[byte + 2] = (value >> 4).to_le_bytes()[0];
                }
                assert_eq!(
                    check_mlkem_encapsulation_key(&candidate).is_ok(),
                    valid,
                    "coefficient {index} value {value}"
                );
            }
        }
        key[0] = 1;
        check_mlkem_encapsulation_key(&key).unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn open_inverts_seal(
            key_seed in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 0..128),
            info in proptest::collection::vec(any::<u8>(), 0..32),
            aad in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let secret = KemSecretKey::from_seed(&SecretKey::from_bytes(key_seed)).unwrap();
            let public = secret.public_key();
            let sealed = hpke_seal(&public, &info, &aad, &plaintext).unwrap();
            let opened = hpke_open(&secret, &sealed.enc, &info, &aad, &sealed.ct).unwrap();
            prop_assert_eq!(opened.expose(), plaintext.as_slice());
        }
    }
}
