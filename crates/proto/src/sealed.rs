use core::fmt;
use core::marker::PhantomData;

use hasp_crypto::{NONCE_LEN, SecretBytes, SecretKey, TAG_LEN, open, seal_with_nonce};

use crate::ProtoError;
use crate::aad::Aad;
use crate::cbor::{MAX_RECORD, Reader, Wire, Writer};
use crate::entropy::{Entropy, OsEntropy};
use hasp_crypto::to_hex as hex;

const PAD_MARKER: u8 = 0x80;
const MIN_BUCKET: usize = 256;
const MAX_POWER_BUCKET: usize = 65_536;

pub trait SecretWire: Wire {}

pub fn pad(plaintext: &[u8]) -> Result<SecretBytes, ProtoError> {
    let total = bucket(plaintext.len())?;
    let mut padded = Vec::with_capacity(total);
    padded.extend_from_slice(plaintext);
    padded.push(PAD_MARKER);
    padded.resize(total, 0);
    Ok(SecretBytes::from_vec(padded))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "consuming the buffer zeroizes the padded secret on drop"
)]
pub fn unpad(padded: SecretBytes) -> Result<SecretBytes, ProtoError> {
    let data = padded.expose();
    let marker = data
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or(ProtoError::Format)?;
    if data.get(marker) != Some(&PAD_MARKER) || bucket(marker)? != data.len() {
        return Err(ProtoError::Format);
    }
    let mut plaintext = Vec::with_capacity(marker);
    plaintext.extend_from_slice(data.get(..marker).ok_or(ProtoError::Format)?);
    Ok(SecretBytes::from_vec(plaintext))
}

fn bucket(plaintext_len: usize) -> Result<usize, ProtoError> {
    let needed = plaintext_len.checked_add(1).ok_or(ProtoError::Format)?;
    let total = if needed <= MAX_POWER_BUCKET {
        needed.next_power_of_two().max(MIN_BUCKET)
    } else {
        needed
            .div_ceil(MAX_POWER_BUCKET)
            .checked_mul(MAX_POWER_BUCKET)
            .ok_or(ProtoError::Format)?
    };
    if total > MAX_RECORD {
        return Err(ProtoError::Format);
    }
    Ok(total)
}

#[derive(Clone, PartialEq, Eq)]
struct Blob {
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

impl Blob {
    fn new(nonce: [u8; NONCE_LEN], ct: Vec<u8>) -> Result<Self, ProtoError> {
        if ct.len() < TAG_LEN || ct.len() > MAX_RECORD {
            return Err(ProtoError::Format);
        }
        Ok(Self { nonce, ct })
    }

    fn seal(
        entropy: &mut impl Entropy,
        key: &SecretKey,
        plaintext: &[u8],
        aad: &Aad,
    ) -> Result<Self, ProtoError> {
        let nonce = entropy.nonce()?;
        let ct = seal_with_nonce(key, &nonce, plaintext, &aad.to_bytes()?)?;
        Self::new(nonce, ct)
    }

    fn open(&self, key: &SecretKey, aad: &Aad) -> Result<SecretBytes, ProtoError> {
        open(key, &self.nonce, &self.ct, &aad.to_bytes()?).map_err(|_| ProtoError::Aead)
    }

    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.array(2)?;
        w.bytes(&self.nonce)?;
        w.bytes(&self.ct)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.array(|r, n| {
            if n != 2 {
                return Err(ProtoError::Format);
            }
            let nonce = r.fixed()?;
            Self::new(nonce, r.bytes()?.to_vec())
        })
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nonce={} ct_len={}", hex(&self.nonce), self.ct.len())
    }
}

macro_rules! sealed_wrapper {
    ($name:ident $(<$t:ident>)?) => {
        impl$(<$t>)? Wire for $name$(<$t>)? {
            fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
                self.blob.encode(w)
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
                Blob::decode(r).map(Self::from_blob)
            }
        }

        impl$(<$t>)? Clone for $name$(<$t>)? {
            fn clone(&self) -> Self {
                Self::from_blob(self.blob.clone())
            }
        }

        impl$(<$t>)? PartialEq for $name$(<$t>)? {
            fn eq(&self, other: &Self) -> bool {
                self.blob == other.blob
            }
        }

        impl$(<$t>)? Eq for $name$(<$t>)? {}

        impl$(<$t>)? fmt::Debug for $name$(<$t>)? {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.blob)
            }
        }

        impl$(<$t>)? $name$(<$t>)? {
            pub fn from_parts(nonce: [u8; NONCE_LEN], ct: Vec<u8>) -> Result<Self, ProtoError> {
                Blob::new(nonce, ct).map(Self::from_blob)
            }

            pub fn nonce(&self) -> &[u8; NONCE_LEN] {
                &self.blob.nonce
            }

            pub fn ct(&self) -> &[u8] {
                &self.blob.ct
            }

            fn from_blob(blob: Blob) -> Self {
                Self { blob $(, _payload: PhantomData::<fn() -> $t>)? }
            }
        }
    };
}

pub struct Sealed<T> {
    blob: Blob,
    _payload: PhantomData<fn() -> T>,
}

sealed_wrapper!(Sealed<T>);

impl<T: SecretWire> Sealed<T> {
    pub fn seal(key: &SecretKey, value: &T, aad: &Aad) -> Result<Self, ProtoError> {
        Self::seal_with(&mut OsEntropy, key, value, aad)
    }

    pub fn seal_with(
        entropy: &mut impl Entropy,
        key: &SecretKey,
        value: &T,
        aad: &Aad,
    ) -> Result<Self, ProtoError> {
        let padded = pad(&value.to_cbor_secret()?)?;
        Blob::seal(entropy, key, padded.expose(), aad).map(Self::from_blob)
    }

    pub fn open(&self, key: &SecretKey, aad: &Aad) -> Result<T, ProtoError> {
        let plaintext = unpad(self.blob.open(key, aad)?)?;
        T::from_cbor(plaintext.expose())
    }
}

pub struct SealedPadded {
    blob: Blob,
}

sealed_wrapper!(SealedPadded);

impl SealedPadded {
    pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &Aad) -> Result<Self, ProtoError> {
        Self::seal_with(&mut OsEntropy, key, plaintext, aad)
    }

    pub fn seal_with(
        entropy: &mut impl Entropy,
        key: &SecretKey,
        plaintext: &[u8],
        aad: &Aad,
    ) -> Result<Self, ProtoError> {
        let padded = pad(plaintext)?;
        Blob::seal(entropy, key, padded.expose(), aad).map(Self::from_blob)
    }

    pub fn open(&self, key: &SecretKey, aad: &Aad) -> Result<SecretBytes, ProtoError> {
        unpad(self.blob.open(key, aad)?)
    }
}

pub struct SealedRaw {
    blob: Blob,
}

sealed_wrapper!(SealedRaw);

impl SealedRaw {
    pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &Aad) -> Result<Self, ProtoError> {
        Self::seal_with(&mut OsEntropy, key, plaintext, aad)
    }

    pub fn seal_with(
        entropy: &mut impl Entropy,
        key: &SecretKey,
        plaintext: &[u8],
        aad: &Aad,
    ) -> Result<Self, ProtoError> {
        Blob::seal(entropy, key, plaintext, aad).map(Self::from_blob)
    }

    pub fn open(&self, key: &SecretKey, aad: &Aad) -> Result<SecretBytes, ProtoError> {
        self.blob.open(key, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aad::Rtype;
    use crate::id::AccountId;

    fn aad() -> Aad {
        Aad::new(Rtype::Keyset)
            .account(AccountId::from_bytes([1; 16]))
            .field(2)
    }

    #[test]
    fn pad_fills_the_smallest_bucket() {
        assert_eq!(pad(b"").unwrap().len(), 256);
        assert_eq!(pad(&[1; 255]).unwrap().len(), 256);
        assert_eq!(pad(&[1; 256]).unwrap().len(), 512);
        assert_eq!(pad(&vec![1; 65_535]).unwrap().len(), 65_536);
        assert_eq!(pad(&vec![1; 65_536]).unwrap().len(), 131_072);
        assert_eq!(pad(&vec![1; 131_071]).unwrap().len(), 131_072);
        assert_eq!(pad(&vec![1; 131_072]).unwrap().len(), 196_608);
    }

    #[test]
    fn pad_appends_marker_then_zeros() {
        let padded = pad(b"abc").unwrap();
        assert_eq!(&padded.expose()[..5], b"abc\x80\x00");
        assert!(padded.expose()[3..].iter().skip(1).all(|b| *b == 0));
    }

    #[test]
    fn unpad_roundtrips_every_boundary_length() {
        for len in [0, 1, 254, 255, 256, 257, 511, 512, 65_535, 65_536, 65_537] {
            let data = vec![0x7e; len];
            let out = unpad(pad(&data).unwrap()).unwrap();
            assert_eq!(out.expose(), &data[..]);
        }
    }

    #[test]
    fn unpad_rejects_inexact_padding() {
        let mut short = vec![0_u8; 256];
        short[0] = 1;
        short[1] = 0x80;
        assert!(unpad(SecretBytes::from_vec(short.clone())).is_ok());
        short.pop();
        assert!(unpad(SecretBytes::from_vec(short)).is_err());
        assert!(unpad(SecretBytes::from_vec(vec![0; 256])).is_err());
        assert!(unpad(SecretBytes::from_vec(vec![1; 256])).is_err());
        let mut oversize = vec![0_u8; 512];
        oversize[1] = 0x80;
        assert!(unpad(SecretBytes::from_vec(oversize)).is_err());
        assert!(unpad(SecretBytes::from_vec(Vec::new())).is_err());
    }

    #[test]
    fn sealed_padded_roundtrips_and_fails_with_wrong_key_or_aad() {
        let key = SecretKey::from_bytes([3; 32]);
        let sealed = SealedPadded::seal(&key, b"overview", &aad()).unwrap();
        assert_eq!(sealed.open(&key, &aad()).unwrap().expose(), b"overview");
        let other = SecretKey::from_bytes([4; 32]);
        assert!(matches!(sealed.open(&other, &aad()), Err(ProtoError::Aead)));
        let other_aad = Aad::new(Rtype::Keyset)
            .account(AccountId::from_bytes([2; 16]))
            .field(2);
        assert!(matches!(
            sealed.open(&key, &other_aad),
            Err(ProtoError::Aead)
        ));
    }

    #[test]
    fn sealed_raw_is_not_padded() {
        let key = SecretKey::from_bytes([3; 32]);
        let sealed = SealedRaw::seal(&key, &[9; 32], &aad()).unwrap();
        assert_eq!(sealed.ct().len(), 32 + TAG_LEN);
        assert_eq!(sealed.open(&key, &aad()).unwrap().expose(), &[9; 32]);
    }

    #[test]
    fn wire_form_is_nonce_and_ciphertext_and_rejects_short_ciphertext() {
        let key = SecretKey::from_bytes([3; 32]);
        let sealed = SealedRaw::seal(&key, &[9; 32], &aad()).unwrap();
        let bytes = sealed.to_cbor().unwrap();
        assert_eq!(&bytes[..3], [0x82, 0x58, 24]);
        assert_eq!(SealedRaw::from_cbor(&bytes).unwrap(), sealed);
        let mut w = Writer::new();
        w.array(2).unwrap();
        w.bytes(&[0; 24]).unwrap();
        w.bytes(&[0; 15]).unwrap();
        assert!(SealedRaw::from_cbor(&w.into_bytes()).is_err());
    }

    #[test]
    fn flipping_any_ciphertext_byte_fails_closed() {
        let key = SecretKey::from_bytes([3; 32]);
        let sealed = SealedPadded::seal(&key, b"x", &aad()).unwrap();
        for i in 0..sealed.ct().len() {
            let mut ct = sealed.ct().to_vec();
            ct[i] ^= 1;
            let forged = SealedPadded::from_parts(*sealed.nonce(), ct).unwrap();
            assert!(matches!(forged.open(&key, &aad()), Err(ProtoError::Aead)));
        }
    }

    #[test]
    fn seeded_entropy_is_deterministic_and_os_entropy_is_not() {
        use crate::entropy::SeededEntropy;
        let key = SecretKey::from_bytes([3; 32]);
        let seal = |e: &mut SeededEntropy| SealedRaw::seal_with(e, &key, &[1; 32], &aad()).unwrap();
        assert_eq!(
            seal(&mut SeededEntropy::new([5; 32])),
            seal(&mut SeededEntropy::new([5; 32]))
        );
        let a = SealedRaw::seal(&key, &[1; 32], &aad()).unwrap();
        let b = SealedRaw::seal(&key, &[1; 32], &aad()).unwrap();
        assert_ne!(a.nonce(), b.nonce());
    }
}
