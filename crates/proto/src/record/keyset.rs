use core::fmt;

use hasp_crypto::{SecretBytes, SecretKey};

use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::AccountId;
use crate::record::{begin, read_exact};
use crate::sealed::{Sealed, SealedRaw, SecretWire};
use crate::uint::Uint53;

const KEYSET_ENTRIES: usize = 6;
const KEYS_ENTRIES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetiredKey {}

impl Wire for RetiredKey {
    fn encode(&self, _w: &mut Writer) -> Result<(), ProtoError> {
        match *self {}
    }

    fn decode(_r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Err(ProtoError::Format)
    }
}

pub struct KeysetKeys {
    pub ik_seed: SecretKey,
    pub kem_seed: SecretKey,
    pub sk_ascii: SecretBytes,
    pub retired: Vec<RetiredKey>,
}

impl fmt::Debug for KeysetKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeysetKeys(..)")
    }
}

impl Wire for KeysetKeys {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.map(KEYS_ENTRIES)?;
        w.field(0, &self.ik_seed)?;
        w.field(1, &self.kem_seed)?;
        w.key(2)?;
        w.bytes(self.sk_ascii.expose())?;
        w.field(3, &self.retired)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.map(|r, n| {
            if n != KEYS_ENTRIES {
                return Err(ProtoError::Format);
            }
            let ik_seed = r.field(0)?;
            let kem_seed = r.field(1)?;
            r.key(2)?;
            let sk_ascii = SecretBytes::from_vec(r.bytes()?.to_vec());
            let retired = r.field(3)?;
            Ok(Self {
                ik_seed,
                kem_seed,
                sk_ascii,
                retired,
            })
        })
    }
}

impl SecretWire for KeysetKeys {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keyset {
    pub account_id: AccountId,
    pub generation: Uint53,
    pub ak_wrap: SealedRaw,
    pub keys: Sealed<KeysetKeys>,
}

impl Wire for Keyset {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::Keyset, KEYSET_ENTRIES)?;
        w.field(2, &self.account_id)?;
        w.field(3, &self.generation)?;
        w.field(4, &self.ak_wrap)?;
        w.field(5, &self.keys)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::Keyset, KEYSET_ENTRIES, |r| {
            Ok(Self {
                account_id: r.field(2)?,
                generation: r.field(3)?,
                ak_wrap: r.field(4)?,
                keys: r.field(5)?,
            })
        })
    }
}
