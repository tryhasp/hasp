use core::fmt;

use hasp_crypto::{random_array, sha256};

use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};
use hasp_crypto::to_hex as hex;

pub(crate) const ID_LEN: usize = 16;
pub(crate) const HASH_LEN: usize = 32;
const PIN_ID_LABEL: &[u8] = b"hasp/v1/pin-id";

macro_rules! id16 {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            pub fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            pub fn random() -> Result<Self, ProtoError> {
                random_array::<ID_LEN>().map(Self).map_err(ProtoError::from)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex(&self.0))
            }
        }

        impl Wire for $name {
            fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
                w.bytes(&self.0)
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
                r.fixed().map(Self)
            }
        }
    };
}

id16!(AccountId);
id16!(VaultId);
id16!(ItemId);
id16!(DeviceId);
id16!(AttId);
id16!(InviteId);
id16!(Esid);

impl ItemId {
    pub const VAULT_SETTINGS: Self = Self([0; ID_LEN]);

    pub fn pin(account: &AccountId) -> Self {
        let digest = sha256(&[PIN_ID_LABEL, account.as_bytes()]);
        let mut id = [0; ID_LEN];
        id.copy_from_slice(digest.get(..ID_LEN).unwrap_or(&[0; ID_LEN]));
        Self(id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32([u8; HASH_LEN]);

impl Hash32 {
    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn digest(parts: &[&[u8]]) -> Self {
        Self(sha256(parts))
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex(&self.0))
    }
}

impl Wire for Hash32 {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.bytes(&self.0)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.fixed().map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_id_is_the_truncated_hash_of_label_and_account() {
        let account = AccountId::from_bytes([7; ID_LEN]);
        let digest = Hash32::digest(&[b"hasp/v1/pin-id", account.as_bytes()]);
        assert_eq!(
            ItemId::pin(&account).as_bytes()[..],
            digest.as_bytes()[..ID_LEN]
        );
    }

    #[test]
    fn ids_decode_only_sixteen_bytes() {
        assert!(AccountId::from_cbor(&[0x4f]).is_err());
        let mut w = Writer::new();
        w.bytes(&[1; 17]).unwrap();
        assert!(VaultId::from_cbor(&w.into_bytes()).is_err());
    }

    #[test]
    fn debug_prints_hex() {
        assert_eq!(
            format!("{:?}", ItemId::VAULT_SETTINGS),
            format!("ItemId({})", "00".repeat(16))
        );
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(AccountId::random().unwrap(), AccountId::random().unwrap());
    }
}
