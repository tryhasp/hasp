use std::fmt;

use crate::model::ModelError;

pub const ID_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; ID_LEN]);

impl Id {
    pub fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Result<Self, ModelError> {
        Ok(Self(hasp_crypto::random_array::<ID_LEN>()?))
    }

    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_hex() {
        assert_eq!(
            format!("{:?}", Id::from_bytes([0xab; ID_LEN])),
            "ab".repeat(ID_LEN)
        );
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(Id::random().unwrap(), Id::random().unwrap());
    }
}
