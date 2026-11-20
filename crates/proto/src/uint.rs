use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uint53(u64);

impl Uint53 {
    pub const MAX: u64 = (1 << 53) - 1;
    pub const ZERO: Self = Self(0);

    pub fn new(value: u64) -> Result<Self, ProtoError> {
        if value > Self::MAX {
            return Err(ProtoError::Format);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> Result<Self, ProtoError> {
        let next = self.0.checked_add(1).ok_or(ProtoError::Format)?;
        Self::new(next)
    }
}

impl From<u32> for Uint53 {
    fn from(value: u32) -> Self {
        Self(u64::from(value))
    }
}

impl Wire for Uint53 {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.uint(self.0)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.uint()
    }
}

macro_rules! counter {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uint53);

        impl $name {
            pub const ZERO: Self = Self(Uint53::ZERO);

            pub fn new(value: u64) -> Result<Self, ProtoError> {
                Uint53::new(value).map(Self)
            }

            pub fn get(self) -> u64 {
                self.0.get()
            }

            pub fn uint(self) -> Uint53 {
                self.0
            }

            pub fn checked_next(self) -> Result<Self, ProtoError> {
                self.0.checked_next().map(Self)
            }
        }

        impl Wire for $name {
            fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
                self.0.encode(w)
            }

            fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
                Uint53::decode(r).map(Self)
            }
        }
    };
}

counter!(Epoch);
counter!(Version);
counter!(Seq);
counter!(Rver);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_checks_the_53_bit_range() {
        assert!(Uint53::new(Uint53::MAX).is_ok());
        assert!(Uint53::new(Uint53::MAX + 1).is_err());
    }

    #[test]
    fn next_fails_at_the_maximum() {
        assert_eq!(Seq::new(4).unwrap().checked_next().unwrap().get(), 5);
        assert!(Seq::new(Uint53::MAX).unwrap().checked_next().is_err());
    }

    #[test]
    fn decode_rejects_values_above_the_range() {
        let bytes = [0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(Epoch::from_cbor(&bytes).is_err());
    }
}
