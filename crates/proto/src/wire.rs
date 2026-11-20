macro_rules! message {
    ($name:ident {}) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name;

        impl $crate::Wire for $name {
            fn encode(&self, w: &mut $crate::Writer) -> Result<(), $crate::ProtoError> {
                w.map(0)
            }

            fn decode(r: &mut $crate::Reader<'_>) -> Result<Self, $crate::ProtoError> {
                r.map(|_, n| {
                    if n == 0 {
                        Ok(Self)
                    } else {
                        Err($crate::ProtoError::Format)
                    }
                })
            }
        }
    };
    ($(#[$meta:meta])* $name:ident { $($key:literal $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            $(pub $field: $ty),*
        }

        impl $name {
            const KEYS: &'static [u8] = &[$($key),*];
        }

        impl $crate::Wire for $name {
            fn encode(&self, w: &mut $crate::Writer) -> Result<(), $crate::ProtoError> {
                w.map(Self::KEYS.len())?;
                $(w.field($key, &self.$field)?;)*
                Ok(())
            }

            fn decode(r: &mut $crate::Reader<'_>) -> Result<Self, $crate::ProtoError> {
                r.map(|r, n| {
                    if n != Self::KEYS.len() {
                        return Err($crate::ProtoError::Format);
                    }
                    Ok(Self {
                        $($field: r.field($key)?),*
                    })
                })
            }
        }
    };
}

macro_rules! code_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $code:literal),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum $name {
            $($variant),*
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            pub fn code(self) -> u64 {
                match self {
                    $(Self::$variant => $code),*
                }
            }

            pub fn from_code(code: u64) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }

        impl $crate::Wire for $name {
            fn encode(&self, w: &mut $crate::Writer) -> Result<(), $crate::ProtoError> {
                w.uint(self.code())
            }

            fn decode(r: &mut $crate::Reader<'_>) -> Result<Self, $crate::ProtoError> {
                Self::from_code(r.uint()?.get()).ok_or($crate::ProtoError::Format)
            }
        }
    };
}

macro_rules! operation {
    ($request:ident => $response:ty, $id:ident) => {
        impl Operation for $request {
            type Response = $response;
            const ID: OpId = OpId::$id;
        }
    };
}

mod account;
mod common;
mod enrol;
mod vault;

pub use account::*;
pub use common::*;
pub use enrol::*;
pub use vault::*;

#[cfg(test)]
mod tests;
