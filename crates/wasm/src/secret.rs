use hasp_boundary::Mirror;
use hasp_core::api::Secret as CoreSecret;
use serde::de::{Deserializer, Error, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroize;

#[wasm_bindgen(typescript_custom_section)]
const SECRET_TYPE: &str = "export type Secret = Uint8Array;";

pub struct Secret(Vec<u8>);

impl Secret {
    fn take(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

struct Bytes;

impl<'de> Visitor<'de> for Bytes {
    type Value = Secret;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a Uint8Array")
    }

    fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Secret, E> {
        Ok(Secret(value.to_vec()))
    }

    fn visit_byte_buf<E: Error>(self, value: Vec<u8>) -> Result<Secret, E> {
        Ok(Secret(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Secret, A::Error> {
        let mut out = Vec::new();
        while let Some(byte) = seq.next_element::<u8>()? {
            out.push(byte);
        }
        Ok(Secret(out))
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_byte_buf(Bytes)
    }
}

impl Mirror<CoreSecret> for Secret {
    fn mirror(self) -> CoreSecret {
        CoreSecret::new(self.take())
    }
}

impl Mirror<Secret> for CoreSecret {
    fn mirror(self) -> Secret {
        Secret(self.take())
    }
}
