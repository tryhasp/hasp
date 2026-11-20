mod harness;
mod person;
mod scratch;
mod vault_model;

pub use harness::{Client, Harness, HarnessOf, ORIGIN, TestStore, Transport};
pub use person::{Person, SecretBytesKey, credential};
pub use scratch::Scratch;
pub use vault_model::VaultModel;

use hasp_crypto::SecretKey;
use hasp_proto::{KdfWire, Uint53};

pub const FLOOR_KDF: KdfWire = KdfWire {
    m: 65_536,
    t: 3,
    p: 4,
};

pub(super) fn copy(key: &SecretKey) -> SecretKey {
    SecretKey::from_bytes(*key.expose())
}

pub(super) fn rnd() -> SecretKey {
    SecretKey::random().expect("os randomness")
}

pub(super) fn uint(value: u64) -> Uint53 {
    Uint53::new(value).expect("small value")
}
