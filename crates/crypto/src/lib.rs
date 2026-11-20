#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::float_arithmetic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::wildcard_enum_match_arm
)]

#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("the testing feature must not be enabled in a release build");

mod aead;
mod es256;
mod hash;
mod hex;
mod kdf;
mod kem;
mod opaque;
mod random;
mod secret;
mod sign;
#[cfg(test)]
mod testutil;
mod x25519;

pub use aead::{Sealed, open, seal, seal_with_nonce};
pub use es256::{ES256_COORD_LEN, ES256_SEC1_LEN, Es256Key, verify_es256};
pub use hash::{HmacAlg, SHA1_LEN, SHA256_LEN, ct_eq, hmac, hmac_sha256, sha1_of_secret, sha256};
pub use hex::{from_hex, to_hex};
pub use kdf::{Argon2idParams, Prk, argon2id, hkdf_expand, hkdf_expand_key, hkdf_extract};
#[cfg(feature = "testing")]
pub use kem::hpke_seal_with_randomness;
pub use kem::{HpkeSealed, KemPublicKey, KemSecretKey, hpke_open, hpke_seal};
pub use opaque::{
    OpaqueClientLogin, OpaqueClientRegistration, OpaqueIdentities, OpaqueLoginBinding,
    OpaqueServerLogin, OpaqueServerSetup, OpaqueSessionKey, opaque_check_record,
    opaque_login_start, opaque_register_response,
};
pub use random::{fill_random, random_array};
pub use secret::{SecretBytes, SecretKey};
pub use sign::{Signature, SigningKey, VerifyingKey, verify_strict};
pub use x25519::{X25519_LEN, X25519Secret};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;
pub const VERIFYING_KEY_LEN: usize = 32;
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_ENCAPSULATED_LEN: usize = 1120;
pub const XWING_SEED_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("aead open failed")]
    Aead,
    #[error("signature rejected")]
    Signature,
    #[error("invalid length")]
    Length,
    #[error("kdf parameters out of range")]
    KdfParams,
    #[error("invalid key encapsulation")]
    Kem,
    #[error("opaque failure")]
    Opaque,
    #[error("randomness unavailable")]
    Random,
    #[error("internal: {0}")]
    Internal(&'static str),
}
