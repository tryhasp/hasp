mod crypto;
mod json;
mod proto;
mod text;
mod verify;

use serde_json::Value;

pub use text::{normalise_login, normalise_password};

pub const GROUPS: [&str; 19] = [
    "crypto/sha256",
    "crypto/hkdf-sha256",
    "crypto/hmac-sha256",
    "crypto/ed25519",
    "crypto/argon2id",
    "crypto/xchacha20poly1305",
    "crypto/xwing-draft11",
    "crypto/xwing-invalid-ek",
    "crypto/hpke-xwing",
    "proto/aad",
    "proto/cbor",
    "proto/fingerprint",
    "proto/labels",
    "proto/padding",
    "proto/records",
    "proto/secret-key",
    "proto/verify",
    "text/password",
    "text/login",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub name: String,
    pub expected: String,
    pub actual: String,
}

impl Outcome {
    pub fn matches(&self) -> bool {
        self.expected == self.actual
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("vector: {0}")]
    Vector(&'static str),
    #[error("proto")]
    Proto(hasp_proto::ProtoError),
    #[error("crypto")]
    Crypto(hasp_crypto::CryptoError),
    #[error("unknown group")]
    Group,
}

pub fn replay(group: &str, vectors: &str) -> Result<Vec<Outcome>, ReplayError> {
    let value: Value =
        serde_json::from_str(vectors).map_err(|_| ReplayError::Vector("not json"))?;
    match group {
        "crypto/sha256" => crypto::sha256_cases(&value),
        "crypto/hkdf-sha256" => crypto::hkdf_cases(&value),
        "crypto/hmac-sha256" => crypto::hmac_cases(&value),
        "crypto/ed25519" => crypto::ed25519_cases(&value),
        "crypto/argon2id" => crypto::argon2id_cases(&value),
        "crypto/xchacha20poly1305" => crypto::xchacha_cases(&value),
        "crypto/xwing-draft11" => crypto::xwing_cases(&value),
        "crypto/xwing-invalid-ek" => crypto::xwing_invalid_cases(&value),
        "crypto/hpke-xwing" => crypto::hpke_cases(&value),
        "proto/aad" => proto::aad(&value),
        "proto/cbor" => proto::cbor(&value),
        "proto/fingerprint" => proto::fingerprints(&value),
        "proto/labels" => proto::labels(&value),
        "proto/padding" => proto::padding(&value),
        "proto/records" => proto::records(&value),
        "proto/secret-key" => proto::secret_key(&value),
        "proto/verify" => verify::replay(&value),
        "text/password" => text::replay(&value, |input| Ok(normalise_password(input))),
        "text/login" => text::replay(&value, normalise_login),
        _ => Err(ReplayError::Group),
    }
}

impl From<hasp_proto::ProtoError> for ReplayError {
    fn from(error: hasp_proto::ProtoError) -> Self {
        Self::Proto(error)
    }
}

impl From<hasp_crypto::CryptoError> for ReplayError {
    fn from(error: hasp_crypto::CryptoError) -> Self {
        Self::Crypto(error)
    }
}
