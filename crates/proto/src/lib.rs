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

mod aad;
pub mod base64url;
mod cbor;
mod entropy;
mod fingerprint;
mod hexenc;
pub use hexenc::{crockford_decode, crockford_encode};
mod id;
mod label;
mod ops;
pub mod payload;
mod pin;
mod record;
mod sealed;
mod secret_key;
mod signed;
mod uint;
mod verify;
pub mod wire;
mod wirekeys;

#[cfg(test)]
mod codec;
#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod identity;
#[cfg(test)]
mod scenarios;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod vectors;

pub use aad::{Aad, Extra, ExtraValue, LocalField, Rtype};
pub use cbor::{MAX_ARRAY, MAX_NESTING, MAX_RECORD, MAX_TEXT, Reader, Wire, Writer};
#[cfg(any(test, feature = "testing"))]
pub use entropy::SeededEntropy;
pub use entropy::{Entropy, OsEntropy};
pub use fingerprint::{fingerprint, format_fingerprint, head_code, parse_fingerprint};
pub use id::{AccountId, AttId, DeviceId, Esid, Hash32, InviteId, ItemId, VaultId};
pub use label::{CtxValue, HPKE_SHARE_AAD, HPKE_SHARE_INFO, Kdf, SigLabel, derive};
pub use ops::{ItemOp, Leaf, LeafFlag, LeafSet, item_wire_hash, leaf_hash, leafset_root};
pub use pin::{Pin, PinCheck, PinLevel, PinState, pin_check};
pub use record::account::{AccountRecord, AccountStatus, KdfWire};
pub use record::dissolve::Dissolve;
pub use record::invite::{FINGERPRINT_LEN, InviteCode};
pub use record::item::{ItemBody, ItemWire};
pub use record::keyset::{Keyset, KeysetKeys, RetiredKey};
pub use record::leave::LeaveRequest;
pub use record::manifest::Manifest;
pub use record::recovery::RecoveryEnrolment;
pub use record::roster::{Member, Role, Roster, VaultKind};
pub use record::share::{SHARE_CT_LEN, Share};
pub use sealed::{Sealed, SealedPadded, SealedRaw, SecretWire, pad, unpad};
pub use secret_key::{
    SECRET_SYMBOLS, SecretAscii, SecretKind, SecretText, encode_secret_key, parse_secret_key,
};
pub use signed::Signed;
pub use uint::{Epoch, Rver, Seq, Uint53, Version};
#[cfg(any(test, feature = "testing"))]
pub use verify::seal_share_with_randomness;
pub use verify::{
    AccountSeen, ChainError, Commit, HeadRoot, ItemParams, OpenedItem, OwnKeys, ShareKey,
    VaultState, VerifiedRoster, VerifiedShare, chained_history, open_item, open_item_unverified,
    open_share, rewrap_item, seal_item, seal_item_with, seal_share, tombstone,
    verify_account_record, verify_batch, verify_chain, verify_dissolve, verify_genesis,
    verify_leave, verify_repair, verify_roster, verify_share, vk_commit,
};

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("format")]
    Format,
    #[error("version")]
    Version,
    #[error("signature")]
    Sig,
    #[error("aead")]
    Aead,
    #[error("pin")]
    Pin,
    #[error("rollback")]
    Rollback,
    #[error("fork")]
    Fork,
    #[error("roster")]
    Roster,
    #[error("kdf parameters")]
    KdfParams,
    #[error("epoch")]
    Epoch,
    #[error("root")]
    Root,
    #[error("authorization")]
    Authz,
    #[error("invite")]
    Invite,
    #[error("internal: {0}")]
    Internal(&'static str),
}

impl ProtoError {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Format => "Format",
            Self::Version => "Version",
            Self::Sig => "Sig",
            Self::Aead => "Aead",
            Self::Pin => "Pin",
            Self::Rollback => "Rollback",
            Self::Fork => "Fork",
            Self::Roster => "Roster",
            Self::KdfParams => "KdfParams",
            Self::Epoch => "Epoch",
            Self::Root => "Root",
            Self::Authz => "Authz",
            Self::Invite => "Invite",
            Self::Internal(_) => "Internal",
        }
    }
}

impl From<hasp_crypto::CryptoError> for ProtoError {
    fn from(error: hasp_crypto::CryptoError) -> Self {
        match error {
            hasp_crypto::CryptoError::Aead => Self::Aead,
            hasp_crypto::CryptoError::Signature => Self::Sig,
            hasp_crypto::CryptoError::KdfParams => Self::KdfParams,
            hasp_crypto::CryptoError::Length | hasp_crypto::CryptoError::Kem => Self::Format,
            hasp_crypto::CryptoError::Opaque
            | hasp_crypto::CryptoError::Random
            | hasp_crypto::CryptoError::Internal(_) => Self::Internal("crypto"),
        }
    }
}
