use hasp_crypto::{Prk, SecretKey, hkdf_expand_key};

use crate::ProtoError;
use crate::cbor::Writer;
use crate::uint::Uint53;

pub const HPKE_SHARE_INFO: &str = "hasp/v1/share";
pub const HPKE_SHARE_AAD: &str = "hasp/v1/share-aad";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kdf {
    ArgonSalt,
    TwoSkd,
    Auk,
    OpaqueInput,
    KeysetSeal,
    SelfWrap,
    AccountMeta,
    ItemWrap,
    Field,
    AttChunk,
    VkCommit,
    RcPrk,
    RcWrap,
    RcAuth,
    SessionToken,
    EnrolMac,
    EnrolKey,
    EnrolCode,
    EnrolCommit,
    Fp,
    SkCheck,
    HeadCode,
    Leafset,
    PinId,
    ExportKey,
    ExportKcv,
    SrvOprf,
    SrvAke,
    SrvPrelogin,
}

impl Kdf {
    pub const ALL: [Self; 29] = [
        Self::ArgonSalt,
        Self::TwoSkd,
        Self::Auk,
        Self::OpaqueInput,
        Self::KeysetSeal,
        Self::SelfWrap,
        Self::AccountMeta,
        Self::ItemWrap,
        Self::Field,
        Self::AttChunk,
        Self::VkCommit,
        Self::RcPrk,
        Self::RcWrap,
        Self::RcAuth,
        Self::SessionToken,
        Self::EnrolMac,
        Self::EnrolKey,
        Self::EnrolCode,
        Self::EnrolCommit,
        Self::Fp,
        Self::SkCheck,
        Self::HeadCode,
        Self::Leafset,
        Self::PinId,
        Self::ExportKey,
        Self::ExportKcv,
        Self::SrvOprf,
        Self::SrvAke,
        Self::SrvPrelogin,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::ArgonSalt => "hasp/v1/argon-salt",
            Self::TwoSkd => "hasp/v1/2skd",
            Self::Auk => "hasp/v1/auk",
            Self::OpaqueInput => "hasp/v1/opaque-input",
            Self::KeysetSeal => "hasp/v1/keyset-seal",
            Self::SelfWrap => "hasp/v1/self-wrap",
            Self::AccountMeta => "hasp/v1/account-meta",
            Self::ItemWrap => "hasp/v1/item-wrap",
            Self::Field => "hasp/v1/field",
            Self::AttChunk => "hasp/v1/att-chunk",
            Self::VkCommit => "hasp/v1/vk-commit",
            Self::RcPrk => "hasp/v1/rc-prk",
            Self::RcWrap => "hasp/v1/rc-wrap",
            Self::RcAuth => "hasp/v1/rc-auth",
            Self::SessionToken => "hasp/v1/session-token",
            Self::EnrolMac => "hasp/v1/enrol-mac",
            Self::EnrolKey => "hasp/v1/enrol-key",
            Self::EnrolCode => "hasp/v1/enrol-code",
            Self::EnrolCommit => "hasp/v1/enrol-commit",
            Self::Fp => "hasp/v1/fp",
            Self::SkCheck => "hasp/v1/sk-check",
            Self::HeadCode => "hasp/v1/head-code",
            Self::Leafset => "hasp/v1/leafset",
            Self::PinId => "hasp/v1/pin-id",
            Self::ExportKey => "hasp/v1/export-key",
            Self::ExportKcv => "hasp/v1/export-kcv",
            Self::SrvOprf => "hasp/v1/srv/oprf",
            Self::SrvAke => "hasp/v1/srv/ake",
            Self::SrvPrelogin => "hasp/v1/srv/prelogin",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigLabel {
    Account,
    Roster,
    Manifest,
    Share,
    Recovery,
    Dissolve,
    Leave,
}

impl SigLabel {
    pub const ALL: [Self; 7] = [
        Self::Account,
        Self::Roster,
        Self::Manifest,
        Self::Share,
        Self::Recovery,
        Self::Dissolve,
        Self::Leave,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Account => "hasp/v1/sig/account",
            Self::Roster => "hasp/v1/sig/roster",
            Self::Manifest => "hasp/v1/sig/manifest",
            Self::Share => "hasp/v1/sig/share",
            Self::Recovery => "hasp/v1/sig/recovery",
            Self::Dissolve => "hasp/v1/sig/dissolve",
            Self::Leave => "hasp/v1/sig/leave",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CtxValue {
    Uint(Uint53),
    Bytes(Vec<u8>),
    Id16([u8; 16]),
}

impl CtxValue {
    pub(crate) fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        match self {
            Self::Uint(value) => w.uint(value.get()),
            Self::Bytes(bytes) => w.bytes(bytes),
            Self::Id16(id) => w.bytes(id),
        }
    }
}

pub(crate) fn info(label: &str, ctx: &[CtxValue]) -> Result<Vec<u8>, ProtoError> {
    let mut w = Writer::new();
    w.array(ctx.len().checked_add(1).ok_or(ProtoError::Format)?)?;
    w.text(label)?;
    for value in ctx {
        value.encode(&mut w)?;
    }
    Ok(w.into_bytes())
}

pub fn derive(key: &SecretKey, label: Kdf, ctx: &[CtxValue]) -> Result<SecretKey, ProtoError> {
    let prk = Prk::from_secret(key.duplicate());
    hkdf_expand_key(&prk, &info(label.name(), ctx)?).map_err(ProtoError::from)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const KDF_NAMES: [&str; 29] = [
        "argon-salt",
        "2skd",
        "auk",
        "opaque-input",
        "keyset-seal",
        "self-wrap",
        "account-meta",
        "item-wrap",
        "field",
        "att-chunk",
        "vk-commit",
        "rc-prk",
        "rc-wrap",
        "rc-auth",
        "session-token",
        "enrol-mac",
        "enrol-key",
        "enrol-code",
        "enrol-commit",
        "fp",
        "sk-check",
        "head-code",
        "leafset",
        "pin-id",
        "export-key",
        "export-kcv",
        "srv/oprf",
        "srv/ake",
        "srv/prelogin",
    ];

    #[test]
    fn kdf_labels_match_appendix_a_exactly() {
        for (kdf, name) in Kdf::ALL.iter().zip(KDF_NAMES) {
            assert_eq!(kdf.name(), format!("hasp/v1/{name}"));
        }
    }

    #[test]
    fn every_label_is_unique() {
        let mut seen = BTreeSet::new();
        for kdf in Kdf::ALL {
            assert!(seen.insert(kdf.name()));
        }
        for label in SigLabel::ALL {
            assert!(seen.insert(label.name()));
        }
        assert!(seen.insert(HPKE_SHARE_INFO));
        assert!(seen.insert(HPKE_SHARE_AAD));
        assert_eq!(seen.len(), 29 + 7 + 2);
    }

    #[test]
    fn signature_labels_match_appendix_a_exactly() {
        let names: Vec<_> = SigLabel::ALL.iter().map(|l| l.name()).collect();
        assert_eq!(
            names,
            [
                "hasp/v1/sig/account",
                "hasp/v1/sig/roster",
                "hasp/v1/sig/manifest",
                "hasp/v1/sig/share",
                "hasp/v1/sig/recovery",
                "hasp/v1/sig/dissolve",
                "hasp/v1/sig/leave",
            ]
        );
    }

    #[test]
    fn info_is_a_cbor_array_of_label_and_context() {
        let bytes = info("hasp/v1/field", &[CtxValue::Uint(Uint53::new(1).unwrap())]).unwrap();
        assert_eq!(&bytes[..2], [0x82, 0x6d]);
        assert_eq!(bytes.last(), Some(&0x01));
    }

    #[test]
    fn different_labels_and_contexts_derive_different_keys() {
        let key = SecretKey::from_bytes([9; 32]);
        let a = derive(&key, Kdf::Auk, &[]).unwrap();
        let b = derive(&key, Kdf::OpaqueInput, &[]).unwrap();
        let c = derive(&key, Kdf::Auk, &[CtxValue::Id16([1; 16])]).unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
        assert_eq!(a.expose(), derive(&key, Kdf::Auk, &[]).unwrap().expose());
    }
}
