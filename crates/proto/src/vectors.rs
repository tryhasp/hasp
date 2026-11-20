use std::fs;
use std::path::PathBuf;

use hasp_crypto::{KemPublicKey, SecretBytes, SecretKey, VerifyingKey};
use serde_json::{Value, json};

use crate::testkit::{CloneKey, Entry, Person, Vault, bump, dissolve_entries, map_bytes, resign};
use crate::{
    Aad, AccountId, AccountRecord, AccountSeen, AccountStatus, AttId, Commit, CtxValue, DeviceId,
    Dissolve, Epoch, Extra, ExtraValue, HPKE_SHARE_AAD, HPKE_SHARE_INFO, Hash32, InviteCode,
    InviteId, ItemId, ItemOp, ItemParams, Kdf, KdfWire, Keyset, KeysetKeys, Leaf, LeafFlag,
    LeaveRequest, LocalField, Manifest, OpenedItem, Pin, PinLevel, PinState, ProtoError,
    RecoveryEnrolment, Role, Roster, Rver, Sealed, SealedPadded, SealedRaw, SecretAscii,
    SecretKind, SeededEntropy, Seq, Share, SigLabel, Signed, Uint53, VaultId, VaultKind,
    VaultState, Version, Wire, Writer, encode_secret_key, fingerprint, format_fingerprint,
    head_code, leafset_root, open_item, open_share, pad, parse_secret_key, seal_item_with,
    tombstone, unpad, verify_account_record, verify_batch, verify_dissolve, verify_genesis,
    verify_leave, verify_repair, verify_share,
};
use hasp_crypto::to_hex as hex;

pub(super) type Mutation = fn(&mut Manifest);
pub(super) type Entries = Vec<(u64, Entry)>;

const GENERATOR: &str =
    "hasp-proto testvectors v1: HASP_UPDATE_VECTORS=1 cargo test -p hasp-proto vectors";

pub(super) fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/proto")
}

pub(super) fn sync(name: &str, mut value: Value) -> Value {
    value["generator"] = json!(GENERATOR);
    let text = format!("{}\n", serde_json::to_string(&value).unwrap());
    let path = dir().join(name);
    if std::env::var_os("HASP_UPDATE_VECTORS").is_some() {
        fs::create_dir_all(dir()).unwrap();
        fs::write(&path, &text).unwrap();
    }
    let on_disk = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing {name}: run with HASP_UPDATE_VECTORS=1"));
    assert_eq!(
        on_disk, text,
        "{name} is out of date: run with HASP_UPDATE_VECTORS=1"
    );
    serde_json::from_str(&on_disk).unwrap()
}

pub(super) fn drop_last(text: &str) -> String {
    let mut owned = text.to_owned();
    owned.pop();
    owned
}

pub(super) fn unhex(text: &str) -> Vec<u8> {
    hasp_crypto::from_hex(text).unwrap()
}

pub(super) fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

pub(super) fn bytes_of(value: &Value, key: &str) -> Vec<u8> {
    unhex(field(value, key).as_str().unwrap())
}

pub(super) fn array16(value: &Value, key: &str) -> [u8; 16] {
    bytes_of(value, key).try_into().unwrap()
}

pub(super) fn array32(value: &Value, key: &str) -> [u8; 32] {
    bytes_of(value, key).try_into().unwrap()
}

pub(super) fn uint(value: &Value, key: &str) -> Uint53 {
    Uint53::new(field(value, key).as_u64().unwrap()).unwrap()
}

mod aad;
mod account;
mod cbor;
mod chain;
mod fingerprints;
mod fixtures;
mod item;
mod labels;
mod lifecycle;
mod padding;
mod records;
mod secret_key;
mod share;
mod verify;

use account::*;
use cbor::decode_named;
use chain::*;
use fixtures::*;
use item::*;
use lifecycle::*;
use share::*;
