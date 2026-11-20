use hasp_crypto::{Argon2idParams, SecretKey};
use hasp_proto::{ProtoError, VaultKind};
use secrecy::SecretString;

use crate::import::AttachedFile;
use crate::model::ModelError;
use crate::model::id::Id;
use crate::model::item::Item;

#[derive(Debug, Clone, Copy)]
struct Counts {
    vaults: u64,
    items: u64,
    attachments: u64,
}

mod header;
mod reader;
mod writer;

#[cfg(test)]
mod tests;

pub use header::peek;
pub use reader::read;
pub use writer::write;

pub const MAGIC: [u8; 4] = *b"VLTX";
pub const VERSION: u64 = 1;
pub const CHUNK_SIZE: usize = 1 << 20;
pub const PIECE_SIZE: usize = 1 << 20;
const NONCE_PREFIX_LEN: usize = 15;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const MAX_KDF_M_KIB: u32 = 524_288;
const MAX_KDF_T: u32 = 12;
const MAX_KDF_P: u32 = 4;
const KCV_LEN: usize = 16;
const MAX_FILE_BYTES: usize = 2 << 30;
const MAX_ATTACHMENT_BYTES: u64 = 100 << 20;
const MODE_PASSPHRASE: u64 = 1;
const MODE_BACKUP_KEY: u64 = 2;
const RECORD_VAULT: u64 = 1;
const RECORD_ITEM: u64 = 2;
const RECORD_ATTACHMENT: u64 = 3;
const RECORD_END: u64 = 9;

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("format: {0}")]
    Format(&'static str),
    #[error("unsupported version")]
    Version,
    #[error("wrong passphrase or damaged header")]
    WrongPassphrase,
    #[error("corrupt export: {0}")]
    Corrupt(&'static str),
    #[error("the file needs a different kind of key")]
    KeyMode,
    #[error("kdf parameters out of range")]
    KdfParams,
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    #[error("model: {0}")]
    Model(#[from] ModelError),
    #[error("proto: {0}")]
    Proto(#[from] ProtoError),
    #[error("crypto: {0}")]
    Crypto(#[from] hasp_crypto::CryptoError),
    #[error("io")]
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportVault {
    pub id: Id,
    pub name: String,
    pub kind: VaultKind,
}

/// Items carry no attachment descriptors; file bytes travel in `files`.
#[derive(Debug)]
pub struct ExportItem {
    pub vault_id: Id,
    pub item_id: Id,
    pub item: Item,
    pub history: Vec<Item>,
    pub files: Vec<AttachedFile>,
}

#[derive(Debug)]
pub struct ExportContent {
    pub vaults: Vec<ExportVault>,
    pub items: Vec<ExportItem>,
}

pub enum Protection<'a> {
    Passphrase {
        passphrase: &'a SecretString,
        params: Argon2idParams,
    },
    BackupKey {
        key: &'a SecretKey,
        params: Argon2idParams,
        salt: [u8; SALT_LEN],
    },
}

pub enum Unlock<'a> {
    Passphrase(&'a SecretString),
    BackupKey(&'a SecretKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    Passphrase,
    BackupKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    pub created: u64,
    pub key_mode: KeyMode,
}

impl std::fmt::Debug for Protection<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Protection(..)")
    }
}

impl std::fmt::Debug for Unlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Unlock(..)")
    }
}
