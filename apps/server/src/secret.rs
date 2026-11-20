use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use hasp_crypto::{
    Argon2idParams, OpaqueServerSetup, SecretKey, argon2id, fill_random, open, seal, sha256,
};
use hasp_proto::wire::{SignupToken, TokenKind};
use hasp_proto::{AccountId, FINGERPRINT_LEN, format_fingerprint};
use zeroize::Zeroizing;

use crate::persist::{PersistError, create_dir_durable, sync_dir, write_durable};
use crate::store::{AccountState, Store, TokenRow};

const EXPORT_MAGIC: &[u8; 4] = b"HSK1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 12 + SALT_LEN;
const MAX_M_KIB: u32 = 524_288;
const MAX_T: u32 = 12;
const MAX_P: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    Loaded,
    Generated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReregisterToken {
    pub account_id: AccountId,
    pub login: String,
    pub token: SignupToken,
    pub expires: u64,
}

/// Writes the key with mode 0600 and fsyncs it; refuses to overwrite one.
pub fn generate_server_key(path: &Path) -> Result<SecretKey, PersistError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_durable(parent)?;
    }
    let key = SecretKey::random()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            PersistError::KeyExists
        } else {
            PersistError::Io(error)
        }
    })?;
    file.write_all(key.expose())?;
    file.sync_all()?;
    drop(file);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent)?;
    }
    Ok(key)
}

#[cfg(unix)]
fn require_private(path: &Path) -> Result<(), PersistError> {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(meta) if meta.permissions().mode() & 0o077 != 0 => Err(PersistError::KeyPermissions),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn require_private(_: &Path) -> Result<(), PersistError> {
    Ok(())
}

pub fn load_server_key(path: &Path) -> Result<SecretKey, PersistError> {
    require_private(path)?;
    let bytes = match fs::read(path).map(Zeroizing::new) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PersistError::KeyMissing);
        }
        Err(error) => return Err(error.into()),
    };
    SecretKey::from_slice(&bytes).map_err(|_| PersistError::KeyFormat)
}

pub fn load_or_generate_server_key(path: &Path) -> Result<(SecretKey, KeyOrigin), PersistError> {
    match load_server_key(path) {
        Ok(key) => Ok((key, KeyOrigin::Loaded)),
        Err(PersistError::KeyMissing) => Ok((generate_server_key(path)?, KeyOrigin::Generated)),
        Err(error) => Err(error),
    }
}

pub fn install_server_key(path: &Path, key: &SecretKey) -> Result<(), PersistError> {
    if path.exists() {
        return Err(PersistError::KeyExists);
    }
    Ok(write_durable(path, key.expose())?)
}

/// The key as `haspd fingerprint` prints it: protocol 2.3 `sf`, the first 15 bytes of
/// SHA-256 over the OPAQUE public key, in Crockford base32 groups.
pub fn server_fingerprint(key: &SecretKey) -> Result<String, PersistError> {
    let public = OpaqueServerSetup::derive(key)?.public_key();
    let digest = sha256(&[&public]);
    let head: [u8; FINGERPRINT_LEN] = digest
        .get(..FINGERPRINT_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PersistError::Encoding)?;
    Ok(format_fingerprint(&head))
}

/// `"HSK1" || m || t || p (u32 BE) || salt || nonce || ciphertext`, sealed with XChaCha20-Poly1305
/// under Argon2id(passphrase, salt). The header is the AAD, so any edit of it fails as a wrong
/// passphrase. The passphrase is taken as the bytes the operator typed.
pub fn export_server_key(
    key: &SecretKey,
    passphrase: &[u8],
    params: Argon2idParams,
) -> Result<Vec<u8>, PersistError> {
    let mut salt = [0_u8; SALT_LEN];
    fill_random(&mut salt)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(EXPORT_MAGIC);
    for value in [params.m_kib(), params.t(), params.p()] {
        header.extend_from_slice(&value.to_be_bytes());
    }
    header.extend_from_slice(&salt);
    let wrapping = argon2id(passphrase, &salt, &params)?;
    let sealed = seal(&wrapping, key.expose(), &header)?;
    let mut out = header;
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ct);
    Ok(out)
}

pub fn import_server_key(export: &[u8], passphrase: &[u8]) -> Result<SecretKey, PersistError> {
    let (header, rest) = export
        .split_at_checked(HEADER_LEN)
        .ok_or(PersistError::KeyFormat)?;
    let (magic, params_and_salt) = header.split_at(EXPORT_MAGIC.len());
    if magic != EXPORT_MAGIC {
        return Err(PersistError::KeyFormat);
    }
    let (numbers, salt) = params_and_salt.split_at(12);
    let mut values = numbers
        .as_chunks::<4>()
        .0
        .iter()
        .copied()
        .map(u32::from_be_bytes);
    let (Some(m), Some(t), Some(p)) = (values.next(), values.next(), values.next()) else {
        return Err(PersistError::KeyFormat);
    };
    if m == 0 || t == 0 || p == 0 || m > MAX_M_KIB || t > MAX_T || p > MAX_P {
        return Err(PersistError::KdfParams);
    }
    let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| PersistError::KeyFormat)?;
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or(PersistError::KeyFormat)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| PersistError::KeyFormat)?;
    let wrapping = argon2id(passphrase, &salt, &Argon2idParams::local(m, t, p)?)?;
    let plain = open(&wrapping, &nonce, ciphertext, header)?;
    SecretKey::from_slice(plain.expose()).map_err(|_| PersistError::KeyFormat)
}

/// For a lost `server.key` (protocol 7.14): one re-registration token per active account, each
/// bound to its account through the token's `target`.
pub fn issue_reregister_tokens(
    store: &mut dyn Store,
    now: u64,
    ttl: u64,
) -> Result<Vec<ReregisterToken>, PersistError> {
    store.begin().map_err(|_| PersistError::Corrupt("begin"))?;
    let issued = issue_inside(store, now, ttl);
    match issued {
        Ok(tokens) => {
            store
                .commit()
                .map_err(|_| PersistError::Corrupt("commit"))?;
            Ok(tokens)
        }
        Err(error) => {
            store
                .rollback()
                .map_err(|_| PersistError::Corrupt("rollback"))?;
            Err(error)
        }
    }
}

fn issue_inside(
    store: &mut dyn Store,
    now: u64,
    ttl: u64,
) -> Result<Vec<ReregisterToken>, PersistError> {
    let lowest = AccountId::from_bytes([0; 16]);
    let highest = AccountId::from_bytes([0xff; 16]);
    let accounts = store
        .accounts()
        .range(&lowest, &highest)
        .map_err(|_| PersistError::Corrupt("accounts"))?;
    let expires = now.saturating_add(ttl);
    let mut out = Vec::new();
    for (account_id, row) in accounts {
        if row.state != AccountState::Active {
            continue;
        }
        let token = SignupToken::random()?;
        store
            .signup_tokens()
            .put(
                token.hash(),
                TokenRow {
                    creator: None,
                    target: Some(account_id),
                    expires,
                    used_by: None,
                    kind: TokenKind::Reregister,
                    makes_admin: false,
                },
            )
            .map_err(|_| PersistError::Corrupt("tokens"))?;
        out.push(ReregisterToken {
            account_id,
            login: row.login,
            token,
            expires,
        });
    }
    Ok(out)
}
