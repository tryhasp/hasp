use hasp_crypto::{
    Argon2idParams, SecretBytes, SecretKey, argon2id, hkdf_expand, hkdf_extract, sha256,
};
use hasp_proto::{AccountId, CtxValue, Kdf, KdfWire, SecretAscii, Writer, derive};
use zeroize::Zeroizing;

use crate::CoreError;
use crate::text::normalise_password;

pub(crate) const SALT_LEN: usize = 16;

pub(crate) struct AccountSecrets {
    pub auk: SecretKey,
    pub opk: SecretKey,
}

impl std::fmt::Debug for AccountSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountSecrets(..)")
    }
}

pub(crate) struct AkKeys {
    pub keyset: SecretKey,
    pub self_wrap: SecretKey,
}

impl std::fmt::Debug for AkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AkKeys(..)")
    }
}

pub(crate) fn copy_key(key: &SecretKey) -> SecretKey {
    key.duplicate()
}

pub(crate) fn kdf_params(kdf: &KdfWire, max_m_kib: u32) -> Result<Argon2idParams, CoreError> {
    let params = Argon2idParams::account(kdf.m, kdf.t, kdf.p)?;
    params.within_capability(max_m_kib)?;
    Ok(params)
}

fn argon_salt(sk: &SecretAscii, account: &AccountId) -> Result<[u8; SALT_LEN], CoreError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(sk.expose().len().saturating_add(16)));
    ikm.extend_from_slice(sk.expose());
    ikm.extend_from_slice(account.as_bytes());
    let prk = hkdf_extract(Kdf::ArgonSalt.name().as_bytes(), &ikm);
    let mut w = Writer::new();
    w.array(1)?;
    w.text(Kdf::ArgonSalt.name())?;
    let salt = hkdf_expand(&prk, &w.into_bytes(), SALT_LEN)?;
    salt.expose()
        .try_into()
        .map_err(|_| CoreError::Internal("argon salt length"))
}

pub(crate) fn derive_account_secrets(
    password: &str,
    sk: &SecretAscii,
    account: &AccountId,
    params: &Argon2idParams,
) -> Result<AccountSecrets, CoreError> {
    let normalised = normalise_password(password);
    let salt = argon_salt(sk, account)?;
    let k_pw = argon2id(normalised.as_bytes(), &salt, params)?;
    let mut w = Writer::new();
    w.array(5)?;
    w.text(Kdf::TwoSkd.name())?;
    w.bytes(account.as_bytes())?;
    w.uint(u64::from(params.m_kib()))?;
    w.uint(u64::from(params.t()))?;
    w.uint(u64::from(params.p()))?;
    let salt_hash = sha256(&[&w.into_bytes()]);
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        32usize.saturating_add(sk.expose().len()),
    ));
    ikm.extend_from_slice(k_pw.expose());
    ikm.extend_from_slice(sk.expose());
    let prk = hkdf_extract(&salt_hash, &ikm).into_secret();
    let ctx = [CtxValue::Id16(*account.as_bytes())];
    Ok(AccountSecrets {
        auk: derive(&prk, Kdf::Auk, &ctx)?,
        opk: derive(&prk, Kdf::OpaqueInput, &ctx)?,
    })
}

pub(crate) fn ak_keys(ak: &SecretKey) -> Result<AkKeys, CoreError> {
    Ok(AkKeys {
        keyset: derive(ak, Kdf::KeysetSeal, &[])?,
        self_wrap: derive(ak, Kdf::SelfWrap, &[])?,
    })
}

pub(crate) struct RecoveryKeys {
    pub wrap: SecretKey,
    pub auth: SecretKey,
}

impl std::fmt::Debug for RecoveryKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKeys(..)")
    }
}

pub(crate) fn recovery_keys(
    rc: &SecretAscii,
    account: &AccountId,
) -> Result<RecoveryKeys, CoreError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(rc.expose().len().saturating_add(16)));
    ikm.extend_from_slice(rc.expose());
    ikm.extend_from_slice(account.as_bytes());
    let prk = hkdf_extract(Kdf::RcPrk.name().as_bytes(), &ikm).into_secret();
    Ok(RecoveryKeys {
        wrap: derive(&prk, Kdf::RcWrap, &[])?,
        auth: derive(&prk, Kdf::RcAuth, &[])?,
    })
}

pub(crate) fn local_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: &Argon2idParams,
) -> Result<SecretKey, CoreError> {
    let normalised = normalise_password(password);
    Ok(argon2id(normalised.as_bytes(), salt, params)?)
}

pub(crate) fn enrol_mac_key(e: &SecretKey) -> SecretKey {
    hkdf_extract(Kdf::EnrolMac.name().as_bytes(), e.expose()).into_secret()
}

pub(crate) fn secret_from_slice(bytes: &SecretBytes) -> Result<SecretKey, CoreError> {
    SecretKey::from_slice(bytes.expose()).map_err(|_| CoreError::Internal("key length"))
}
