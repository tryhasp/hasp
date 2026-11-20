use hasp_crypto::{Argon2idParams, SecretKey, argon2id};
use hasp_proto::{Aad, CtxValue, Hash32, Kdf, ProtoError, Reader, Uint53, Writer, derive};
use secrecy::{ExposeSecret, SecretString};

use super::{
    CHUNK_SIZE, ExportError, HeaderInfo, KCV_LEN, KeyMode, MAGIC, MAX_KDF_M_KIB, MAX_KDF_P,
    MAX_KDF_T, MODE_BACKUP_KEY, MODE_PASSPHRASE, NONCE_PREFIX_LEN, SALT_LEN, VERSION,
};

pub(super) struct Header {
    pub(super) created: u64,
    pub(super) mode: u64,
    pub(super) params: Argon2idParams,
    pub(super) salt: [u8; SALT_LEN],
    pub(super) nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub(super) chunk_size: u64,
    pub(super) bk_nonce: Option<[u8; SALT_LEN]>,
    pub(super) kcv: [u8; KCV_LEN],
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

pub fn peek(bytes: &[u8]) -> Result<HeaderInfo, ExportError> {
    let (header, _) = parse_header(bytes)?;
    Ok(HeaderInfo {
        created: header.created,
        key_mode: if header.mode == MODE_PASSPHRASE {
            KeyMode::Passphrase
        } else {
            KeyMode::BackupKey
        },
    })
}

pub(super) fn encode_header(
    header: &Header,
    kcv: Option<&[u8; KCV_LEN]>,
) -> Result<Vec<u8>, ExportError> {
    let mut w = Writer::new();
    let entries = if header.bk_nonce.is_some() { 7 } else { 6 };
    w.map(if kcv.is_some() { entries + 1 } else { entries })?;
    w.key(0)?;
    w.uint(VERSION)?;
    w.key(1)?;
    w.uint(header.created)?;
    w.key(2)?;
    w.uint(header.mode)?;
    w.key(3)?;
    w.map(4)?;
    w.key(0)?;
    w.uint(u64::from(header.params.m_kib()))?;
    w.key(1)?;
    w.uint(u64::from(header.params.t()))?;
    w.key(2)?;
    w.uint(u64::from(header.params.p()))?;
    w.key(3)?;
    w.bytes(&header.salt)?;
    w.key(4)?;
    w.bytes(&header.nonce_prefix)?;
    w.key(5)?;
    w.uint(header.chunk_size)?;
    if let Some(nonce) = &header.bk_nonce {
        w.key(6)?;
        w.bytes(nonce)?;
    }
    if let Some(kcv) = kcv {
        w.key(7)?;
        w.bytes(kcv)?;
    }
    Ok(w.into_bytes())
}

pub(super) fn key_check(key: &SecretKey) -> [u8; KCV_LEN] {
    let mut kcv = [0_u8; KCV_LEN];
    if let Ok(check) = derive(key, Kdf::ExportKcv, &[]) {
        kcv.copy_from_slice(check.expose().get(..KCV_LEN).unwrap_or(&[0; KCV_LEN]));
    }
    kcv
}

pub(super) fn chunk_size_u64() -> Result<u64, ExportError> {
    u64::try_from(CHUNK_SIZE).map_err(|_| ExportError::Limit("chunk size"))
}

struct RawHeader {
    created: u64,
    mode: u64,
    kdf: [u64; 3],
    salt: [u8; SALT_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: u64,
    bk_nonce: Option<[u8; SALT_LEN]>,
    kcv: [u8; KCV_LEN],
}

fn read_kdf(r: &mut Reader<'_>) -> Result<([u64; 3], [u8; SALT_LEN]), ProtoError> {
    r.map(|r, n| {
        if n != 4 {
            return Err(ProtoError::Format);
        }
        r.key(0)?;
        let m = r.uint()?.get();
        r.key(1)?;
        let t = r.uint()?.get();
        r.key(2)?;
        let p = r.uint()?.get();
        r.key(3)?;
        Ok(([m, t, p], r.fixed::<SALT_LEN>()?))
    })
}

fn read_fields(r: &mut Reader<'_>, n: usize) -> Result<RawHeader, ProtoError> {
    r.key(0)?;
    if r.uint()?.get() != VERSION {
        return Err(ProtoError::Version);
    }
    r.key(1)?;
    let created = r.uint()?.get();
    r.key(2)?;
    let mode = r.uint()?.get();
    if mode != MODE_PASSPHRASE && mode != MODE_BACKUP_KEY {
        return Err(ProtoError::Format);
    }
    if n != if mode == MODE_BACKUP_KEY { 8 } else { 7 } {
        return Err(ProtoError::Format);
    }
    r.key(3)?;
    let (kdf, salt) = read_kdf(r)?;
    r.key(4)?;
    let nonce_prefix = r.fixed::<NONCE_PREFIX_LEN>()?;
    r.key(5)?;
    let chunk_size = r.uint()?.get();
    let bk_nonce = if mode == MODE_BACKUP_KEY {
        r.key(6)?;
        Some(r.fixed::<SALT_LEN>()?)
    } else {
        None
    };
    r.key(7)?;
    let kcv = r.fixed::<KCV_LEN>()?;
    Ok(RawHeader {
        created,
        mode,
        kdf,
        salt,
        nonce_prefix,
        chunk_size,
        bk_nonce,
        kcv,
    })
}

fn validate(raw: &RawHeader) -> Result<Header, ExportError> {
    if raw.chunk_size != chunk_size_u64()? {
        return Err(ExportError::Format("chunk size"));
    }
    let [m, t, p] = raw.kdf.map(u32::try_from);
    let (m, t, p) = (
        m.map_err(|_| ExportError::KdfParams)?,
        t.map_err(|_| ExportError::KdfParams)?,
        p.map_err(|_| ExportError::KdfParams)?,
    );
    if m > MAX_KDF_M_KIB || t > MAX_KDF_T || p > MAX_KDF_P {
        return Err(ExportError::KdfParams);
    }
    let params = Argon2idParams::local(m, t, p).map_err(|_| ExportError::KdfParams)?;
    Ok(Header {
        created: raw.created,
        mode: raw.mode,
        params,
        salt: raw.salt,
        nonce_prefix: raw.nonce_prefix,
        chunk_size: raw.chunk_size,
        bk_nonce: raw.bk_nonce,
        kcv: raw.kcv,
    })
}

pub(super) fn parse_header(bytes: &[u8]) -> Result<(Header, usize), ExportError> {
    let body = bytes
        .strip_prefix(&MAGIC)
        .ok_or(ExportError::Format("magic"))?;
    let raw = Reader::new(body).map(read_fields).map_err(|e| match e {
        ProtoError::Version => ExportError::Version,
        _ => ExportError::Format("header"),
    })?;
    let parsed = validate(&raw)?;
    let consumed = encode_header(&parsed, Some(&parsed.kcv))?;
    if body.get(..consumed.len()) != Some(consumed.as_slice()) {
        return Err(ExportError::Format("header is not canonical"));
    }
    let length = MAGIC
        .len()
        .checked_add(consumed.len())
        .ok_or(ExportError::Format("header"))?;
    Ok((parsed, length))
}

pub(super) fn from_passphrase(
    passphrase: &SecretString,
    header: &Header,
) -> Result<SecretKey, ExportError> {
    let normalized = crate::text::nfkd(passphrase.expose_secret());
    Ok(argon2id(
        normalized.as_bytes(),
        &header.salt,
        &header.params,
    )?)
}

pub(super) fn export_key(
    base: &SecretKey,
    header_bytes: &[u8],
    bk_nonce: Option<&[u8; SALT_LEN]>,
) -> Result<SecretKey, ExportError> {
    let digest = Hash32::digest(&[header_bytes]);
    let mut context = vec![CtxValue::Bytes(digest.as_bytes().to_vec())];
    if let Some(nonce) = bk_nonce {
        context.push(CtxValue::Bytes(nonce.to_vec()));
    }
    Ok(derive(base, Kdf::ExportKey, &context)?)
}

pub(super) fn stream_aad(header_bytes: &[u8]) -> Result<Vec<u8>, ExportError> {
    let digest = Hash32::digest(&[header_bytes]);
    let chunk = Uint53::new(chunk_size_u64()?)?;
    Ok(Aad::export_stream(digest, chunk).to_bytes()?)
}
