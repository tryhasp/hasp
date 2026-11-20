use std::io::Write;

use hasp_crypto::{SecretKey, seal_with_nonce};
use hasp_proto::{Wire, Writer};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::header::{
    Header, chunk_size_u64, encode_header, export_key, from_passphrase, key_check, stream_aad,
};
use super::{
    CHUNK_SIZE, Counts, ExportContent, ExportError, ExportItem, ExportVault, KCV_LEN, MAGIC,
    MAX_ATTACHMENT_BYTES, MAX_KDF_M_KIB, MAX_KDF_P, MAX_KDF_T, MODE_BACKUP_KEY, MODE_PASSPHRASE,
    NONCE_PREFIX_LEN, PIECE_SIZE, Protection, RECORD_ATTACHMENT, RECORD_END, RECORD_ITEM,
    RECORD_VAULT, SALT_LEN,
};
use crate::import::AttachedFile;
use crate::model::id::Id;
use crate::model::wire as payload;
use crate::stream;

pub fn write<W: Write>(
    out: &mut W,
    content: &ExportContent,
    protection: &Protection<'_>,
    created: u64,
) -> Result<(), ExportError> {
    write_stream(out, protection, created, |stream| {
        let counts = write_records(stream, content)?;
        stream.record(&end_record(counts)?)
    })
}

fn new_header(protection: &Protection<'_>, created: u64) -> Result<Header, ExportError> {
    let nonce_prefix = hasp_crypto::random_array::<NONCE_PREFIX_LEN>()?;
    let (Protection::Passphrase { params, .. } | Protection::BackupKey { params, .. }) = protection;
    if params.m_kib() > MAX_KDF_M_KIB || params.t() > MAX_KDF_T || params.p() > MAX_KDF_P {
        return Err(ExportError::KdfParams);
    }
    Ok(match protection {
        Protection::Passphrase { params, .. } => Header {
            created,
            mode: MODE_PASSPHRASE,
            params: *params,
            salt: hasp_crypto::random_array::<SALT_LEN>()?,
            nonce_prefix,
            chunk_size: chunk_size_u64()?,
            bk_nonce: None,
            kcv: [0; KCV_LEN],
        },
        Protection::BackupKey { params, salt, .. } => Header {
            created,
            mode: MODE_BACKUP_KEY,
            params: *params,
            salt: *salt,
            nonce_prefix,
            chunk_size: chunk_size_u64()?,
            bk_nonce: Some(hasp_crypto::random_array::<SALT_LEN>()?),
            kcv: [0; KCV_LEN],
        },
    })
}

fn protection_key(
    protection: &Protection<'_>,
    header: &Header,
    header_bytes: &[u8],
) -> Result<SecretKey, ExportError> {
    match protection {
        Protection::Passphrase { passphrase, .. } => {
            let derived = from_passphrase(passphrase, header)?;
            export_key(&derived, header_bytes, None)
        }
        Protection::BackupKey { key, .. } => {
            export_key(key, header_bytes, header.bk_nonce.as_ref())
        }
    }
}

pub(super) fn write_stream<W: Write>(
    out: &mut W,
    protection: &Protection<'_>,
    created: u64,
    body: impl FnOnce(&mut StreamWriter<'_, W>) -> Result<(), ExportError>,
) -> Result<(), ExportError> {
    let header = new_header(protection, created)?;
    let header_bytes = encode_header(&header, None)?;
    let key = protection_key(protection, &header, &header_bytes)?;
    let kcv = key_check(&key);
    out.write_all(&MAGIC).map_err(|_| ExportError::Io)?;
    out.write_all(&encode_header(&header, Some(&kcv))?)
        .map_err(|_| ExportError::Io)?;
    let aad = stream_aad(&header_bytes)?;
    let mut stream = StreamWriter {
        out,
        key,
        aad,
        prefix: header.nonce_prefix,
        buffer: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE.saturating_add(PIECE_SIZE))),
        index: 0,
    };
    body(&mut stream)?;
    stream.finish()
}

pub(super) struct StreamWriter<'a, W: Write> {
    pub(super) out: &'a mut W,
    pub(super) key: SecretKey,
    pub(super) aad: Vec<u8>,
    pub(super) prefix: [u8; NONCE_PREFIX_LEN],
    pub(super) buffer: Zeroizing<Vec<u8>>,
    pub(super) index: u64,
}

impl<W: Write> StreamWriter<'_, W> {
    pub(super) fn record(&mut self, record: &[u8]) -> Result<(), ExportError> {
        if record.len() > hasp_proto::MAX_RECORD {
            return Err(ExportError::Limit("record size"));
        }
        let length = u32::try_from(record.len()).map_err(|_| ExportError::Limit("record size"))?;
        self.push(&length.to_be_bytes())?;
        self.push(record)
    }

    pub(super) fn push(&mut self, data: &[u8]) -> Result<(), ExportError> {
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= CHUNK_SIZE {
            let rest = self.buffer.split_off(CHUNK_SIZE);
            let chunk = std::mem::replace(&mut self.buffer, Zeroizing::new(Vec::new()));
            self.seal_chunk(&chunk, false)?;
            self.buffer = Zeroizing::new(rest);
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<(), ExportError> {
        let last = std::mem::take(&mut self.buffer);
        let padded = stream::pad_last(&last);
        self.seal_chunk(&padded, true)
    }

    fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<(), ExportError> {
        let nonce = stream::chunk_nonce(&self.prefix, self.index, last);
        let ct = seal_with_nonce(&self.key, &nonce, plaintext, &self.aad)?;
        self.out.write_all(&ct).map_err(|_| ExportError::Io)?;
        self.index = self
            .index
            .checked_add(1)
            .ok_or(ExportError::Limit("chunks"))?;
        Ok(())
    }
}

fn write_records<W: Write>(
    stream: &mut StreamWriter<'_, W>,
    content: &ExportContent,
) -> Result<Counts, ExportError> {
    let mut counts = Counts {
        vaults: 0,
        items: 0,
        attachments: 0,
    };
    for vault in &content.vaults {
        stream.record(&vault_record(vault)?)?;
        counts.vaults += 1;
    }
    for entry in &content.items {
        stream.record(&item_record(entry)?)?;
        counts.items += 1;
        for file in &entry.files {
            for piece in attachment_records(entry.item_id, file)? {
                stream.record(&piece)?;
            }
            counts.attachments += 1;
        }
    }
    Ok(counts)
}

pub(super) fn vault_record(vault: &ExportVault) -> Result<Vec<u8>, ExportError> {
    let mut w = Writer::new();
    w.map(4)?;
    w.key(0)?;
    w.uint(RECORD_VAULT)?;
    w.key(1)?;
    w.bytes(vault.id.as_bytes())?;
    w.key(2)?;
    w.bytes(vault.name.as_bytes())?;
    w.key(3)?;
    vault.kind.encode(&mut w)?;
    Ok(w.into_bytes())
}

fn item_record(entry: &ExportItem) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    for item in std::iter::once(&entry.item).chain(&entry.history) {
        if !item.details().attachments.is_empty() {
            return Err(ExportError::Format("attachment descriptors"));
        }
    }
    let (overview, details) = payload::encode_item(&entry.item)?;
    let mut w = Writer::new();
    w.map(6)?;
    w.key(0)?;
    w.uint(RECORD_ITEM)?;
    w.key(1)?;
    w.bytes(entry.vault_id.as_bytes())?;
    w.key(2)?;
    w.bytes(entry.item_id.as_bytes())?;
    w.key(3)?;
    w.bytes(&overview)?;
    w.key(4)?;
    w.bytes(&details)?;
    w.key(5)?;
    w.array(entry.history.len())?;
    for old in &entry.history {
        let (overview, details) = payload::encode_item(old)?;
        w.array(2)?;
        w.bytes(&overview)?;
        w.bytes(&details)?;
    }
    Ok(w.into_zeroizing())
}

pub(super) fn attachment_records(
    item_id: Id,
    file: &AttachedFile,
) -> Result<Vec<Zeroizing<Vec<u8>>>, ExportError> {
    let data = file.data.expose_secret();
    let size = u64::try_from(data.len()).map_err(|_| ExportError::Limit("attachment"))?;
    if size > MAX_ATTACHMENT_BYTES {
        return Err(ExportError::Limit("attachment"));
    }
    let mut pieces: Vec<&[u8]> = data.chunks(PIECE_SIZE).collect();
    if pieces.is_empty() {
        pieces.push(&[]);
    }
    let mut records = Vec::with_capacity(pieces.len());
    let mut offset = 0_u64;
    for piece in pieces {
        let mut w = Writer::new();
        w.map(8)?;
        w.key(0)?;
        w.uint(RECORD_ATTACHMENT)?;
        w.key(1)?;
        w.bytes(file.id.as_bytes())?;
        w.key(2)?;
        w.bytes(item_id.as_bytes())?;
        w.key(3)?;
        w.bytes(file.name.as_bytes())?;
        w.key(4)?;
        w.uint(size)?;
        w.key(5)?;
        w.bytes(file.mime.as_bytes())?;
        w.key(6)?;
        w.uint(offset)?;
        w.key(7)?;
        w.bytes(piece)?;
        records.push(w.into_zeroizing());
        offset += u64::try_from(piece.len()).map_err(|_| ExportError::Limit("attachment"))?;
    }
    Ok(records)
}

pub(super) fn end_record(counts: Counts) -> Result<Vec<u8>, ExportError> {
    let mut w = Writer::new();
    w.map(4)?;
    w.key(0)?;
    w.uint(RECORD_END)?;
    w.key(1)?;
    w.uint(counts.vaults)?;
    w.key(2)?;
    w.uint(counts.items)?;
    w.key(3)?;
    w.uint(counts.attachments)?;
    Ok(w.into_bytes())
}
