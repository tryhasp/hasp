use secrecy::SecretSlice;
use std::collections::BTreeMap;

use hasp_crypto::{SecretKey, open};
use hasp_proto::{ProtoError, Reader, VaultKind};
use zeroize::Zeroizing;

use super::header::{
    Header, encode_header, export_key, from_passphrase, key_check, parse_header, stream_aad,
};
use super::{
    CHUNK_SIZE, Counts, ExportContent, ExportError, ExportItem, ExportVault, MAX_ATTACHMENT_BYTES,
    MAX_FILE_BYTES, MODE_BACKUP_KEY, MODE_PASSPHRASE, NONCE_PREFIX_LEN, PIECE_SIZE,
    RECORD_ATTACHMENT, RECORD_END, RECORD_ITEM, RECORD_VAULT, TAG_LEN, Unlock,
};
use crate::import::AttachedFile;
use crate::model::id::Id;
use crate::model::wire as payload;
use crate::stream;

/// Verifies every chunk and record before returning anything.
pub fn read(bytes: &[u8], unlock: &Unlock<'_>) -> Result<ExportContent, ExportError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ExportError::Limit("file size"));
    }
    let (header, header_len) = parse_header(bytes)?;
    let header_bytes = encode_header(&header, None)?;
    let key = unlock_key(unlock, &header, &header_bytes)?;
    if !hasp_crypto::ct_eq(&key_check(&key), &header.kcv) {
        return Err(ExportError::WrongPassphrase);
    }
    let aad = stream_aad(&header_bytes)?;
    let stream = bytes
        .get(header_len..)
        .ok_or(ExportError::Format("header"))?;
    let plaintext = decrypt_stream(stream, &key, &header.nonce_prefix, &aad)?;
    parse_records(&plaintext)
}

fn unlock_key(
    unlock: &Unlock<'_>,
    header: &Header,
    header_bytes: &[u8],
) -> Result<SecretKey, ExportError> {
    match (unlock, header.mode) {
        (Unlock::Passphrase(passphrase), MODE_PASSPHRASE) => {
            let derived = from_passphrase(passphrase, header)?;
            export_key(&derived, header_bytes, None)
        }
        (Unlock::Passphrase(passphrase), _) => {
            let derived = from_passphrase(passphrase, header)?;
            export_key(&derived, header_bytes, header.bk_nonce.as_ref())
        }
        (Unlock::BackupKey(key), MODE_BACKUP_KEY) => {
            export_key(key, header_bytes, header.bk_nonce.as_ref())
        }
        (Unlock::BackupKey(_), _) => Err(ExportError::KeyMode),
    }
}

struct PartialFile {
    item_id: Id,
    name: String,
    mime: String,
    size: u64,
    data: Zeroizing<Vec<u8>>,
}

pub(super) fn parse_records(plaintext: &[u8]) -> Result<ExportContent, ExportError> {
    let corrupt = |_| ExportError::Corrupt("record");
    let mut content = ExportContent {
        vaults: Vec::new(),
        items: Vec::new(),
    };
    let mut files: BTreeMap<Id, PartialFile> = BTreeMap::new();
    let mut file_order: Vec<Id> = Vec::new();
    let mut ended: Option<Counts> = None;
    let mut rest = plaintext;
    while !rest.is_empty() {
        if ended.is_some() {
            return Err(ExportError::Corrupt("data after end"));
        }
        let (length, tail) = rest
            .split_first_chunk::<4>()
            .ok_or(ExportError::Corrupt("record length"))?;
        let length = usize::try_from(u32::from_be_bytes(*length))
            .map_err(|_| ExportError::Corrupt("record length"))?;
        if length > hasp_proto::MAX_RECORD {
            return Err(ExportError::Corrupt("record length"));
        }
        let record = tail
            .get(..length)
            .ok_or(ExportError::Corrupt("record length"))?;
        rest = tail.get(length..).unwrap_or_default();
        let mut r = Reader::new(record);
        let kind = {
            let mut peek = Reader::new(record);
            peek.map(|p, _| {
                p.key(0)?;
                Ok(p.uint()?.get())
            })
            .map_err(corrupt)?
        };
        match kind {
            RECORD_VAULT => content.vaults.push(read_vault(&mut r).map_err(corrupt)?),
            RECORD_ITEM => content.items.push(read_item(&mut r)?),
            RECORD_ATTACHMENT => read_piece(&mut r, &content, &mut files, &mut file_order)?,
            RECORD_END => ended = Some(read_end(&mut r).map_err(corrupt)?),
            _ => return Err(ExportError::Format("record type")),
        }
        r.finish().map_err(corrupt)?;
    }
    let counts = ended.ok_or(ExportError::Corrupt("missing end record"))?;
    for id in file_order {
        let partial = files
            .remove(&id)
            .ok_or(ExportError::Corrupt("attachment"))?;
        if u64::try_from(partial.data.len()).ok() != Some(partial.size) {
            return Err(ExportError::Corrupt("attachment size"));
        }
        let entry = content
            .items
            .iter_mut()
            .find(|i| i.item_id == partial.item_id)
            .ok_or(ExportError::Corrupt("attachment owner"))?;
        entry.files.push(AttachedFile {
            id,
            name: partial.name,
            mime: partial.mime,
            data: SecretSlice::from(std::mem::take(&mut *partial.data.clone())),
        });
    }
    let attachments: usize = content.items.iter().map(|i| i.files.len()).sum();
    let matches = u64::try_from(content.vaults.len()).ok() == Some(counts.vaults)
        && u64::try_from(content.items.len()).ok() == Some(counts.items)
        && u64::try_from(attachments).ok() == Some(counts.attachments);
    if !matches {
        return Err(ExportError::Corrupt("record counts"));
    }
    Ok(content)
}

fn read_vault(r: &mut Reader<'_>) -> Result<ExportVault, ProtoError> {
    r.map(|r, n| {
        if n != 4 {
            return Err(ProtoError::Format);
        }
        r.key(0)?;
        r.uint()?;
        r.key(1)?;
        let id = Id::from_bytes(r.fixed()?);
        r.key(2)?;
        let name = get_text(r)?;
        r.key(3)?;
        let kind = r.value::<VaultKind>()?;
        Ok(ExportVault { id, name, kind })
    })
}

fn read_item(r: &mut Reader<'_>) -> Result<ExportItem, ExportError> {
    let corrupt = |_| ExportError::Corrupt("item record");
    let (vault_id, item_id, overview, details, history) = r
        .map(|r, n| {
            if n != 6 {
                return Err(ProtoError::Format);
            }
            r.key(0)?;
            r.uint()?;
            r.key(1)?;
            let vault_id = Id::from_bytes(r.fixed()?);
            r.key(2)?;
            let item_id = Id::from_bytes(r.fixed()?);
            r.key(3)?;
            let overview = r.bytes()?;
            r.key(4)?;
            let details = r.bytes()?;
            r.key(5)?;
            let history = r.array(|r, n| {
                let mut history = Vec::with_capacity(n);
                for _ in 0..n {
                    history.push(r.array(|r, n| {
                        if n != 2 {
                            return Err(ProtoError::Format);
                        }
                        Ok((r.bytes()?, r.bytes()?))
                    })?);
                }
                Ok(history)
            })?;
            Ok((vault_id, item_id, overview, details, history))
        })
        .map_err(corrupt)?;
    let item = payload::decode_item(overview, details).map_err(corrupt)?;
    let history = history
        .into_iter()
        .map(|(o, d)| payload::decode_item(o, d))
        .collect::<Result<Vec<_>, _>>()
        .map_err(corrupt)?;
    Ok(ExportItem {
        vault_id,
        item_id,
        item,
        history,
        files: Vec::new(),
    })
}

fn read_piece(
    r: &mut Reader<'_>,
    content: &ExportContent,
    files: &mut BTreeMap<Id, PartialFile>,
    order: &mut Vec<Id>,
) -> Result<(), ExportError> {
    let corrupt = |_| ExportError::Corrupt("attachment record");
    let (att, item_id, name, size, mime, offset, data) = r
        .map(|r, n| {
            if n != 8 {
                return Err(ProtoError::Format);
            }
            r.key(0)?;
            r.uint()?;
            r.key(1)?;
            let att = Id::from_bytes(r.fixed()?);
            r.key(2)?;
            let item_id = Id::from_bytes(r.fixed()?);
            r.key(3)?;
            let name = get_text(r)?;
            r.key(4)?;
            let size = r.uint()?.get();
            r.key(5)?;
            let mime = get_text(r)?;
            r.key(6)?;
            let offset = r.uint()?.get();
            r.key(7)?;
            let data = r.bytes()?;
            Ok((att, item_id, name, size, mime, offset, data))
        })
        .map_err(corrupt)?;
    if size > MAX_ATTACHMENT_BYTES || data.len() > PIECE_SIZE {
        return Err(ExportError::Limit("attachment"));
    }
    if !content.items.iter().any(|i| i.item_id == item_id) {
        return Err(ExportError::Corrupt("attachment owner"));
    }
    let entry = files.entry(att).or_insert_with(|| {
        order.push(att);
        PartialFile {
            item_id,
            name: name.clone(),
            mime: mime.clone(),
            size,
            data: Zeroizing::new(Vec::new()),
        }
    });
    let consistent = entry.item_id == item_id
        && entry.name == name
        && entry.mime == mime
        && entry.size == size
        && u64::try_from(entry.data.len()).ok() == Some(offset);
    if !consistent {
        return Err(ExportError::Corrupt("attachment pieces"));
    }
    entry.data.extend_from_slice(data);
    Ok(())
}

fn read_end(r: &mut Reader<'_>) -> Result<Counts, ProtoError> {
    r.map(|r, n| {
        if n != 4 {
            return Err(ProtoError::Format);
        }
        r.key(0)?;
        r.uint()?;
        r.key(1)?;
        let vaults = r.uint()?.get();
        r.key(2)?;
        let items = r.uint()?.get();
        r.key(3)?;
        let attachments = r.uint()?.get();
        Ok(Counts {
            vaults,
            items,
            attachments,
        })
    })
}

pub(super) fn decrypt_stream(
    stream: &[u8],
    key: &SecretKey,
    prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let full = CHUNK_SIZE + TAG_LEN;
    if stream.is_empty() {
        return Err(ExportError::Corrupt("no chunks"));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(stream.len()));
    let mut rest = stream;
    let mut index = 0_u64;
    while !rest.is_empty() {
        let take = rest.len().min(full);
        let (chunk, tail) = rest.split_at(take);
        let last = tail.is_empty();
        let nonce = stream::chunk_nonce(prefix, index, last);
        let opened = open(key, &nonce, chunk, aad).map_err(|_| {
            if last && open(key, &stream::chunk_nonce(prefix, index, false), chunk, aad).is_ok() {
                ExportError::Corrupt("truncated")
            } else {
                ExportError::Corrupt("chunk")
            }
        })?;
        if last {
            let body = unpad_last(opened.expose())?;
            plaintext.extend_from_slice(body);
        } else {
            plaintext.extend_from_slice(opened.expose());
        }
        rest = tail;
        index = index.checked_add(1).ok_or(ExportError::Limit("chunks"))?;
    }
    Ok(plaintext)
}

fn get_text(r: &mut Reader<'_>) -> Result<String, ProtoError> {
    String::from_utf8(r.bytes()?.to_vec()).map_err(|_| ProtoError::Format)
}

pub(super) fn unpad_last(padded: &[u8]) -> Result<&[u8], ExportError> {
    stream::unpad_last(padded).ok_or(ExportError::Corrupt("padding"))
}
