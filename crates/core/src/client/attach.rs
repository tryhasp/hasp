use hasp_crypto::{SecretKey, open, seal_with_nonce};
use hasp_proto::wire::{AttachmentComplete, AttachmentGet, AttachmentPut, Blob};
use hasp_proto::{Aad, AttId, CtxValue, ItemId, Kdf, Uint53, VaultId, derive};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::{Client, ctx};
use crate::CoreError;
use crate::model::id::Id;
use crate::model::item::{AttachmentDesc, Item};
use crate::session::Cancel;
use crate::store::Store;
use crate::stream::{CHUNK_SIZE, NONCE_PREFIX_LEN, chunk_nonce, pad_last, unpad_last};
use crate::transport::Transport;

pub(crate) const MAX_ATTACHMENT_BYTES: usize = 100 << 20;

#[derive(Clone, Copy, Debug)]
pub struct NewAttachment<'a> {
    pub name: &'a str,
    pub mime: &'a str,
    pub data: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub att_id: AttId,
    pub name: String,
    pub mime: String,
    pub size: u64,
}

pub(crate) struct Staged {
    pub vault_id: VaultId,
    pub chunks: Vec<Vec<u8>>,
}

fn chunk_key(
    file_key: &SecretKey,
    vault: &VaultId,
    item: &ItemId,
    att: &AttId,
) -> Result<SecretKey, CoreError> {
    Ok(derive(
        file_key,
        Kdf::AttChunk,
        &[
            CtxValue::Id16(*vault.as_bytes()),
            CtxValue::Id16(*item.as_bytes()),
            CtxValue::Id16(*att.as_bytes()),
        ],
    )?)
}

fn chunk_aad(vault: &VaultId, item: &ItemId, att: &AttId) -> Result<Vec<u8>, CoreError> {
    let size =
        Uint53::new(u64::try_from(CHUNK_SIZE).map_err(|_| CoreError::Internal("chunk size"))?)?;
    Ok(Aad::attachment_chunk(*vault, *item, *att, size).to_bytes()?)
}

fn encrypt_chunks(
    data: &[u8],
    key: &SecretKey,
    prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
) -> Result<Vec<Vec<u8>>, CoreError> {
    let mut chunks = Vec::new();
    let mut index = 0_u64;
    let mut rest = data;
    while rest.len() >= CHUNK_SIZE {
        let (head, tail) = rest.split_at(CHUNK_SIZE);
        chunks.push(seal_with_nonce(
            key,
            &chunk_nonce(prefix, index, false),
            head,
            aad,
        )?);
        rest = tail;
        index = index
            .checked_add(1)
            .ok_or(CoreError::Refused("attachment too large"))?;
    }
    let last = pad_last(rest);
    chunks.push(seal_with_nonce(
        key,
        &chunk_nonce(prefix, index, true),
        &last,
        aad,
    )?);
    Ok(chunks)
}

impl<T: Transport, S: Store> Client<T, S> {
    pub async fn attach_file(
        &mut self,
        vault: &VaultId,
        item_id: &ItemId,
        file: &NewAttachment<'_>,
        call: &CancellationToken,
    ) -> Result<AttachmentInfo, CoreError> {
        let item = self.item(vault, item_id)?;
        let desc = self.upload_blob(vault, item_id, file, call).await?;
        let info = AttachmentInfo {
            att_id: AttId::from_bytes(*desc.att_id.as_bytes()),
            name: desc.name.clone(),
            mime: desc.mime.clone(),
            size: desc.size,
        };
        let mut parts = item.into_parts();
        parts.attachments.push(desc);
        let updated = Item::new(parts)?;
        self.write_item(vault, *item_id, &updated)?;
        Ok(info)
    }

    pub(crate) async fn upload_blob(
        &mut self,
        vault: &VaultId,
        item_id: &ItemId,
        file: &NewAttachment<'_>,
        call: &CancellationToken,
    ) -> Result<AttachmentDesc, CoreError> {
        let (name, mime, data) = (file.name, file.mime, file.data);
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(CoreError::Refused("attachment is over 100 MiB"));
        }
        let cancel = self.begin(call);
        let att_id = AttId::from_bytes(self.platform.array()?);
        let file_key = SecretKey::from_bytes(*Zeroizing::new(self.platform.array()?));
        let prefix: [u8; NONCE_PREFIX_LEN] = self.platform.array()?;
        let key = chunk_key(&file_key, vault, item_id, &att_id)?;
        let chunks = encrypt_chunks(data, &key, &prefix, &chunk_aad(vault, item_id, &att_id)?)?;
        self.staged.insert(
            att_id,
            Staged {
                vault_id: *vault,
                chunks,
            },
        );
        self.send_staged(&att_id, &cancel).await?;
        Ok(AttachmentDesc {
            att_id: Id::from_bytes(*att_id.as_bytes()),
            file_key,
            nonce_prefix: prefix,
            size: u64::try_from(data.len()).map_err(|_| CoreError::Refused("attachment size"))?,
            chunk_size: u32::try_from(CHUNK_SIZE).map_err(|_| CoreError::Internal("chunk size"))?,
            name: name.to_owned(),
            mime: mime.to_owned(),
        })
    }

    pub async fn resume_upload(
        &mut self,
        att_id: &AttId,
        call: &CancellationToken,
    ) -> Result<(), CoreError> {
        let cancel = self.begin(call);
        self.send_staged(att_id, &cancel).await
    }

    async fn send_staged(&mut self, att_id: &AttId, cancel: &Cancel) -> Result<(), CoreError> {
        let staged = self
            .staged
            .get(att_id)
            .ok_or(CoreError::NotFound("staged upload"))?;
        let vault_id = staged.vault_id;
        let chunks = staged.chunks.clone();
        let count =
            Uint53::new(u64::try_from(chunks.len()).map_err(|_| CoreError::Internal("chunks"))?)?;
        let cx = ctx!(self, cancel);
        for (index, chunk) in chunks.into_iter().enumerate() {
            cx.call(&AttachmentPut {
                vault_id,
                att_id: *att_id,
                index: Uint53::new(
                    u64::try_from(index).map_err(|_| CoreError::Internal("index"))?,
                )?,
                data: Blob(chunk),
            })
            .await?;
        }
        cx.call(&AttachmentComplete {
            vault_id,
            att_id: *att_id,
            chunks: count,
        })
        .await?;
        self.staged.remove(att_id);
        Ok(())
    }

    /// Fetches chunks in order, decrypts by the nonce rule and checks the last flag and `size`
    /// before returning anything. A chunk failure aborts the download.
    pub async fn download_attachment(
        &mut self,
        vault: &VaultId,
        item_id: &ItemId,
        att_id: &AttId,
        call: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let cancel = self.begin(call);
        let item = self.item(vault, item_id)?;
        let desc = item
            .details()
            .attachments
            .iter()
            .find(|a| a.att_id.as_bytes() == att_id.as_bytes())
            .ok_or(CoreError::NotFound("attachment"))?;
        let key = chunk_key(&desc.file_key, vault, item_id, att_id)?;
        let aad = chunk_aad(vault, item_id, att_id)?;
        let prefix = desc.nonce_prefix;
        let size = desc.size;
        let mut out = Zeroizing::new(Vec::new());
        let mut index = 0_u64;
        let cx = ctx!(self, &cancel);
        loop {
            let reply = cx
                .call(&AttachmentGet {
                    vault_id: *vault,
                    att_id: *att_id,
                    index: Uint53::new(index)?,
                })
                .await?;
            let nonce = chunk_nonce(&prefix, index, reply.last);
            let opened = open(&key, &nonce, reply.data.as_slice(), &aad)
                .map_err(|_| CoreError::Credentials)?;
            if reply.last {
                let body = unpad_last(opened.expose()).ok_or(CoreError::Credentials)?;
                out.extend_from_slice(body);
                break;
            }
            out.extend_from_slice(opened.expose());
            index = index
                .checked_add(1)
                .ok_or(CoreError::Refused("attachment too long"))?;
        }
        if u64::try_from(out.len()).ok() != Some(size) {
            return Err(CoreError::Credentials);
        }
        Ok(out)
    }
}
