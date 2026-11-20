use hasp_crypto::{SecretBytes, SecretKey};

use crate::ProtoError;
use crate::aad::Aad;
use crate::cbor::Wire;
use crate::entropy::{Entropy, OsEntropy};
use crate::id::{AttId, Hash32, ItemId, VaultId};
use crate::label::{CtxValue, Kdf, derive};
use crate::ops::{LeafFlag, item_wire_hash};
use crate::record::item::{ItemBody, ItemWire};
use crate::sealed::{SealedPadded, SealedRaw};
use crate::uint::{Epoch, Uint53, Version};
use crate::verify::batch::VaultState;

const FIELD_OVERVIEW: u64 = 1;
const FIELD_DETAILS: u64 = 2;

#[derive(Debug)]
pub enum OpenedItem {
    Live {
        item_id: ItemId,
        ver: Version,
        epoch: Epoch,
        overview: SecretBytes,
        details: SecretBytes,
        att_ids: Vec<AttId>,
    },
    Tombstone {
        item_id: ItemId,
        ver: Version,
    },
}

#[derive(Clone, Debug)]
pub struct ItemParams<'a> {
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub ver: Version,
    pub epoch: Epoch,
    pub overview: &'a [u8],
    pub details: &'a [u8],
    pub att_ids: Vec<AttId>,
    pub prev_h: Option<Hash32>,
}

pub fn open_item(
    item: &ItemWire,
    wire_bytes: &[u8],
    state: &VaultState,
    vk: &SecretKey,
) -> Result<OpenedItem, ProtoError> {
    if item.to_cbor()? != wire_bytes || item.vault_id != state.roster.vault_id {
        return Err(ProtoError::Format);
    }
    let leaf = state.leafset.get(&item.item_id).ok_or(ProtoError::Root)?;
    if leaf.ver != item.ver || leaf.epoch != item.epoch || leaf.h_item != item_wire_hash(wire_bytes)
    {
        return Err(ProtoError::Root);
    }
    match (&item.body, leaf.flag) {
        (ItemBody::Tombstone, LeafFlag::Tombstone) => Ok(OpenedItem::Tombstone {
            item_id: item.item_id,
            ver: item.ver,
        }),
        (ItemBody::Live { wrap, ov, det }, LeafFlag::Live) => {
            let item_key = open_wrap(item, wrap, vk)?;
            let overview = ov.open(
                &field_key(&item_key, item, FIELD_OVERVIEW)?,
                &aad_overview(item),
            )?;
            let details = det.open(
                &field_key(&item_key, item, FIELD_DETAILS)?,
                &aad_details(item),
            )?;
            Ok(OpenedItem::Live {
                item_id: item.item_id,
                ver: item.ver,
                epoch: item.epoch,
                overview,
                details,
                att_ids: item.att_ids.clone(),
            })
        }
        (ItemBody::Tombstone, LeafFlag::Live) | (ItemBody::Live { .. }, LeafFlag::Tombstone) => {
            Err(ProtoError::Root)
        }
    }
}

/// Opens a version that is not in a verified leaf set yet, such as a pending local edit that
/// must be re-sealed at a new version. The key wrap and both fields still authenticate against
/// the wire's own ids.
pub fn open_item_unverified(
    item: &ItemWire,
    vk: &SecretKey,
) -> Result<(SecretBytes, SecretBytes), ProtoError> {
    let ItemBody::Live { wrap, ov, det } = &item.body else {
        return Err(ProtoError::Format);
    };
    let item_key = open_wrap(item, wrap, vk)?;
    let overview = ov.open(
        &field_key(&item_key, item, FIELD_OVERVIEW)?,
        &aad_overview(item),
    )?;
    let details = det.open(
        &field_key(&item_key, item, FIELD_DETAILS)?,
        &aad_details(item),
    )?;
    Ok((overview, details))
}

pub fn tombstone(
    vault_id: VaultId,
    item_id: ItemId,
    ver: Version,
    epoch: Epoch,
    prev_h: Option<Hash32>,
) -> ItemWire {
    ItemWire {
        vault_id,
        item_id,
        ver,
        epoch,
        body: ItemBody::Tombstone,
        att_ids: Vec::new(),
        prev_h,
    }
}

pub fn seal_item(vk: &SecretKey, params: &ItemParams<'_>) -> Result<ItemWire, ProtoError> {
    seal_item_with(&mut OsEntropy, vk, params)
}

pub fn seal_item_with(
    entropy: &mut impl Entropy,
    vk: &SecretKey,
    params: &ItemParams<'_>,
) -> Result<ItemWire, ProtoError> {
    let item_key = entropy.key()?;
    let shell = ItemWire {
        vault_id: params.vault_id,
        item_id: params.item_id,
        ver: params.ver,
        epoch: params.epoch,
        body: ItemBody::Tombstone,
        att_ids: params.att_ids.clone(),
        prev_h: params.prev_h,
    };
    let wrap = SealedRaw::seal_with(
        entropy,
        &wrap_key(vk, &shell)?,
        item_key.expose(),
        &aad_wrap(&shell),
    )?;
    let ov = SealedPadded::seal_with(
        entropy,
        &field_key(&item_key, &shell, FIELD_OVERVIEW)?,
        params.overview,
        &aad_overview(&shell),
    )?;
    let det = SealedPadded::seal_with(
        entropy,
        &field_key(&item_key, &shell, FIELD_DETAILS)?,
        params.details,
        &aad_details(&shell),
    )?;
    Ok(ItemWire {
        body: ItemBody::Live { wrap, ov, det },
        ..shell
    })
}

pub fn rewrap_item(
    entropy: &mut impl Entropy,
    old_vk: &SecretKey,
    new_vk: &SecretKey,
    item: &ItemWire,
    new_epoch: Epoch,
) -> Result<ItemWire, ProtoError> {
    let ItemBody::Live { wrap, ov, det } = &item.body else {
        return Err(ProtoError::Format);
    };
    let item_key = open_wrap(item, wrap, old_vk)?;
    let moved = ItemWire {
        epoch: new_epoch,
        ..item.clone()
    };
    let new_wrap = SealedRaw::seal_with(
        entropy,
        &wrap_key(new_vk, &moved)?,
        item_key.expose(),
        &aad_wrap(&moved),
    )?;
    Ok(ItemWire {
        body: ItemBody::Live {
            wrap: new_wrap,
            ov: ov.clone(),
            det: det.clone(),
        },
        ..moved
    })
}

fn open_wrap(item: &ItemWire, wrap: &SealedRaw, vk: &SecretKey) -> Result<SecretKey, ProtoError> {
    let opened = wrap.open(&wrap_key(vk, item)?, &aad_wrap(item))?;
    SecretKey::from_slice(opened.expose()).map_err(|_| ProtoError::Format)
}

fn wrap_key(vk: &SecretKey, item: &ItemWire) -> Result<SecretKey, ProtoError> {
    derive(
        vk,
        Kdf::ItemWrap,
        &[
            CtxValue::Id16(*item.vault_id.as_bytes()),
            CtxValue::Uint(item.epoch.uint()),
        ],
    )
}

fn field_key(item_key: &SecretKey, item: &ItemWire, field: u64) -> Result<SecretKey, ProtoError> {
    derive(
        item_key,
        Kdf::Field,
        &[
            CtxValue::Id16(*item.vault_id.as_bytes()),
            CtxValue::Id16(*item.item_id.as_bytes()),
            CtxValue::Uint(item.ver.uint()),
            CtxValue::Uint(Uint53::new(field)?),
        ],
    )
}

fn aad_wrap(item: &ItemWire) -> Aad {
    Aad::item_key_wrap(item.vault_id, item.item_id, item.epoch, item.ver)
}

fn aad_overview(item: &ItemWire) -> Aad {
    Aad::item_overview(item.vault_id, item.item_id, item.ver)
}

fn aad_details(item: &ItemWire) -> Aad {
    Aad::item_details(item.vault_id, item.item_id, item.ver)
}

/// Versions that chain back from `head` through `prev_h`, newest first. `head` must be a leaf
/// version already checked by `open_item`. A stored version that is not the exact predecessor
/// named by the hash is never returned, so a holder of the vault key cannot add history.
pub fn chained_history(
    head: &ItemWire,
    stored: &[(Version, Epoch, Vec<u8>)],
) -> Vec<(Version, Epoch)> {
    let mut chain = Vec::new();
    let mut current = head.clone();
    while let Some(want) = current.prev_h {
        let found = stored.iter().find_map(|(_, _, bytes)| {
            if item_wire_hash(bytes) != want {
                return None;
            }
            let wire = ItemWire::from_cbor(bytes).ok()?;
            let predecessor = current.ver.get().checked_sub(1)?;
            (wire.vault_id == head.vault_id
                && wire.item_id == head.item_id
                && wire.ver.get() == predecessor
                && wire.to_cbor().ok()? == *bytes)
                .then_some(wire)
        });
        let Some(wire) = found else { break };
        chain.push((wire.ver, wire.epoch));
        current = wire;
    }
    chain
}
