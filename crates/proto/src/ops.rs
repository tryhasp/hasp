use std::collections::BTreeMap;

use crate::ProtoError;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{Hash32, ItemId};
use crate::label::Kdf;
use crate::record::item::{ItemBody, ItemWire};
use crate::uint::{Epoch, Version};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafFlag {
    Live,
    Tombstone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub item_id: ItemId,
    pub ver: Version,
    pub epoch: Epoch,
    pub h_item: Hash32,
    pub flag: LeafFlag,
}

impl Wire for Leaf {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        w.array(5)?;
        self.item_id.encode(w)?;
        self.ver.encode(w)?;
        self.epoch.encode(w)?;
        self.h_item.encode(w)?;
        w.uint(match self.flag {
            LeafFlag::Live => 0,
            LeafFlag::Tombstone => 1,
        })
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        r.array_of_decode(5, |r| {
            let item_id = r.value()?;
            let ver = r.value()?;
            let epoch = r.value()?;
            let h_item = r.value()?;
            let flag = match r.uint()?.get() {
                0 => LeafFlag::Live,
                1 => LeafFlag::Tombstone,
                _ => return Err(ProtoError::Format),
            };
            Ok(Self {
                item_id,
                ver,
                epoch,
                h_item,
                flag,
            })
        })
    }
}

pub fn leaf_hash(leaf: &Leaf) -> Result<Hash32, ProtoError> {
    Ok(Hash32::digest(&[&leaf.to_cbor()?]))
}

pub fn item_wire_hash(wire_bytes: &[u8]) -> Hash32 {
    Hash32::digest(&[wire_bytes])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemOp {
    wire: ItemWire,
    h_item: Hash32,
}

impl ItemOp {
    pub fn from_wire_bytes(wire_bytes: &[u8]) -> Result<Self, ProtoError> {
        Ok(Self {
            wire: ItemWire::from_cbor(wire_bytes)?,
            h_item: item_wire_hash(wire_bytes),
        })
    }

    pub fn wire(&self) -> &ItemWire {
        &self.wire
    }

    pub fn h_item(&self) -> &Hash32 {
        &self.h_item
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafSet {
    leaves: BTreeMap<ItemId, Leaf>,
}

impl LeafSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_leaves(leaves: impl IntoIterator<Item = Leaf>) -> Self {
        Self {
            leaves: leaves
                .into_iter()
                .map(|leaf| (leaf.item_id, leaf))
                .collect(),
        }
    }

    /// Accepts a first version 1, the next version of a known item, or a re-wrap of the same
    /// live version at a higher epoch (epoch bump). Anything else is `Epoch`.
    pub fn apply(&mut self, op: &ItemOp) -> Result<(), ProtoError> {
        let wire = op.wire();
        let flag = match wire.body {
            ItemBody::Live { .. } => LeafFlag::Live,
            ItemBody::Tombstone => LeafFlag::Tombstone,
        };
        let current = self.leaves.get(&wire.item_id);
        let accepted = match current {
            None => wire.ver.get() == 1,
            Some(leaf) => {
                let next = leaf.ver.checked_next()?;
                wire.ver == next
                    || (wire.ver == leaf.ver
                        && wire.epoch > leaf.epoch
                        && leaf.flag == LeafFlag::Live
                        && flag == LeafFlag::Live)
            }
        };
        if !accepted {
            return Err(ProtoError::Epoch);
        }
        self.leaves.insert(
            wire.item_id,
            Leaf {
                item_id: wire.item_id,
                ver: wire.ver,
                epoch: wire.epoch,
                h_item: *op.h_item(),
                flag,
            },
        );
        Ok(())
    }

    /// Records the highest `(ver, epoch)` seen for the item without the version rules of
    /// `apply`. Used for stateless replay: the signed `root` at
    /// the adopted head is the check.
    pub fn absorb(&mut self, op: &ItemOp) {
        let wire = op.wire();
        let flag = match wire.body {
            ItemBody::Live { .. } => LeafFlag::Live,
            ItemBody::Tombstone => LeafFlag::Tombstone,
        };
        let newer = self
            .leaves
            .get(&wire.item_id)
            .is_none_or(|leaf| (wire.ver, wire.epoch) > (leaf.ver, leaf.epoch));
        if newer {
            self.leaves.insert(
                wire.item_id,
                Leaf {
                    item_id: wire.item_id,
                    ver: wire.ver,
                    epoch: wire.epoch,
                    h_item: *op.h_item(),
                    flag,
                },
            );
        }
    }

    pub fn get(&self, id: &ItemId) -> Option<&Leaf> {
        self.leaves.get(id)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Leaf> {
        self.leaves.values()
    }

    pub fn live_epochs_equal(&self, epoch: Epoch) -> bool {
        self.leaves
            .values()
            .all(|leaf| leaf.flag == LeafFlag::Tombstone || leaf.epoch == epoch)
    }
}

pub fn leafset_root(leaves: &LeafSet) -> Result<Hash32, ProtoError> {
    let count = u32::try_from(leaves.len()).map_err(|_| ProtoError::Format)?;
    let hashes = leaves
        .iter()
        .map(leaf_hash)
        .collect::<Result<Vec<_>, _>>()?;
    let count_bytes = count.to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(hashes.len().saturating_add(2));
    parts.push(Kdf::Leafset.name().as_bytes());
    parts.push(&count_bytes);
    parts.extend(hashes.iter().map(|hash| hash.as_bytes().as_slice()));
    Ok(Hash32::digest(&parts))
}
