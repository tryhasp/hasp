use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AttId, Hash32, ItemId, VaultId};
use crate::record::{begin, read};
use crate::sealed::{SealedPadded, SealedRaw};
use crate::uint::{Epoch, Version};

const LIVE_ENTRIES: usize = 11;
const TOMBSTONE_ENTRIES: usize = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemBody {
    Live {
        wrap: SealedRaw,
        ov: SealedPadded,
        det: SealedPadded,
    },
    Tombstone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemWire {
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub ver: Version,
    pub epoch: Epoch,
    pub body: ItemBody,
    pub att_ids: Vec<AttId>,
    pub prev_h: Option<Hash32>,
}

impl Wire for ItemWire {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        let entries = match self.body {
            ItemBody::Live { .. } => LIVE_ENTRIES,
            ItemBody::Tombstone => TOMBSTONE_ENTRIES,
        };
        begin(w, Rtype::ItemPayload, entries)?;
        w.field(2, &self.vault_id)?;
        w.field(3, &self.item_id)?;
        w.field(4, &self.ver)?;
        w.field(5, &self.epoch)?;
        match &self.body {
            ItemBody::Live { wrap, ov, det } => {
                w.field(6, wrap)?;
                w.field(7, ov)?;
                w.field(8, det)?;
            }
            ItemBody::Tombstone => {
                w.key(9)?;
                w.bool(true);
            }
        }
        w.field(10, &self.att_ids)?;
        w.field(11, &self.prev_h)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read(r, Rtype::ItemPayload, |r, entries| {
            let vault_id = r.field(2)?;
            let item_id = r.field(3)?;
            let ver = r.field(4)?;
            let epoch = r.field(5)?;
            let body = match entries {
                LIVE_ENTRIES => ItemBody::Live {
                    wrap: r.field(6)?,
                    ov: r.field(7)?,
                    det: r.field(8)?,
                },
                TOMBSTONE_ENTRIES => {
                    r.key(9)?;
                    if !r.bool()? {
                        return Err(ProtoError::Format);
                    }
                    ItemBody::Tombstone
                }
                _ => return Err(ProtoError::Format),
            };
            let att_ids: Vec<AttId> = r.field(10)?;
            let prev_h: Option<Hash32> = r.field(11)?;
            if matches!(body, ItemBody::Tombstone) && !att_ids.is_empty() {
                return Err(ProtoError::Format);
            }
            Ok(Self {
                vault_id,
                item_id,
                ver,
                epoch,
                body,
                att_ids,
                prev_h,
            })
        })
    }
}
