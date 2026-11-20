use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, Hash32, VaultId};
use crate::record::{begin, read_exact};
use crate::uint::{Epoch, Rver, Seq};

const MANIFEST_ENTRIES: usize = 11;
const REPAIR_MARK: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub vault_id: VaultId,
    pub seq: Seq,
    pub prev: Option<Hash32>,
    pub epoch: Epoch,
    pub rver: Rver,
    pub roster_hash: Hash32,
    pub root: Hash32,
    pub author: AccountId,
    pub repair: bool,
}

impl Wire for Manifest {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::Manifest, MANIFEST_ENTRIES)?;
        w.field(2, &self.vault_id)?;
        w.field(3, &self.seq)?;
        w.field(4, &self.prev)?;
        w.field(5, &self.epoch)?;
        w.field(6, &self.rver)?;
        w.field(7, &self.roster_hash)?;
        w.field(8, &self.root)?;
        w.field(9, &self.author)?;
        w.key(10)?;
        if self.repair {
            w.uint(REPAIR_MARK)
        } else {
            w.null();
            Ok(())
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::Manifest, MANIFEST_ENTRIES, |r| {
            let vault_id = r.field(2)?;
            let seq = r.field(3)?;
            let prev = r.field(4)?;
            let epoch = r.field(5)?;
            let rver = r.field(6)?;
            let roster_hash = r.field(7)?;
            let root = r.field(8)?;
            let author = r.field(9)?;
            r.key(10)?;
            let repair = if r.is_null() {
                r.null()?;
                false
            } else if r.uint()?.get() == REPAIR_MARK {
                true
            } else {
                return Err(ProtoError::Format);
            };
            Ok(Self {
                vault_id,
                seq,
                prev,
                epoch,
                rver,
                roster_hash,
                root,
                author,
                repair,
            })
        })
    }
}
