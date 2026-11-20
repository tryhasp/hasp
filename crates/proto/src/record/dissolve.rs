use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{Hash32, VaultId};
use crate::record::{begin, read_exact};
use crate::uint::{Epoch, Rver, Seq};

const DISSOLVE_ENTRIES: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dissolve {
    pub vault_id: VaultId,
    pub rver: Rver,
    pub epoch: Epoch,
    pub seq: Seq,
    pub head: Hash32,
}

impl Wire for Dissolve {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::VaultDissolve, DISSOLVE_ENTRIES)?;
        w.field(2, &self.vault_id)?;
        w.field(3, &self.rver)?;
        w.field(4, &self.epoch)?;
        w.field(5, &self.seq)?;
        w.field(6, &self.head)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::VaultDissolve, DISSOLVE_ENTRIES, |r| {
            Ok(Self {
                vault_id: r.field(2)?,
                rver: r.field(3)?,
                epoch: r.field(4)?,
                seq: r.field(5)?,
                head: r.field(6)?,
            })
        })
    }
}
