use hasp_crypto::XWING_ENCAPSULATED_LEN;

use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, Hash32, VaultId};
use crate::record::{begin, read_exact};
use crate::uint::{Epoch, Rver};

pub const SHARE_CT_LEN: usize = 48;
const SHARE_ENTRIES: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub rver: Rver,
    pub from: AccountId,
    pub to: AccountId,
    pub kem_pk_hash: Hash32,
    pub enc: [u8; XWING_ENCAPSULATED_LEN],
    pub ct: [u8; SHARE_CT_LEN],
}

impl Wire for Share {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::Share, SHARE_ENTRIES)?;
        w.field(2, &self.vault_id)?;
        w.field(3, &self.epoch)?;
        w.field(4, &self.rver)?;
        w.field(5, &self.from)?;
        w.field(6, &self.to)?;
        w.field(7, &self.kem_pk_hash)?;
        w.field(8, &self.enc)?;
        w.field(9, &self.ct)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::Share, SHARE_ENTRIES, |r| {
            Ok(Self {
                vault_id: r.field(2)?,
                epoch: r.field(3)?,
                rver: r.field(4)?,
                from: r.field(5)?,
                to: r.field(6)?,
                kem_pk_hash: r.field(7)?,
                enc: r.field(8)?,
                ct: r.field(9)?,
            })
        })
    }
}
