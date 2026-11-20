use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, VaultId};
use crate::record::{begin, read_exact};
use crate::uint::{Epoch, Rver};

const LEAVE_ENTRIES: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaveRequest {
    pub vault_id: VaultId,
    pub account_id: AccountId,
    pub rver: Rver,
    pub epoch: Epoch,
}

impl Wire for LeaveRequest {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::LeaveRequest, LEAVE_ENTRIES)?;
        w.field(2, &self.vault_id)?;
        w.field(3, &self.account_id)?;
        w.field(4, &self.rver)?;
        w.field(5, &self.epoch)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::LeaveRequest, LEAVE_ENTRIES, |r| {
            Ok(Self {
                vault_id: r.field(2)?,
                account_id: r.field(3)?,
                rver: r.field(4)?,
                epoch: r.field(5)?,
            })
        })
    }
}
