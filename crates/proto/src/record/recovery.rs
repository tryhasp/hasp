use crate::ProtoError;
use crate::aad::Rtype;
use crate::cbor::{Reader, Wire, Writer};
use crate::id::{AccountId, Hash32};
use crate::record::{begin, read_exact};
use crate::uint::Uint53;

const RECOVERY_ENTRIES: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryEnrolment {
    pub account_id: AccountId,
    pub rgen: Uint53,
    pub h_wrap: Hash32,
}

impl Wire for RecoveryEnrolment {
    fn encode(&self, w: &mut Writer) -> Result<(), ProtoError> {
        begin(w, Rtype::Recovery, RECOVERY_ENTRIES)?;
        w.field(2, &self.account_id)?;
        w.field(3, &self.rgen)?;
        w.field(4, &self.h_wrap)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        read_exact(r, Rtype::Recovery, RECOVERY_ENTRIES, |r| {
            Ok(Self {
                account_id: r.field(2)?,
                rgen: r.field(3)?,
                h_wrap: r.field(4)?,
            })
        })
    }
}
