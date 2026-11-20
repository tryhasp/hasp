use hasp_crypto::Argon2idParams;

use crate::ProtoError;
use crate::id::Hash32;
use crate::label::SigLabel;
use crate::pin::{PinCheck, PinState, pin_check};
use crate::record::account::AccountRecord;
use crate::signed::Signed;
use crate::uint::Seq;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSeen {
    pub seq: Seq,
    pub hash: Hash32,
}

pub fn verify_account_record(
    rec: &Signed<AccountRecord>,
    seen: Option<&AccountSeen>,
    pins: &PinState,
) -> Result<AccountRecord, ProtoError> {
    let claimed = rec.unverified()?;
    Argon2idParams::account(claimed.kdf.m, claimed.kdf.t, claimed.kdf.p)
        .map_err(|_| ProtoError::KdfParams)?;
    let record = rec.verify(SigLabel::Account, &claimed.ik_pk)?;
    if (record.seq.get() == 1) != record.prev.is_none() {
        return Err(ProtoError::Format);
    }
    if let Some(seen) = seen {
        check_chain(rec, &record, seen)?;
    }
    match pin_check(pins, &record.account_id, &record.ik_pk, &record.kem_pk) {
        PinCheck::New | PinCheck::Ok | PinCheck::Unverified => Ok(record),
        PinCheck::KeyChanged => Err(ProtoError::Pin),
    }
}

fn check_chain(
    rec: &Signed<AccountRecord>,
    record: &AccountRecord,
    seen: &AccountSeen,
) -> Result<(), ProtoError> {
    if record.seq < seen.seq {
        return Err(ProtoError::Rollback);
    }
    if record.seq == seen.seq {
        return if rec.hash() == seen.hash {
            Ok(())
        } else {
            Err(ProtoError::Fork)
        };
    }
    if record.seq == seen.seq.checked_next()? && record.prev != Some(seen.hash) {
        return Err(ProtoError::Fork);
    }
    Ok(())
}
