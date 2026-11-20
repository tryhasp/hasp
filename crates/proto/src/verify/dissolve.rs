use crate::ProtoError;
use crate::label::SigLabel;
use crate::record::dissolve::Dissolve;
use crate::record::leave::LeaveRequest;
use crate::record::roster::{Role, VaultKind};
use crate::signed::Signed;
use crate::verify::batch::VaultState;

pub fn verify_dissolve(rec: &Signed<Dissolve>, state: &VaultState) -> Result<Dissolve, ProtoError> {
    let owner = state.roster.owner().ok_or(ProtoError::Roster)?;
    let dissolve = rec.verify(SigLabel::Dissolve, &owner.ik_pk)?;
    if dissolve.vault_id != state.roster.vault_id || state.roster.kind != VaultKind::Shared {
        return Err(ProtoError::Roster);
    }
    if dissolve.rver < state.rver || dissolve.epoch < state.epoch || dissolve.seq < state.seq {
        return Err(ProtoError::Rollback);
    }
    if dissolve.seq == state.seq && dissolve.head != state.hash {
        return Err(ProtoError::Fork);
    }
    Ok(dissolve)
}

pub fn verify_leave(
    rec: &Signed<LeaveRequest>,
    state: &VaultState,
) -> Result<LeaveRequest, ProtoError> {
    let claimed = rec.unverified()?;
    let member = state
        .roster
        .member(&claimed.account_id)
        .ok_or(ProtoError::Authz)?;
    if member.role == Role::Owner {
        return Err(ProtoError::Authz);
    }
    let leave = rec.verify(SigLabel::Leave, &member.ik_pk)?;
    if leave.vault_id != state.roster.vault_id {
        return Err(ProtoError::Roster);
    }
    if leave.rver != state.rver {
        return Err(ProtoError::Roster);
    }
    if leave.epoch != state.epoch {
        return Err(ProtoError::Epoch);
    }
    Ok(leave)
}
