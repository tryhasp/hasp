use hasp_crypto::{KemPublicKey, VerifyingKey};

use crate::ProtoError;
use crate::id::{AccountId, Hash32};
use crate::label::SigLabel;
use crate::pin::{PinCheck, PinState, kem_hash, pin_check};
use crate::record::roster::{Member, Roster, VaultKind};
use crate::signed::Signed;

#[derive(Clone, Debug)]
pub struct OwnKeys {
    pub account_id: AccountId,
    pub ik_pk: VerifyingKey,
    pub kem_pk: KemPublicKey,
    pub retired_kem_pk_hashes: Vec<Hash32>,
}

impl OwnKeys {
    pub fn owns_kem_hash(&self, hash: &Hash32) -> bool {
        kem_hash(&self.kem_pk) == *hash || self.retired_kem_pk_hashes.contains(hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRoster {
    roster: Roster,
    hash: Hash32,
}

impl VerifiedRoster {
    pub(crate) fn trusted(roster: Roster, hash: Hash32) -> Self {
        Self { roster, hash }
    }

    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    pub fn hash(&self) -> &Hash32 {
        &self.hash
    }
}

pub fn verify_roster(
    rec: &Signed<Roster>,
    prior: Option<&VerifiedRoster>,
    own: &OwnKeys,
    pins: &PinState,
) -> Result<VerifiedRoster, ProtoError> {
    let claimed = rec.unverified()?;
    let owner = claimed.owner().ok_or(ProtoError::Roster)?;
    let signer = match prior {
        Some(prior) => &prior.roster.owner().ok_or(ProtoError::Roster)?.ik_pk,
        None => &owner.ik_pk,
    };
    let roster = rec.verify(SigLabel::Roster, signer)?;
    let hash = rec.hash();
    check_shape(&roster)?;
    check_members(&roster, own, pins)?;
    match prior {
        Some(prior) => check_successor(&roster, &hash, prior)?,
        None => check_genesis(&roster)?,
    }
    Ok(VerifiedRoster { roster, hash })
}

fn check_shape(roster: &Roster) -> Result<(), ProtoError> {
    let one_member_only = roster.kind == VaultKind::Private;
    if roster.members.is_empty() || (one_member_only && roster.members.len() != 1) {
        return Err(ProtoError::Roster);
    }
    if roster
        .members
        .iter()
        .any(|member| member.added_rver > roster.rver)
    {
        return Err(ProtoError::Roster);
    }
    Ok(())
}

fn check_members(roster: &Roster, own: &OwnKeys, pins: &PinState) -> Result<(), ProtoError> {
    for member in &roster.members {
        if member.account_id == own.account_id {
            if member.ik_pk != own.ik_pk || member.kem_pk != own.kem_pk {
                return Err(ProtoError::Roster);
            }
        } else if pin_check(pins, &member.account_id, &member.ik_pk, &member.kem_pk)
            == PinCheck::KeyChanged
        {
            return Err(ProtoError::Pin);
        }
    }
    Ok(())
}

fn check_genesis(roster: &Roster) -> Result<(), ProtoError> {
    if roster.rver.get() != 1 || roster.prev.is_some() {
        return Err(ProtoError::Roster);
    }
    Ok(())
}

fn check_successor(
    roster: &Roster,
    hash: &Hash32,
    prior: &VerifiedRoster,
) -> Result<(), ProtoError> {
    let before = &prior.roster;
    if roster.rver < before.rver {
        return Err(ProtoError::Rollback);
    }
    if roster.rver == before.rver {
        return Err(if *hash == prior.hash {
            ProtoError::Rollback
        } else {
            ProtoError::Fork
        });
    }
    if roster.rver != before.rver.checked_next()? || roster.prev != Some(prior.hash) {
        return Err(ProtoError::Roster);
    }
    if roster.vault_id != before.vault_id || roster.kind != before.kind {
        return Err(ProtoError::Roster);
    }
    let before_owner = before.owner().ok_or(ProtoError::Roster)?;
    let owner = roster.owner().ok_or(ProtoError::Roster)?;
    if owner != before_owner {
        return Err(ProtoError::Roster);
    }
    check_epoch(roster, before)
}

fn check_epoch(roster: &Roster, before: &Roster) -> Result<(), ProtoError> {
    if roster.epoch < before.epoch {
        return Err(ProtoError::Epoch);
    }
    let bumped = roster.epoch > before.epoch;
    if bumped == (roster.vk_commit == before.vk_commit) {
        return Err(ProtoError::Roster);
    }
    if removes_member(before, roster) && roster.epoch != before.epoch.checked_next()? {
        return Err(ProtoError::Epoch);
    }
    Ok(())
}

pub(crate) fn removes_member(before: &Roster, after: &Roster) -> bool {
    before
        .members
        .iter()
        .any(|member: &Member| after.member(&member.account_id).is_none())
}
