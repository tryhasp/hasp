use hasp_crypto::{
    HpkeSealed, KemPublicKey, KemSecretKey, SecretKey, SigningKey, VerifyingKey, ct_eq, hpke_open,
    hpke_seal,
};

use crate::ProtoError;
use crate::fingerprint::fingerprint;
use crate::id::{AccountId, Hash32, VaultId};
use crate::label::{CtxValue, HPKE_SHARE_AAD, HPKE_SHARE_INFO, Kdf, SigLabel, derive, info};
use crate::pin::{PinCheck, PinState, kem_hash, pin_check};
use crate::record::invite::InviteCode;
use crate::record::roster::{Role, Roster, VaultKind};
use crate::record::share::{SHARE_CT_LEN, Share};
use crate::signed::Signed;
use crate::uint::Epoch;
use crate::verify::roster::{OwnKeys, VerifiedRoster};

#[derive(Clone, Debug)]
pub struct VerifiedShare {
    share: Share,
    from_ik_pk: VerifyingKey,
    to_ik_pk: VerifyingKey,
    roster_hash: Hash32,
}

impl VerifiedShare {
    pub fn share(&self) -> &Share {
        &self.share
    }
}

pub fn verify_share(
    share: &Signed<Share>,
    own: &OwnKeys,
    roster: &VerifiedRoster,
    invite: Option<&InviteCode>,
    pins: &PinState,
) -> Result<VerifiedShare, ProtoError> {
    let claimed = share.unverified()?;
    if claimed.to != own.account_id {
        return Err(ProtoError::Authz);
    }
    if !own.owns_kem_hash(&claimed.kem_pk_hash) {
        return Err(ProtoError::Roster);
    }
    let owner = roster.roster().owner().ok_or(ProtoError::Roster)?;
    if claimed.from != owner.account_id {
        return Err(ProtoError::Roster);
    }
    check_owner_identity(owner.account_id, &owner.ik_pk, &owner.kem_pk, invite, pins)?;
    let body = share.verify(SigLabel::Share, &owner.ik_pk)?;
    let recipient = check_roster_binding(&body, own, roster.roster())?;
    Ok(VerifiedShare {
        share: body,
        from_ik_pk: owner.ik_pk,
        to_ik_pk: recipient,
        roster_hash: *roster.hash(),
    })
}

fn check_owner_identity(
    owner: AccountId,
    ik_pk: &VerifyingKey,
    kem_pk: &KemPublicKey,
    invite: Option<&InviteCode>,
    pins: &PinState,
) -> Result<(), ProtoError> {
    if let Some(invite) = invite
        && fingerprint(ik_pk, kem_pk) != invite.fp_owner
    {
        return Err(ProtoError::Invite);
    }
    match pin_check(pins, &owner, ik_pk, kem_pk) {
        PinCheck::Ok => Ok(()),
        PinCheck::KeyChanged => Err(ProtoError::Pin),
        PinCheck::New | PinCheck::Unverified if invite.is_some() => Ok(()),
        PinCheck::New | PinCheck::Unverified => Err(ProtoError::Invite),
    }
}

fn check_roster_binding(
    share: &Share,
    own: &OwnKeys,
    roster: &Roster,
) -> Result<VerifyingKey, ProtoError> {
    if roster.kind != VaultKind::Shared
        || share.vault_id != roster.vault_id
        || share.rver != roster.rver
    {
        return Err(ProtoError::Roster);
    }
    if share.epoch != roster.epoch {
        return Err(ProtoError::Epoch);
    }
    let member = roster.member(&share.to).ok_or(ProtoError::Roster)?;
    if member.ik_pk != own.ik_pk || kem_hash(&member.kem_pk) != share.kem_pk_hash {
        return Err(ProtoError::Roster);
    }
    if member.role == Role::Owner {
        return Err(ProtoError::Roster);
    }
    Ok(member.ik_pk)
}

pub fn open_share(
    verified: &VerifiedShare,
    own_kem: &KemSecretKey,
    roster: &VerifiedRoster,
) -> Result<SecretKey, ProtoError> {
    if *roster.hash() != verified.roster_hash {
        return Err(ProtoError::Roster);
    }
    let share = &verified.share;
    let (info, aad) = share_context(
        share,
        &verified.from_ik_pk,
        &verified.to_ik_pk,
        roster.hash(),
    )?;
    let plaintext =
        hpke_open(own_kem, &share.enc, &info, &aad, &share.ct).map_err(|_| ProtoError::Aead)?;
    let vk = SecretKey::from_slice(plaintext.expose()).map_err(|_| ProtoError::Aead)?;
    let commit = vk_commit(&vk, &share.vault_id, share.epoch)?;
    if !ct_eq(commit.as_bytes(), roster.roster().vk_commit.as_bytes()) {
        return Err(ProtoError::Roster);
    }
    Ok(vk)
}

pub fn vk_commit(vk: &SecretKey, vault: &VaultId, epoch: Epoch) -> Result<Hash32, ProtoError> {
    let key = derive(
        vk,
        Kdf::VkCommit,
        &[
            CtxValue::Id16(*vault.as_bytes()),
            CtxValue::Uint(epoch.uint()),
        ],
    )?;
    Ok(Hash32::from_bytes(*key.expose()))
}

#[derive(Debug)]
pub struct ShareKey<'a> {
    pub owner_key: &'a SigningKey,
    pub vk: &'a SecretKey,
    pub to: &'a AccountId,
}

pub fn seal_share(
    roster: &VerifiedRoster,
    key: &ShareKey<'_>,
) -> Result<Signed<Share>, ProtoError> {
    seal_share_inner(roster, key, |recipient, info, aad, plaintext| {
        hpke_seal(recipient, info, aad, plaintext)
    })
}

#[cfg(any(test, feature = "testing"))]
pub fn seal_share_with_randomness(
    roster: &VerifiedRoster,
    key: &ShareKey<'_>,
    randomness: [u8; 64],
) -> Result<Signed<Share>, ProtoError> {
    seal_share_inner(roster, key, |recipient, info, aad, plaintext| {
        hasp_crypto::hpke_seal_with_randomness(recipient, randomness, info, aad, plaintext)
    })
}

fn seal_share_inner(
    roster: &VerifiedRoster,
    key: &ShareKey<'_>,
    hpke: impl FnOnce(
        &KemPublicKey,
        &[u8],
        &[u8],
        &[u8],
    ) -> Result<HpkeSealed, hasp_crypto::CryptoError>,
) -> Result<Signed<Share>, ProtoError> {
    let rows = roster.roster();
    let owner = rows.owner().ok_or(ProtoError::Roster)?;
    let recipient = rows.member(key.to).ok_or(ProtoError::Roster)?;
    let mut share = Share {
        vault_id: rows.vault_id,
        epoch: rows.epoch,
        rver: rows.rver,
        from: owner.account_id,
        to: recipient.account_id,
        kem_pk_hash: kem_hash(&recipient.kem_pk),
        enc: [0; hasp_crypto::XWING_ENCAPSULATED_LEN],
        ct: [0; SHARE_CT_LEN],
    };
    let (info, aad) = share_context(&share, &owner.ik_pk, &recipient.ik_pk, roster.hash())?;
    let sealed = hpke(&recipient.kem_pk, &info, &aad, key.vk.expose())?;
    share.enc = sealed.enc;
    share.ct = sealed
        .ct
        .try_into()
        .map_err(|_| ProtoError::Internal("share ciphertext length"))?;
    Signed::sign(SigLabel::Share, &share, key.owner_key)
}

fn share_context(
    share: &Share,
    from_ik_pk: &VerifyingKey,
    to_ik_pk: &VerifyingKey,
    roster_hash: &Hash32,
) -> Result<(Vec<u8>, Vec<u8>), ProtoError> {
    let share_info = info(
        HPKE_SHARE_INFO,
        &[
            CtxValue::Id16(*share.vault_id.as_bytes()),
            CtxValue::Uint(share.epoch.uint()),
            CtxValue::Uint(share.rver.uint()),
            CtxValue::Id16(*share.from.as_bytes()),
            CtxValue::Id16(*share.to.as_bytes()),
            CtxValue::Bytes(from_ik_pk.as_bytes().to_vec()),
            CtxValue::Bytes(to_ik_pk.as_bytes().to_vec()),
            CtxValue::Bytes(share.kem_pk_hash.as_bytes().to_vec()),
        ],
    )?;
    let share_aad = info(
        HPKE_SHARE_AAD,
        &[CtxValue::Bytes(roster_hash.as_bytes().to_vec())],
    )?;
    Ok((share_info, share_aad))
}
