use std::collections::BTreeMap;

use hasp_crypto::SecretKey;
use hasp_proto::wire::{SelfWrapEntry, SelfWrapPut};
use hasp_proto::{
    Aad, Commit as ProtoCommit, Epoch, InviteCode, OwnKeys, PinState, SealedRaw, Share, Signed,
    VaultId, VaultState, Wire, open_share, verify_roster, verify_share, vk_commit,
};

use super::Ctx;
use crate::CoreError;
use crate::keys::secret_from_slice;
use crate::store::Records;
use crate::store::{Batch, EventKind, Store, VaultLocal};
use crate::transport::Transport;

pub(crate) type RosterIndex = BTreeMap<u64, hasp_proto::VerifiedRoster>;

pub(crate) fn roster_index(
    prior: Option<&VaultState>,
    commits: &[ProtoCommit],
    own: &OwnKeys,
    pins: &PinState,
) -> RosterIndex {
    let mut index = RosterIndex::new();
    let mut last = prior.map(VaultState::verified_roster);
    if let Some(prior) = &last {
        index.insert(prior.roster().rver.get(), prior.clone());
    }
    for commit in commits {
        if let Some(rec) = &commit.roster
            && let Ok(verified) = verify_roster(rec, last.as_ref(), own, pins)
        {
            index.insert(verified.roster().rver.get(), verified.clone());
            last = Some(verified);
        }
    }
    index
}

pub(crate) async fn process_shares<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    shares: &[Signed<Share>],
    rosters: &RosterIndex,
    batch: &mut Batch,
) -> Result<(), CoreError> {
    let invite = cx
        .cache
        .invite(&local.vault_id)?
        .map(|bytes| InviteCode::from_cbor(&bytes))
        .transpose()?;
    let mut consumed = false;
    for share in shares {
        let body = share.unverified()?;
        if body.vault_id != local.vault_id || cx.session.vk(&local.vault_id, body.epoch).is_some() {
            continue;
        }
        let Some(roster) = rosters.get(&body.rver.get()) else {
            continue;
        };
        let verified = verify_share(
            share,
            &cx.session.identity.own,
            roster,
            invite.as_ref(),
            &cx.session.pins,
        )?;
        let vk = open_share(&verified, &cx.session.identity.kem, roster)?;
        let wrap = seal_self_wrap(cx, &local.vault_id, body.epoch, &vk)?;
        cx.call(&SelfWrapPut {
            vault_id: local.vault_id,
            entry: SelfWrapEntry {
                epoch: body.epoch,
                wrap: wrap.clone(),
            },
        })
        .await?;
        Records::put_self_wrap(batch, &local.vault_id, body.epoch, &wrap)?;
        cx.session.put_vk(local.vault_id, body.epoch, &vk);
        consumed = true;
    }
    if consumed && invite.is_some() {
        Records::delete_invite(batch, &local.vault_id);
    }
    Ok(())
}

pub(crate) fn seal_self_wrap<T: Transport, S: Store>(
    cx: &Ctx<'_, T, S>,
    vault: &VaultId,
    epoch: Epoch,
    vk: &SecretKey,
) -> Result<SealedRaw, CoreError> {
    Ok(SealedRaw::seal(
        &cx.session.identity.k_self,
        vk.expose(),
        &Aad::self_wrap(cx.account_id(), *vault, epoch),
    )?)
}

pub(crate) fn refresh_self_wraps<T: Transport, S: Store>(
    cx: &mut Ctx<'_, T, S>,
    local: &VaultLocal,
    wraps: &[SelfWrapEntry],
    batch: &mut Batch,
    kinds: &mut Vec<EventKind>,
) -> Result<(), CoreError> {
    for entry in wraps {
        if cx.session.vk(&local.vault_id, entry.epoch).is_some() {
            continue;
        }
        let opened = entry.wrap.open(
            &cx.session.identity.k_self,
            &Aad::self_wrap(cx.account_id(), local.vault_id, entry.epoch),
        );
        let Ok(opened) = opened else {
            continue;
        };
        let vk = secret_from_slice(&opened)?;
        let expected = local.vk_commits.get(&entry.epoch.get());
        let computed = vk_commit(&vk, &local.vault_id, entry.epoch)?;
        if expected.is_some_and(|commit| *commit != computed) {
            kinds.push(EventKind::NeedsAttention {
                vault_id: local.vault_id,
                reason: "self-wrap does not match the roster commitment".to_owned(),
            });
            continue;
        }
        Records::put_self_wrap(batch, &local.vault_id, entry.epoch, &entry.wrap)?;
        cx.session.put_vk(local.vault_id, entry.epoch, &vk);
    }
    Ok(())
}
