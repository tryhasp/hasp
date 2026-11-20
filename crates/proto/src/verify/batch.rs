use crate::ProtoError;
use crate::id::Hash32;
use crate::label::SigLabel;
use crate::ops::{ItemOp, LeafSet, leafset_root};
use crate::pin::PinState;
use crate::record::manifest::Manifest;
use crate::record::roster::{Role, Roster};
use crate::record::share::Share;
use crate::signed::Signed;
use crate::uint::{Epoch, Rver, Seq};
use crate::verify::roster::{OwnKeys, VerifiedRoster, removes_member, verify_roster};

#[derive(Clone, Debug)]
pub struct VaultState {
    pub seq: Seq,
    pub hash: Hash32,
    pub rver: Rver,
    pub roster_hash: Hash32,
    pub epoch: Epoch,
    pub roster: Roster,
    pub leafset: LeafSet,
}

impl VaultState {
    pub fn verified_roster(&self) -> VerifiedRoster {
        VerifiedRoster::trusted(self.roster.clone(), self.roster_hash)
    }
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub manifest: Signed<Manifest>,
    pub roster: Option<Signed<Roster>>,
    pub ops: Vec<ItemOp>,
    pub shares: Vec<Signed<Share>>,
}

#[derive(Clone, Copy)]
struct Verifier<'a> {
    own: &'a OwnKeys,
    pins: &'a PinState,
}

pub fn verify_genesis(
    commit: &Commit,
    own: &OwnKeys,
    pins: &PinState,
) -> Result<VaultState, ProtoError> {
    apply_commit(None, commit, Some(Verifier { own, pins }))
}

/// Verifies commits in order against a trusted state. Returns the
/// new state only if every commit passes; on any failure nothing is returned.
pub fn verify_batch(
    state: &VaultState,
    commits: &[Commit],
    own: &OwnKeys,
    pins: &PinState,
) -> Result<VaultState, ProtoError> {
    let verifier = Verifier { own, pins };
    let mut current = state.clone();
    for commit in commits {
        current = apply_commit(Some(&current), commit, Some(verifier))?;
    }
    Ok(current)
}

/// Applies an owner repair manifest. The caller must obtain user confirmation
/// first.
pub fn verify_repair(
    state: &VaultState,
    quarantined: Option<&Commit>,
    repair: &Commit,
) -> Result<VaultState, ProtoError> {
    let manifest = repair.manifest.unverified()?;
    if !manifest.repair || repair.roster.is_some() || !repair.shares.is_empty() {
        return Err(ProtoError::Format);
    }
    if let Some(bad) = quarantined {
        let bad_manifest = bad.manifest.unverified()?;
        if bad_manifest.seq != manifest.seq || bad.manifest.hash() == repair.manifest.hash() {
            return Err(ProtoError::Fork);
        }
    }
    apply_commit(Some(state), repair, None)
}

struct Prechecked {
    manifest: Manifest,
    manifest_hash: Hash32,
    roster: Roster,
    roster_hash: Hash32,
}

fn precheck(
    state: Option<&VaultState>,
    commit: &Commit,
    verifier: Option<Verifier<'_>>,
) -> Result<Prechecked, ProtoError> {
    let manifest = commit.manifest.unverified()?;
    let manifest_hash = commit.manifest.hash();
    check_chain(state, &manifest, &manifest_hash)?;
    let (roster, roster_hash) = resolve_roster(state, commit, verifier)?;
    check_binding(
        state,
        &manifest,
        &roster,
        &roster_hash,
        commit.roster.is_some(),
    )?;
    authorize(state, commit, &manifest, &roster)?;
    Ok(Prechecked {
        manifest,
        manifest_hash,
        roster,
        roster_hash,
    })
}

fn apply_commit(
    state: Option<&VaultState>,
    commit: &Commit,
    verifier: Option<Verifier<'_>>,
) -> Result<VaultState, ProtoError> {
    let checked = precheck(state, commit, verifier)?;
    let leafset = apply_ops(state, commit, &checked.manifest)?;
    if leafset_root(&leafset)? != checked.manifest.root {
        return Err(ProtoError::Root);
    }
    Ok(VaultState {
        seq: checked.manifest.seq,
        hash: checked.manifest_hash,
        rver: checked.roster.rver,
        roster_hash: checked.roster_hash,
        epoch: checked.roster.epoch,
        roster: checked.roster,
        leafset,
    })
}

#[derive(Debug)]
pub struct ChainError {
    pub index: usize,
    pub error: ProtoError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadRoot {
    Check,
    Skip,
}

/// Replays commits for a client that cannot rebuild every intermediate leaf set: a device with
/// no state (rulings, retention vs replay), or one whose gap spans pruned item versions. Every
/// signature, chain, roster, epoch and share rule applies to every commit; the leaf-set
/// root is recomputed only at the last commit, over the highest version seen of each item.
/// `HeadRoot::Skip` is for a page that is not the head of the pull. With `state` absent, the
/// first commit must be the genesis commit.
pub fn verify_chain(
    state: Option<&VaultState>,
    commits: &[Commit],
    own: &OwnKeys,
    pins: &PinState,
    head_root: HeadRoot,
) -> Result<VaultState, ChainError> {
    let verifier = Verifier { own, pins };
    let mut current: Option<VaultState> = state.cloned();
    for (index, commit) in commits.iter().enumerate() {
        let at = |error| ChainError { index, error };
        let checked = precheck(current.as_ref(), commit, Some(verifier)).map_err(at)?;
        let mut leafset = current
            .as_ref()
            .map(|state| state.leafset.clone())
            .unwrap_or_default();
        for op in &commit.ops {
            if op.wire().vault_id != checked.manifest.vault_id {
                return Err(at(ProtoError::Format));
            }
            if op.wire().epoch != checked.manifest.epoch {
                return Err(at(ProtoError::Epoch));
            }
            leafset.absorb(op);
        }
        let last = index.saturating_add(1) == commits.len();
        if last && head_root == HeadRoot::Check {
            if leafset_root(&leafset).map_err(at)? != checked.manifest.root {
                return Err(at(ProtoError::Root));
            }
            if !leafset.live_epochs_equal(checked.manifest.epoch) {
                return Err(at(ProtoError::Epoch));
            }
        }
        current = Some(VaultState {
            seq: checked.manifest.seq,
            hash: checked.manifest_hash,
            rver: checked.roster.rver,
            roster_hash: checked.roster_hash,
            epoch: checked.roster.epoch,
            roster: checked.roster,
            leafset,
        });
    }
    current.ok_or(ChainError {
        index: 0,
        error: ProtoError::Format,
    })
}

fn check_chain(
    state: Option<&VaultState>,
    manifest: &Manifest,
    manifest_hash: &Hash32,
) -> Result<(), ProtoError> {
    let Some(state) = state else {
        if manifest.seq.get() != 1 {
            return Err(ProtoError::Rollback);
        }
        return if manifest.prev.is_some() {
            Err(ProtoError::Fork)
        } else {
            Ok(())
        };
    };
    if manifest.vault_id != state.roster.vault_id {
        return Err(ProtoError::Roster);
    }
    if manifest.seq == state.seq && *manifest_hash != state.hash {
        return Err(ProtoError::Fork);
    }
    if manifest.seq != state.seq.checked_next()? {
        return Err(ProtoError::Rollback);
    }
    if manifest.prev != Some(state.hash) {
        return Err(ProtoError::Fork);
    }
    Ok(())
}

fn resolve_roster(
    state: Option<&VaultState>,
    commit: &Commit,
    verifier: Option<Verifier<'_>>,
) -> Result<(Roster, Hash32), ProtoError> {
    match (&commit.roster, state) {
        (Some(rec), _) => {
            let verifier = verifier.ok_or(ProtoError::Format)?;
            let prior = state.map(VaultState::verified_roster);
            let checked = verify_roster(rec, prior.as_ref(), verifier.own, verifier.pins)?;
            Ok((checked.roster().clone(), *checked.hash()))
        }
        (None, Some(state)) => Ok((state.roster.clone(), state.roster_hash)),
        (None, None) => Err(ProtoError::Roster),
    }
}

fn check_binding(
    state: Option<&VaultState>,
    manifest: &Manifest,
    roster: &Roster,
    roster_hash: &Hash32,
    roster_changed: bool,
) -> Result<(), ProtoError> {
    if manifest.vault_id != roster.vault_id
        || manifest.rver != roster.rver
        || manifest.roster_hash != *roster_hash
    {
        return Err(ProtoError::Roster);
    }
    if manifest.epoch != roster.epoch {
        return Err(ProtoError::Epoch);
    }
    let Some(state) = state else {
        return Ok(());
    };
    if manifest.epoch < state.epoch {
        return Err(ProtoError::Epoch);
    }
    if manifest.rver < state.rver {
        return Err(ProtoError::Roster);
    }
    if roster_changed
        && removes_member(&state.roster, roster)
        && manifest.epoch != state.epoch.checked_next()?
    {
        return Err(ProtoError::Epoch);
    }
    Ok(())
}

fn authorize(
    state: Option<&VaultState>,
    commit: &Commit,
    manifest: &Manifest,
    roster: &Roster,
) -> Result<(), ProtoError> {
    let author = roster.member(&manifest.author).ok_or(ProtoError::Authz)?;
    commit.manifest.verify(SigLabel::Manifest, &author.ik_pk)?;
    let epoch_change = state.is_some_and(|state| manifest.epoch != state.epoch);
    let owner_only =
        commit.roster.is_some() || !commit.shares.is_empty() || epoch_change || manifest.repair;
    let allowed = if owner_only {
        author.role == Role::Owner
    } else {
        author.role.can_write()
    };
    if !allowed {
        return Err(ProtoError::Authz);
    }
    for share in &commit.shares {
        check_bundled_share(share, manifest, roster, author.ik_pk)?;
    }
    Ok(())
}

fn check_bundled_share(
    share: &Signed<Share>,
    manifest: &Manifest,
    roster: &Roster,
    owner_key: hasp_crypto::VerifyingKey,
) -> Result<(), ProtoError> {
    let body = share.verify(SigLabel::Share, &owner_key)?;
    if body.vault_id != manifest.vault_id
        || body.from != manifest.author
        || body.rver != manifest.rver
        || body.to == body.from
        || roster.member(&body.to).is_none()
    {
        return Err(ProtoError::Roster);
    }
    if body.epoch != manifest.epoch {
        return Err(ProtoError::Epoch);
    }
    Ok(())
}

fn apply_ops(
    state: Option<&VaultState>,
    commit: &Commit,
    manifest: &Manifest,
) -> Result<LeafSet, ProtoError> {
    let mut leafset = state.map(|state| state.leafset.clone()).unwrap_or_default();
    for op in &commit.ops {
        let wire = op.wire();
        if wire.vault_id != manifest.vault_id {
            return Err(ProtoError::Format);
        }
        if wire.epoch != manifest.epoch {
            return Err(ProtoError::Epoch);
        }
        leafset.apply(op)?;
    }
    if !leafset.live_epochs_equal(manifest.epoch) {
        return Err(ProtoError::Epoch);
    }
    Ok(leafset)
}
