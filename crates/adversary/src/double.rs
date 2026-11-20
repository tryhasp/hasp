use std::collections::BTreeMap;

use hasp_crypto::{Argon2idParams, KemSecretKey, SecretKey, VerifyingKey, ct_eq, hpke_open};
use hasp_proto::{
    Aad, AccountRecord, AccountSeen, Commit, CtxValue, Dissolve, HPKE_SHARE_AAD, HPKE_SHARE_INFO,
    Hash32, InviteCode, ItemBody, ItemId, ItemOp, Kdf, Leaf, LeafFlag, LeaveRequest, OwnKeys,
    PinCheck, PinState, ProtoError, Role, Roster, Share, SigLabel, Signed, VaultKind, VaultState,
    Wire, Writer, derive, fingerprint, leaf_hash, pin_check, vk_commit,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Check {
    Chain,
    VaultMatch,
    RosterSigner,
    RosterSignature,
    RosterOwnKey,
    RosterPins,
    RosterShape,
    RosterSuccessor,
    RosterImmutable,
    RosterEpoch,
    RemovalBump,
    BindRoster,
    BindEpoch,
    EpochNotLower,
    RverNotLower,
    AuthorMember,
    ManifestSignature,
    OwnerOnly,
    BundledShare,
    OpVault,
    OpEpoch,
    OpVersion,
    LiveEpochs,
    Root,
    ShareTo,
    ShareKemHash,
    ShareFrom,
    ShareInviteFingerprint,
    SharePin,
    ShareSignature,
    ShareBinding,
    ShareVkCommit,
    KdfFloor,
    AccountSignature,
    AccountChain,
    AccountPin,
    DissolveSignature,
    DissolveMarks,
    DissolveFork,
    LeaveSignature,
    LeaveBinding,
    ItemLeaf,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Opened {
    Live { overview: Vec<u8>, details: Vec<u8> },
    Tombstone,
}

#[derive(Clone, Debug)]
pub(crate) struct DState {
    pub(crate) seq: u64,
    pub(crate) hash: Hash32,
    pub(crate) rver: u64,
    pub(crate) roster_hash: Hash32,
    pub(crate) epoch: u64,
    pub(crate) roster: Roster,
    pub(crate) leaves: BTreeMap<ItemId, Leaf>,
}

impl DState {
    pub(crate) fn from_real(state: &VaultState) -> Self {
        Self {
            seq: state.seq.get(),
            hash: state.hash,
            rver: state.rver.get(),
            roster_hash: state.roster_hash,
            epoch: state.epoch.get(),
            roster: state.roster.clone(),
            leaves: state
                .leafset
                .iter()
                .map(|leaf| (leaf.item_id, leaf.clone()))
                .collect(),
        }
    }
}

pub(crate) fn root_of(leaves: &BTreeMap<ItemId, Leaf>) -> Hash32 {
    let count = u32::try_from(leaves.len()).unwrap().to_be_bytes();
    let hashes: Vec<Hash32> = leaves.values().map(|l| leaf_hash(l).unwrap()).collect();
    let mut parts: Vec<&[u8]> = vec![Kdf::Leafset.name().as_bytes(), &count];
    parts.extend(hashes.iter().map(|h| h.as_bytes().as_slice()));
    Hash32::digest(&parts)
}

pub(crate) fn kem_hash(kem_pk: &hasp_crypto::KemPublicKey) -> Hash32 {
    Hash32::digest(&[kem_pk.as_bytes()])
}

fn removes_member(before: &Roster, after: &Roster) -> bool {
    before
        .members
        .iter()
        .any(|m| after.member(&m.account_id).is_none())
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Verifier {
    skip: Vec<Check>,
}

type RosterWithHash = (Roster, Hash32);

impl Verifier {
    pub(crate) fn full() -> Self {
        Self::default()
    }

    pub(crate) fn without(skip: &[Check]) -> Self {
        Self {
            skip: skip.to_vec(),
        }
    }

    fn on(&self, check: Check) -> bool {
        !self.skip.contains(&check)
    }

    fn open<T: Wire>(
        &self,
        check: Check,
        rec: &Signed<T>,
        label: SigLabel,
        key: &VerifyingKey,
    ) -> Result<T, ProtoError> {
        if self.on(check) {
            rec.verify(label, key)
        } else {
            rec.unverified()
        }
    }

    pub(crate) fn genesis(
        &self,
        commit: &Commit,
        own: &OwnKeys,
        pins: &PinState,
    ) -> Result<DState, ProtoError> {
        self.apply(None, commit, own, pins)
    }

    pub(crate) fn batch(
        &self,
        state: &DState,
        commits: &[Commit],
        own: &OwnKeys,
        pins: &PinState,
    ) -> Result<DState, ProtoError> {
        let mut current = state.clone();
        for commit in commits {
            current = self.apply(Some(&current), commit, own, pins)?;
        }
        Ok(current)
    }

    fn apply(
        &self,
        state: Option<&DState>,
        commit: &Commit,
        own: &OwnKeys,
        pins: &PinState,
    ) -> Result<DState, ProtoError> {
        let manifest = commit.manifest.unverified()?;
        let hash = commit.manifest.hash();
        self.chain(state, &manifest, &hash)?;
        let (roster, roster_hash) = match (&commit.roster, state) {
            (Some(rec), _) => {
                let prior = state.map(|s| (&s.roster, &s.roster_hash));
                self.roster(rec, prior, own, pins)?
            }
            (None, Some(s)) => (s.roster.clone(), s.roster_hash),
            (None, None) => return Err(ProtoError::Roster),
        };
        self.bind(
            state,
            &manifest,
            &(roster.clone(), roster_hash),
            commit.roster.is_some(),
        )?;
        self.authorize(state, commit, &manifest, &roster)?;
        let mut leaves = state.map(|s| s.leaves.clone()).unwrap_or_default();
        for op in &commit.ops {
            self.apply_op(&mut leaves, op, &manifest)?;
        }
        if self.on(Check::LiveEpochs)
            && leaves
                .values()
                .any(|l| l.flag == LeafFlag::Live && l.epoch != manifest.epoch)
        {
            return Err(ProtoError::Epoch);
        }
        if self.on(Check::Root) && root_of(&leaves) != manifest.root {
            return Err(ProtoError::Root);
        }
        Ok(DState {
            seq: manifest.seq.get(),
            hash,
            rver: roster.rver.get(),
            roster_hash,
            epoch: roster.epoch.get(),
            roster,
            leaves,
        })
    }

    fn chain(
        &self,
        state: Option<&DState>,
        manifest: &hasp_proto::Manifest,
        hash: &Hash32,
    ) -> Result<(), ProtoError> {
        let Some(state) = state else {
            if self.on(Check::Chain) {
                if manifest.seq.get() != 1 {
                    return Err(ProtoError::Rollback);
                }
                if manifest.prev.is_some() {
                    return Err(ProtoError::Fork);
                }
            }
            return Ok(());
        };
        if self.on(Check::VaultMatch) && manifest.vault_id != state.roster.vault_id {
            return Err(ProtoError::Roster);
        }
        if self.on(Check::Chain) {
            if manifest.seq.get() == state.seq && *hash != state.hash {
                return Err(ProtoError::Fork);
            }
            if manifest.seq.get() != state.seq.checked_add(1).unwrap() {
                return Err(ProtoError::Rollback);
            }
            if manifest.prev != Some(state.hash) {
                return Err(ProtoError::Fork);
            }
        }
        Ok(())
    }

    pub(crate) fn roster(
        &self,
        rec: &Signed<Roster>,
        prior: Option<(&Roster, &Hash32)>,
        own: &OwnKeys,
        pins: &PinState,
    ) -> Result<RosterWithHash, ProtoError> {
        let claimed = rec.unverified()?;
        let owner = claimed.owner().ok_or(ProtoError::Roster)?;
        let signer = match prior {
            Some((before, _)) if self.on(Check::RosterSigner) => {
                before.owner().ok_or(ProtoError::Roster)?.ik_pk
            }
            Some(_) | None => owner.ik_pk,
        };
        let roster = self.open(Check::RosterSignature, rec, SigLabel::Roster, &signer)?;
        let hash = rec.hash();
        if self.on(Check::RosterShape) {
            let one_only = roster.kind == VaultKind::Private;
            if roster.members.is_empty()
                || (one_only && roster.members.len() != 1)
                || roster.members.iter().any(|m| m.added_rver > roster.rver)
            {
                return Err(ProtoError::Roster);
            }
        }
        for member in &roster.members {
            if member.account_id == own.account_id {
                if self.on(Check::RosterOwnKey)
                    && (member.ik_pk != own.ik_pk || member.kem_pk != own.kem_pk)
                {
                    return Err(ProtoError::Roster);
                }
            } else if self.on(Check::RosterPins)
                && pin_check(pins, &member.account_id, &member.ik_pk, &member.kem_pk)
                    == PinCheck::KeyChanged
            {
                return Err(ProtoError::Pin);
            }
        }
        match prior {
            Some((before, before_hash)) => self.successor(&roster, &hash, before, before_hash)?,
            None => {
                if self.on(Check::RosterSuccessor)
                    && (roster.rver.get() != 1 || roster.prev.is_some())
                {
                    return Err(ProtoError::Roster);
                }
            }
        }
        Ok((roster, hash))
    }

    fn successor(
        &self,
        roster: &Roster,
        hash: &Hash32,
        before: &Roster,
        before_hash: &Hash32,
    ) -> Result<(), ProtoError> {
        if self.on(Check::RosterSuccessor) {
            if roster.rver < before.rver {
                return Err(ProtoError::Rollback);
            }
            if roster.rver == before.rver {
                return Err(if hash == before_hash {
                    ProtoError::Rollback
                } else {
                    ProtoError::Fork
                });
            }
            if roster.rver.get() != before.rver.get().checked_add(1).unwrap()
                || roster.prev != Some(*before_hash)
            {
                return Err(ProtoError::Roster);
            }
        }
        if self.on(Check::RosterImmutable) {
            if roster.vault_id != before.vault_id || roster.kind != before.kind {
                return Err(ProtoError::Roster);
            }
            if roster.owner().ok_or(ProtoError::Roster)?
                != before.owner().ok_or(ProtoError::Roster)?
            {
                return Err(ProtoError::Roster);
            }
        }
        if self.on(Check::RosterEpoch) {
            if roster.epoch < before.epoch {
                return Err(ProtoError::Epoch);
            }
            let bumped = roster.epoch > before.epoch;
            if bumped == (roster.vk_commit == before.vk_commit) {
                return Err(ProtoError::Roster);
            }
        }
        if self.on(Check::RemovalBump)
            && removes_member(before, roster)
            && roster.epoch.get() != before.epoch.get().checked_add(1).unwrap()
        {
            return Err(ProtoError::Epoch);
        }
        Ok(())
    }

    fn bind(
        &self,
        state: Option<&DState>,
        manifest: &hasp_proto::Manifest,
        (roster, roster_hash): &RosterWithHash,
        changed: bool,
    ) -> Result<(), ProtoError> {
        if self.on(Check::BindRoster)
            && (manifest.vault_id != roster.vault_id
                || manifest.rver != roster.rver
                || manifest.roster_hash != *roster_hash)
        {
            return Err(ProtoError::Roster);
        }
        if self.on(Check::BindEpoch) && manifest.epoch != roster.epoch {
            return Err(ProtoError::Epoch);
        }
        let Some(state) = state else {
            return Ok(());
        };
        if self.on(Check::EpochNotLower) && manifest.epoch.get() < state.epoch {
            return Err(ProtoError::Epoch);
        }
        if self.on(Check::RverNotLower) && manifest.rver.get() < state.rver {
            return Err(ProtoError::Roster);
        }
        if self.on(Check::RemovalBump)
            && changed
            && removes_member(&state.roster, roster)
            && manifest.epoch.get() != state.epoch.checked_add(1).unwrap()
        {
            return Err(ProtoError::Epoch);
        }
        Ok(())
    }

    fn authorize(
        &self,
        state: Option<&DState>,
        commit: &Commit,
        manifest: &hasp_proto::Manifest,
        roster: &Roster,
    ) -> Result<(), ProtoError> {
        let (key, role) = match roster.member(&manifest.author) {
            Some(member) => (member.ik_pk, member.role),
            None if !self.on(Check::AuthorMember) => (commit.manifest.signer, Role::Owner),
            None => return Err(ProtoError::Authz),
        };
        self.open(
            Check::ManifestSignature,
            &commit.manifest,
            SigLabel::Manifest,
            &key,
        )?;
        let epoch_change = state.is_some_and(|s| manifest.epoch.get() != s.epoch);
        let owner_only =
            commit.roster.is_some() || !commit.shares.is_empty() || epoch_change || manifest.repair;
        let allowed = if owner_only {
            role == Role::Owner
        } else {
            role.can_write()
        };
        if self.on(Check::OwnerOnly) && !allowed {
            return Err(ProtoError::Authz);
        }
        if self.on(Check::BundledShare) {
            for share in &commit.shares {
                let body = share.verify(SigLabel::Share, &key)?;
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
            }
        }
        Ok(())
    }

    fn apply_op(
        &self,
        leaves: &mut BTreeMap<ItemId, Leaf>,
        op: &ItemOp,
        manifest: &hasp_proto::Manifest,
    ) -> Result<(), ProtoError> {
        let wire = op.wire();
        if self.on(Check::OpVault) && wire.vault_id != manifest.vault_id {
            return Err(ProtoError::Format);
        }
        if self.on(Check::OpEpoch) && wire.epoch != manifest.epoch {
            return Err(ProtoError::Epoch);
        }
        let flag = match wire.body {
            ItemBody::Live { .. } => LeafFlag::Live,
            ItemBody::Tombstone => LeafFlag::Tombstone,
        };
        if self.on(Check::OpVersion) {
            let accepted = match leaves.get(&wire.item_id) {
                None => wire.ver.get() == 1,
                Some(leaf) => {
                    wire.ver.get() == leaf.ver.get().checked_add(1).unwrap()
                        || (wire.ver == leaf.ver
                            && wire.epoch > leaf.epoch
                            && leaf.flag == LeafFlag::Live
                            && flag == LeafFlag::Live)
                }
            };
            if !accepted {
                return Err(ProtoError::Epoch);
            }
        }
        leaves.insert(
            wire.item_id,
            Leaf {
                item_id: wire.item_id,
                ver: wire.ver,
                epoch: wire.epoch,
                h_item: *op.h_item(),
                flag,
            },
        );
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the signature of hasp_proto::verify_share plus self"
    )]
    pub(crate) fn share(
        &self,
        share: &Signed<Share>,
        own: &OwnKeys,
        (roster, _): (&Roster, &Hash32),
        invite: Option<&InviteCode>,
        pins: &PinState,
    ) -> Result<Share, ProtoError> {
        let claimed = share.unverified()?;
        if self.on(Check::ShareTo) && claimed.to != own.account_id {
            return Err(ProtoError::Authz);
        }
        if self.on(Check::ShareKemHash)
            && kem_hash(&own.kem_pk) != claimed.kem_pk_hash
            && !own.retired_kem_pk_hashes.contains(&claimed.kem_pk_hash)
        {
            return Err(ProtoError::Roster);
        }
        let owner = roster.owner().ok_or(ProtoError::Roster)?;
        if self.on(Check::ShareFrom) && claimed.from != owner.account_id {
            return Err(ProtoError::Roster);
        }
        if let Some(invite) = invite
            && self.on(Check::ShareInviteFingerprint)
            && fingerprint(&owner.ik_pk, &owner.kem_pk) != invite.fp_owner
        {
            return Err(ProtoError::Invite);
        }
        if self.on(Check::SharePin) {
            match pin_check(pins, &owner.account_id, &owner.ik_pk, &owner.kem_pk) {
                PinCheck::Ok => {}
                PinCheck::KeyChanged => return Err(ProtoError::Pin),
                PinCheck::New | PinCheck::Unverified if invite.is_some() => {}
                PinCheck::New | PinCheck::Unverified => return Err(ProtoError::Invite),
            }
        }
        let body = self.open(Check::ShareSignature, share, SigLabel::Share, &owner.ik_pk)?;
        if self.on(Check::ShareBinding) {
            if roster.kind != VaultKind::Shared
                || body.vault_id != roster.vault_id
                || body.rver != roster.rver
            {
                return Err(ProtoError::Roster);
            }
            if body.epoch != roster.epoch {
                return Err(ProtoError::Epoch);
            }
            let member = roster.member(&body.to).ok_or(ProtoError::Roster)?;
            if member.ik_pk != own.ik_pk
                || kem_hash(&member.kem_pk) != body.kem_pk_hash
                || member.role == Role::Owner
            {
                return Err(ProtoError::Roster);
            }
        }
        Ok(body)
    }

    pub(crate) fn open_share(
        &self,
        share: &Share,
        own_kem: &KemSecretKey,
        (roster, roster_hash): (&Roster, &Hash32),
    ) -> Result<SecretKey, ProtoError> {
        let owner = roster.owner().ok_or(ProtoError::Roster)?;
        let recipient = roster.member(&share.to).ok_or(ProtoError::Roster)?;
        let (info, aad) = share_context(share, &owner.ik_pk, &recipient.ik_pk, roster_hash)?;
        let plain =
            hpke_open(own_kem, &share.enc, &info, &aad, &share.ct).map_err(|_| ProtoError::Aead)?;
        let bytes: [u8; 32] = plain.expose().try_into().map_err(|_| ProtoError::Aead)?;
        let vk = SecretKey::from_bytes(bytes);
        if self.on(Check::ShareVkCommit) {
            let commit = vk_commit(&vk, &share.vault_id, share.epoch)?;
            if !ct_eq(commit.as_bytes(), roster.vk_commit.as_bytes()) {
                return Err(ProtoError::Roster);
            }
        }
        Ok(vk)
    }

    pub(crate) fn account(
        &self,
        rec: &Signed<AccountRecord>,
        seen: Option<&AccountSeen>,
        pins: &PinState,
    ) -> Result<AccountRecord, ProtoError> {
        let claimed = rec.unverified()?;
        if self.on(Check::KdfFloor) {
            Argon2idParams::account(claimed.kdf.m, claimed.kdf.t, claimed.kdf.p)
                .map_err(|_| ProtoError::KdfParams)?;
        }
        let record = self.open(
            Check::AccountSignature,
            rec,
            SigLabel::Account,
            &claimed.ik_pk,
        )?;
        if let Some(seen) = seen
            && self.on(Check::AccountChain)
        {
            if record.seq.get() < seen.seq.get() {
                return Err(ProtoError::Rollback);
            }
            if record.seq == seen.seq && rec.hash() != seen.hash {
                return Err(ProtoError::Fork);
            }
            if record.seq.get() == seen.seq.get().checked_add(1).unwrap()
                && record.prev != Some(seen.hash)
            {
                return Err(ProtoError::Fork);
            }
        }
        if self.on(Check::AccountPin)
            && pin_check(pins, &record.account_id, &record.ik_pk, &record.kem_pk)
                == PinCheck::KeyChanged
        {
            return Err(ProtoError::Pin);
        }
        Ok(record)
    }

    pub(crate) fn open_item(
        &self,
        item: &hasp_proto::ItemWire,
        wire_bytes: &[u8],
        state: &DState,
        vk: &SecretKey,
    ) -> Result<Opened, ProtoError> {
        if item.to_cbor()? != wire_bytes || item.vault_id != state.roster.vault_id {
            return Err(ProtoError::Format);
        }
        if self.on(Check::ItemLeaf) {
            let leaf = state.leaves.get(&item.item_id).ok_or(ProtoError::Root)?;
            if leaf.ver != item.ver
                || leaf.epoch != item.epoch
                || leaf.h_item != hasp_proto::item_wire_hash(wire_bytes)
            {
                return Err(ProtoError::Root);
            }
            let live = matches!(item.body, ItemBody::Live { .. });
            if live != (leaf.flag == LeafFlag::Live) {
                return Err(ProtoError::Root);
            }
        }
        let ItemBody::Live { wrap, ov, det } = &item.body else {
            return Ok(Opened::Tombstone);
        };
        let wrap_key = derive(
            vk,
            Kdf::ItemWrap,
            &[
                CtxValue::Id16(*item.vault_id.as_bytes()),
                CtxValue::Uint(item.epoch.uint()),
            ],
        )?;
        let opened = wrap.open(
            &wrap_key,
            &Aad::item_key_wrap(item.vault_id, item.item_id, item.epoch, item.ver),
        )?;
        let item_key =
            SecretKey::from_bytes(opened.expose().try_into().map_err(|_| ProtoError::Format)?);
        let field = |n: u64| {
            derive(
                &item_key,
                Kdf::Field,
                &[
                    CtxValue::Id16(*item.vault_id.as_bytes()),
                    CtxValue::Id16(*item.item_id.as_bytes()),
                    CtxValue::Uint(item.ver.uint()),
                    CtxValue::Uint(hasp_proto::Uint53::new(n)?),
                ],
            )
        };
        let overview = ov.open(
            &field(1)?,
            &Aad::item_overview(item.vault_id, item.item_id, item.ver),
        )?;
        let details = det.open(
            &field(2)?,
            &Aad::item_details(item.vault_id, item.item_id, item.ver),
        )?;
        Ok(Opened::Live {
            overview: overview.expose().to_vec(),
            details: details.expose().to_vec(),
        })
    }

    pub(crate) fn dissolve(
        &self,
        rec: &Signed<Dissolve>,
        state: &DState,
    ) -> Result<Dissolve, ProtoError> {
        let owner = state.roster.owner().ok_or(ProtoError::Roster)?;
        let dissolve = self.open(
            Check::DissolveSignature,
            rec,
            SigLabel::Dissolve,
            &owner.ik_pk,
        )?;
        if dissolve.vault_id != state.roster.vault_id || state.roster.kind != VaultKind::Shared {
            return Err(ProtoError::Roster);
        }
        if self.on(Check::DissolveMarks)
            && (dissolve.rver.get() < state.rver
                || dissolve.epoch.get() < state.epoch
                || dissolve.seq.get() < state.seq)
        {
            return Err(ProtoError::Rollback);
        }
        if self.on(Check::DissolveFork)
            && dissolve.seq.get() == state.seq
            && dissolve.head != state.hash
        {
            return Err(ProtoError::Fork);
        }
        Ok(dissolve)
    }

    pub(crate) fn leave(
        &self,
        rec: &Signed<LeaveRequest>,
        state: &DState,
    ) -> Result<LeaveRequest, ProtoError> {
        let claimed = rec.unverified()?;
        let member = state
            .roster
            .member(&claimed.account_id)
            .ok_or(ProtoError::Authz)?;
        if member.role == Role::Owner {
            return Err(ProtoError::Authz);
        }
        let leave = self.open(Check::LeaveSignature, rec, SigLabel::Leave, &member.ik_pk)?;
        if leave.vault_id != state.roster.vault_id {
            return Err(ProtoError::Roster);
        }
        if self.on(Check::LeaveBinding) {
            if leave.rver.get() != state.rver {
                return Err(ProtoError::Roster);
            }
            if leave.epoch.get() != state.epoch {
                return Err(ProtoError::Epoch);
            }
        }
        Ok(leave)
    }
}

pub(crate) fn share_context(
    share: &Share,
    from_ik_pk: &VerifyingKey,
    to_ik_pk: &VerifyingKey,
    roster_hash: &Hash32,
) -> Result<(Vec<u8>, Vec<u8>), ProtoError> {
    let mut info = Writer::new();
    info.array(9)?;
    info.text(HPKE_SHARE_INFO)?;
    info.bytes(share.vault_id.as_bytes())?;
    info.uint(share.epoch.get())?;
    info.uint(share.rver.get())?;
    info.bytes(share.from.as_bytes())?;
    info.bytes(share.to.as_bytes())?;
    info.bytes(from_ik_pk.as_bytes())?;
    info.bytes(to_ik_pk.as_bytes())?;
    info.bytes(share.kem_pk_hash.as_bytes())?;
    let mut aad = Writer::new();
    aad.array(2)?;
    aad.text(HPKE_SHARE_AAD)?;
    aad.bytes(roster_hash.as_bytes())?;
    Ok((info.into_bytes(), aad.into_bytes()))
}

pub(crate) fn directory_share(
    roster: (&Roster, &Hash32),
    owner_key: &hasp_crypto::SigningKey,
    vk: &SecretKey,
    to: &hasp_proto::AccountId,
    directory_kem: &hasp_crypto::KemPublicKey,
) -> Signed<Share> {
    let (rows, roster_hash) = roster;
    let owner = rows.owner().unwrap();
    let recipient = rows.member(to).unwrap();
    let mut share = Share {
        vault_id: rows.vault_id,
        epoch: rows.epoch,
        rver: rows.rver,
        from: owner.account_id,
        to: *to,
        kem_pk_hash: kem_hash(directory_kem),
        enc: [0; hasp_crypto::XWING_ENCAPSULATED_LEN],
        ct: [0; hasp_proto::SHARE_CT_LEN],
    };
    let (info, aad) = share_context(&share, &owner.ik_pk, &recipient.ik_pk, roster_hash).unwrap();
    let sealed = hasp_crypto::hpke_seal(directory_kem, &info, &aad, vk.expose()).unwrap();
    share.enc = sealed.enc;
    share.ct = sealed.ct.try_into().unwrap();
    Signed::sign(SigLabel::Share, &share, owner_key).unwrap()
}
