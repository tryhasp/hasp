use std::collections::BTreeMap;

use hasp_crypto::{KemPublicKey, KemSecretKey, SecretKey, SigningKey, VerifyingKey};
use hasp_proto::{
    AccountId, Commit, Entropy, Epoch, Hash32, ItemBody, ItemId, ItemOp, ItemParams, ItemWire,
    LeafSet, Manifest, Member, OwnKeys, PinState, ProtoError, Role, Roster, Rver, SeededEntropy,
    Seq, ShareKey, SigLabel, Signed, VaultId, VaultKind, VaultState, VerifiedRoster, Version, Wire,
    leafset_root, rewrap_item, seal_item_with, seal_share_with_randomness, tombstone, verify_batch,
    verify_genesis, vk_commit,
};

pub(crate) const OWNER: u8 = 1;
pub(crate) const EDITOR: u8 = 2;
pub(crate) const VIEWER: u8 = 3;
pub(crate) const INVITEE: u8 = 4;
pub(crate) const ATTACKER: u8 = 0xa0;

pub(crate) struct Person {
    pub(crate) account: AccountId,
    pub(crate) signing: SigningKey,
    pub(crate) kem: KemSecretKey,
    pub(crate) ik_pk: VerifyingKey,
    pub(crate) kem_pk: KemPublicKey,
}

impl Person {
    pub(crate) fn new(n: u8) -> Self {
        let signing = SigningKey::from_seed(&SecretKey::from_bytes([n.wrapping_add(0x40); 32]));
        let kem =
            KemSecretKey::from_seed(&SecretKey::from_bytes([n.wrapping_add(0x80); 32])).unwrap();
        Self {
            account: AccountId::from_bytes([n; 16]),
            ik_pk: signing.verifying_key(),
            kem_pk: kem.public_key(),
            signing,
            kem,
        }
    }

    pub(crate) fn impersonating(n: u8, victim: u8) -> Self {
        let mut person = Self::new(n);
        person.account = AccountId::from_bytes([victim; 16]);
        person
    }

    pub(crate) fn own(&self) -> OwnKeys {
        OwnKeys {
            account_id: self.account,
            ik_pk: self.ik_pk,
            kem_pk: self.kem_pk.clone(),
            retired_kem_pk_hashes: Vec::new(),
        }
    }

    pub(crate) fn member(&self, role: Role, added_rver: u64) -> Member {
        Member {
            account_id: self.account,
            ik_pk: self.ik_pk,
            kem_pk: self.kem_pk.clone(),
            role,
            added_rver: Rver::new(added_rver).unwrap(),
        }
    }
}

pub(crate) fn clone_key(key: &SecretKey) -> SecretKey {
    SecretKey::from_bytes(*key.expose())
}

pub(crate) fn verified(roster: &Roster, hash: Hash32) -> VerifiedRoster {
    VaultState {
        seq: Seq::new(1).unwrap(),
        hash,
        rver: roster.rver,
        roster_hash: hash,
        epoch: roster.epoch,
        roster: roster.clone(),
        leafset: LeafSet::new(),
    }
    .verified_roster()
}

pub(crate) fn bump(value: u64) -> u64 {
    value.checked_add(1).unwrap()
}

pub(crate) fn err_name<T>(result: Result<T, ProtoError>) -> &'static str {
    match result {
        Ok(_) => "Ok",
        Err(error) => error.name(),
    }
}

pub(crate) struct Chain {
    pub(crate) id: VaultId,
    pub(crate) kind: VaultKind,
    pub(crate) owner: u8,
    pub(crate) owner_keys: u8,
    pub(crate) others: BTreeMap<u8, (Role, u64)>,
    pub(crate) substitute: BTreeMap<u8, u8>,
    pub(crate) substitute_ik: BTreeMap<u8, u8>,
    pub(crate) substitute_kem: BTreeMap<u8, u8>,
    pub(crate) vks: Vec<SecretKey>,
    pub(crate) rver: u64,
    pub(crate) epoch: u64,
    pub(crate) seq: u64,
    pub(crate) roster: Option<(Roster, Hash32)>,
    pub(crate) head: Option<Hash32>,
    pub(crate) leaves: LeafSet,
    pub(crate) items: BTreeMap<ItemId, ItemWire>,
    pub(crate) entropy: SeededEntropy,
}

impl Chain {
    pub(crate) fn new(kind: VaultKind, owner: u8) -> Self {
        let mut entropy = SeededEntropy::new([owner; 32]);
        let vk0 = entropy.key().unwrap();
        Self {
            id: VaultId::from_bytes([0xee; 16]),
            kind,
            owner,
            owner_keys: owner,
            others: BTreeMap::new(),
            substitute: BTreeMap::new(),
            substitute_ik: BTreeMap::new(),
            substitute_kem: BTreeMap::new(),
            vks: vec![vk0],
            rver: 0,
            epoch: 0,
            seq: 0,
            roster: None,
            head: None,
            leaves: LeafSet::new(),
            items: BTreeMap::new(),
            entropy,
        }
    }

    pub(crate) fn person(&self, n: u8) -> Person {
        if n == self.owner {
            Person::impersonating(self.owner_keys, n)
        } else {
            Person::new(n)
        }
    }

    pub(crate) fn fork(&self) -> Self {
        Self {
            id: self.id,
            kind: self.kind,
            owner: self.owner,
            owner_keys: self.owner_keys,
            others: self.others.clone(),
            substitute: self.substitute.clone(),
            substitute_ik: self.substitute_ik.clone(),
            substitute_kem: self.substitute_kem.clone(),
            vks: self.vks.iter().map(clone_key).collect(),
            rver: self.rver,
            epoch: self.epoch,
            seq: self.seq,
            roster: self.roster.clone(),
            head: self.head,
            leaves: self.leaves.clone(),
            items: self.items.clone(),
            entropy: self.entropy.clone(),
        }
    }

    pub(crate) fn vk(&self) -> &SecretKey {
        self.vks.last().unwrap()
    }

    pub(crate) fn item_id(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    pub(crate) fn roster_hash(&self) -> Hash32 {
        self.roster.as_ref().unwrap().1
    }

    pub(crate) fn roster_body(&self, rver: u64, epoch: u64, vk: &SecretKey) -> Roster {
        let mut members = vec![(self.owner, self.person(self.owner).member(Role::Owner, 1))];
        for (n, (role, added)) in &self.others {
            let source = |map: &BTreeMap<u8, u8>| {
                map.get(n)
                    .or_else(|| self.substitute.get(n))
                    .copied()
                    .unwrap_or(*n)
            };
            let mut member = Person::new(*n).member(*role, *added);
            member.ik_pk = Person::new(source(&self.substitute_ik)).ik_pk;
            member.kem_pk = Person::new(source(&self.substitute_kem)).kem_pk;
            members.push((*n, member));
        }
        members.sort_by_key(|(n, _)| *n);
        Roster {
            vault_id: self.id,
            rver: Rver::new(rver).unwrap(),
            epoch: Epoch::new(epoch).unwrap(),
            prev: self.roster.as_ref().map(|(_, hash)| *hash),
            kind: self.kind,
            members: members.into_iter().map(|(_, member)| member).collect(),
            vk_commit: vk_commit(vk, &self.id, Epoch::new(epoch).unwrap()).unwrap(),
        }
    }

    pub(crate) fn sign_roster(&self, roster: &Roster) -> Signed<Roster> {
        Signed::sign(SigLabel::Roster, roster, &self.person(self.owner).signing).unwrap()
    }

    pub(crate) fn manifest_body(&self, roster_hash: Hash32, root: Hash32, author: u8) -> Manifest {
        Manifest {
            vault_id: self.id,
            seq: Seq::new(bump(self.seq)).unwrap(),
            prev: self.head,
            epoch: Epoch::new(self.epoch).unwrap(),
            rver: Rver::new(self.rver).unwrap(),
            roster_hash,
            root,
            author: AccountId::from_bytes([author; 16]),
            repair: false,
        }
    }

    pub(crate) fn finish(
        &mut self,
        author: u8,
        roster: Option<Signed<Roster>>,
        shares: Vec<Signed<hasp_proto::Share>>,
        wires: Vec<ItemWire>,
    ) -> Commit {
        let mut ops = Vec::new();
        for wire in wires {
            let op = ItemOp::from_wire_bytes(&wire.to_cbor().unwrap()).unwrap();
            self.leaves.apply(&op).unwrap();
            self.items.insert(wire.item_id, wire);
            ops.push(op);
        }
        let root = leafset_root(&self.leaves).unwrap();
        let manifest = self.manifest_body(self.roster_hash(), root, author);
        let signed =
            Signed::sign(SigLabel::Manifest, &manifest, &self.person(author).signing).unwrap();
        self.seq = bump(self.seq);
        self.head = Some(signed.hash());
        Commit {
            manifest: signed,
            roster,
            ops,
            shares,
        }
    }

    pub(crate) fn genesis(&mut self) -> Commit {
        self.rver = 1;
        let roster = self.roster_body(1, 0, &clone_key(&self.vks[0]));
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster, signed.hash()));
        self.finish(self.owner, Some(signed), Vec::new(), Vec::new())
    }

    pub(crate) fn wire(&mut self, item_n: u8, ver: u64, epoch: u64, overview: &[u8]) -> ItemWire {
        let vk = clone_key(&self.vks[usize::try_from(epoch).unwrap()]);
        let params = ItemParams {
            vault_id: self.id,
            item_id: Self::item_id(item_n),
            ver: Version::new(ver).unwrap(),
            epoch: Epoch::new(epoch).unwrap(),
            overview,
            details: b"details",
            att_ids: Vec::new(),
            prev_h: None,
        };
        seal_item_with(&mut self.entropy, &vk, &params).unwrap()
    }

    pub(crate) fn next_ver(&self, item_n: u8) -> u64 {
        self.leaves
            .get(&Self::item_id(item_n))
            .map_or(1, |leaf| bump(leaf.ver.get()))
    }

    pub(crate) fn put(&mut self, author: u8, item_n: u8, overview: &[u8]) -> Commit {
        let wire = self.wire(item_n, self.next_ver(item_n), self.epoch, overview);
        self.finish(author, None, Vec::new(), vec![wire])
    }

    pub(crate) fn delete(&mut self, author: u8, item_n: u8) -> Commit {
        let wire = tombstone(
            self.id,
            Self::item_id(item_n),
            Version::new(self.next_ver(item_n)).unwrap(),
            Epoch::new(self.epoch).unwrap(),
            None,
        );
        self.finish(author, None, Vec::new(), vec![wire])
    }

    pub(crate) fn add_member(&mut self, n: u8, role: Role) -> Commit {
        self.rver = bump(self.rver);
        self.others.insert(n, (role, self.rver));
        let roster = self.roster_body(self.rver, self.epoch, &clone_key(self.vk()));
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster.clone(), signed.hash()));
        let share = self.share_for(&roster, signed.hash(), n);
        self.finish(self.owner, Some(signed), vec![share], Vec::new())
    }

    pub(crate) fn remove_member(&mut self, n: u8) -> Commit {
        self.rver = bump(self.rver);
        self.others.remove(&n);
        self.epoch = bump(self.epoch);
        let old_vk = clone_key(self.vk());
        let new_vk = self.entropy.key().unwrap();
        self.vks.push(clone_key(&new_vk));
        let roster = self.roster_body(self.rver, self.epoch, &new_vk);
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster.clone(), signed.hash()));
        let shares: Vec<_> = self
            .others
            .keys()
            .map(|m| self.share_for(&roster, signed.hash(), *m))
            .collect();
        let mut rewrapped = Vec::new();
        for item in self.items.values().cloned().collect::<Vec<_>>() {
            if matches!(item.body, ItemBody::Live { .. }) {
                rewrapped.push(
                    rewrap_item(
                        &mut self.entropy,
                        &old_vk,
                        &new_vk,
                        &item,
                        Epoch::new(self.epoch).unwrap(),
                    )
                    .unwrap(),
                );
            }
        }
        self.finish(self.owner, Some(signed), shares, rewrapped)
    }

    pub(crate) fn share_for(
        &self,
        roster: &Roster,
        roster_hash: Hash32,
        to: u8,
    ) -> Signed<hasp_proto::Share> {
        let verified = verified(roster, roster_hash);
        let owner = self.person(self.owner);
        let recipient = AccountId::from_bytes([to; 16]);
        let vk = clone_key(&self.vks[usize::try_from(roster.epoch.get()).unwrap()]);
        seal_share_with_randomness(
            &verified,
            &ShareKey {
                owner_key: &owner.signing,
                vk: &vk,
                to: &recipient,
            },
            [to; 64],
        )
        .unwrap()
    }

    pub(crate) fn roster_commit(&mut self, author: u8, roster: Roster) -> Commit {
        self.rver = roster.rver.get();
        self.epoch = roster.epoch.get();
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster, signed.hash()));
        self.finish(author, Some(signed), Vec::new(), Vec::new())
    }

    pub(crate) fn resign(
        &self,
        commit: &Commit,
        author: u8,
        edit: impl FnOnce(&mut Manifest),
    ) -> Commit {
        let mut manifest = commit.manifest.unverified().unwrap();
        edit(&mut manifest);
        Commit {
            manifest: Signed::sign(SigLabel::Manifest, &manifest, &self.person(author).signing)
                .unwrap(),
            ..commit.clone()
        }
    }
}

pub(crate) struct Session {
    pub(crate) chain: Chain,
    pub(crate) viewer: Person,
    pub(crate) state: VaultState,
    pub(crate) pins: PinState,
}

impl Session {
    pub(crate) fn shared(viewer: u8, roles: &[(u8, Role)]) -> Self {
        let mut chain = Chain::new(VaultKind::Shared, OWNER);
        let genesis = chain.genesis();
        let pins = PinState::new();
        let owner = Person::new(OWNER);
        let mut state = verify_genesis(&genesis, &owner.own(), &pins).unwrap();
        let viewer = Person::new(viewer);
        for (n, role) in roles {
            let commit = chain.add_member(*n, *role);
            let own = if *n == viewer.account.as_bytes()[0] {
                viewer.own()
            } else {
                owner.own()
            };
            state = verify_batch(&state, &[commit], &own, &pins).unwrap();
        }
        Self {
            chain,
            viewer,
            state,
            pins,
        }
    }

    pub(crate) fn bare(viewer: u8) -> Self {
        Self::shared(viewer, &[])
    }

    pub(crate) fn owner() -> Self {
        Self::shared(OWNER, &[(EDITOR, Role::Editor), (VIEWER, Role::Viewer)])
    }

    pub(crate) fn verify(&self, commits: &[Commit]) -> Result<VaultState, ProtoError> {
        self.verify_from(&self.state, commits)
    }

    pub(crate) fn verify_from(
        &self,
        state: &VaultState,
        commits: &[Commit],
    ) -> Result<VaultState, ProtoError> {
        verify_batch(state, commits, &self.viewer.own(), &self.pins)
    }

    pub(crate) fn advance(&mut self, commits: &[Commit]) {
        self.state = self.verify(commits).unwrap();
    }
}
