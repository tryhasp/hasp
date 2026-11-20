use std::collections::BTreeMap;

use hasp_crypto::{KemPublicKey, KemSecretKey, SecretKey, SigningKey, VerifyingKey};

use crate::Writer;
use crate::{
    AccountId, Commit, Entropy, Epoch, Hash32, ItemId, ItemOp, ItemParams, ItemWire, LeafSet,
    Manifest, Member, OwnKeys, Role, Roster, Rver, SeededEntropy, Seq, ShareKey, SigLabel, Signed,
    VaultId, VaultKind, VaultState, VerifiedRoster, Version, Wire, leafset_root, rewrap_item,
    seal_item_with, seal_share_with_randomness, tombstone, vk_commit,
};

pub(crate) struct Person {
    pub(crate) n: u8,
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
            n,
            account: AccountId::from_bytes([n; 16]),
            ik_pk: signing.verifying_key(),
            kem_pk: kem.public_key(),
            signing,
            kem,
        }
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

pub(crate) struct Vault {
    pub(crate) id: VaultId,
    pub(crate) kind: VaultKind,
    pub(crate) owner: u8,
    pub(crate) others: BTreeMap<u8, (Role, u64)>,
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

impl Vault {
    pub(crate) fn new(kind: VaultKind, owner: u8) -> Self {
        let mut entropy = SeededEntropy::new([owner; 32]);
        let vk0 = entropy.key().unwrap();
        Self {
            id: VaultId::from_bytes([0xee; 16]),
            kind,
            owner,
            others: BTreeMap::new(),
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

    pub(crate) fn vk(&self) -> &SecretKey {
        self.vks.last().unwrap()
    }

    pub(crate) fn item_id(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    pub(crate) fn roster_body(&self, rver: u64, epoch: u64, vk: &SecretKey) -> Roster {
        let mut members = vec![(self.owner, Person::new(self.owner).member(Role::Owner, 1))];
        for (n, (role, added)) in &self.others {
            members.push((*n, Person::new(*n).member(*role, *added)));
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
        Signed::sign(SigLabel::Roster, roster, &Person::new(self.owner).signing).unwrap()
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
        shares: Vec<Signed<crate::Share>>,
        wires: Vec<ItemWire>,
    ) -> Commit {
        let mut ops = Vec::new();
        for wire in wires {
            let op = ItemOp::from_wire_bytes(&wire.to_cbor().unwrap()).unwrap();
            self.leaves.apply(&op).unwrap();
            self.items.insert(wire.item_id, wire);
            ops.push(op);
        }
        let (_, roster_hash) = self.roster.clone().unwrap();
        let root = leafset_root(&self.leaves).unwrap();
        let manifest = self.manifest_body(roster_hash, root, author);
        let signed =
            Signed::sign(SigLabel::Manifest, &manifest, &Person::new(author).signing).unwrap();
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
        let roster = self.roster_body(1, 0, &self.vks[0].clone_key());
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster, signed.hash()));
        self.finish(self.owner, Some(signed), Vec::new(), Vec::new())
    }

    pub(crate) fn seal(&mut self, item_n: u8, ver: u64, epoch: u64, overview: &[u8]) -> ItemWire {
        let vk = self.vks[usize::try_from(epoch).unwrap()].clone_key();
        let params = ItemParams {
            vault_id: self.id,
            item_id: Self::item_id(item_n),
            ver: Version::new(ver).unwrap(),
            epoch: Epoch::new(epoch).unwrap(),
            overview,
            details: b"details",
            att_ids: Vec::new(),
            prev_h: self.prev_h(item_n, ver),
        };
        seal_item_with(&mut self.entropy, &vk, &params).unwrap()
    }

    pub(crate) fn prev_h(&self, item_n: u8, ver: u64) -> Option<Hash32> {
        self.leaves
            .get(&Self::item_id(item_n))
            .filter(|leaf| bump(leaf.ver.get()) == ver)
            .map(|leaf| leaf.h_item)
    }

    pub(crate) fn next_ver(&self, item_n: u8) -> u64 {
        self.leaves
            .get(&Self::item_id(item_n))
            .map_or(1, |leaf| bump(leaf.ver.get()))
    }

    pub(crate) fn put(&mut self, author: u8, item_n: u8, overview: &[u8]) -> Commit {
        let wire = self.seal(item_n, self.next_ver(item_n), self.epoch, overview);
        self.finish(author, None, Vec::new(), vec![wire])
    }

    pub(crate) fn delete(&mut self, author: u8, item_n: u8) -> Commit {
        let wire = tombstone(
            self.id,
            Self::item_id(item_n),
            Version::new(self.next_ver(item_n)).unwrap(),
            Epoch::new(self.epoch).unwrap(),
            self.prev_h(item_n, self.next_ver(item_n)),
        );
        self.finish(author, None, Vec::new(), vec![wire])
    }

    pub(crate) fn add_member(&mut self, n: u8, role: Role) -> Commit {
        self.rver = bump(self.rver);
        self.others.insert(n, (role, self.rver));
        let roster = self.roster_body(self.rver, self.epoch, &self.vk().clone_key());
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster.clone(), signed.hash()));
        let share = self.share_for(&roster, signed.hash(), n);
        self.finish(self.owner, Some(signed), vec![share], Vec::new())
    }

    pub(crate) fn change_role(&mut self, n: u8, role: Role) -> Commit {
        self.rver = bump(self.rver);
        let added = self.others.get(&n).unwrap().1;
        self.others.insert(n, (role, added));
        let roster = self.roster_body(self.rver, self.epoch, &self.vk().clone_key());
        let signed = self.sign_roster(&roster);
        self.roster = Some((roster, signed.hash()));
        self.finish(self.owner, Some(signed), Vec::new(), Vec::new())
    }

    pub(crate) fn remove_member(&mut self, n: u8) -> Commit {
        self.rver = bump(self.rver);
        self.others.remove(&n);
        self.epoch = bump(self.epoch);
        let old_vk = self.vk().clone_key();
        let new_vk = self.entropy.key().unwrap();
        self.vks.push(new_vk.clone_key());
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
            if matches!(item.body, crate::ItemBody::Live { .. }) {
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
    ) -> Signed<crate::Share> {
        let verified = VerifiedRoster::trusted(roster.clone(), roster_hash);
        let owner = Person::new(self.owner);
        let recipient = AccountId::from_bytes([to; 16]);
        let vk = self.vks[usize::try_from(roster.epoch.get()).unwrap_or(0)].clone_key();
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

    pub(crate) fn entropy_key(&mut self) -> SecretKey {
        self.entropy.key().unwrap()
    }

    pub(crate) fn finish_unchecked(&mut self, author: u8, wires: Vec<ItemWire>) -> Commit {
        let (_, roster_hash) = self.roster.clone().unwrap();
        let mut ops = Vec::new();
        for wire in wires {
            let op = ItemOp::from_wire_bytes(&wire.to_cbor().unwrap()).unwrap();
            ops.push(op);
        }
        let root = leafset_root(&self.leaves).unwrap();
        let manifest = self.manifest_body(roster_hash, root, author);
        let signed =
            Signed::sign(SigLabel::Manifest, &manifest, &Person::new(author).signing).unwrap();
        Commit {
            manifest: signed,
            roster: None,
            ops,
            shares: Vec::new(),
        }
    }

    pub(crate) fn mirror(&mut self, other: &Self, state: &VaultState) {
        self.id = other.id;
        self.others = other.others.clone();
        self.vks = other.vks.iter().map(CloneKey::clone_key).collect();
        self.rver = other.rver;
        self.epoch = other.epoch;
        self.seq = state.seq.get();
        self.roster = other.roster.clone();
        self.head = Some(state.hash);
        self.leaves = state.leafset.clone();
        self.items = other.items.clone();
    }

    pub(crate) fn state_after(&self, state: &VaultState) -> bool {
        state.seq.get() == self.seq
            && Some(state.hash) == self.head
            && state.epoch.get() == self.epoch
            && state.rver.get() == self.rver
    }
}

pub(crate) trait CloneKey {
    fn clone_key(&self) -> SecretKey;
}

impl CloneKey for SecretKey {
    fn clone_key(&self) -> SecretKey {
        SecretKey::from_bytes(*self.expose())
    }
}

pub(crate) enum Entry {
    Uint(u64),
    Bytes(Vec<u8>),
    Null,
    Text(&'static str),
}

pub(crate) fn map_bytes(entries: &[(u64, Entry)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.map(entries.len()).unwrap();
    for (key, entry) in entries {
        w.uint(*key).unwrap();
        match entry {
            Entry::Uint(v) => w.uint(*v).unwrap(),
            Entry::Bytes(b) => w.bytes(b).unwrap(),
            Entry::Null => w.null(),
            Entry::Text(t) => w.text(t).unwrap(),
        }
    }
    w.into_bytes()
}

pub(crate) fn dissolve_entries(version: u64, rtype: u64) -> Vec<(u64, Entry)> {
    vec![
        (0, Entry::Uint(version)),
        (1, Entry::Uint(rtype)),
        (2, Entry::Bytes(vec![1; 16])),
        (3, Entry::Uint(1)),
        (4, Entry::Uint(0)),
        (5, Entry::Uint(2)),
        (6, Entry::Bytes(vec![2; 32])),
    ]
}

pub(crate) fn resign(commit: &mut Commit, author: &Person, edit: impl FnOnce(&mut Manifest)) {
    let mut manifest = commit.manifest.unverified().unwrap();
    edit(&mut manifest);
    commit.manifest = Signed::sign(SigLabel::Manifest, &manifest, &author.signing).unwrap();
}

pub(crate) fn bump(value: u64) -> u64 {
    value.checked_add(1).unwrap()
}
