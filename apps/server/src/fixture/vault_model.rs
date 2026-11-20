use std::collections::BTreeMap;

use hasp_crypto::SecretKey;
use hasp_proto::wire::CommitBundle;
use hasp_proto::{
    AccountId, Commit as ProtoCommit, Epoch, Hash32, ItemBody, ItemId, ItemOp, ItemParams,
    ItemWire, LeafSet, Manifest, Member, OsEntropy, PinState, Role, Roster, Rver, Seq, ShareKey,
    SigLabel, Signed, VaultId, VaultKind, VerifiedRoster, Version, Wire, leafset_root, rewrap_item,
    seal_item, seal_share, tombstone, verify_roster, vk_commit,
};

use super::person::Person;
use super::{copy, rnd};

#[derive(Debug)]
pub struct VaultModel {
    pub id: VaultId,
    pub kind: VaultKind,
    pub owner: AccountId,
    pub members: BTreeMap<AccountId, Member>,
    pub rver: u64,
    pub epoch: u64,
    pub seq: u64,
    pub head: Option<Hash32>,
    pub roster: Option<(Roster, Hash32)>,
    pub verified: Option<VerifiedRoster>,
    pub vks: Vec<SecretKey>,
    pub leaves: LeafSet,
    pub items: BTreeMap<ItemId, ItemWire>,
}

impl Clone for VaultModel {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            kind: self.kind,
            owner: self.owner,
            members: self.members.clone(),
            rver: self.rver,
            epoch: self.epoch,
            seq: self.seq,
            head: self.head,
            roster: self.roster.clone(),
            verified: self.verified.clone(),
            vks: self.vks.iter().map(copy).collect(),
            leaves: self.leaves.clone(),
            items: self.items.clone(),
        }
    }
}

impl VaultModel {
    pub fn new(kind: VaultKind, owner: &Person) -> Self {
        Self {
            id: VaultId::random().expect("os randomness"),
            kind,
            owner: owner.account_id,
            members: BTreeMap::from([(owner.account_id, owner.member(Role::Owner, 1))]),
            rver: 0,
            epoch: 0,
            seq: 0,
            head: None,
            roster: None,
            verified: None,
            vks: vec![rnd()],
            leaves: LeafSet::new(),
            items: BTreeMap::new(),
        }
    }

    pub fn vk_at(&self, epoch: Epoch) -> &SecretKey {
        self.vks
            .get(usize::try_from(epoch.get()).expect("epoch"))
            .expect("vault key for epoch")
    }

    pub fn vk(&self) -> &SecretKey {
        self.vks.last().expect("a vault key")
    }

    pub fn item_id(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    fn roster_body(&self) -> Roster {
        Roster {
            vault_id: self.id,
            rver: Rver::new(self.rver).expect("rver"),
            epoch: Epoch::new(self.epoch).expect("epoch"),
            prev: self.roster.as_ref().map(|(_, hash)| *hash),
            kind: self.kind,
            members: self.members.values().cloned().collect(),
            vk_commit: vk_commit(self.vk(), &self.id, Epoch::new(self.epoch).expect("epoch"))
                .expect("commit"),
        }
    }

    fn sign_roster(&mut self, owner: &Person) -> Signed<Roster> {
        let roster = self.roster_body();
        let signed = Signed::sign(SigLabel::Roster, &roster, &owner.signing).expect("sign");
        let verified = verify_roster(
            &signed,
            self.verified.as_ref(),
            &owner.own_keys(),
            &PinState::new(),
        )
        .expect("fixture roster verifies");
        self.roster = Some((roster, signed.hash()));
        self.verified = Some(verified);
        signed
    }

    fn finish(
        &mut self,
        author: &Person,
        roster: Option<Signed<Roster>>,
        shares: Vec<Signed<hasp_proto::Share>>,
        wires: Vec<ItemWire>,
    ) -> CommitBundle {
        for wire in &wires {
            let op = ItemOp::from_wire_bytes(&wire.to_cbor().expect("wire")).expect("op");
            self.leaves.apply(&op).expect("fixture ops apply");
            self.items.insert(wire.item_id, wire.clone());
        }
        let (_, roster_hash) = self.roster.clone().expect("roster");
        let manifest = Manifest {
            vault_id: self.id,
            seq: Seq::new(self.seq.checked_add(1).expect("seq")).expect("seq"),
            prev: self.head,
            epoch: Epoch::new(self.epoch).expect("epoch"),
            rver: Rver::new(self.rver).expect("rver"),
            roster_hash,
            root: leafset_root(&self.leaves).expect("root"),
            author: author.account_id,
            repair: false,
        };
        let signed = Signed::sign(SigLabel::Manifest, &manifest, &author.signing).expect("sign");
        self.seq = self.seq.checked_add(1).expect("seq");
        self.head = Some(signed.hash());
        CommitBundle {
            manifest: signed,
            roster,
            shares,
            ops: wires,
        }
    }

    pub fn genesis(&mut self, owner: &Person) -> CommitBundle {
        self.rver = 1;
        let signed = self.sign_roster(owner);
        let settings = self.seal(ItemId::VAULT_SETTINGS, 1, 0, b"settings");
        self.finish(owner, Some(signed), Vec::new(), vec![settings])
    }

    pub fn seal(&self, item: ItemId, ver: u64, epoch: u64, overview: &[u8]) -> ItemWire {
        let epoch = Epoch::new(epoch).expect("epoch");
        seal_item(
            self.vk_at(epoch),
            &ItemParams {
                vault_id: self.id,
                item_id: item,
                ver: Version::new(ver).expect("ver"),
                epoch,
                overview,
                details: b"details",
                att_ids: Vec::new(),
                prev_h: if ver > 1 { self.prev_h(&item) } else { None },
            },
        )
        .expect("seal item")
    }

    fn prev_h(&self, item: &ItemId) -> Option<Hash32> {
        self.leaves.get(item).map(|leaf| leaf.h_item)
    }

    pub fn next_ver(&self, item: &ItemId) -> u64 {
        self.leaves
            .get(item)
            .map_or(1, |leaf| leaf.ver.get().checked_add(1).expect("ver"))
    }

    pub fn put_item(&mut self, author: &Person, n: u8, overview: &[u8]) -> CommitBundle {
        let id = Self::item_id(n);
        let wire = self.seal(id, self.next_ver(&id), self.epoch, overview);
        self.finish(author, None, Vec::new(), vec![wire])
    }

    pub fn put_item_with_attachments(
        &mut self,
        author: &Person,
        n: u8,
        att_ids: Vec<hasp_proto::AttId>,
    ) -> CommitBundle {
        let id = Self::item_id(n);
        let epoch = Epoch::new(self.epoch).expect("epoch");
        let wire = seal_item(
            self.vk(),
            &ItemParams {
                vault_id: self.id,
                item_id: id,
                ver: Version::new(self.next_ver(&id)).expect("ver"),
                epoch,
                overview: b"with attachment",
                details: b"details",
                att_ids,
                prev_h: self.prev_h(&id),
            },
        )
        .expect("seal item");
        self.finish(author, None, Vec::new(), vec![wire])
    }

    pub fn delete_item(&mut self, author: &Person, n: u8) -> CommitBundle {
        let id = Self::item_id(n);
        let wire = tombstone(
            self.id,
            id,
            Version::new(self.next_ver(&id)).expect("ver"),
            Epoch::new(self.epoch).expect("epoch"),
            self.prev_h(&id),
        );
        self.finish(author, None, Vec::new(), vec![wire])
    }

    fn share_to(&self, owner: &Person, to: &AccountId) -> Signed<hasp_proto::Share> {
        seal_share(
            self.verified.as_ref().expect("verified roster"),
            &ShareKey {
                owner_key: &owner.signing,
                vk: self.vk(),
                to,
            },
        )
        .expect("share")
    }

    pub fn add_member(&mut self, owner: &Person, who: &Person, role: Role) -> CommitBundle {
        self.rver = self.rver.checked_add(1).expect("rver");
        self.members
            .insert(who.account_id, who.member(role, self.rver));
        let signed = self.sign_roster(owner);
        let share = self.share_to(owner, &who.account_id);
        self.finish(owner, Some(signed), vec![share], Vec::new())
    }

    pub fn change_role(&mut self, owner: &Person, who: &AccountId, role: Role) -> CommitBundle {
        self.rver = self.rver.checked_add(1).expect("rver");
        let member = self.members.get_mut(who).expect("member");
        member.role = role;
        let signed = self.sign_roster(owner);
        self.finish(owner, Some(signed), Vec::new(), Vec::new())
    }

    pub fn remove_member(&mut self, owner: &Person, who: &AccountId) -> CommitBundle {
        self.rver = self.rver.checked_add(1).expect("rver");
        self.members.remove(who);
        self.epoch = self.epoch.checked_add(1).expect("epoch");
        let old_vk = copy(self.vk());
        let new_vk = rnd();
        self.vks.push(copy(&new_vk));
        let signed = self.sign_roster(owner);
        let epoch = Epoch::new(self.epoch).expect("epoch");
        let shares = self
            .members
            .keys()
            .filter(|account| **account != owner.account_id)
            .map(|account| self.share_to(owner, account))
            .collect();
        let rewrapped = self
            .items
            .values()
            .filter(|wire| matches!(wire.body, ItemBody::Live { .. }))
            .map(|wire| rewrap_item(&mut OsEntropy, &old_vk, &new_vk, wire, epoch).expect("rewrap"))
            .collect();
        self.finish(owner, Some(signed), shares, rewrapped)
    }

    pub fn commit(&self, bundle: CommitBundle) -> hasp_proto::wire::Commit {
        let seq = bundle.manifest.unverified().expect("manifest").seq.get();
        hasp_proto::wire::Commit {
            vault_id: self.id,
            base_seq: Seq::new(seq.checked_sub(1).expect("base")).expect("seq"),
            bundle,
            self_wraps: Vec::new(),
        }
    }

    pub fn genesis_commit(&self, owner: &Person, bundle: CommitBundle) -> hasp_proto::wire::Commit {
        let mut commit = self.commit(bundle);
        commit.self_wraps = vec![hasp_proto::wire::SelfWrapEntry {
            epoch: Epoch::ZERO,
            wrap: owner.self_wrap(self, 0),
        }];
        commit
    }

    pub fn proto_commit(bundle: &CommitBundle) -> ProtoCommit {
        ProtoCommit {
            manifest: bundle.manifest.clone(),
            roster: bundle.roster.clone(),
            ops: bundle
                .ops
                .iter()
                .map(|wire| ItemOp::from_wire_bytes(&wire.to_cbor().expect("wire")).expect("op"))
                .collect(),
            shares: bundle.shares.clone(),
        }
    }
}
