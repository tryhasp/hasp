use hasp_proto::wire::{
    Blob, Commit, CommitBundle, InviteAccept, InviteCreate, InviteList, Operation,
};
use hasp_proto::{
    AccountId, AccountRecord, Epoch, InviteCode, Manifest, Member, PinState, Role, Roster, Rver,
    Seq, ShareKey, SigLabel, Signed, VaultId, VaultKind, Wire, fingerprint, leafset_root,
    seal_share, verify_account_record, vk_commit,
};
use hasp_server::Caller;
use hasp_server::fixture::VaultModel;
use hasp_testsupport::World;

use super::lab::{ORIGIN, Phone, cancel, phone};
use super::mallory::Mallory;
use super::rogue::{Rogue, rogue};

pub(crate) struct Lair {
    pub(crate) world: World,
    pub(crate) link: Mallory,
    pub(crate) bob: Phone,
    pub(crate) owner: Rogue,
    pub(crate) model: VaultModel,
}

impl Lair {
    pub(crate) async fn new() -> Self {
        let mut world = World::new();
        let link = Mallory::new(&world.server);
        let bob = phone(&mut world, &link, "bob@example.com", true).await;
        let owner = rogue(&mut world, "mallory@example.com").await;
        let mut model = VaultModel::new(VaultKind::Shared, &owner.person);
        let genesis = model.genesis(&owner.person);
        let lair = Self {
            world,
            link,
            bob,
            owner,
            model,
        };
        let commit = lair.model.genesis_commit(&lair.owner.person, genesis);
        lair.owner_call(&commit);
        lair
    }

    pub(crate) fn vault(&self) -> VaultId {
        self.model.id
    }

    pub(crate) fn owner_call<O: Operation>(&self, request: &O) -> O::Response {
        self.world
            .server
            .call(&Caller::with_token(self.owner.token.clone()), request)
            .unwrap()
    }

    pub(crate) fn publish(&self, bundle: CommitBundle) -> Commit {
        let commit = self.model.commit(bundle);
        self.owner_call(&commit);
        commit
    }

    pub(crate) fn put(&mut self, item: u8, overview: &[u8]) {
        let bundle = self.model.put_item(&self.owner.person, item, overview);
        self.publish(bundle);
    }

    fn invite(&self, role: Role) -> hasp_proto::InviteId {
        self.owner_call(&InviteCreate {
            vault_id: self.vault(),
            role,
        })
        .invite_id
    }

    fn invitee_record(&self, invite: &hasp_proto::InviteId) -> AccountRecord {
        let list = self.owner_call(&InviteList {
            vault_id: self.vault(),
        });
        let signed = list
            .invites
            .into_iter()
            .find(|entry| entry.invite_id == *invite)
            .and_then(|entry| entry.invitee)
            .unwrap();
        verify_account_record(&signed, None, &PinState::new()).unwrap()
    }

    pub(crate) async fn admit_bob(&mut self, role: Role) {
        let invite = self.invite(role);
        let code = InviteCode {
            invite_id: invite,
            fp_owner: fingerprint(&self.owner.person.ik_pk(), &self.owner.person.kem_pk()),
            origin: ORIGIN.to_owned(),
        };
        self.bob
            .client
            .invite_accept(&code.to_text().unwrap(), &cancel())
            .await
            .unwrap();
        let record = self.invitee_record(&invite);
        self.add(&record, role);
    }

    pub(crate) fn admit(&mut self, other: &Rogue, role: Role) {
        let invite = self.invite(role);
        self.world
            .server
            .call(
                &Caller::with_token(other.token.clone()),
                &InviteAccept {
                    invite_id: invite,
                    accept: Blob(other.person.account_id.to_cbor().unwrap()),
                },
            )
            .unwrap();
        let record = self.invitee_record(&invite);
        self.add(&record, role);
    }

    fn add(&mut self, record: &AccountRecord, role: Role) {
        let added_rver = Rver::new(self.model.rver + 1).unwrap();
        self.model.members.insert(
            record.account_id,
            Member {
                account_id: record.account_id,
                ik_pk: record.ik_pk,
                kem_pk: record.kem_pk.clone(),
                role,
                added_rver,
            },
        );
        let mut bundle = self
            .model
            .change_role(&self.owner.person, &record.account_id, role);
        let verified = self.model.verified.as_ref().unwrap();
        bundle.shares.push(
            seal_share(
                verified,
                &ShareKey {
                    owner_key: &self.owner.person.signing,
                    vk: self.model.vk(),
                    to: &record.account_id,
                },
            )
            .unwrap(),
        );
        self.publish(bundle);
    }

    pub(crate) fn removal_without_bump(&self, member: &AccountId) -> CommitBundle {
        let model = &self.model;
        let epoch = Epoch::new(model.epoch).unwrap();
        let rver = Rver::new(model.rver + 1).unwrap();
        let roster = Roster {
            vault_id: model.id,
            rver,
            epoch,
            prev: model.roster.as_ref().map(|(_, hash)| *hash),
            kind: model.kind,
            members: model
                .members
                .values()
                .filter(|m| m.account_id != *member)
                .cloned()
                .collect(),
            vk_commit: vk_commit(model.vk(), &model.id, epoch).unwrap(),
        };
        let signing = &self.owner.person.signing;
        let signed = Signed::sign(SigLabel::Roster, &roster, signing).unwrap();
        let manifest = Manifest {
            vault_id: model.id,
            seq: Seq::new(model.seq + 1).unwrap(),
            prev: model.head,
            epoch,
            rver,
            roster_hash: signed.hash(),
            root: leafset_root(&model.leaves).unwrap(),
            author: self.owner.person.account_id,
            repair: false,
        };
        CommitBundle {
            manifest: Signed::sign(SigLabel::Manifest, &manifest, signing).unwrap(),
            roster: Some(signed),
            shares: Vec::new(),
            ops: Vec::new(),
        }
    }
}
