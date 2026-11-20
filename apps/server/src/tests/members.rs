use hasp_proto::Role;
use hasp_proto::wire::{InviteAccept, InviteCreate, SessionToken};

use super::Harness;
use crate::fixture::{Client, VaultModel};

pub(super) fn invite_raw(
    h: &Harness,
    owner: &Client,
    invitee_token: &SessionToken,
    vault: &VaultModel,
    role: Role,
) -> hasp_proto::InviteId {
    let created = h
        .call(
            Some(&owner.token),
            &InviteCreate {
                vault_id: vault.id,
                role,
            },
        )
        .expect("invite");
    h.call(
        Some(invitee_token),
        &InviteAccept {
            invite_id: created.invite_id,
            accept: vec![1].into(),
        },
    )
    .expect("accept");
    created.invite_id
}

use hasp_proto::wire::{
    ErrorCode, InviteDecline, InviteGet, InviteList, InviteState, MemberState, NoticeKind,
    VaultStatus,
};
use hasp_proto::{Epoch, Rver, SigLabel, Signed};

use super::vault::{code, pull_one, shared_vault};

pub(super) fn add(h: &Harness, owner: &Client, who: &Client, model: &mut VaultModel, role: Role) {
    invite_raw(h, owner, &who.token, model, role);
    let bundle = model.add_member(&owner.person, &who.person, role);
    h.call(Some(&owner.token), &model.commit(bundle)).unwrap();
}

#[test]
fn invite_flow_exposes_the_inviter_record_and_the_accept_blob() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let model = shared_vault(&h, &alice);
    let created = h
        .call(
            Some(&alice.token),
            &InviteCreate {
                vault_id: model.id,
                role: Role::Editor,
            },
        )
        .unwrap();
    let view = h
        .call(
            Some(&bob.token),
            &InviteGet {
                invite_id: created.invite_id,
            },
        )
        .unwrap();
    assert_eq!(view.state, InviteState::Open);
    assert_eq!(view.vault_id, model.id);
    assert_eq!(
        view.inviter.unverified().unwrap().account_id,
        alice.person.account_id
    );
    h.call(
        Some(&bob.token),
        &InviteAccept {
            invite_id: created.invite_id,
            accept: vec![7, 7].into(),
        },
    )
    .unwrap();
    let listed = h
        .call(Some(&alice.token), &InviteList { vault_id: model.id })
        .unwrap();
    assert_eq!(listed.invites.len(), 1);
    assert_eq!(listed.invites[0].state, InviteState::Accepted);
    assert_eq!(listed.invites[0].accept.as_ref().unwrap().0, [7, 7]);
    assert_eq!(
        listed.invites[0]
            .invitee
            .as_ref()
            .unwrap()
            .unverified()
            .unwrap()
            .account_id,
        bob.person.account_id
    );
    let notices = h.pull(&alice, &[]).unwrap().notices;
    assert!(notices.iter().any(|n| n.kind == NoticeKind::InviteAccepted));
    let memberships = h.pull(&bob, &[]).unwrap().memberships;
    assert!(
        memberships
            .iter()
            .any(|m| m.vault_id == model.id && m.state == MemberState::Invited)
    );
}

#[test]
fn only_the_owner_creates_and_lists_invites_and_private_vaults_take_none() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    let by_editor = InviteCreate {
        vault_id: model.id,
        role: Role::Viewer,
    };
    assert_eq!(code(h.call(Some(&bob.token), &by_editor)), ErrorCode::Authz);
    assert_eq!(
        code(h.call(Some(&bob.token), &InviteList { vault_id: model.id })),
        ErrorCode::Authz
    );
    let private = InviteCreate {
        vault_id: alice.vault.id,
        role: Role::Viewer,
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &private)),
        ErrorCode::Format
    );
    let owner_role = InviteCreate {
        vault_id: model.id,
        role: Role::Owner,
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &owner_role)),
        ErrorCode::Format
    );
}

#[test]
fn invites_expire_and_cannot_be_accepted_twice_or_by_the_inviter() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let model = shared_vault(&h, &alice);
    let create = || InviteCreate {
        vault_id: model.id,
        role: Role::Viewer,
    };
    let first = h.call(Some(&alice.token), &create()).unwrap().invite_id;
    let accept = |id| InviteAccept {
        invite_id: id,
        accept: vec![].into(),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &accept(first))),
        ErrorCode::Conflict
    );
    h.call(Some(&bob.token), &accept(first)).unwrap();
    assert_eq!(
        code(h.call(Some(&carol.token), &accept(first))),
        ErrorCode::Conflict
    );
    let late = h.call(Some(&alice.token), &create()).unwrap().invite_id;
    h.clock.advance(8 * 24 * 3600);
    assert_eq!(
        code(h.call(Some(&carol.token), &accept(late))),
        ErrorCode::Conflict
    );
    let view = h
        .call(Some(&carol.token), &InviteGet { invite_id: late })
        .unwrap();
    assert_eq!(view.state, InviteState::Expired);
    assert_eq!(
        code(h.call(
            Some(&carol.token),
            &InviteGet {
                invite_id: hasp_proto::InviteId::from_bytes([1; 16])
            }
        )),
        ErrorCode::NotFound
    );
}

#[test]
fn declined_invites_cannot_be_used_and_remove_the_pending_membership() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    let id = invite_raw(&h, &alice, &bob.token, &model, Role::Editor);
    h.call(Some(&bob.token), &InviteDecline { invite_id: id })
        .unwrap();
    let bundle = model.add_member(&alice.person, &bob.person, Role::Editor);
    assert_eq!(
        code(h.call(Some(&alice.token), &model.commit(bundle))),
        ErrorCode::Invite
    );
    assert_eq!(
        code(h.call(Some(&bob.token), &InviteDecline { invite_id: id })),
        ErrorCode::Conflict
    );
}

#[test]
fn adding_a_member_without_an_accepted_invite_or_with_another_role_is_refused() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    let mut uninvited = model.clone();
    let bundle = uninvited.add_member(&alice.person, &bob.person, Role::Editor);
    assert_eq!(
        code(h.call(Some(&alice.token), &uninvited.commit(bundle))),
        ErrorCode::Invite
    );
    invite_raw(&h, &alice, &bob.token, &model, Role::Viewer);
    let bundle = model.add_member(&alice.person, &bob.person, Role::Editor);
    assert_eq!(
        code(h.call(Some(&alice.token), &model.commit(bundle))),
        ErrorCode::Invite
    );
}

#[test]
fn roster_members_must_carry_the_keys_of_their_account_records() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    invite_raw(&h, &alice, &bob.token, &model, Role::Editor);
    let impostor = crate::fixture::Person::new("bob");
    let mut forged = impostor;
    forged.account_id = bob.person.account_id;
    let bundle = model.add_member(&alice.person, &forged, Role::Editor);
    assert_eq!(
        code(h.call(Some(&alice.token), &model.commit(bundle))),
        ErrorCode::Roster
    );
}

#[test]
fn a_new_member_receives_the_share_and_the_membership_turns_active() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Viewer);
    let pulled = pull_one(&h, &bob, &model, 0);
    assert_eq!(pulled.status, VaultStatus::Ok);
    assert_eq!(pulled.shares.len(), 1);
    assert_eq!(pulled.commits.len(), 2);
    assert_eq!(pulled.commits[1].shares.len(), 1);
    let listed = h.pull(&bob, &[]).unwrap().memberships;
    assert!(listed.iter().any(|m| m.vault_id == model.id
        && m.state == MemberState::Active
        && m.role == Role::Viewer));
    let invites = h
        .call(Some(&alice.token), &InviteList { vault_id: model.id })
        .unwrap();
    assert_eq!(invites.invites[0].state, InviteState::Used);
    let upload = hasp_proto::wire::SelfWrapPut {
        vault_id: model.id,
        entry: hasp_proto::wire::SelfWrapEntry {
            epoch: Epoch::ZERO,
            wrap: bob.person.self_wrap(&model, 0),
        },
    };
    h.call(Some(&bob.token), &upload).unwrap();
    let again = pull_one(&h, &bob, &model, 2);
    assert_eq!(again.self_wraps.len(), 1);
    let future = hasp_proto::wire::SelfWrapPut {
        entry: hasp_proto::wire::SelfWrapEntry {
            epoch: Epoch::new(3).unwrap(),
            ..upload.entry.clone()
        },
        ..upload
    };
    assert_eq!(code(h.call(Some(&bob.token), &future)), ErrorCode::Epoch);
}

#[test]
fn removal_bumps_the_epoch_deletes_shares_and_cuts_the_member_off() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    add(&h, &alice, &carol, &mut model, Role::Editor);
    let b = model.put_item(&alice.person, 1, b"secret");
    h.call(Some(&alice.token), &model.commit(b)).unwrap();
    let bundle = model.remove_member(&alice.person, &bob.person.account_id);
    assert_eq!(bundle.shares.len(), 1);
    assert_eq!(bundle.ops.len(), 2);
    h.call(Some(&alice.token), &model.commit(bundle)).unwrap();

    let gone = pull_one(&h, &bob, &model, 0);
    assert_eq!(gone.status, VaultStatus::NotMember);
    assert!(gone.commits.is_empty() && gone.shares.is_empty() && gone.self_wraps.is_empty());
    let kept = pull_one(&h, &carol, &model, 0);
    assert_eq!(kept.shares.len(), 2);
    assert!(
        kept.shares
            .iter()
            .any(|s| s.unverified().unwrap().epoch.get() == 1)
    );
    let notices = h.pull(&bob, &[]).unwrap().notices;
    assert!(notices.iter().any(|n| n.kind == NoticeKind::MemberRemoved));

    let mut stale = model.clone();
    stale.seq = model.seq;
    let late = stale.put_item(&bob.person, 2, b"after removal");
    assert_eq!(
        code(h.call(Some(&bob.token), &stale.commit(late))),
        ErrorCode::NotMember
    );
}

#[test]
fn removal_without_the_next_epoch_is_rejected() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    let (roster, _) = model.roster.clone().unwrap();
    let rver = Rver::new(model.rver + 1).unwrap();
    let body = hasp_proto::Roster {
        rver,
        prev: model.roster.as_ref().map(|(_, hash)| *hash),
        members: roster
            .members
            .iter()
            .filter(|m| m.account_id != bob.person.account_id)
            .cloned()
            .collect(),
        ..roster
    };
    let signed = Signed::sign(SigLabel::Roster, &body, &alice.person.signing).unwrap();
    let manifest = hasp_proto::Manifest {
        vault_id: model.id,
        seq: hasp_proto::Seq::new(model.seq + 1).unwrap(),
        prev: model.head,
        epoch: Epoch::new(model.epoch).unwrap(),
        rver,
        roster_hash: signed.hash(),
        root: hasp_proto::leafset_root(&model.leaves).unwrap(),
        author: alice.person.account_id,
        repair: false,
    };
    let bundle = hasp_proto::wire::CommitBundle {
        manifest: Signed::sign(SigLabel::Manifest, &manifest, &alice.person.signing).unwrap(),
        roster: Some(signed),
        shares: Vec::new(),
        ops: Vec::new(),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &model.commit(bundle))),
        ErrorCode::Epoch
    );
}
