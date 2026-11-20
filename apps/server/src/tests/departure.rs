use hasp_proto::wire::{
    ErrorCode, InviteCreate, Leave, MemberState, NoticeKind, VaultDissolve, VaultStatus,
};
use hasp_proto::{Dissolve, Epoch, LeaveRequest, Role, Rver, SigLabel, Signed};

use super::members::add;
use super::vault::{code, pull_one, shared_vault};
use super::Harness;
use crate::fixture::{Client, VaultModel};

fn leave_request(model: &VaultModel, who: &Client) -> Signed<LeaveRequest> {
    Signed::sign(
        SigLabel::Leave,
        &LeaveRequest {
            vault_id: model.id,
            account_id: who.person.account_id,
            rver: Rver::new(model.rver).unwrap(),
            epoch: Epoch::new(model.epoch).unwrap(),
        },
        &who.person.signing,
    )
    .unwrap()
}

#[test]
fn leaving_stops_service_and_hands_the_request_to_the_owner() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    let request = leave_request(&model, &bob);
    h.call(
        Some(&bob.token),
        &Leave {
            request: request.clone(),
        },
    )
    .unwrap();

    assert_eq!(pull_one(&h, &bob, &model, 0).status, VaultStatus::NotMember);
    let owner_view = pull_one(&h, &alice, &model, 2);
    assert_eq!(owner_view.leave_requests, [request]);
    let notices = h.pull(&alice, &[]).unwrap().notices;
    assert!(notices.iter().any(|n| n.kind == NoticeKind::MemberLeaving));
    let bundle = model.clone().put_item(&bob.person, 1, b"x");
    assert_eq!(
        code(h.call(Some(&bob.token), &model.commit(bundle))),
        ErrorCode::NotMember
    );

    let removal = model.remove_member(&alice.person, &bob.person.account_id);
    h.call(Some(&alice.token), &model.commit(removal)).unwrap();
    assert!(pull_one(&h, &alice, &model, 3).leave_requests.is_empty());
    let memberships = h.pull(&bob, &[]).unwrap().memberships;
    assert!(
        memberships
            .iter()
            .any(|m| m.vault_id == model.id && m.state == MemberState::Removed)
    );
}

#[test]
fn leave_requests_are_checked_for_signer_owner_and_staleness() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    add(&h, &alice, &carol, &mut model, Role::Viewer);

    let forged = Signed::sign(
        SigLabel::Leave,
        &LeaveRequest {
            vault_id: model.id,
            account_id: bob.person.account_id,
            rver: Rver::new(model.rver).unwrap(),
            epoch: Epoch::ZERO,
        },
        &carol.person.signing,
    )
    .unwrap();
    assert!(
        h.call(
            Some(&bob.token),
            &Leave {
                request: forged.clone()
            }
        )
        .is_err()
    );
    assert_eq!(
        code(h.call(Some(&carol.token), &Leave { request: forged })),
        ErrorCode::Authz
    );
    let owner_leave = leave_request(&model, &alice);
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &Leave {
                request: owner_leave
            }
        )),
        ErrorCode::Authz
    );
    let mut stale = leave_request(&model, &bob).unverified().unwrap();
    stale.rver = Rver::new(1).unwrap();
    let stale = Signed::sign(SigLabel::Leave, &stale, &bob.person.signing).unwrap();
    assert_eq!(
        code(h.call(Some(&bob.token), &Leave { request: stale })),
        ErrorCode::Roster
    );
}

fn dissolve(model: &VaultModel, owner: &Client) -> Signed<Dissolve> {
    Signed::sign(
        SigLabel::Dissolve,
        &Dissolve {
            vault_id: model.id,
            rver: Rver::new(model.rver).unwrap(),
            epoch: Epoch::new(model.epoch).unwrap(),
            seq: hasp_proto::Seq::new(model.seq).unwrap(),
            head: model.head.unwrap(),
        },
        &owner.person.signing,
    )
    .unwrap()
}

#[test]
fn dissolve_needs_reauth_the_owner_and_the_current_head() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    let record = dissolve(&model, &alice);
    let call = VaultDissolve {
        record: record.clone(),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &call)),
        ErrorCode::ReauthRequired
    );
    h.reauth(&alice.person, &alice.token).unwrap();
    h.reauth(&bob.person, &bob.token).unwrap();
    assert_eq!(code(h.call(Some(&bob.token), &call)), ErrorCode::Authz);
    let mut older = model.clone();
    older.seq -= 1;
    older.head = Some(hasp_proto::Hash32::from_bytes([1; 32]));
    let stale = VaultDissolve {
        record: dissolve(&older, &alice),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &stale)),
        ErrorCode::StaleHead
    );
    let private = VaultDissolve {
        record: dissolve(&alice.vault, &alice),
    };
    assert_eq!(code(h.call(Some(&alice.token), &private)), ErrorCode::Authz);
    h.clock.advance(6 * 60);
    assert_eq!(
        code(h.call(Some(&alice.token), &call)),
        ErrorCode::ReauthRequired
    );
}

#[test]
fn dissolve_deletes_everything_and_serves_the_signed_record_to_members() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    add(&h, &alice, &bob, &mut model, Role::Editor);
    let b = model.put_item(&alice.person, 1, b"x");
    h.call(Some(&alice.token), &model.commit(b)).unwrap();
    h.reauth(&alice.person, &alice.token).unwrap();
    let record = dissolve(&model, &alice);
    h.call(
        Some(&alice.token),
        &VaultDissolve {
            record: record.clone(),
        },
    )
    .unwrap();

    let seen = pull_one(&h, &bob, &model, 0);
    assert_eq!(seen.status, VaultStatus::Dissolved);
    assert_eq!(seen.dissolve, Some(record));
    assert!(seen.commits.is_empty());
    let notices = h.pull(&bob, &[]).unwrap().notices;
    assert!(notices.iter().any(|n| n.kind == NoticeKind::VaultDissolved));
    let memberships = h.pull(&bob, &[]).unwrap().memberships;
    assert!(
        memberships
            .iter()
            .any(|m| m.vault_id == model.id && m.state == MemberState::Dissolved)
    );
    let counts = h
        .server
        .with_store(|store| {
            use crate::store::Store;
            let vault = model.id;
            let manifests = store.manifests().len().unwrap();
            let shares = store.shares().len().unwrap();
            let log = store
                .commit_log()
                .range(
                    &(vault, hasp_proto::Seq::ZERO),
                    &(vault, hasp_proto::Seq::new(1 << 40).unwrap()),
                )
                .unwrap()
                .len();
            (manifests, shares, log)
        })
        .unwrap();
    assert_eq!(counts, (2, 0, 0));

    let again = model.clone().put_item(&alice.person, 2, b"after");
    assert_eq!(
        code(h.call(Some(&alice.token), &model.commit(again))),
        ErrorCode::NotMember
    );
    let revive = InviteCreate {
        vault_id: model.id,
        role: Role::Viewer,
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &revive)),
        ErrorCode::NotMember
    );
    h.reauth(&alice.person, &alice.token).unwrap();
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &VaultDissolve {
                record: dissolve(&model, &alice)
            }
        )),
        ErrorCode::NotMember
    );
}
