use hasp_proto::wire::{Commit, ErrorCode, VaultPull, VaultStatus};
use hasp_proto::{Role, Seq, VaultKind, Wire};

use super::Harness;
use crate::fixture::{Client, VaultModel};

pub(super) fn code<T: std::fmt::Debug>(
    result: Result<T, hasp_proto::wire::WireError>,
) -> ErrorCode {
    result.expect_err("expected an error").code
}

pub(super) fn shared_vault(h: &Harness, owner: &Client) -> VaultModel {
    let mut vault = VaultModel::new(VaultKind::Shared, &owner.person);
    let genesis = vault.genesis(&owner.person);
    let commit = vault.genesis_commit(&owner.person, genesis);
    h.call(Some(&owner.token), &commit).expect("shared genesis");
    vault
}

pub(super) fn pull_one(h: &Harness, client: &Client, vault: &VaultModel, seq: u64) -> VaultPull {
    let mut response = h.pull(client, &[(vault.id, seq)]).expect("pull");
    response.vaults.remove(0)
}

#[test]
fn private_vault_from_registration_is_pullable() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let pulled = pull_one(&h, &alice, &alice.vault, 0);
    assert_eq!(pulled.status, VaultStatus::Ok);
    assert_eq!(pulled.head_seq.get(), 1);
    assert_eq!(pulled.commits.len(), 1);
    assert!(pulled.commits[0].roster.is_some());
    assert_eq!(pulled.commits[0].ops.len(), 1);
    assert_eq!(pulled.self_wraps.len(), 1);
    assert!(!pulled.has_more);
}

#[test]
fn commit_advances_the_head_and_pull_returns_only_newer_commits() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let bundle = alice.vault.put_item(&alice.person, 1, b"one");
    let commit = alice.vault.commit(bundle);
    let response = h.call(Some(&alice.token), &commit).unwrap();
    assert_eq!(response.head_seq.get(), 2);
    let bundle = alice.vault.put_item(&alice.person, 1, b"two");
    let commit = alice.vault.commit(bundle);
    h.call(Some(&alice.token), &commit).unwrap();
    let all = pull_one(&h, &alice, &alice.vault, 0);
    assert_eq!(all.commits.len(), 3);
    let tail = pull_one(&h, &alice, &alice.vault, 2);
    assert_eq!(tail.commits.len(), 1);
    assert_eq!(tail.head_seq.get(), 3);
    assert_eq!(tail.commits[0].ops[0].ver.get(), 2);
}

#[test]
fn pull_pages_by_limit_and_reports_has_more() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    for n in 0..4 {
        let bundle = alice.vault.put_item(&alice.person, n, b"x");
        let commit = alice.vault.commit(bundle);
        h.call(Some(&alice.token), &commit).unwrap();
    }
    let response = h
        .call(
            Some(&alice.token),
            &hasp_proto::wire::Pull {
                vaults: vec![hasp_proto::wire::VaultCursor {
                    vault_id: alice.vault.id,
                    seq: Seq::ZERO,
                }],
                notices_after: hasp_proto::Uint53::ZERO,
                limit: hasp_proto::Uint53::new(2).unwrap(),
            },
        )
        .unwrap();
    let page = &response.vaults[0];
    assert_eq!(page.commits.len(), 2);
    assert!(page.has_more);
    assert_eq!(page.head_seq.get(), 5);
}

#[test]
fn stale_base_seq_is_a_conflict() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let mut fork = alice.vault.clone();
    let first = alice.vault.put_item(&alice.person, 1, b"a");
    h.call(Some(&alice.token), &alice.vault.commit(first))
        .unwrap();
    let competing = fork.put_item(&alice.person, 2, b"b");
    let commit = fork.commit(competing);
    assert_eq!(
        code(h.call(Some(&alice.token), &commit)),
        ErrorCode::StaleHead
    );
}

#[test]
fn identical_retry_is_idempotent_and_changed_retry_is_not() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let bundle = alice.vault.put_item(&alice.person, 1, b"a");
    let commit = alice.vault.commit(bundle);
    let first = h.call(Some(&alice.token), &commit).unwrap();
    let again = h.call(Some(&alice.token), &commit).unwrap();
    assert_eq!(first, again);
    let pulled = pull_one(&h, &alice, &alice.vault, 0);
    assert_eq!(pulled.commits.len(), 2);

    let mut fork = alice.vault.clone();
    fork.seq = 1;
    fork.head = Some(pulled.commits[0].manifest.hash());
    let other = fork.put_item(&alice.person, 1, b"different");
    assert_eq!(
        code(h.call(Some(&alice.token), &fork.commit(other))),
        ErrorCode::StaleHead
    );
}

#[test]
fn replay_after_a_later_commit_is_still_idempotent_by_base_seq_and_hash() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let bundle = alice.vault.put_item(&alice.person, 1, b"a");
    let first = alice.vault.commit(bundle);
    h.call(Some(&alice.token), &first).unwrap();
    let bundle = alice.vault.put_item(&alice.person, 2, b"b");
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();
    assert!(h.call(Some(&alice.token), &first).is_ok());
}

fn with_flipped_signature(commit: &Commit) -> Commit {
    let mut altered = commit.clone();
    let mut sig = *altered.bundle.manifest.sig.as_bytes();
    sig[0] ^= 1;
    altered.bundle.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
    altered
}

#[test]
fn a_replayed_commit_with_altered_bytes_is_refused_not_acknowledged() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let bundle = alice.vault.put_item(&alice.person, 1, b"a");
    let commit = alice.vault.commit(bundle);
    h.call(Some(&alice.token), &commit).unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &with_flipped_signature(&commit))),
        ErrorCode::Sig
    );
    h.call(Some(&alice.token), &commit).unwrap();

    let bundle = alice.vault.put_item(&alice.person, 2, b"b");
    h.call(Some(&alice.token), &alice.vault.commit(bundle))
        .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &with_flipped_signature(&commit))),
        ErrorCode::Sig
    );
    h.call(Some(&alice.token), &commit).unwrap();
}

#[test]
fn commit_requires_a_session_and_membership() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let bob = h.signup("bob");
    let bundle = alice.vault.put_item(&alice.person, 1, b"a");
    let commit = alice.vault.commit(bundle);
    assert_eq!(code(h.call(None, &commit)), ErrorCode::Auth);
    assert_eq!(
        code(h.call(Some(&bob.token), &commit)),
        ErrorCode::NotMember
    );
}

#[test]
fn author_must_be_the_session_account() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    super::members::invite_raw(&h, &alice, &bob.token, &model, Role::Editor);
    let bundle = model.add_member(&alice.person, &bob.person, Role::Editor);
    h.call(Some(&alice.token), &model.commit(bundle)).unwrap();
    let forged = model.put_item(&alice.person, 1, b"as alice");
    assert_eq!(
        code(h.call(Some(&bob.token), &model.commit(forged))),
        ErrorCode::Authz
    );
}

fn reauthored(
    bundle: &hasp_proto::wire::CommitBundle,
    author: &crate::fixture::Person,
) -> hasp_proto::wire::CommitBundle {
    let manifest = bundle.manifest.unverified().unwrap();
    let signed = hasp_proto::Signed::sign(
        hasp_proto::SigLabel::Manifest,
        &hasp_proto::Manifest {
            author: author.account_id,
            ..manifest
        },
        &author.signing,
    )
    .unwrap();
    hasp_proto::wire::CommitBundle {
        manifest: signed,
        ..bundle.clone()
    }
}

#[test]
fn viewers_cannot_write_and_editors_cannot_change_the_roster() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let mut model = shared_vault(&h, &alice);
    for (who, role) in [(&bob, Role::Editor), (&carol, Role::Viewer)] {
        super::members::invite_raw(&h, &alice, &who.token, &model, role);
        let bundle = model.add_member(&alice.person, &who.person, role);
        h.call(Some(&alice.token), &model.commit(bundle)).unwrap();
    }
    let by_viewer = model.clone().put_item(&carol.person, 1, b"nope");
    assert_eq!(
        code(h.call(Some(&carol.token), &model.commit(by_viewer))),
        ErrorCode::ReadOnly
    );
    let by_editor = model.put_item(&bob.person, 1, b"fine");
    h.call(Some(&bob.token), &model.commit(by_editor)).unwrap();

    let roster_change =
        model
            .clone()
            .change_role(&alice.person, &carol.person.account_id, Role::Editor);
    let smuggled = reauthored(&roster_change, &bob.person);
    assert_eq!(
        code(h.call(Some(&bob.token), &model.commit(smuggled))),
        ErrorCode::Authz
    );
}

#[test]
fn bad_root_signature_and_version_gaps_are_rejected() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let mut fork = alice.vault.clone();
    let bundle = fork.put_item(&alice.person, 1, b"a");
    let mut bad_root = bundle.clone();
    let manifest = bad_root.manifest.unverified().unwrap();
    bad_root.manifest = hasp_proto::Signed::sign(
        hasp_proto::SigLabel::Manifest,
        &hasp_proto::Manifest {
            root: hasp_proto::Hash32::from_bytes([9; 32]),
            ..manifest
        },
        &alice.person.signing,
    )
    .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &alice.vault.commit(bad_root))),
        ErrorCode::Root
    );

    let mut forged_sig = bundle.clone();
    let signer = forged_sig.manifest.signer;
    let mut bytes = forged_sig.manifest.to_cbor().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    forged_sig.manifest = hasp_proto::Signed::from_cbor(&bytes).unwrap();
    assert_eq!(forged_sig.manifest.signer, signer);
    assert_eq!(
        code(h.call(Some(&alice.token), &alice.vault.commit(forged_sig))),
        ErrorCode::Sig
    );

    let skip = alice
        .vault
        .seal(VaultModel::item_id(1), 5, 0, b"skipping versions");
    let mut gap = fork.clone();
    gap.leaves = alice.vault.leaves.clone();
    gap.seq = alice.vault.seq;
    gap.head = alice.vault.head;
    let mut gapped = gap.put_item(&alice.person, 9, b"y");
    gapped.ops = vec![skip];
    let result = h.call(Some(&alice.token), &alice.vault.commit(gapped));
    assert!(result.is_err());
    let _ = alice.vault.put_item(&alice.person, 3, b"ok");
}

#[test]
fn too_many_ops_are_refused_before_verification() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let mut fork = alice.vault.clone();
    let mut bundle = fork.put_item(&alice.person, 1, b"a");
    let wire = bundle.ops[0].clone();
    bundle.ops = vec![wire; 501];
    assert_eq!(
        code(h.call(Some(&alice.token), &alice.vault.commit(bundle))),
        ErrorCode::TooLarge
    );
    let _ = alice.vault.put_item(&alice.person, 2, b"x");
}

#[test]
fn tombstones_become_leaves_and_resurrection_needs_the_next_version() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let b = alice.vault.put_item(&alice.person, 1, b"a");
    h.call(Some(&alice.token), &alice.vault.commit(b)).unwrap();
    let b = alice.vault.delete_item(&alice.person, 1);
    h.call(Some(&alice.token), &alice.vault.commit(b)).unwrap();
    let b = alice.vault.put_item(&alice.person, 1, b"back");
    h.call(Some(&alice.token), &alice.vault.commit(b)).unwrap();
    let pulled = pull_one(&h, &alice, &alice.vault, 0);
    let vers: Vec<u64> = pulled
        .commits
        .iter()
        .flat_map(|c| c.ops.iter())
        .filter(|op| op.item_id == VaultModel::item_id(1))
        .map(|op| op.ver.get())
        .collect();
    assert_eq!(vers, [1, 2, 3]);
}

#[test]
fn history_keeps_the_newest_ten_versions() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    for n in 0..12_u8 {
        let b = alice.vault.put_item(&alice.person, 1, &[n]);
        h.call(Some(&alice.token), &alice.vault.commit(b)).unwrap();
    }
    let stored = h
        .server
        .with_store(|store| {
            use crate::store::Store;
            store.items().len().unwrap()
        })
        .unwrap();
    assert_eq!(stored, 11);
}

#[test]
fn pull_for_unknown_or_foreign_vaults_reports_not_member() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let unknown = hasp_proto::VaultId::from_bytes([3; 16]);
    let response = h.pull(&bob, &[(alice.vault.id, 0), (unknown, 0)]).unwrap();
    assert!(
        response
            .vaults
            .iter()
            .all(|v| v.status == VaultStatus::NotMember)
    );
    assert!(response.vaults.iter().all(|v| v.commits.is_empty()));
}

#[test]
fn creating_a_vault_needs_base_seq_zero_and_a_self_wrap() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let mut vault = VaultModel::new(VaultKind::Shared, &alice.person);
    let genesis = vault.genesis(&alice.person);
    let no_wrap = vault.commit(genesis.clone());
    assert_eq!(
        code(h.call(Some(&alice.token), &no_wrap)),
        ErrorCode::Format
    );
    let mut shifted: Commit = vault.genesis_commit(&alice.person, genesis);
    shifted.base_seq = Seq::new(4).unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &shifted)),
        ErrorCode::NotFound
    );
}

#[test]
fn a_vault_cannot_be_created_with_another_owner() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut vault = VaultModel::new(VaultKind::Shared, &bob.person);
    let genesis = vault.genesis(&bob.person);
    let commit = vault.genesis_commit(&bob.person, genesis);
    assert!(h.call(Some(&alice.token), &commit).is_err());
}

#[test]
fn epoch_older_than_the_vault_is_a_stale_epoch() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let carol = h.signup("carol");
    let mut model = shared_vault(&h, &alice);
    for who in [&bob, &carol] {
        super::members::invite_raw(&h, &alice, &who.token, &model, Role::Editor);
        let bundle = model.add_member(&alice.person, &who.person, Role::Editor);
        h.call(Some(&alice.token), &model.commit(bundle)).unwrap();
    }
    let stale = model.clone();
    let bundle = model.remove_member(&alice.person, &carol.person.account_id);
    h.call(Some(&alice.token), &model.commit(bundle)).unwrap();
    let mut old = stale;
    old.seq = model.seq;
    old.head = model.head;
    let bundle = old.put_item(&bob.person, 1, b"written at epoch 0");
    assert_eq!(
        code(h.call(Some(&bob.token), &old.commit(bundle))),
        ErrorCode::EpochStale
    );
}
