use hasp_crypto::{Signature, SigningKey};

use crate::testkit::{CloneKey, Person, Vault, bump, resign};
use crate::{
    Epoch, Hash32, ItemBody, ItemOp, ItemWire, Manifest, OpenedItem, PinState, ProtoError, Role,
    Roster, Seq, SigLabel, Signed, VaultKind, VaultState, Version, Wire, leafset_root, open_item,
    verify_batch, verify_genesis, verify_repair,
};

fn setup() -> (Vault, Person, PinState, VaultState) {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let pins = PinState::new();
    let genesis = vault.genesis();
    let state = verify_genesis(&genesis, &owner.own(), &pins).unwrap();
    (vault, owner, pins, state)
}

fn expect(result: Result<VaultState, ProtoError>) -> ProtoError {
    result.map(|_| ()).unwrap_err()
}

#[test]
fn genesis_then_item_edits_and_deletes_verify() {
    let (mut vault, owner, pins, state) = setup();
    assert!(vault.state_after(&state));
    let commits = vec![
        vault.put(1, 7, b"one"),
        vault.put(1, 8, b"two"),
        vault.put(1, 7, b"one edited"),
        vault.delete(1, 8),
    ];
    let next = verify_batch(&state, &commits, &owner.own(), &pins).unwrap();
    assert!(vault.state_after(&next));
    assert_eq!(next.leafset.len(), 2);
    assert_eq!(
        next.leafset.get(&Vault::item_id(7)).unwrap().ver,
        Version::new(2).unwrap()
    );
}

#[test]
fn empty_batch_returns_the_same_state() {
    let (vault, owner, pins, state) = setup();
    let next = verify_batch(&state, &[], &owner.own(), &pins).unwrap();
    assert!(vault.state_after(&next));
}

#[test]
fn full_lifecycle_with_member_add_role_change_and_removal_verifies() {
    let (mut vault, owner, pins, state) = setup();
    let commits = vec![
        vault.put(1, 7, b"secret"),
        vault.add_member(2, Role::Editor),
        vault.add_member(3, Role::Viewer),
        vault.put(2, 9, b"by editor"),
        vault.change_role(3, Role::Editor),
        vault.remove_member(2),
        vault.put(3, 10, b"after removal"),
    ];
    let next = verify_batch(&state, &commits, &owner.own(), &pins).unwrap();
    assert!(vault.state_after(&next));
    assert_eq!(next.epoch.get(), 1);
    assert_eq!(next.roster.members.len(), 2);
}

#[test]
fn a_member_verifies_the_same_chain_with_their_own_keys() {
    let (mut vault, _, pins, state) = setup();
    let commits = vec![vault.add_member(2, Role::Editor), vault.put(2, 9, b"x")];
    let member = Person::new(2);
    let next = verify_batch(&state, &commits, &member.own(), &pins).unwrap();
    assert!(vault.state_after(&next));
}

#[test]
fn batch_is_atomic_a_late_failure_returns_an_error_not_a_partial_state() {
    let (mut vault, owner, pins, state) = setup();
    let good = vault.put(1, 7, b"a");
    let mut bad = vault.put(1, 8, b"b");
    bad.manifest = Signed::sign(
        SigLabel::Manifest,
        &Manifest {
            root: Hash32::from_bytes([0; 32]),
            ..bad.manifest.unverified().unwrap()
        },
        &owner.signing,
    )
    .unwrap();
    assert!(matches!(
        verify_batch(&state, &[good, bad], &owner.own(), &pins),
        Err(ProtoError::Root)
    ));
}

#[test]
fn replayed_lower_and_gapped_commits_are_rollbacks() {
    let (mut vault, owner, pins, state) = setup();
    let first = vault.put(1, 7, b"a");
    let second = vault.put(1, 8, b"b");
    let third = vault.put(1, 9, b"c");
    let after_first =
        verify_batch(&state, std::slice::from_ref(&first), &owner.own(), &pins).unwrap();
    assert!(matches!(
        expect(verify_batch(&after_first, &[first], &owner.own(), &pins)),
        ProtoError::Rollback
    ));
    assert!(matches!(
        expect(verify_batch(&state, &[third], &owner.own(), &pins)),
        ProtoError::Rollback
    ));
    assert!(verify_batch(&after_first, &[second], &owner.own(), &pins).is_ok());
}

#[test]
fn two_different_commits_at_the_same_seq_are_a_fork() {
    let (mut vault, owner, pins, state) = setup();
    let first = vault.put(1, 7, b"a");
    let after = verify_batch(&state, &[first], &owner.own(), &pins).unwrap();
    let mut other = Vault::new(VaultKind::Shared, 1);
    let g = other.genesis();
    let _ = g;
    let fork = other.put(1, 7, b"different");
    assert!(matches!(
        expect(verify_batch(&after, &[fork], &owner.own(), &pins)),
        ProtoError::Fork
    ));
}

#[test]
fn wrong_prev_hash_is_a_fork() {
    let (mut vault, owner, pins, state) = setup();
    let mut commit = vault.put(1, 7, b"a");
    let manifest = Manifest {
        prev: Some(Hash32::from_bytes([9; 32])),
        ..commit.manifest.unverified().unwrap()
    };
    commit.manifest = Signed::sign(SigLabel::Manifest, &manifest, &owner.signing).unwrap();
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Fork
    ));
}

#[test]
fn manifest_roster_binding_mismatches_are_roster_or_epoch_errors() {
    let (mut vault, owner, pins, state) = setup();
    let base = vault.put(1, 7, b"a");
    let mut wrong_hash = base.clone();
    resign(&mut wrong_hash, &owner, |m| {
        m.roster_hash = Hash32::from_bytes([1; 32]);
    });
    let mut wrong_rver = base.clone();
    resign(&mut wrong_rver, &owner, |m| {
        m.rver = crate::Rver::new(5).unwrap();
    });
    let mut wrong_epoch = base.clone();
    resign(&mut wrong_epoch, &owner, |m| {
        m.epoch = Epoch::new(3).unwrap();
    });
    let mut wrong_vault = base;
    resign(&mut wrong_vault, &owner, |m| {
        m.vault_id = crate::VaultId::from_bytes([1; 16]);
    });
    for (commit, expected) in [
        (wrong_hash, ProtoError::Roster),
        (wrong_rver, ProtoError::Roster),
        (wrong_epoch, ProtoError::Epoch),
        (wrong_vault, ProtoError::Roster),
    ] {
        let got = expect(verify_batch(&state, &[commit], &owner.own(), &pins));
        assert_eq!(
            std::mem::discriminant(&got),
            std::mem::discriminant(&expected)
        );
    }
}

#[test]
fn forged_signatures_and_foreign_signers_are_rejected() {
    let (mut vault, owner, pins, state) = setup();
    let base = vault.put(1, 7, b"a");
    let mut flipped = base.clone();
    let mut sig = *flipped.manifest.sig.as_bytes();
    sig[0] ^= 1;
    flipped.manifest.sig = Signature::from_bytes(sig);
    assert!(matches!(
        expect(verify_batch(&state, &[flipped], &owner.own(), &pins)),
        ProtoError::Sig
    ));
    let stranger = Person::new(9);
    let mut foreign = base;
    foreign.manifest = Signed::sign(
        SigLabel::Manifest,
        &foreign.manifest.unverified().unwrap(),
        &stranger.signing,
    )
    .unwrap();
    assert!(matches!(
        expect(verify_batch(&state, &[foreign], &owner.own(), &pins)),
        ProtoError::Sig
    ));
}

#[test]
fn author_outside_the_roster_or_without_write_role_is_authz() {
    let (mut vault, owner, pins, state) = setup();
    let joined = vault.add_member(2, Role::Viewer);
    let state = verify_batch(&state, &[joined], &owner.own(), &pins).unwrap();
    let mut by_viewer = vault.put(2, 7, b"viewer write");
    assert!(matches!(
        expect(verify_batch(
            &state,
            &[by_viewer.clone()],
            &owner.own(),
            &pins
        )),
        ProtoError::Authz
    ));
    let stranger = Person::new(9);
    resign(&mut by_viewer, &stranger, |m| m.author = stranger.account);
    assert!(matches!(
        expect(verify_batch(&state, &[by_viewer], &owner.own(), &pins)),
        ProtoError::Authz
    ));
}

#[test]
fn editor_cannot_commit_rosters_shares_or_repairs() {
    let (mut vault, owner, pins, state) = setup();
    let joined = vault.add_member(2, Role::Editor);
    let state = verify_batch(&state, &[joined], &owner.own(), &pins).unwrap();
    let editor = Person::new(2);
    let base = vault.put(2, 7, b"x");
    let mut repair = base.clone();
    resign(&mut repair, &editor, |m| m.repair = true);
    assert!(matches!(
        expect(verify_batch(&state, &[repair], &owner.own(), &pins)),
        ProtoError::Authz
    ));
    let mut with_share = base;
    with_share.shares = vec![vault.share_for(
        &vault.roster.clone().unwrap().0,
        vault.roster.clone().unwrap().1,
        2,
    )];
    assert!(matches!(
        expect(verify_batch(&state, &[with_share], &owner.own(), &pins)),
        ProtoError::Authz
    ));
}

#[test]
fn stale_roster_signer_with_old_version_is_a_roster_error() {
    let (mut vault, owner, pins, state) = setup();
    let setup_commits = vec![vault.add_member(2, Role::Editor), vault.put(2, 9, b"x")];
    let state = verify_batch(&state, &setup_commits, &owner.own(), &pins).unwrap();
    let old_rver = vault.rver;
    let old_roster_hash = vault.roster.clone().unwrap().1;
    let removal = vault.remove_member(2);
    let state = verify_batch(&state, &[removal], &owner.own(), &pins).unwrap();
    let editor = Person::new(2);
    let mut late = vault.put(2, 10, b"stale");
    resign(&mut late, &editor, |m| {
        m.rver = crate::Rver::new(old_rver).unwrap();
        m.roster_hash = old_roster_hash;
        m.epoch = Epoch::new(0).unwrap();
    });
    assert!(matches!(
        expect(verify_batch(&state, &[late], &owner.own(), &pins)),
        ProtoError::Roster | ProtoError::Epoch
    ));
}

#[test]
fn removal_without_epoch_bump_is_an_epoch_error() {
    let (mut vault, owner, pins, state) = setup();
    let joined = vault.add_member(2, Role::Editor);
    let state = verify_batch(&state, &[joined], &owner.own(), &pins).unwrap();
    vault.rver = bump(vault.rver);
    vault.others.remove(&2);
    let vk = vault.vk().clone_key();
    let roster = vault.roster_body(vault.rver, vault.epoch, &vk);
    let signed = vault.sign_roster(&roster);
    vault.roster = Some((roster, signed.hash()));
    let commit = vault.finish(1, Some(signed), Vec::new(), Vec::new());
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Epoch
    ));
}

#[test]
fn epoch_bump_without_new_vk_commit_and_new_commit_without_bump_are_roster_errors() {
    let (mut vault, owner, pins, state) = setup();
    let vk = vault.vk().clone_key();
    vault.rver = bump(vault.rver);
    let mut bumped = vault.roster_body(vault.rver, 1, &vk);
    bumped.vk_commit = vault.roster.clone().unwrap().0.vk_commit;
    let signed = vault.sign_roster(&bumped);
    vault.roster = Some((bumped.clone(), signed.hash()));
    vault.epoch = 1;
    let commit = vault.finish(1, Some(signed), Vec::new(), Vec::new());
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Roster
    ));

    let (mut vault, owner, pins, state) = setup();
    vault.rver = bump(vault.rver);
    let other_vk = vault.entropy_key();
    let roster = vault.roster_body(vault.rver, 0, &other_vk);
    let signed = vault.sign_roster(&roster);
    vault.roster = Some((roster, signed.hash()));
    let commit = vault.finish(1, Some(signed), Vec::new(), Vec::new());
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Roster
    ));
}

#[test]
fn leaf_with_a_lower_epoch_than_the_manifest_is_an_epoch_error() {
    let (mut vault, owner, pins, state) = setup();
    let first = vault.put(1, 7, b"a");
    let joined = vault.add_member(2, Role::Editor);
    let state = verify_batch(&state, &[first, joined], &owner.own(), &pins).unwrap();
    let mut bumped = vault.remove_member(2);
    bumped.ops.clear();
    resign(&mut bumped, &owner, |_| {});
    let got = expect(verify_batch(&state, &[bumped], &owner.own(), &pins));
    assert!(matches!(got, ProtoError::Epoch));
}

#[test]
fn item_version_must_increase_by_exactly_one() {
    let (mut vault, owner, pins, state) = setup();
    let wire = vault.seal(7, 2, 0, b"skipped version one");
    let commit = vault.finish_unchecked(1, vec![wire]);
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Epoch
    ));
}

#[test]
fn ops_from_another_vault_are_rejected() {
    let (mut vault, owner, pins, state) = setup();
    let mut wire = vault.seal(7, 1, 0, b"a");
    wire.vault_id = crate::VaultId::from_bytes([3; 16]);
    let commit = vault.finish_unchecked(1, vec![wire]);
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Format
    ));
}

#[test]
fn wrong_root_is_rejected_on_every_commit_and_owner_repair_applies() {
    let (mut vault, owner, pins, state) = setup();
    let joined = vault.add_member(2, Role::Editor);
    let state = verify_batch(&state, &[joined], &owner.own(), &pins).unwrap();
    let editor = Person::new(2);
    let good_head = state.hash;
    let mut bad = vault.put(2, 7, b"bad root");
    resign(&mut bad, &editor, |m| m.root = Hash32::from_bytes([7; 32]));
    assert!(matches!(
        expect(verify_batch(&state, &[bad.clone()], &owner.own(), &pins)),
        ProtoError::Root
    ));

    let mut repair_vault = Vault::new(VaultKind::Shared, 1);
    repair_vault.mirror(&vault, &state);
    let mut repair = repair_vault.put(1, 8, b"repair content");
    resign(&mut repair, &owner, |m| {
        m.repair = true;
        m.prev = Some(good_head);
        m.seq = state.seq.checked_next().unwrap();
    });
    let repaired = verify_repair(&state, Some(&bad), &repair).unwrap();
    assert_eq!(repaired.seq, state.seq.checked_next().unwrap());
    assert!(verify_repair(&state, None, &repair).is_ok());
    assert!(matches!(
        verify_repair(&state, Some(&repair), &repair),
        Err(ProtoError::Fork)
    ));
}

#[test]
fn repair_must_be_flagged_owner_signed_and_free_of_rosters() {
    let (mut vault, owner, pins, state) = setup();
    let joined = vault.add_member(2, Role::Editor);
    let state = verify_batch(&state, &[joined], &owner.own(), &pins).unwrap();
    let plain = vault.put(1, 7, b"not flagged");
    assert!(matches!(
        verify_repair(&state, None, &plain),
        Err(ProtoError::Format)
    ));
    let editor = Person::new(2);
    let mut by_editor = vault.put(2, 8, b"x");
    resign(&mut by_editor, &editor, |m| m.repair = true);
    let mut vault = vault;
    let _ = &mut vault;
    assert!(matches!(
        verify_repair(&state, None, &by_editor),
        Err(ProtoError::Authz | ProtoError::Root | ProtoError::Rollback | ProtoError::Fork)
    ));
}

#[test]
fn unsupported_version_and_wrong_record_type_are_distinguished() {
    let (mut vault, owner, pins, state) = setup();
    let mut commit = vault.put(1, 7, b"a");
    let mut body = commit.manifest.body.clone();
    body[2] = 0x02;
    commit.manifest = Signed::from_parts(
        body.clone(),
        owner.ik_pk,
        owner
            .signing
            .sign(&[SigLabel::Manifest.name().as_bytes(), &[0], &body].concat()),
    );
    assert!(matches!(
        expect(verify_batch(&state, &[commit.clone()], &owner.own(), &pins)),
        ProtoError::Version
    ));
    body[2] = 0x01;
    body[4] = 0x03;
    commit.manifest = Signed::from_parts(
        body.clone(),
        owner.ik_pk,
        owner
            .signing
            .sign(&[SigLabel::Manifest.name().as_bytes(), &[0], &body].concat()),
    );
    assert!(matches!(
        expect(verify_batch(&state, &[commit], &owner.own(), &pins)),
        ProtoError::Format
    ));
}

mod items;
