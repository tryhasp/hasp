use hasp_proto::{Commit, Hash32, Seq, SigLabel, Signed, verify_repair};

use crate::double::{Check, DState};
use crate::harness::{Chain, EDITOR, OWNER, Person, Session, VIEWER, bump, err_name};
use crate::scenarios::{attack, attack_from};

fn with_item() -> (Session, Commit) {
    let mut session = Session::shared(
        VIEWER,
        &[
            (EDITOR, hasp_proto::Role::Editor),
            (VIEWER, hasp_proto::Role::Viewer),
        ],
    );
    let commit = session.chain.put(OWNER, 1, b"first");
    session.advance(std::slice::from_ref(&commit));
    (session, commit)
}

#[test]
fn e7_replay_of_an_applied_commit_is_a_rollback() {
    let (session, applied) = with_item();
    attack(
        &session,
        &[applied],
        "Rollback",
        &[Check::Chain, Check::OpVersion],
    );
}

#[test]
fn e7_duplicated_commit_in_one_batch_is_a_rollback() {
    let mut session = Session::owner();
    let commit = session.chain.put(OWNER, 1, b"once");
    attack(
        &session,
        &[commit.clone(), commit],
        "Rollback",
        &[Check::Chain, Check::OpVersion],
    );
}

#[test]
fn e7_dropped_commit_is_a_rollback_and_its_item_is_missing_from_the_root() {
    let mut session = Session::owner();
    let _dropped = session.chain.put(OWNER, 1, b"dropped");
    let later = session.chain.put(OWNER, 2, b"later");
    attack(&session, &[later], "Rollback", &[Check::Chain, Check::Root]);
}

#[test]
fn e7_reordered_commits_are_a_rollback() {
    let mut session = Session::owner();
    let first = session.chain.put(OWNER, 1, b"a");
    let second = session.chain.put(OWNER, 2, b"b");
    attack(
        &session,
        &[second, first],
        "Rollback",
        &[Check::Chain, Check::Root],
    );
}

#[test]
fn e7_commit_stripped_of_an_item_op_fails_the_root() {
    let mut session = Session::owner();
    let mut commit = session.chain.put(OWNER, 1, b"secret");
    commit.ops.clear();
    attack(&session, &[commit], "Root", &[Check::Root]);
}

#[test]
fn e7_duplicated_item_op_is_rejected() {
    let mut session = Session::owner();
    let mut commit = session.chain.put(OWNER, 1, b"twice");
    let op = commit.ops[0].clone();
    commit.ops.push(op);
    attack(&session, &[commit], "Epoch", &[Check::OpVersion]);
}

#[test]
fn e7_item_op_replayed_at_a_stale_version_is_rejected() {
    let mut session = Session::owner();
    let first = session.chain.put(OWNER, 1, b"v1");
    session.advance(std::slice::from_ref(&first));
    let second = session.chain.put(OWNER, 1, b"v2");
    session.advance(std::slice::from_ref(&second));
    let mut stale = session.chain.put(OWNER, 2, b"other");
    stale.ops = vec![first.ops[0].clone()];
    let mut manifest = stale.manifest.unverified().unwrap();
    let mut leaves = DState::from_real(&session.state).leaves;
    leaves.insert(
        first.ops[0].wire().item_id,
        hasp_proto::Leaf {
            item_id: first.ops[0].wire().item_id,
            ver: first.ops[0].wire().ver,
            epoch: first.ops[0].wire().epoch,
            h_item: *first.ops[0].h_item(),
            flag: hasp_proto::LeafFlag::Live,
        },
    );
    manifest.root = crate::double::root_of(&leaves);
    let owner = Person::new(OWNER);
    stale.manifest = Signed::sign(SigLabel::Manifest, &manifest, &owner.signing).unwrap();
    attack(&session, &[stale], "Epoch", &[Check::OpVersion]);
}

fn concurrent_heads() -> (Session, Commit, Commit, Chain) {
    let session = Session::shared(
        VIEWER,
        &[
            (EDITOR, hasp_proto::Role::Editor),
            (VIEWER, hasp_proto::Role::Viewer),
        ],
    );
    let mut owner_branch = session.chain.fork();
    let mut editor_branch = session.chain.fork();
    let x = owner_branch.put(OWNER, 1, b"owner wins");
    let y = editor_branch.put(EDITOR, 1, b"editor wins");
    (session, x, y, editor_branch)
}

#[test]
fn e8_two_heads_at_the_same_seq_are_a_fork_on_contact() {
    let (session, x, y, _) = concurrent_heads();
    let client_a = session.verify(std::slice::from_ref(&x)).unwrap();
    let client_b = session.verify(std::slice::from_ref(&y)).unwrap();
    assert_ne!(client_a.hash, client_b.hash);
    attack_from(
        &session,
        &client_a,
        &[y],
        "Fork",
        &[Check::Chain, Check::OpVersion],
    );
    attack_from(
        &session,
        &client_b,
        &[x],
        "Fork",
        &[Check::Chain, Check::OpVersion],
    );
}

#[test]
fn e8_branch_continuation_on_the_wrong_head_is_a_fork() {
    let (session, x, _, mut editor_branch) = concurrent_heads();
    let client_a = session.verify(std::slice::from_ref(&x)).unwrap();
    let z = editor_branch.put(EDITOR, 2, b"on the other branch");
    attack_from(
        &session,
        &client_a,
        &[z],
        "Fork",
        &[Check::Chain, Check::Root],
    );
}

fn forged_root(session: &Session, author: u8) -> Commit {
    let mut chain = session.chain.fork();
    let commit = chain.put(author, 1, b"bad root");
    chain.resign(&commit, author, |m| m.root = Hash32::from_bytes([9; 32]))
}

#[test]
fn e22_editor_commit_with_a_wrong_root_is_rejected_on_the_commit() {
    let session = Session::owner();
    let bad = forged_root(&session, EDITOR);
    attack(&session, &[bad], "Root", &[Check::Root]);
}

#[test]
fn e22_owner_repair_applies_only_to_the_quarantined_seq_and_must_be_flagged_and_owner_signed() {
    let session = Session::owner();
    let bad = forged_root(&session, EDITOR);
    assert_eq!(err_name(session.verify(std::slice::from_ref(&bad))), "Root");
    let honest_state = &session.state;
    let mut chain = session.chain.fork();
    let ops_commit = chain.put(OWNER, 1, b"repaired");
    let repair = chain.resign(&ops_commit, OWNER, |m| {
        m.repair = true;
        m.prev = Some(honest_state.hash);
        m.seq = Seq::new(bump(honest_state.seq.get())).unwrap();
    });
    let repaired = verify_repair(honest_state, Some(&bad), &repair).unwrap();
    assert_eq!(repaired.seq.get(), bump(honest_state.seq.get()));
    assert_eq!(repaired.leafset.len(), 1);
    assert_eq!(
        err_name(verify_repair(honest_state, Some(&repair), &repair)),
        "Fork"
    );
    let by_editor = chain.resign(&repair, EDITOR, |m| {
        m.author = hasp_proto::AccountId::from_bytes([EDITOR; 16]);
    });
    assert_eq!(
        err_name(verify_repair(honest_state, Some(&bad), &by_editor)),
        "Authz"
    );
    let unflagged = chain.resign(&repair, OWNER, |m| m.repair = false);
    assert_eq!(
        err_name(verify_repair(honest_state, Some(&bad), &unflagged)),
        "Format"
    );
}

#[test]
fn e22_repair_is_rejected_when_it_does_not_replace_the_quarantined_seq() {
    let session = Session::owner();
    let bad = forged_root(&session, EDITOR);
    let mut chain = session.chain.fork();
    let commit = chain.put(OWNER, 1, b"x");
    let later = chain.resign(&commit, OWNER, |m| {
        m.repair = true;
        m.seq = Seq::new(bump(bump(session.state.seq.get()))).unwrap();
        m.prev = Some(session.state.hash);
    });
    assert_eq!(
        err_name(verify_repair(&session.state, Some(&bad), &later)),
        "Fork"
    );
}

fn removal_session() -> (Session, Session) {
    let before = Session::owner();
    let mut after = Session::owner();
    let removal = after.chain.remove_member(EDITOR);
    after.advance(std::slice::from_ref(&removal));
    (before, after)
}

#[test]
fn e21_commit_by_a_removed_writer_under_the_old_roster_is_rejected() {
    let (before, after) = removal_session();
    let mut stale = before.chain.fork();
    stale.seq = after.chain.seq;
    stale.head = after.chain.head;
    let state_leaves = DState::from_real(&after.state).leaves;
    let mut manifest =
        stale.manifest_body(stale.roster_hash(), Hash32::from_bytes([0; 32]), EDITOR);
    manifest.root = crate::double::root_of(&state_leaves);
    let editor = Person::new(EDITOR);
    let commit = Commit {
        manifest: Signed::sign(SigLabel::Manifest, &manifest, &editor.signing).unwrap(),
        roster: None,
        ops: Vec::new(),
        shares: Vec::new(),
    };
    attack(
        &after,
        &[commit],
        "Roster",
        &[
            Check::BindRoster,
            Check::BindEpoch,
            Check::EpochNotLower,
            Check::RverNotLower,
            Check::AuthorMember,
        ],
    );
}

#[test]
fn e21_removed_writer_cannot_author_under_the_current_roster() {
    let (_, after) = removal_session();
    let mut chain = after.chain.fork();
    let commit = chain.put(EDITOR, 1, b"still here?");
    attack(&after, &[commit], "Authz", &[Check::AuthorMember]);
}

#[test]
fn e28_item_sealed_at_a_lower_epoch_than_the_manifest_is_rejected() {
    let (_, mut after) = removal_session();
    let wire = after.chain.wire(1, 1, 0, b"old epoch key");
    let commit = after.chain.finish(OWNER, None, Vec::new(), vec![wire]);
    let mut fresh = Session::owner();
    let removal = fresh.chain.remove_member(EDITOR);
    fresh.advance(std::slice::from_ref(&removal));
    attack(
        &fresh,
        &[commit],
        "Epoch",
        &[Check::OpEpoch, Check::LiveEpochs],
    );
}

#[test]
fn e28_removal_commit_that_skips_the_rewrap_leaves_a_low_epoch_leaf() {
    let mut session = Session::owner();
    let put = session.chain.put(OWNER, 1, b"live item");
    session.advance(std::slice::from_ref(&put));
    let mut chain = session.chain.fork();
    chain.rver = bump(chain.rver);
    chain.others.remove(&EDITOR);
    chain.epoch = bump(chain.epoch);
    let new_vk = hasp_proto::Entropy::key(&mut chain.entropy).unwrap();
    chain.vks.push(crate::harness::clone_key(&new_vk));
    let roster = chain.roster_body(chain.rver, chain.epoch, &new_vk);
    let signed = chain.sign_roster(&roster);
    chain.roster = Some((roster.clone(), signed.hash()));
    let shares: Vec<_> = chain
        .others
        .keys()
        .filter(|n| **n != OWNER)
        .map(|n| chain.share_for(&roster, signed.hash(), *n))
        .collect();
    let commit = chain.finish(OWNER, Some(signed), shares, Vec::new());
    attack(&session, &[commit], "Epoch", &[Check::LiveEpochs]);
}

fn removal_without_bump(session: &Session) -> Commit {
    let mut chain = session.chain.fork();
    chain.rver = bump(chain.rver);
    chain.others.remove(&EDITOR);
    let roster = chain.roster_body(
        chain.rver,
        chain.epoch,
        &crate::harness::clone_key(chain.vk()),
    );
    let signed = chain.sign_roster(&roster);
    chain.roster = Some((roster, signed.hash()));
    chain.finish(OWNER, Some(signed), Vec::new(), Vec::new())
}

#[test]
fn e31_owner_roster_removing_a_member_at_the_same_epoch_is_rejected() {
    let session = Session::owner();
    let commit = removal_without_bump(&session);
    attack(&session, &[commit], "Epoch", &[Check::RemovalBump]);
}

#[test]
fn e31_bump_by_two_epochs_is_also_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    chain.rver = bump(chain.rver);
    chain.others.remove(&EDITOR);
    chain.epoch = bump(bump(chain.epoch));
    let new_vk = hasp_proto::Entropy::key(&mut chain.entropy).unwrap();
    chain.vks.push(crate::harness::clone_key(&new_vk));
    chain.vks.push(crate::harness::clone_key(&new_vk));
    let roster = chain.roster_body(chain.rver, chain.epoch, &new_vk);
    let signed = chain.sign_roster(&roster);
    chain.roster = Some((roster, signed.hash()));
    let commit = chain.finish(OWNER, Some(signed), Vec::new(), Vec::new());
    attack(&session, &[commit], "Epoch", &[Check::RemovalBump]);
}

#[test]
fn e12_roster_signed_by_anyone_but_the_current_owner_is_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    chain.rver = bump(chain.rver);
    let attacker_owner = Person::new(crate::harness::ATTACKER);
    let mut roster = chain.roster_body(
        chain.rver,
        chain.epoch,
        &crate::harness::clone_key(chain.vk()),
    );
    roster
        .members
        .push(attacker_owner.member(hasp_proto::Role::Editor, chain.rver));
    roster.members.sort_by_key(|m| *m.account_id.as_bytes());
    let signed = Signed::sign(SigLabel::Roster, &roster, &attacker_owner.signing).unwrap();
    chain.roster = Some((roster, signed.hash()));
    let commit = chain.finish(OWNER, Some(signed), Vec::new(), Vec::new());
    attack(&session, &[commit], "Sig", &[Check::RosterSignature]);
}

#[test]
fn e12_roster_of_a_foreign_vault_is_rejected_by_a_member_chain() {
    let session = Session::owner();
    let mut foreign = Chain::new(hasp_proto::VaultKind::Shared, crate::harness::ATTACKER);
    foreign.id = hasp_proto::VaultId::from_bytes([0xdd; 16]);
    foreign.genesis();
    let injected = foreign.put(crate::harness::ATTACKER, 1, b"planted");
    let mut forged = injected.clone();
    forged.manifest = Signed::sign(
        SigLabel::Manifest,
        &{
            let mut m = forged.manifest.unverified().unwrap();
            m.seq = Seq::new(bump(session.state.seq.get())).unwrap();
            m.prev = Some(session.state.hash);
            m
        },
        &Person::new(crate::harness::ATTACKER).signing,
    )
    .unwrap();
    attack(
        &session,
        &[forged],
        "Roster",
        &[
            Check::VaultMatch,
            Check::BindRoster,
            Check::RverNotLower,
            Check::AuthorMember,
            Check::OpVault,
            Check::Root,
        ],
    );
}

#[test]
fn e12_old_roster_replayed_over_a_newer_one_is_a_rollback() {
    let (before, after) = removal_session();
    let old_roster = before.chain.roster.clone().unwrap().0;
    let old_signed = before.chain.sign_roster(&old_roster);
    let mut chain = after.chain.fork();
    let carrier = chain.put(OWNER, 1, b"carrier");
    let commit = Commit {
        roster: Some(old_signed),
        ..carrier
    };
    attack(
        &after,
        &[commit],
        "Rollback",
        &[
            Check::RosterSuccessor,
            Check::RosterEpoch,
            Check::BindRoster,
            Check::BindEpoch,
        ],
    );
}

#[test]
fn e12_roster_that_skips_or_forks_the_version_is_rejected() {
    let session = Session::owner();
    let mut gap = session.chain.fork();
    gap.rver = bump(bump(gap.rver));
    let roster = gap.roster_body(gap.rver, gap.epoch, &crate::harness::clone_key(gap.vk()));
    let signed = gap.sign_roster(&roster);
    gap.roster = Some((roster, signed.hash()));
    let commit = gap.finish(OWNER, Some(signed), Vec::new(), Vec::new());
    attack(&session, &[commit], "Roster", &[Check::RosterSuccessor]);
}

#[test]
fn e12_second_owner_or_ownerless_roster_is_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    chain.rver = bump(chain.rver);
    let mut roster = chain.roster_body(
        chain.rver,
        chain.epoch,
        &crate::harness::clone_key(chain.vk()),
    );
    for member in &mut roster.members {
        member.role = hasp_proto::Role::Owner;
    }
    let signed = chain.sign_roster(&roster);
    chain.roster = Some((roster, signed.hash()));
    let commit = chain.finish(OWNER, Some(signed), Vec::new(), Vec::new());
    assert_eq!(
        err_name(session.verify(std::slice::from_ref(&commit))),
        "Roster"
    );
}
