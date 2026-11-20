use hasp_crypto::SecretKey;
use hasp_proto::{
    AccountId, Commit, Dissolve, Epoch, Hash32, PinState, Role, Roster, Rver, Seq, Share, SigLabel,
    Signed, VaultKind, VaultState, Wire, open_item, verify_dissolve, verify_genesis,
};

use crate::double::{Check, Verifier};
use crate::harness::{
    ATTACKER, Chain, EDITOR, INVITEE, OWNER, Person, Session, VIEWER, bump, clone_key, err_name,
};
use crate::scenarios::{attack, reject};

fn genesis_attack(chain_edit: impl FnOnce(&mut Chain), expected: &str, skip: &[Check]) {
    let mut chain = Chain::new(VaultKind::Shared, OWNER);
    chain_edit(&mut chain);
    let commit = chain.genesis();
    genesis_judge(&commit, expected, skip);
}

fn genesis_judge(commit: &Commit, expected: &str, skip: &[Check]) {
    let own = Person::new(OWNER).own();
    let pins = PinState::new();
    assert_eq!(
        err_name(verify_genesis(commit, &own, &pins)),
        expected,
        "real verifier"
    );
    assert_eq!(
        err_name(Verifier::full().genesis(commit, &own, &pins)),
        expected,
        "reference parity"
    );
    assert_eq!(
        err_name(Verifier::without(skip).genesis(commit, &own, &pins)),
        "Ok",
        "vulnerable double {skip:?}"
    );
}

#[test]
fn private_vault_roster_with_a_second_member_is_rejected() {
    let mut chain = Chain::new(VaultKind::Private, OWNER);
    chain.others.insert(EDITOR, (Role::Editor, 1));
    let commit = chain.genesis();
    genesis_judge(&commit, "Roster", &[Check::RosterShape]);
}

#[test]
fn member_added_in_a_future_roster_version_is_rejected() {
    genesis_attack(
        |chain| {
            chain.others.insert(EDITOR, (Role::Editor, 5));
        },
        "Roster",
        &[Check::RosterShape],
    );
}

#[test]
fn genesis_roster_must_start_at_version_one_without_a_predecessor() {
    let mut chain = Chain::new(VaultKind::Shared, OWNER);
    let vk = clone_key(chain.vk());
    let roster = chain.roster_body(2, 0, &vk);
    let commit = chain.roster_commit(OWNER, roster);
    genesis_judge(&commit, "Roster", &[Check::RosterSuccessor]);

    let mut chain = Chain::new(VaultKind::Shared, OWNER);
    chain.roster = Some((
        chain.roster_body(1, 0, &clone_key(chain.vk())),
        Hash32::from_bytes([5; 32]),
    ));
    let roster = chain.roster_body(1, 0, &clone_key(chain.vk()));
    let commit = chain.roster_commit(OWNER, roster);
    genesis_judge(&commit, "Roster", &[Check::RosterSuccessor]);
}

#[test]
fn genesis_manifest_naming_another_vault_than_its_roster_is_rejected() {
    let mut chain = Chain::new(VaultKind::Shared, OWNER);
    let genesis = chain.genesis();
    let forged = chain.resign(&genesis, OWNER, |m| {
        m.vault_id = hasp_proto::VaultId::from_bytes([0x42; 16]);
    });
    genesis_judge(&forged, "Roster", &[Check::BindRoster]);
}

#[test]
fn own_identity_key_alone_or_own_kem_key_alone_substituted_is_rejected() {
    let mut ik_only = Session::bare(INVITEE);
    ik_only.chain.substitute_ik.insert(INVITEE, ATTACKER);
    let add = ik_only.chain.add_member(INVITEE, Role::Editor);
    attack(&ik_only, &[add], "Roster", &[Check::RosterOwnKey]);

    let mut kem_only = Session::bare(INVITEE);
    kem_only.chain.substitute_kem.insert(INVITEE, ATTACKER);
    let add = kem_only.chain.add_member(INVITEE, Role::Editor);
    attack(&kem_only, &[add], "Roster", &[Check::RosterOwnKey]);
}

fn successor(session: &Session, edit: impl FnOnce(&mut Roster)) -> Commit {
    let chain = session.chain.fork();
    let mut roster = chain.roster_body(bump(chain.rver), chain.epoch, &clone_key(chain.vk()));
    edit(&mut roster);
    let carrier = chain.fork().put(OWNER, 1, b"carrier");
    let signed = chain.sign_roster(&roster);
    Commit {
        roster: Some(signed),
        ..carrier
    }
}

fn same_version(session: &Session, edit: impl FnOnce(&mut Roster)) -> Commit {
    let mut roster = session.state.roster.clone();
    edit(&mut roster);
    let carrier = session.chain.fork().put(OWNER, 1, b"carrier");
    Commit {
        roster: Some(session.chain.sign_roster(&roster)),
        ..carrier
    }
}

#[test]
fn second_roster_at_the_held_version_is_a_fork_and_the_identical_one_a_rollback() {
    let session = Session::owner();
    let rival = same_version(&session, |roster| {
        roster.members[1].role = Role::Viewer;
        roster.members[2].role = Role::Editor;
    });
    reject(&session, &[rival], "Fork");
    let replay = same_version(&session, |_| {});
    reject(&session, &[replay], "Rollback");
}

#[test]
fn roster_kind_change_alone_is_rejected() {
    let session = Session::bare(OWNER);
    let mut chain = session.chain.fork();
    let mut roster = chain.roster_body(bump(chain.rver), chain.epoch, &clone_key(chain.vk()));
    roster.kind = VaultKind::Private;
    let commit = chain.roster_commit(OWNER, roster);
    reject(&session, &[commit], "Roster");
}

#[test]
fn roster_vault_change_alone_is_rejected() {
    let session = Session::bare(OWNER);
    let commit = successor(&session, |roster| {
        roster.vault_id = hasp_proto::VaultId::from_bytes([0x43; 16]);
    });
    reject(&session, &[commit], "Roster");
}

#[test]
fn roster_epoch_rules_each_fail_on_their_own() {
    let mut session = Session::owner();
    let removal = session.chain.remove_member(VIEWER);
    session.advance(std::slice::from_ref(&removal));
    let lower = successor(&session, |roster| {
        roster.epoch = Epoch::new(0).unwrap();
        roster.vk_commit = Hash32::from_bytes([1; 32]);
    });
    reject(&session, &[lower], "Epoch");
    let changed_key_only = successor(&session, |roster| {
        roster.vk_commit = Hash32::from_bytes([2; 32]);
    });
    reject(&session, &[changed_key_only], "Roster");
    let bumped_only = successor(&session, |roster| {
        roster.epoch = Epoch::new(bump(roster.epoch.get())).unwrap();
    });
    reject(&session, &[bumped_only], "Roster");
}

#[test]
fn manifest_rver_or_roster_hash_wrong_on_its_own_is_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let commit = chain.put(OWNER, 1, b"x");
    let wrong_rver = chain.resign(&commit, OWNER, |m| {
        m.rver = Rver::new(bump(m.rver.get())).unwrap();
    });
    attack(
        &session,
        &[wrong_rver],
        "Roster",
        &[Check::BindRoster, Check::RverNotLower],
    );
    let wrong_hash = chain.resign(&commit, OWNER, |m| {
        m.roster_hash = Hash32::from_bytes([8; 32]);
    });
    attack(&session, &[wrong_hash], "Roster", &[Check::BindRoster]);
}

type ShareEdit = Box<dyn FnOnce(&mut Share)>;

fn share_body(session: &Session, edit: impl FnOnce(&mut Share)) -> Signed<Share> {
    let mut body = Share {
        vault_id: session.state.roster.vault_id,
        epoch: session.state.epoch,
        rver: session.state.rver,
        from: AccountId::from_bytes([OWNER; 16]),
        to: AccountId::from_bytes([EDITOR; 16]),
        kem_pk_hash: Hash32::from_bytes([0; 32]),
        enc: [0; hasp_crypto::XWING_ENCAPSULATED_LEN],
        ct: [0; hasp_proto::SHARE_CT_LEN],
    };
    edit(&mut body);
    Signed::sign(SigLabel::Share, &body, &Person::new(OWNER).signing).unwrap()
}

fn with_share(session: &Session, share: Signed<Share>) -> Commit {
    let mut commit = session.chain.fork().put(OWNER, 1, b"carrier");
    commit.shares = vec![share];
    commit
}

#[test]
fn bundled_share_with_one_wrong_field_is_rejected() {
    let session = Session::owner();
    let accepted = with_share(&session, share_body(&session, |_| {}));
    assert!(session.verify(&[accepted]).is_ok());
    let cases: [(&str, ShareEdit, &str); 6] = [
        (
            "vault",
            Box::new(|s| s.vault_id = hasp_proto::VaultId::from_bytes([1; 16])),
            "Roster",
        ),
        (
            "from",
            Box::new(|s| s.from = AccountId::from_bytes([EDITOR; 16])),
            "Roster",
        ),
        (
            "rver",
            Box::new(|s| s.rver = Rver::new(bump(s.rver.get())).unwrap()),
            "Roster",
        ),
        (
            "to self",
            Box::new(|s| s.to = AccountId::from_bytes([OWNER; 16])),
            "Roster",
        ),
        (
            "to stranger",
            Box::new(|s| s.to = AccountId::from_bytes([ATTACKER; 16])),
            "Roster",
        ),
        (
            "epoch",
            Box::new(|s| s.epoch = Epoch::new(bump(s.epoch.get())).unwrap()),
            "Epoch",
        ),
    ];
    for (name, edit, expected) in cases {
        let commit = with_share(&session, share_body(&session, edit));
        assert_eq!(
            err_name(session.verify(std::slice::from_ref(&commit))),
            expected,
            "{name}"
        );
        attack(&session, &[commit], expected, &[Check::BundledShare]);
    }
}

#[test]
fn editor_commit_carrying_only_a_share_or_only_a_roster_is_not_authorised() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let editor = Person::new(EDITOR);
    let mut body = share_body(&session, |s| {
        s.from = AccountId::from_bytes([EDITOR; 16]);
        s.to = AccountId::from_bytes([VIEWER; 16]);
    });
    body = Signed::sign(
        SigLabel::Share,
        &body.unverified().unwrap(),
        &editor.signing,
    )
    .unwrap();
    let mut commit = chain.put(EDITOR, 1, b"editor share");
    commit.shares = vec![body];
    attack(&session, &[commit], "Authz", &[Check::OwnerOnly]);

    let mut chain = session.chain.fork();
    let mut roster = chain.roster_body(bump(chain.rver), chain.epoch, &clone_key(chain.vk()));
    roster.members[2].role = Role::Editor;
    let rostered = chain.roster_commit(OWNER, roster);
    let by_editor = chain.resign(&rostered, EDITOR, |m| {
        m.author = AccountId::from_bytes([EDITOR; 16]);
    });
    attack(&session, &[by_editor], "Authz", &[Check::OwnerOnly]);
}

#[test]
fn repair_manifest_carrying_a_share_is_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let commit = chain.put(OWNER, 1, b"repair");
    let mut repair = chain.resign(&commit, OWNER, |m| m.repair = true);
    repair.shares = vec![share_body(&session, |_| {})];
    assert_eq!(
        err_name(hasp_proto::verify_repair(&session.state, None, &repair)),
        "Format"
    );
}

fn dissolve_with(state: &VaultState, edit: impl FnOnce(&mut Dissolve)) -> Signed<Dissolve> {
    let mut body = Dissolve {
        vault_id: state.roster.vault_id,
        rver: state.rver,
        epoch: state.epoch,
        seq: state.seq,
        head: state.hash,
    };
    edit(&mut body);
    Signed::sign(SigLabel::Dissolve, &body, &Person::new(OWNER).signing).unwrap()
}

#[test]
fn dissolve_below_any_one_stored_mark_is_a_rollback_and_above_is_accepted() {
    let mut session = Session::owner();
    let removal = session.chain.remove_member(VIEWER);
    session.advance(std::slice::from_ref(&removal));
    let state = &session.state;
    let rver_below = dissolve_with(state, |d| d.rver = Rver::new(d.rver.get() - 1).unwrap());
    let epoch_below = dissolve_with(state, |d| d.epoch = Epoch::new(d.epoch.get() - 1).unwrap());
    let seq_below = dissolve_with(state, |d| d.seq = Seq::new(d.seq.get() - 1).unwrap());
    for below in [rver_below, epoch_below, seq_below] {
        assert_eq!(err_name(verify_dissolve(&below, state)), "Rollback");
    }
    let rver_above = dissolve_with(state, |d| d.rver = Rver::new(d.rver.get() + 1).unwrap());
    let epoch_above = dissolve_with(state, |d| d.epoch = Epoch::new(d.epoch.get() + 1).unwrap());
    let seq_above = dissolve_with(state, |d| d.seq = Seq::new(d.seq.get() + 1).unwrap());
    for above in [rver_above, epoch_above, seq_above] {
        assert!(verify_dissolve(&above, state).is_ok());
    }
}

#[test]
fn rewrapped_items_open_under_the_new_epoch_key_and_not_the_old_one() {
    let mut session = Session::owner();
    let put = session.chain.put(OWNER, 1, b"keep me");
    session.advance(std::slice::from_ref(&put));
    let old_vk = clone_key(session.chain.vk());
    let removal = session.chain.remove_member(VIEWER);
    session.advance(std::slice::from_ref(&removal));
    let new_vk = clone_key(session.chain.vk());
    let item = session.chain.items.values().next().unwrap().clone();
    let bytes = item.to_cbor().unwrap();
    assert!(open_item(&item, &bytes, &session.state, &new_vk).is_ok());
    assert_eq!(
        err_name(open_item(&item, &bytes, &session.state, &old_vk)),
        "Aead"
    );
    let unrelated: SecretKey = SecretKey::from_bytes([1; 32]);
    assert_eq!(
        err_name(open_item(&item, &bytes, &session.state, &unrelated)),
        "Aead"
    );
}
