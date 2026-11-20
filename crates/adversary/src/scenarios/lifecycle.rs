use hasp_proto::{
    AccountId, Commit, Dissolve, Epoch, Hash32, LeaveRequest, PinState, RecoveryEnrolment, Role,
    Rver, Seq, SigLabel, Signed, Uint53, VaultKind, VaultState, head_code, verify_dissolve,
    verify_leave,
};

use crate::double::{Check, DState, Verifier};
use crate::harness::{ATTACKER, Chain, EDITOR, OWNER, Person, Session, VIEWER, bump, err_name};
use crate::scenarios::attack;

fn dissolve_body(state: &VaultState) -> Dissolve {
    Dissolve {
        vault_id: state.roster.vault_id,
        rver: state.rver,
        epoch: state.epoch,
        seq: state.seq,
        head: state.hash,
    }
}

fn sign_dissolve(body: &Dissolve, key: &Person) -> Signed<Dissolve> {
    Signed::sign(SigLabel::Dissolve, body, &key.signing).unwrap()
}

fn judge_dissolve(rec: &Signed<Dissolve>, state: &VaultState, expected: &str, skip: &[Check]) {
    let dstate = DState::from_real(state);
    assert_eq!(
        err_name(verify_dissolve(rec, state)),
        expected,
        "real verifier"
    );
    assert_eq!(
        err_name(Verifier::full().dissolve(rec, &dstate)),
        expected,
        "reference parity"
    );
    assert_eq!(
        err_name(Verifier::without(skip).dissolve(rec, &dstate)),
        "Ok",
        "vulnerable double {skip:?}"
    );
}

fn leave_body(state: &VaultState, member: u8) -> LeaveRequest {
    LeaveRequest {
        vault_id: state.roster.vault_id,
        account_id: AccountId::from_bytes([member; 16]),
        rver: state.rver,
        epoch: state.epoch,
    }
}

fn judge_leave(rec: &Signed<LeaveRequest>, state: &VaultState, expected: &str, skip: &[Check]) {
    let dstate = DState::from_real(state);
    assert_eq!(
        err_name(verify_leave(rec, state)),
        expected,
        "real verifier"
    );
    assert_eq!(
        err_name(Verifier::full().leave(rec, &dstate)),
        expected,
        "reference parity"
    );
    assert_eq!(
        err_name(Verifier::without(skip).leave(rec, &dstate)),
        "Ok",
        "vulnerable double {skip:?}"
    );
}

#[test]
fn honest_dissolve_and_leave_verify_in_both_verifiers() {
    let session = Session::owner();
    let owner = Person::new(OWNER);
    let dissolve = sign_dissolve(&dissolve_body(&session.state), &owner);
    assert!(verify_dissolve(&dissolve, &session.state).is_ok());
    assert!(
        Verifier::full()
            .dissolve(&dissolve, &DState::from_real(&session.state))
            .is_ok()
    );
    let editor = Person::new(EDITOR);
    let leave = Signed::sign(
        SigLabel::Leave,
        &leave_body(&session.state, EDITOR),
        &editor.signing,
    )
    .unwrap();
    assert!(verify_leave(&leave, &session.state).is_ok());
    assert!(
        Verifier::full()
            .leave(&leave, &DState::from_real(&session.state))
            .is_ok()
    );
}

#[test]
fn e32_dissolve_fabricated_by_the_server_is_rejected() {
    let session = Session::owner();
    let attacker = Person::new(ATTACKER);
    let forged = sign_dissolve(&dissolve_body(&session.state), &attacker);
    judge_dissolve(&forged, &session.state, "Sig", &[Check::DissolveSignature]);
}

#[test]
fn e32_dissolve_signed_by_a_non_owner_member_is_rejected() {
    let session = Session::owner();
    let forged = sign_dissolve(&dissolve_body(&session.state), &Person::new(EDITOR));
    judge_dissolve(&forged, &session.state, "Sig", &[Check::DissolveSignature]);
}

#[test]
fn e32_older_dissolve_is_a_rollback() {
    let mut session = Session::owner();
    let owner = Person::new(OWNER);
    let old = sign_dissolve(&dissolve_body(&session.state), &owner);
    let commit = session.chain.put(OWNER, 1, b"later write");
    session.advance(&[commit]);
    judge_dissolve(&old, &session.state, "Rollback", &[Check::DissolveMarks]);
}

#[test]
fn e32_dissolve_naming_another_head_at_the_same_seq_is_a_fork() {
    let session = Session::owner();
    let owner = Person::new(OWNER);
    let mut body = dissolve_body(&session.state);
    body.head = Hash32::from_bytes([0x13; 32]);
    judge_dissolve(
        &sign_dissolve(&body, &owner),
        &session.state,
        "Fork",
        &[Check::DissolveFork],
    );
}

#[test]
fn e32_dissolve_of_a_private_vault_or_another_vault_is_rejected() {
    let mut chain = Chain::new(VaultKind::Private, OWNER);
    let genesis = chain.genesis();
    let owner = Person::new(OWNER);
    let state = hasp_proto::verify_genesis(&genesis, &owner.own(), &PinState::new()).unwrap();
    let dissolve = sign_dissolve(&dissolve_body(&state), &owner);
    assert_eq!(err_name(verify_dissolve(&dissolve, &state)), "Roster");
    let session = Session::owner();
    let mut foreign = dissolve_body(&session.state);
    foreign.vault_id = hasp_proto::VaultId::from_bytes([0x77; 16]);
    assert_eq!(
        err_name(verify_dissolve(
            &sign_dissolve(&foreign, &owner),
            &session.state
        )),
        "Roster"
    );
}

#[test]
fn e32_leave_request_signed_by_the_wrong_key_is_rejected() {
    let session = Session::owner();
    let attacker = Person::new(ATTACKER);
    let forged = Signed::sign(
        SigLabel::Leave,
        &leave_body(&session.state, EDITOR),
        &attacker.signing,
    )
    .unwrap();
    judge_leave(&forged, &session.state, "Sig", &[Check::LeaveSignature]);
}

#[test]
fn e32_stale_leave_request_is_ignored_by_roster_version_and_epoch() {
    let mut session = Session::owner();
    let editor = Person::new(EDITOR);
    let stale_rver = Signed::sign(
        SigLabel::Leave,
        &leave_body(&session.state, EDITOR),
        &editor.signing,
    )
    .unwrap();
    let change = session.chain.add_member(0x30, Role::Viewer);
    session.advance(&[change]);
    judge_leave(
        &stale_rver,
        &session.state,
        "Roster",
        &[Check::LeaveBinding],
    );
    let mut body = leave_body(&session.state, EDITOR);
    body.epoch = Epoch::new(bump(session.state.epoch.get())).unwrap();
    let stale_epoch = Signed::sign(SigLabel::Leave, &body, &editor.signing).unwrap();
    judge_leave(
        &stale_epoch,
        &session.state,
        "Epoch",
        &[Check::LeaveBinding],
    );
}

#[test]
fn e32_leave_request_for_the_owner_or_a_stranger_is_rejected() {
    let session = Session::owner();
    let owner = Person::new(OWNER);
    let for_owner = Signed::sign(
        SigLabel::Leave,
        &leave_body(&session.state, OWNER),
        &owner.signing,
    )
    .unwrap();
    assert_eq!(err_name(verify_leave(&for_owner, &session.state)), "Authz");
    let attacker = Person::new(ATTACKER);
    let stranger = Signed::sign(
        SigLabel::Leave,
        &leave_body(&session.state, ATTACKER),
        &attacker.signing,
    )
    .unwrap();
    assert_eq!(err_name(verify_leave(&stranger, &session.state)), "Authz");
    let mut other_vault = leave_body(&session.state, VIEWER);
    other_vault.vault_id = hasp_proto::VaultId::from_bytes([0x78; 16]);
    let viewer = Person::new(VIEWER);
    let foreign = Signed::sign(SigLabel::Leave, &other_vault, &viewer.signing).unwrap();
    assert_eq!(err_name(verify_leave(&foreign, &session.state)), "Roster");
}

#[test]
fn e32_leave_grants_nothing_without_an_owner_signed_removal() {
    let session = Session::owner();
    let editor = Person::new(EDITOR);
    let leave = Signed::sign(
        SigLabel::Leave,
        &leave_body(&session.state, EDITOR),
        &editor.signing,
    )
    .unwrap();
    assert!(verify_leave(&leave, &session.state).is_ok());
    assert!(
        session
            .state
            .roster
            .member(&AccountId::from_bytes([EDITOR; 16]))
            .is_some()
    );
}

fn forged_write(session: &Session) -> Commit {
    let mut chain = session.chain.fork();
    let genuine = chain.put(OWNER, 1, b"planted by the thief");
    let thief = Person::new(ATTACKER);
    let mut manifest = genuine.manifest.unverified().unwrap();
    manifest.author = AccountId::from_bytes([OWNER; 16]);
    Commit {
        manifest: Signed::sign(SigLabel::Manifest, &manifest, &thief.signing).unwrap(),
        ..genuine
    }
}

#[test]
fn e13_write_forged_with_a_stolen_token_is_rejected_by_signature() {
    let session = Session::owner();
    attack(
        &session,
        &[forged_write(&session)],
        "Sig",
        &[Check::ManifestSignature],
    );
}

#[test]
fn e13_member_write_altered_in_transit_is_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let mut commit = chain.put(EDITOR, 1, b"as written");
    let mut tampered = chain.put(EDITOR, 2, b"swapped in transit");
    tampered.manifest = commit.manifest.clone();
    commit.ops = tampered.ops;
    attack(&session, &[commit], "Root", &[Check::Root]);
}

#[test]
fn e13_writer_without_write_role_is_rejected_even_with_a_valid_signature() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let commit = chain.put(VIEWER, 1, b"viewer write");
    attack(&session, &[commit], "Authz", &[Check::OwnerOnly]);
}

#[test]
fn e13_editor_cannot_commit_rosters_or_shares() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let genuine = chain.add_member(0x31, Role::Viewer);
    let by_editor = chain.resign(&genuine, EDITOR, |m| {
        m.author = AccountId::from_bytes([EDITOR; 16]);
    });
    attack(
        &session,
        &[by_editor],
        "Authz",
        &[Check::OwnerOnly, Check::BundledShare],
    );
}

#[test]
fn e3_enrolment_not_signed_by_the_account_key_is_rejected() {
    let owner = Person::new(OWNER);
    let attacker = Person::new(ATTACKER);
    let body = RecoveryEnrolment {
        account_id: AccountId::from_bytes([OWNER; 16]),
        rgen: Uint53::new(1).unwrap(),
        h_wrap: Hash32::from_bytes([0xee; 32]),
    };
    let escrow = Signed::sign(SigLabel::Recovery, &body, &attacker.signing).unwrap();
    assert_eq!(
        err_name(escrow.verify(SigLabel::Recovery, &owner.ik_pk)),
        "Sig"
    );
    assert!(escrow.unverified().is_ok());
    let honest = Signed::sign(SigLabel::Recovery, &body, &owner.signing).unwrap();
    assert!(honest.verify(SigLabel::Recovery, &owner.ik_pk).is_ok());
}

#[test]
fn e3_signature_labels_separate_record_types() {
    let owner = Person::new(OWNER);
    let body = RecoveryEnrolment {
        account_id: AccountId::from_bytes([OWNER; 16]),
        rgen: Uint53::new(1).unwrap(),
        h_wrap: Hash32::from_bytes([0xee; 32]),
    };
    let honest = Signed::sign(SigLabel::Recovery, &body, &owner.signing).unwrap();
    for wrong in [
        SigLabel::Account,
        SigLabel::Roster,
        SigLabel::Manifest,
        SigLabel::Share,
        SigLabel::Dissolve,
        SigLabel::Leave,
    ] {
        assert_eq!(err_name(honest.verify(wrong, &owner.ik_pk)), "Sig");
    }
}

#[test]
fn e23_stateless_device_cannot_detect_a_truncated_chain_but_the_head_code_differs() {
    let mut session = Session::owner();
    let owner = Person::new(OWNER);
    let before_removal = session.state.clone();
    let removal = session.chain.remove_member(VIEWER);
    session.advance(&[removal]);
    let stateless = hasp_proto::verify_genesis(&session_genesis(), &owner.own(), &PinState::new());
    assert!(stateless.is_ok());
    let stale_code = code(&before_removal);
    let current_code = code(&session.state);
    assert_ne!(stale_code, current_code);
    assert_eq!(stale_code, code(&before_removal));
}

fn session_genesis() -> Commit {
    let mut chain = Chain::new(VaultKind::Shared, OWNER);
    chain.genesis()
}

fn code(state: &VaultState) -> String {
    head_code(
        &state.roster.vault_id,
        Rver::new(state.rver.get()).unwrap(),
        state.epoch,
        Seq::new(state.seq.get()).unwrap(),
        &state.hash,
    )
    .unwrap()
}
