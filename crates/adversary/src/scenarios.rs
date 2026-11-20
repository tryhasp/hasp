mod account;
mod chain;
mod checks;
mod item;
mod lifecycle;
mod share;
mod wire;

use hasp_proto::{Commit, VaultState};

use crate::double::{Check, DState, Verifier};
use crate::harness::{Session, err_name};

pub(crate) fn attack_from(
    session: &Session,
    state: &VaultState,
    commits: &[Commit],
    expected: &str,
    skip: &[Check],
) {
    let own = session.viewer.own();
    assert_eq!(
        err_name(session.verify_from(state, commits)),
        expected,
        "real verifier"
    );
    let dstate = DState::from_real(state);
    assert_eq!(
        err_name(Verifier::full().batch(&dstate, commits, &own, &session.pins)),
        expected,
        "reference verifier parity"
    );
    assert_eq!(
        err_name(Verifier::without(skip).batch(&dstate, commits, &own, &session.pins)),
        "Ok",
        "vulnerable double {skip:?}"
    );
}

pub(crate) fn attack(session: &Session, commits: &[Commit], expected: &str, skip: &[Check]) {
    attack_from(session, &session.state, commits, expected, skip);
}

pub(crate) fn reject(session: &Session, commits: &[Commit], expected: &str) {
    let own = session.viewer.own();
    assert_eq!(err_name(session.verify(commits)), expected, "real verifier");
    let dstate = DState::from_real(&session.state);
    assert_eq!(
        err_name(Verifier::full().batch(&dstate, commits, &own, &session.pins)),
        expected,
        "reference parity"
    );
}

#[test]
fn reference_verifier_agrees_with_the_real_one_on_an_honest_lifecycle() {
    use crate::harness::{Chain, EDITOR, OWNER, VIEWER};
    use hasp_proto::{Role, VaultKind};

    let mut session = Session::owner();
    let own = session.viewer.own();
    let mut chain = session.chain.fork();
    let mut commits = vec![
        chain.put(OWNER, 1, b"one"),
        chain.put(EDITOR, 2, b"two"),
        chain.put(OWNER, 1, b"one again"),
        chain.delete(EDITOR, 2),
        chain.remove_member(VIEWER),
        chain.put(EDITOR, 3, b"three"),
    ];
    let real = session.verify(&commits).unwrap();
    let double = Verifier::full()
        .batch(
            &DState::from_real(&session.state),
            &commits,
            &own,
            &session.pins,
        )
        .unwrap();
    assert_eq!(DState::from_real(&real).hash, double.hash);
    assert_eq!(DState::from_real(&real).leaves.len(), double.leaves.len());
    session.chain = chain;
    session.advance(&commits);
    commits.clear();
    let mut genesis_chain = Chain::new(VaultKind::Shared, OWNER);
    let genesis = genesis_chain.genesis();
    let added = genesis_chain.add_member(EDITOR, Role::Editor);
    let first = Verifier::full()
        .genesis(&genesis, &own, &session.pins)
        .unwrap();
    let both = Verifier::full()
        .batch(&first, &[added], &own, &session.pins)
        .unwrap();
    assert_eq!(both.seq, 2);
}
