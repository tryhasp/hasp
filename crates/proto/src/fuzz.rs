use crate::testkit::{Person, Vault};
use crate::{
    AccountRecord, Commit, Dissolve, InviteCode, ItemOp, ItemWire, Leaf, LeaveRequest, Manifest,
    PinState, Role, Roster, Share, SigLabel, Signed, VaultKind, VaultState, Wire,
    parse_fingerprint, parse_secret_key, verify_batch, verify_genesis,
};

fn accepts_only_canonical<T: Wire>(bytes: &[u8]) {
    if let Ok(value) = T::from_cbor(bytes) {
        assert_eq!(value.to_cbor().unwrap(), bytes);
    }
}

fn decode_everything(bytes: &[u8]) {
    accepts_only_canonical::<Roster>(bytes);
    accepts_only_canonical::<Manifest>(bytes);
    accepts_only_canonical::<ItemWire>(bytes);
    accepts_only_canonical::<Share>(bytes);
    accepts_only_canonical::<AccountRecord>(bytes);
    accepts_only_canonical::<Dissolve>(bytes);
    accepts_only_canonical::<LeaveRequest>(bytes);
    accepts_only_canonical::<Leaf>(bytes);
    accepts_only_canonical::<InviteCode>(bytes);
    accepts_only_canonical::<Signed<Manifest>>(bytes);
    accepts_only_canonical::<Vec<crate::Hash32>>(bytes);
}

#[test]
fn strict_decoder_survives_arbitrary_bytes() {
    bolero::check!()
        .with_iterations(3000)
        .for_each(|bytes: &[u8]| decode_everything(bytes));
}

#[test]
fn text_parsers_survive_arbitrary_strings() {
    bolero::check!()
        .with_iterations(3000)
        .for_each(|bytes: &[u8]| {
            if let Ok(text) = core::str::from_utf8(bytes) {
                parse_secret_key(text).ok();
                parse_fingerprint(text).ok();
                InviteCode::parse(text).ok();
            }
        });
}

struct Fixture {
    state: VaultState,
    commits: Vec<Commit>,
    owner: Person,
    editor: Person,
}

fn fixture() -> Fixture {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let editor = Person::new(2);
    let genesis = vault.genesis();
    let commits = vec![
        vault.put(1, 7, b"one"),
        vault.add_member(2, Role::Editor),
        vault.put(2, 8, b"two"),
        vault.remove_member(2),
        vault.put(1, 9, b"three"),
    ];
    let state = verify_genesis(&genesis, &owner.own(), &PinState::new()).unwrap();
    Fixture {
        state,
        commits,
        owner,
        editor,
    }
}

fn mutate(bytes: &mut [u8], position: u16, xor: u8) {
    let len = bytes.len().max(1);
    let index = usize::from(position).checked_rem(len).unwrap_or(0);
    if let Some(byte) = bytes.get_mut(index) {
        *byte ^= xor;
    }
}

fn author_key<'a>(fixture: &'a Fixture, commit: &Commit) -> &'a Person {
    let author = commit.manifest.unverified().map(|m| m.author);
    if author.ok() == Some(fixture.editor.account) {
        &fixture.editor
    } else {
        &fixture.owner
    }
}

#[test]
fn verifier_survives_resigned_mutations_of_a_valid_chain() {
    let fixture = fixture();
    let honest = verify_batch(
        &fixture.state,
        &fixture.commits,
        &fixture.owner.own(),
        &PinState::new(),
    )
    .unwrap();
    bolero::check!()
        .with_iterations(400)
        .with_type::<Vec<(u8, u8, u16, u8)>>()
        .for_each(|edits| {
            let mut commits = fixture.commits.clone();
            let mut changed = false;
            for (which, part, position, xor) in edits.iter().take(4) {
                let index = usize::from(*which).checked_rem(commits.len()).unwrap_or(0);
                let Some(commit) = commits.get_mut(index) else {
                    continue;
                };
                changed |= *xor != 0;
                match part.checked_rem(3).unwrap_or(0) {
                    0 => {
                        let signer = author_key(&fixture, commit);
                        let mut body = commit.manifest.body.clone();
                        mutate(&mut body, *position, *xor);
                        let sig = signer
                            .signing
                            .sign(&[SigLabel::Manifest.name().as_bytes(), &[0], &body].concat());
                        commit.manifest = Signed::from_parts(body, signer.ik_pk, sig);
                    }
                    1 => {
                        if let Some(roster) = commit.roster.as_mut() {
                            let mut body = roster.body.clone();
                            mutate(&mut body, *position, *xor);
                            let sig = fixture
                                .owner
                                .signing
                                .sign(&[SigLabel::Roster.name().as_bytes(), &[0], &body].concat());
                            *roster = Signed::from_parts(body, fixture.owner.ik_pk, sig);
                        }
                    }
                    _ => {
                        if let Some(op) = commit.ops.first_mut()
                            && let Ok(mut bytes) = op.wire().to_cbor()
                        {
                            mutate(&mut bytes, *position, *xor);
                            if let Ok(replacement) = ItemOp::from_wire_bytes(&bytes) {
                                *op = replacement;
                            }
                        }
                    }
                }
            }
            let outcome = verify_batch(
                &fixture.state,
                &commits,
                &fixture.owner.own(),
                &PinState::new(),
            );
            if !changed {
                let state = outcome.unwrap();
                assert_eq!(state.hash, honest.hash);
                assert_eq!(state.leafset, honest.leafset);
            }
        });
}
