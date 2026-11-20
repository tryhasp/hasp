use hasp_crypto::{SigningKey, VerifyingKey};
use hasp_proto::{
    AccountId, AccountRecord, AccountStatus, Commit, Dissolve, ItemWire, KdfWire, LeaveRequest,
    Manifest, PinState, Roster, Seq, Share, SigLabel, Signed, Uint53, VaultState, Wire, open_item,
    verify_account_record, verify_batch, verify_dissolve, verify_leave,
};

use crate::harness::{EDITOR, OWNER, Person, Session, err_name};

fn resign_raw<T: Wire>(label: SigLabel, body: Vec<u8>, key: &SigningKey) -> Signed<T> {
    let mut message = label.name().as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(&body);
    Signed::from_parts(body, key.verifying_key(), key.sign(&message))
}

fn tolerant_version<T: Wire>(body: &[u8]) -> Result<T, hasp_proto::ProtoError> {
    let mut patched = body.to_vec();
    patched[2] = 1;
    T::from_cbor(&patched)
}

fn manifest_commit(session: &Session, edit: impl FnOnce(&mut Vec<u8>)) -> (Commit, Vec<u8>) {
    let mut chain = session.chain.fork();
    let genuine = chain.put(OWNER, 1, b"payload");
    let owner = Person::new(OWNER);
    let mut body = genuine.manifest.body.clone();
    edit(&mut body);
    let forged = resign_raw::<Manifest>(SigLabel::Manifest, body.clone(), &owner.signing);
    (
        Commit {
            manifest: forged,
            ..genuine
        },
        body,
    )
}

#[test]
fn e10_validly_signed_manifest_with_another_format_version_is_rejected() {
    let session = Session::owner();
    for version in [0u8, 2, 3, 23] {
        let (commit, body) = manifest_commit(&session, |body| body[2] = version);
        assert_eq!(
            err_name(session.verify(&[commit])),
            "Version",
            "v={version}"
        );
        assert!(
            tolerant_version::<Manifest>(&body).is_ok(),
            "tolerant decoder v={version}"
        );
    }
}

#[test]
fn e10_wrong_record_type_is_a_format_error() {
    let session = Session::owner();
    let (commit, _) = manifest_commit(&session, |body| body[4] = 3);
    assert_eq!(err_name(session.verify(&[commit])), "Format");
}

#[test]
fn e10_extra_algorithm_field_is_rejected() {
    let session = Session::owner();
    let (commit, body) = manifest_commit(&session, |body| {
        body[0] = 0xac;
        body.extend_from_slice(&[0x0d, 0x01]);
    });
    assert_eq!(err_name(session.verify(&[commit])), "Format");
    let mut stripped = body.clone();
    stripped[0] = 0xab;
    stripped.truncate(stripped.len() - 2);
    assert!(Manifest::from_cbor(&stripped).is_ok());
}

#[test]
fn e10_cbc_style_blob_in_place_of_a_sealed_value_is_rejected() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let commit = chain.put(OWNER, 1, b"payload");
    let wire = commit.ops[0].wire().to_cbor().unwrap();
    let marker = [0x58, 0x18];
    let at = wire.windows(2).position(|w| w == marker).unwrap();
    let mut cbc = wire[..at].to_vec();
    cbc.push(0x50);
    cbc.extend_from_slice(&wire[at + 2..at + 2 + 16]);
    cbc.extend_from_slice(&wire[at + 2 + 24..]);
    assert_eq!(err_name(ItemWire::from_cbor(&cbc)), "Format");
}

#[test]
fn e10_unknown_map_key_and_negative_or_float_values_are_rejected_in_every_record() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let commit = chain.put(OWNER, 1, b"payload");
    let body = commit.manifest.body.clone();
    for (header, extra) in [
        (0xac_u8, vec![0x0d, 0x20]),
        (0xac, vec![0x0d, 0xf9, 0x3c, 0x00]),
        (0xac, vec![0x0d, 0xc0, 0x01]),
        (0xac, vec![0x0d, 0x9f, 0xff]),
    ] {
        let mut changed = body.clone();
        changed[0] = header;
        changed.extend_from_slice(&extra);
        assert_eq!(err_name(Manifest::from_cbor(&changed)), "Format");
    }
}

fn flip_all<T>(bytes: &[u8], mut accepts: impl FnMut(&[u8]) -> Option<T>) -> usize {
    (0..bytes.len())
        .filter(|at| {
            let mut mutated = bytes.to_vec();
            mutated[*at] ^= 0xff;
            accepts(&mutated).is_some()
        })
        .count()
}

fn signed_accepts<T: Wire>(
    label: SigLabel,
    key: &VerifyingKey,
) -> impl FnMut(&[u8]) -> Option<T> + '_ {
    move |bytes| {
        let rec = Signed::<T>::from_cbor(bytes).ok()?;
        rec.verify(label, key).ok()
    }
}

fn decode_only<T: Wire>(bytes: &[u8]) -> Option<T> {
    Signed::<T>::from_cbor(bytes).ok()?.unverified().ok()
}

#[test]
fn e11_every_byte_flip_of_a_signed_roster_or_manifest_fails_closed() {
    let session = Session::owner();
    let owner = Person::new(OWNER);
    let roster = Signed::<Roster>::sign(
        SigLabel::Roster,
        &session.state.roster,
        &session.chain.person(OWNER).signing,
    )
    .unwrap();
    let wire = roster.to_cbor().unwrap();
    assert_eq!(
        flip_all(
            &wire,
            signed_accepts::<Roster>(SigLabel::Roster, &owner.ik_pk)
        ),
        0
    );
    assert!(flip_all(&wire, decode_only::<Roster>) > 0);
    let mut chain = session.chain.fork();
    let commit = chain.put(OWNER, 1, b"x");
    let manifest = commit.manifest.to_cbor().unwrap();
    assert_eq!(
        flip_all(
            &manifest,
            signed_accepts::<Manifest>(SigLabel::Manifest, &owner.ik_pk)
        ),
        0
    );
    assert!(flip_all(&manifest, decode_only::<Manifest>) > 0);
}

#[test]
fn e11_every_byte_flip_of_a_signed_share_fails_closed() {
    let mut session = Session::bare(OWNER);
    let add = session.chain.add_member(EDITOR, hasp_proto::Role::Editor);
    let owner = Person::new(OWNER);
    let wire = add.shares[0].to_cbor().unwrap();
    assert_eq!(
        flip_all(
            &wire,
            signed_accepts::<Share>(SigLabel::Share, &owner.ik_pk)
        ),
        0
    );
    assert!(flip_all(&wire, decode_only::<Share>) > 0);
}

#[test]
fn e11_every_byte_flip_of_an_item_wire_fails_closed() {
    let mut session = Session::owner();
    let commit = session.chain.put(OWNER, 1, b"overview");
    session.advance(std::slice::from_ref(&commit));
    let wire = commit.ops[0].wire().clone();
    let bytes = wire.to_cbor().unwrap();
    let vk = crate::harness::clone_key(session.chain.vk());
    let state: &VaultState = &session.state;
    let accepted = flip_all(&bytes, |mutated| {
        let item = ItemWire::from_cbor(mutated).ok()?;
        open_item(&item, mutated, state, &vk).ok()
    });
    assert_eq!(accepted, 0);
    assert!(
        flip_all(&bytes, |mutated| ItemWire::from_cbor(mutated).ok()) > 0,
        "byte flips in ciphertext still decode and fail only at the leaf hash and AEAD"
    );
}

#[test]
fn e11_every_byte_flip_of_account_dissolve_and_leave_records_fails_closed() {
    let session = Session::owner();
    let owner = Person::new(OWNER);
    let account = Signed::sign(
        SigLabel::Account,
        &AccountRecord {
            account_id: AccountId::from_bytes([OWNER; 16]),
            seq: Seq::new(1).unwrap(),
            prev: None,
            ik_pk: owner.ik_pk,
            kem_pk: owner.kem_pk.clone(),
            kdf: KdfWire {
                m: 65_536,
                t: 3,
                p: 4,
            },
            status: AccountStatus::Active,
            rc_gen: Uint53::ZERO,
            min_v: Uint53::new(1).unwrap(),
            created: Uint53::new(7).unwrap(),
        },
        &owner.signing,
    )
    .unwrap();
    let wire = account.to_cbor().unwrap();
    assert_eq!(
        flip_all(&wire, |bytes| {
            let rec = Signed::<AccountRecord>::from_cbor(bytes).ok()?;
            verify_account_record(&rec, None, &PinState::new()).ok()
        }),
        0
    );
    let dissolve = Signed::sign(
        SigLabel::Dissolve,
        &Dissolve {
            vault_id: session.state.roster.vault_id,
            rver: session.state.rver,
            epoch: session.state.epoch,
            seq: session.state.seq,
            head: session.state.hash,
        },
        &owner.signing,
    )
    .unwrap();
    let wire = dissolve.to_cbor().unwrap();
    assert_eq!(
        flip_all(&wire, |bytes| {
            let rec = Signed::<Dissolve>::from_cbor(bytes).ok()?;
            verify_dissolve(&rec, &session.state).ok()
        }),
        0
    );
    let editor = Person::new(EDITOR);
    let leave = Signed::sign(
        SigLabel::Leave,
        &LeaveRequest {
            vault_id: session.state.roster.vault_id,
            account_id: AccountId::from_bytes([EDITOR; 16]),
            rver: session.state.rver,
            epoch: session.state.epoch,
        },
        &editor.signing,
    )
    .unwrap();
    let wire = leave.to_cbor().unwrap();
    assert_eq!(
        flip_all(&wire, |bytes| {
            let rec = Signed::<LeaveRequest>::from_cbor(bytes).ok()?;
            verify_leave(&rec, &session.state).ok()
        }),
        0
    );
}

#[test]
fn e11_every_byte_flip_of_a_whole_commit_is_rejected_by_the_batch_verifier() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let commit = chain.put(EDITOR, 1, b"payload");
    let manifest_wire = commit.manifest.to_cbor().unwrap();
    let state = &session.state;
    let own = session.viewer.own();
    let accepted = flip_all(&manifest_wire, |bytes| {
        let manifest = Signed::<Manifest>::from_cbor(bytes).ok()?;
        let flipped = Commit {
            manifest,
            ..commit.clone()
        };
        verify_batch(state, &[flipped], &own, &PinState::new()).ok()
    });
    assert_eq!(accepted, 0);
}
