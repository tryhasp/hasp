use hasp_crypto::{Argon2idParams, SigningKey};
use hasp_proto::{
    AccountId, AccountRecord, AccountSeen, AccountStatus, KdfWire, Pin, PinLevel, PinState, Seq,
    SigLabel, Signed, Uint53, verify_account_record,
};

use crate::double::{Check, Verifier};
use crate::harness::{ATTACKER, OWNER, Person, err_name};

fn record(
    person: &Person,
    seq: u64,
    prev: Option<hasp_proto::Hash32>,
    kdf: KdfWire,
) -> AccountRecord {
    AccountRecord {
        account_id: AccountId::from_bytes([OWNER; 16]),
        seq: Seq::new(seq).unwrap(),
        prev,
        ik_pk: person.ik_pk,
        kem_pk: person.kem_pk.clone(),
        kdf,
        status: AccountStatus::Active,
        rc_gen: Uint53::ZERO,
        min_v: Uint53::new(1).unwrap(),
        created: Uint53::new(1_700_000_000).unwrap(),
    }
}

const GOOD: KdfWire = KdfWire {
    m: 65_536,
    t: 3,
    p: 4,
};

fn sign(record: &AccountRecord, key: &SigningKey) -> Signed<AccountRecord> {
    Signed::sign(SigLabel::Account, record, key).unwrap()
}

fn judge(
    rec: &Signed<AccountRecord>,
    seen: Option<&AccountSeen>,
    pins: &PinState,
    expected: &str,
    skip: &[Check],
) {
    assert_eq!(
        err_name(verify_account_record(rec, seen, pins)),
        expected,
        "real verifier"
    );
    assert_eq!(
        err_name(Verifier::full().account(rec, seen, pins)),
        expected,
        "reference parity"
    );
    assert_eq!(
        err_name(Verifier::without(skip).account(rec, seen, pins)),
        "Ok",
        "vulnerable double {skip:?}"
    );
}

#[test]
fn honest_account_chain_verifies_in_both_verifiers() {
    let owner = Person::new(OWNER);
    let first = sign(&record(&owner, 1, None, GOOD), &owner.signing);
    let second = sign(&record(&owner, 2, Some(first.hash()), GOOD), &owner.signing);
    let seen = AccountSeen {
        seq: Seq::new(1).unwrap(),
        hash: first.hash(),
    };
    let pins = PinState::new();
    assert!(verify_account_record(&second, Some(&seen), &pins).is_ok());
    assert!(
        Verifier::full()
            .account(&second, Some(&seen), &pins)
            .is_ok()
    );
}

#[test]
fn e9_kdf_parameters_below_the_floor_are_rejected_before_any_argon2() {
    let owner = Person::new(OWNER);
    for weak in [
        KdfWire {
            m: 8_192,
            t: 1,
            p: 4,
        },
        KdfWire {
            m: 65_535,
            t: 3,
            p: 4,
        },
        KdfWire {
            m: 65_536,
            t: 2,
            p: 4,
        },
        KdfWire {
            m: 65_536,
            t: 3,
            p: 1,
        },
    ] {
        let signed = sign(&record(&owner, 1, None, weak), &owner.signing);
        judge(
            &signed,
            None,
            &PinState::new(),
            "KdfParams",
            &[Check::KdfFloor],
        );
    }
}

#[test]
fn e9_kdf_parameters_above_the_ceiling_are_rejected_without_allocating() {
    let owner = Person::new(OWNER);
    for heavy in [
        KdfWire {
            m: 524_289,
            t: 3,
            p: 4,
        },
        KdfWire {
            m: 65_536,
            t: 13,
            p: 4,
        },
        KdfWire {
            m: u32::MAX,
            t: 3,
            p: 4,
        },
    ] {
        let signed = sign(&record(&owner, 1, None, heavy), &owner.signing);
        judge(
            &signed,
            None,
            &PinState::new(),
            "KdfParams",
            &[Check::KdfFloor],
        );
    }
}

#[test]
fn e9_kdf_parameters_are_rejected_even_when_the_signature_is_garbage() {
    let owner = Person::new(OWNER);
    let attacker = Person::new(ATTACKER);
    let weak = sign(
        &record(
            &owner,
            1,
            None,
            KdfWire {
                m: 8_192,
                t: 1,
                p: 4,
            },
        ),
        &attacker.signing,
    );
    assert_eq!(
        err_name(verify_account_record(&weak, None, &PinState::new())),
        "KdfParams"
    );
}

#[test]
fn e9_prelogin_hints_below_the_floor_never_reach_argon2() {
    for (m, t, p) in [
        (8_192, 1, 4),
        (65_536, 1, 4),
        (1_048_576, 3, 4),
        (65_536, 3, 8),
    ] {
        assert!(Argon2idParams::account(m, t, p).is_err());
    }
    assert!(Argon2idParams::account(65_536, 3, 4).is_ok());
}

#[test]
fn a3_account_record_with_substituted_keys_is_a_pin_error() {
    let owner = Person::new(OWNER);
    let attacker = Person::new(ATTACKER);
    let mut pins = PinState::new();
    pins.insert(
        AccountId::from_bytes([OWNER; 16]),
        Pin::new(owner.ik_pk, &owner.kem_pk, PinLevel::Verified),
    );
    let forged = sign(&record(&attacker, 1, None, GOOD), &attacker.signing);
    judge(&forged, None, &pins, "Pin", &[Check::AccountPin]);
}

#[test]
fn a3_first_contact_accepts_any_self_signed_record_as_tofu() {
    let attacker = Person::new(ATTACKER);
    let forged = sign(&record(&attacker, 1, None, GOOD), &attacker.signing);
    assert!(verify_account_record(&forged, None, &PinState::new()).is_ok());
}

#[test]
fn a3_record_not_signed_by_its_own_identity_key_is_rejected() {
    let owner = Person::new(OWNER);
    let attacker = Person::new(ATTACKER);
    let forged = sign(&record(&owner, 1, None, GOOD), &attacker.signing);
    judge(
        &forged,
        None,
        &PinState::new(),
        "Sig",
        &[Check::AccountSignature],
    );
}

#[test]
fn a3_edited_status_or_recovery_generation_invalidates_the_signature() {
    let owner = Person::new(OWNER);
    let mut body = record(&owner, 1, None, GOOD);
    let honest = sign(&body, &owner.signing);
    body.status = AccountStatus::Deleted;
    body.rc_gen = Uint53::new(9).unwrap();
    let edited = Signed::<AccountRecord>::from_parts(
        hasp_proto::Wire::to_cbor(&body).unwrap(),
        honest.signer,
        honest.sig,
    );
    judge(
        &edited,
        None,
        &PinState::new(),
        "Sig",
        &[Check::AccountSignature],
    );
}

#[test]
fn a3_older_account_record_is_a_rollback_and_a_second_head_is_a_fork() {
    let owner = Person::new(OWNER);
    let first = sign(&record(&owner, 1, None, GOOD), &owner.signing);
    let second = sign(&record(&owner, 2, Some(first.hash()), GOOD), &owner.signing);
    let third = sign(
        &record(&owner, 3, Some(second.hash()), GOOD),
        &owner.signing,
    );
    let seen_third = AccountSeen {
        seq: Seq::new(3).unwrap(),
        hash: third.hash(),
    };
    let pins = PinState::new();
    judge(
        &second,
        Some(&seen_third),
        &pins,
        "Rollback",
        &[Check::AccountChain],
    );
    let mut other = record(&owner, 3, Some(second.hash()), GOOD);
    other.min_v = Uint53::new(2).unwrap();
    let rival = sign(&other, &owner.signing);
    judge(
        &rival,
        Some(&seen_third),
        &pins,
        "Fork",
        &[Check::AccountChain],
    );
    let seen_first = AccountSeen {
        seq: Seq::new(1).unwrap(),
        hash: first.hash(),
    };
    let detached = sign(&record(&owner, 2, Some(third.hash()), GOOD), &owner.signing);
    judge(
        &detached,
        Some(&seen_first),
        &pins,
        "Fork",
        &[Check::AccountChain],
    );
}

#[test]
fn a3_identical_record_refetched_is_accepted_and_a_jump_ahead_is_accepted_after_signature() {
    let owner = Person::new(OWNER);
    let first = sign(&record(&owner, 1, None, GOOD), &owner.signing);
    let seen = AccountSeen {
        seq: Seq::new(1).unwrap(),
        hash: first.hash(),
    };
    let pins = PinState::new();
    assert!(verify_account_record(&first, Some(&seen), &pins).is_ok());
    let jump = sign(
        &record(
            &owner,
            5,
            Some(hasp_proto::Hash32::from_bytes([1; 32])),
            GOOD,
        ),
        &owner.signing,
    );
    assert!(verify_account_record(&jump, Some(&seen), &pins).is_ok());
}
