use hasp_crypto::Signature;

use crate::testkit::{CloneKey, Person, Vault};
use crate::{
    AccountId, AccountRecord, AccountStatus, Dissolve, Epoch, Hash32, InviteCode, InviteId,
    KdfWire, LeaveRequest, Member, Pin, PinCheck, PinLevel, PinState, ProtoError, Role, Roster,
    Rver, Seq, SigLabel, Signed, Uint53, VaultId, VaultKind, VaultState, VerifiedRoster, Wire,
    fingerprint, open_share, pin_check, verify_account_record, verify_batch, verify_dissolve,
    verify_genesis, verify_leave, verify_roster, verify_share,
};

fn account(p: &Person, seq: u64, prev: Option<Hash32>, kdf: KdfWire) -> AccountRecord {
    AccountRecord {
        account_id: p.account,
        seq: Seq::new(seq).unwrap(),
        prev,
        ik_pk: p.ik_pk,
        kem_pk: p.kem_pk.clone(),
        kdf,
        status: AccountStatus::Active,
        rc_gen: Uint53::ZERO,
        min_v: Uint53::new(1).unwrap(),
        created: Uint53::new(1_700_000_000).unwrap(),
    }
}

const FLOOR: KdfWire = KdfWire {
    m: 65_536,
    t: 3,
    p: 4,
};

fn sign_account(p: &Person, record: &AccountRecord) -> Signed<AccountRecord> {
    Signed::sign(SigLabel::Account, record, &p.signing).unwrap()
}

#[test]
fn account_record_first_version_verifies() {
    let p = Person::new(1);
    let rec = sign_account(&p, &account(&p, 1, None, FLOOR));
    assert_eq!(
        verify_account_record(&rec, None, &PinState::new())
            .unwrap()
            .seq
            .get(),
        1
    );
}

#[test]
fn kdf_bounds_are_checked_before_the_signature() {
    let owner = Person::new(1);
    let boundaries = [
        (65_536, 3, 4, true),
        (524_288, 12, 4, true),
        (65_535, 3, 4, false),
        (8_192, 1, 4, false),
        (524_289, 3, 4, false),
        (65_536, 2, 4, false),
        (65_536, 13, 4, false),
        (65_536, 3, 1, false),
        (65_536, 3, 5, false),
    ];
    for (m, t, p, accepted) in boundaries {
        let kdf = KdfWire { m, t, p };
        let mut rec = sign_account(&owner, &account(&owner, 1, None, kdf));
        let verdict = verify_account_record(&rec, None, &PinState::new());
        assert_eq!(verdict.is_ok(), accepted, "{kdf:?}");
        if !accepted {
            assert!(matches!(verdict, Err(ProtoError::KdfParams)));
            rec.sig = Signature::from_bytes([0; 64]);
            assert!(matches!(
                verify_account_record(&rec, None, &PinState::new()),
                Err(ProtoError::KdfParams)
            ));
        }
    }
}

#[test]
fn account_record_signed_by_another_key_is_rejected() {
    let (p, q) = (Person::new(1), Person::new(2));
    let rec = sign_account(&q, &account(&p, 1, None, FLOOR));
    assert!(matches!(
        verify_account_record(&rec, None, &PinState::new()),
        Err(ProtoError::Sig)
    ));
}

#[test]
fn account_record_prev_must_match_seq() {
    let p = Person::new(1);
    let first_with_prev = sign_account(
        &p,
        &account(&p, 1, Some(Hash32::from_bytes([1; 32])), FLOOR),
    );
    let later_without = sign_account(&p, &account(&p, 2, None, FLOOR));
    for rec in [first_with_prev, later_without] {
        assert!(matches!(
            verify_account_record(&rec, None, &PinState::new()),
            Err(ProtoError::Format)
        ));
    }
}

#[test]
fn account_chain_detects_rollback_and_fork() {
    let p = Person::new(1);
    let first = sign_account(&p, &account(&p, 1, None, FLOOR));
    let seen = crate::AccountSeen {
        seq: Seq::new(1).unwrap(),
        hash: first.hash(),
    };
    let second = sign_account(&p, &account(&p, 2, Some(first.hash()), FLOOR));
    assert!(verify_account_record(&second, Some(&seen), &PinState::new()).is_ok());
    assert!(verify_account_record(&first, Some(&seen), &PinState::new()).is_ok());
    let wrong_prev = sign_account(
        &p,
        &account(&p, 2, Some(Hash32::from_bytes([3; 32])), FLOOR),
    );
    assert!(matches!(
        verify_account_record(&wrong_prev, Some(&seen), &PinState::new()),
        Err(ProtoError::Fork)
    ));
    let sibling = sign_account(
        &p,
        &AccountRecord {
            rc_gen: Uint53::new(1).unwrap(),
            ..account(&p, 1, None, FLOOR)
        },
    );
    assert!(matches!(
        verify_account_record(&sibling, Some(&seen), &PinState::new()),
        Err(ProtoError::Fork)
    ));
    let ahead = crate::AccountSeen {
        seq: Seq::new(2).unwrap(),
        hash: second.hash(),
    };
    assert!(matches!(
        verify_account_record(&first, Some(&ahead), &PinState::new()),
        Err(ProtoError::Rollback)
    ));
}

#[test]
fn account_record_checks_the_pin() {
    let (p, other) = (Person::new(1), Person::new(2));
    let rec = sign_account(&p, &account(&p, 1, None, FLOOR));
    let mut pins = PinState::new();
    pins.insert(p.account, Pin::new(p.ik_pk, &p.kem_pk, PinLevel::Verified));
    assert!(verify_account_record(&rec, None, &pins).is_ok());
    pins.insert(
        p.account,
        Pin::new(other.ik_pk, &other.kem_pk, PinLevel::Verified),
    );
    assert!(matches!(
        verify_account_record(&rec, None, &pins),
        Err(ProtoError::Pin)
    ));
}

#[test]
fn rotation_field_must_be_null() {
    let p = Person::new(1);
    let mut bytes = account(&p, 1, None, FLOOR).to_cbor().unwrap();
    let at = bytes.windows(2).rposition(|w| w == [0x0b, 0xf6]).unwrap();
    bytes[at + 1] = 0x00;
    assert!(matches!(
        AccountRecord::from_cbor(&bytes),
        Err(ProtoError::Format)
    ));
}

#[test]
fn pin_check_distinguishes_new_ok_and_changed_keys() {
    let (p, q) = (Person::new(1), Person::new(2));
    let mut pins = PinState::new();
    assert_eq!(
        pin_check(&pins, &p.account, &p.ik_pk, &p.kem_pk),
        PinCheck::New
    );
    pins.insert(p.account, Pin::new(p.ik_pk, &p.kem_pk, PinLevel::Tofu));
    assert_eq!(
        pin_check(&pins, &p.account, &p.ik_pk, &p.kem_pk),
        PinCheck::Ok
    );
    assert_eq!(
        pin_check(&pins, &p.account, &q.ik_pk, &p.kem_pk),
        PinCheck::KeyChanged
    );
    assert_eq!(
        pin_check(&pins, &p.account, &p.ik_pk, &q.kem_pk),
        PinCheck::KeyChanged
    );
}

fn genesis_roster(vault: &mut Vault) -> (Signed<Roster>, Roster) {
    vault.rver = 1;
    let vk = vault.vk().clone_key();
    let roster = vault.roster_body(1, 0, &vk);
    (vault.sign_roster(&roster), roster)
}

fn mutated_genesis(edit: impl FnOnce(&mut Roster)) -> Result<VerifiedRoster, ProtoError> {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.others.insert(2, (Role::Editor, 1));
    let (_, mut roster) = genesis_roster(&mut vault);
    edit(&mut roster);
    let signed = vault.sign_roster(&roster);
    verify_roster(&signed, None, &Person::new(2).own(), &PinState::new())
}

#[test]
fn roster_genesis_verifies_and_hashes_the_body() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.others.insert(2, (Role::Editor, 1));
    let (signed, _) = genesis_roster(&mut vault);
    let verified = verify_roster(&signed, None, &Person::new(2).own(), &PinState::new()).unwrap();
    assert_eq!(*verified.hash(), signed.hash());
}

#[test]
fn roster_rules_reject_bad_membership_shapes() {
    let owner_twice = mutated_genesis(|r| r.members[1].role = Role::Owner);
    let no_owner = mutated_genesis(|r| r.members[0].role = Role::Editor);
    let private_with_two = mutated_genesis(|r| r.kind = VaultKind::Private);
    let empty = mutated_genesis(|r| r.members.clear());
    let added_in_future = mutated_genesis(|r| r.members[1].added_rver = Rver::new(2).unwrap());
    let not_genesis = mutated_genesis(|r| r.rver = Rver::new(2).unwrap());
    let has_prev = mutated_genesis(|r| r.prev = Some(Hash32::from_bytes([1; 32])));
    for result in [
        owner_twice,
        no_owner,
        private_with_two,
        empty,
        added_in_future,
        not_genesis,
        has_prev,
    ] {
        assert!(matches!(result, Err(ProtoError::Roster)));
    }
}

#[test]
fn own_entry_with_substituted_keys_is_a_roster_error() {
    let imposter = Person::new(7);
    let result = mutated_genesis(|r| {
        r.members[1].ik_pk = imposter.ik_pk;
        r.members[1].kem_pk = imposter.kem_pk.clone();
    });
    assert!(matches!(result, Err(ProtoError::Roster)));
}

#[test]
fn roster_member_with_a_changed_pin_is_rejected() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.others.insert(2, (Role::Editor, 1));
    let (signed, _) = genesis_roster(&mut vault);
    let mut pins = PinState::new();
    let p1 = Person::new(1);
    let imposter = Person::new(7);
    pins.insert(
        p1.account,
        Pin::new(imposter.ik_pk, &imposter.kem_pk, PinLevel::Verified),
    );
    assert!(matches!(
        verify_roster(&signed, None, &Person::new(2).own(), &pins),
        Err(ProtoError::Pin)
    ));
}

#[test]
fn roster_signed_by_a_non_owner_is_a_signature_error() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.others.insert(2, (Role::Editor, 1));
    let (_, roster) = genesis_roster(&mut vault);
    let forged = Signed::sign(SigLabel::Roster, &roster, &Person::new(2).signing).unwrap();
    assert!(matches!(
        verify_roster(&forged, None, &Person::new(2).own(), &PinState::new()),
        Err(ProtoError::Sig)
    ));
}

#[test]
fn roster_successor_rules_cover_version_chain_kind_and_owner() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let pins = PinState::new();
    let genesis = vault.genesis();
    let state = verify_genesis(&genesis, &owner.own(), &pins).unwrap();
    let prior = state.verified_roster();
    let vk = vault.vk().clone_key();
    let base = vault.roster_body(2, 0, &vk);
    let sign = |r: &Roster| vault.sign_roster(r);
    let ok = sign(&Roster {
        prev: Some(*prior.hash()),
        ..base.clone()
    });
    assert!(verify_roster(&ok, Some(&prior), &owner.own(), &pins).is_ok());
    let skip = sign(&Roster {
        rver: Rver::new(3).unwrap(),
        prev: Some(*prior.hash()),
        ..base.clone()
    });
    let bad_prev = sign(&Roster {
        prev: Some(Hash32::from_bytes([1; 32])),
        ..base.clone()
    });
    let kind = sign(&Roster {
        kind: VaultKind::Private,
        prev: Some(*prior.hash()),
        ..base.clone()
    });
    let vault_swap = sign(&Roster {
        vault_id: VaultId::from_bytes([1; 16]),
        prev: Some(*prior.hash()),
        ..base.clone()
    });
    for rec in [skip, bad_prev, kind, vault_swap] {
        assert!(matches!(
            verify_roster(&rec, Some(&prior), &owner.own(), &pins),
            Err(ProtoError::Roster)
        ));
    }
    let same_version = sign(&Roster {
        rver: Rver::new(1).unwrap(),
        prev: None,
        vk_commit: Hash32::from_bytes([2; 32]),
        ..base.clone()
    });
    assert!(matches!(
        verify_roster(&same_version, Some(&prior), &owner.own(), &pins),
        Err(ProtoError::Fork)
    ));
    let replay = Signed::<Roster>::from_parts(
        genesis.roster.clone().unwrap().body,
        genesis.roster.clone().unwrap().signer,
        genesis.roster.clone().unwrap().sig,
    );
    assert!(matches!(
        verify_roster(&replay, Some(&prior), &owner.own(), &pins),
        Err(ProtoError::Rollback)
    ));
    let lower_epoch_after_bump = {
        let bumped_prior = VerifiedRoster::trusted(
            Roster {
                epoch: Epoch::new(2).unwrap(),
                ..prior.roster().clone()
            },
            *prior.hash(),
        );
        let rec = sign(&Roster {
            prev: Some(*prior.hash()),
            ..base
        });
        verify_roster(&rec, Some(&bumped_prior), &owner.own(), &pins)
    };
    assert!(matches!(lower_epoch_after_bump, Err(ProtoError::Epoch)));
}

#[test]
fn roster_owner_change_is_rejected_even_when_the_old_owner_signs() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let pins = PinState::new();
    let genesis = vault.genesis();
    let joined = vault.add_member(2, Role::Editor);
    let state = verify_genesis(&genesis, &owner.own(), &pins).unwrap();
    let state = verify_batch(&state, &[joined], &owner.own(), &pins).unwrap();
    let mut swapped = state.roster.clone();
    swapped.rver = Rver::new(3).unwrap();
    swapped.prev = Some(state.roster_hash);
    swapped.members[0].role = Role::Editor;
    swapped.members[1].role = Role::Owner;
    let rec = Signed::sign(SigLabel::Roster, &swapped, &owner.signing).unwrap();
    assert!(matches!(
        verify_roster(&rec, Some(&state.verified_roster()), &owner.own(), &pins),
        Err(ProtoError::Roster)
    ));
}

#[test]
fn roster_members_must_be_sorted_and_unique_on_the_wire() {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    vault.others.insert(2, (Role::Editor, 1));
    let (_, roster) = genesis_roster(&mut vault);
    let mut reversed = roster.clone();
    reversed.members.reverse();
    assert!(matches!(
        Roster::from_cbor(&reversed.to_cbor().unwrap()),
        Err(ProtoError::Format)
    ));
    let mut duplicated = roster;
    duplicated.members[1] = duplicated.members[0].clone();
    assert!(matches!(
        Roster::from_cbor(&duplicated.to_cbor().unwrap()),
        Err(ProtoError::Format)
    ));
}

mod membership;
