use super::*;

struct Joined {
    vault: Vault,
    state: VaultState,
    share: Signed<crate::Share>,
    invite: InviteCode,
}

fn joined() -> Joined {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let owner = Person::new(1);
    let pins = PinState::new();
    let genesis = vault.genesis();
    let commit = vault.add_member(2, Role::Editor);
    let share = commit.shares[0].clone();
    let state = verify_genesis(&genesis, &owner.own(), &pins).unwrap();
    let state = verify_batch(&state, &[commit], &owner.own(), &pins).unwrap();
    let invite = InviteCode {
        invite_id: InviteId::from_bytes([5; 16]),
        fp_owner: fingerprint(&owner.ik_pk, &owner.kem_pk),
        origin: "https://hasp.example".to_owned(),
    };
    Joined {
        vault,
        state,
        share,
        invite,
    }
}

#[test]
fn share_verifies_with_an_invite_opens_and_matches_the_vault_key() {
    let j = joined();
    let me = Person::new(2);
    let roster = j.state.verified_roster();
    let verified = verify_share(
        &j.share,
        &me.own(),
        &roster,
        Some(&j.invite),
        &PinState::new(),
    )
    .unwrap();
    let vk = open_share(&verified, &me.kem, &roster).unwrap();
    assert_eq!(vk.expose(), j.vault.vk().expose());
}

#[test]
fn share_with_a_pinned_owner_needs_no_invite_and_without_either_it_is_refused() {
    let j = joined();
    let (me, owner) = (Person::new(2), Person::new(1));
    let roster = j.state.verified_roster();
    let mut pins = PinState::new();
    assert!(matches!(
        verify_share(&j.share, &me.own(), &roster, None, &pins),
        Err(ProtoError::Invite)
    ));
    pins.insert(
        owner.account,
        Pin::new(owner.ik_pk, &owner.kem_pk, PinLevel::Verified),
    );
    assert!(verify_share(&j.share, &me.own(), &roster, None, &pins).is_ok());
    let imposter = Person::new(7);
    pins.insert(
        owner.account,
        Pin::new(imposter.ik_pk, &imposter.kem_pk, PinLevel::Verified),
    );
    assert!(matches!(
        verify_share(&j.share, &me.own(), &roster, None, &pins),
        Err(ProtoError::Pin)
    ));
}

#[test]
fn share_with_the_wrong_invite_fingerprint_is_an_invite_error() {
    let j = joined();
    let me = Person::new(2);
    let wrong = InviteCode {
        fp_owner: [9; 15],
        ..j.invite.clone()
    };
    assert!(matches!(
        verify_share(
            &j.share,
            &me.own(),
            &j.state.verified_roster(),
            Some(&wrong),
            &PinState::new()
        ),
        Err(ProtoError::Invite)
    ));
}

#[test]
fn share_addressed_elsewhere_or_to_other_kem_keys_is_refused() {
    let j = joined();
    let roster = j.state.verified_roster();
    let stranger = Person::new(3);
    assert!(matches!(
        verify_share(
            &j.share,
            &stranger.own(),
            &roster,
            Some(&j.invite),
            &PinState::new()
        ),
        Err(ProtoError::Authz)
    ));
    let mut shifted = Person::new(2).own();
    shifted.kem_pk = Person::new(7).kem_pk;
    assert!(matches!(
        verify_share(
            &j.share,
            &shifted,
            &roster,
            Some(&j.invite),
            &PinState::new()
        ),
        Err(ProtoError::Roster)
    ));
}

#[test]
fn share_with_a_forged_signature_or_stale_roster_is_refused() {
    let j = joined();
    let me = Person::new(2);
    let roster = j.state.verified_roster();
    let mut forged = j.share.clone();
    let mut sig = *forged.sig.as_bytes();
    sig[5] ^= 0x10;
    forged.sig = Signature::from_bytes(sig);
    assert!(matches!(
        verify_share(
            &forged,
            &me.own(),
            &roster,
            Some(&j.invite),
            &PinState::new()
        ),
        Err(ProtoError::Sig)
    ));
    let mut older = roster.roster().clone();
    older.rver = Rver::new(1).unwrap();
    let stale = VerifiedRoster::trusted(older, *roster.hash());
    assert!(matches!(
        verify_share(
            &j.share,
            &me.own(),
            &stale,
            Some(&j.invite),
            &PinState::new()
        ),
        Err(ProtoError::Roster)
    ));
    let mut later_epoch = roster.roster().clone();
    later_epoch.epoch = Epoch::new(4).unwrap();
    let wrong_epoch = VerifiedRoster::trusted(later_epoch, *roster.hash());
    assert!(matches!(
        verify_share(
            &j.share,
            &me.own(),
            &wrong_epoch,
            Some(&j.invite),
            &PinState::new()
        ),
        Err(ProtoError::Epoch)
    ));
}

#[test]
fn open_share_fails_for_the_wrong_recipient_key_tampering_and_commit_mismatch() {
    let j = joined();
    let me = Person::new(2);
    let roster = j.state.verified_roster();
    let verified = verify_share(
        &j.share,
        &me.own(),
        &roster,
        Some(&j.invite),
        &PinState::new(),
    )
    .unwrap();
    assert!(matches!(
        open_share(&verified, &Person::new(3).kem, &roster),
        Err(ProtoError::Aead)
    ));

    let mut tampered_body = j.share.unverified().unwrap();
    tampered_body.ct[0] ^= 1;
    let owner = Person::new(1);
    let resigned = Signed::sign(SigLabel::Share, &tampered_body, &owner.signing).unwrap();
    let tampered = verify_share(
        &resigned,
        &me.own(),
        &roster,
        Some(&j.invite),
        &PinState::new(),
    )
    .unwrap();
    assert!(matches!(
        open_share(&tampered, &me.kem, &roster),
        Err(ProtoError::Aead)
    ));

    let mut forged_roster = roster.roster().clone();
    forged_roster.vk_commit = Hash32::from_bytes([8; 32]);
    let forged = VerifiedRoster::trusted(forged_roster, *roster.hash());
    assert!(matches!(
        open_share(&verified, &me.kem, &forged),
        Err(ProtoError::Roster)
    ));
    let other_hash = VerifiedRoster::trusted(roster.roster().clone(), Hash32::from_bytes([1; 32]));
    assert!(matches!(
        open_share(&verified, &me.kem, &other_hash),
        Err(ProtoError::Roster)
    ));
}

fn dissolve_for(state: &VaultState) -> Dissolve {
    Dissolve {
        vault_id: state.roster.vault_id,
        rver: state.rver,
        epoch: state.epoch,
        seq: state.seq,
        head: state.hash,
    }
}

#[test]
fn dissolve_requires_the_owner_a_shared_vault_and_a_current_head() {
    let j = joined();
    let owner = Person::new(1);
    let sign = |d: &Dissolve, p: &Person| Signed::sign(SigLabel::Dissolve, d, &p.signing).unwrap();
    let good = dissolve_for(&j.state);
    assert!(verify_dissolve(&sign(&good, &owner), &j.state).is_ok());
    assert!(matches!(
        verify_dissolve(&sign(&good, &Person::new(2)), &j.state),
        Err(ProtoError::Sig)
    ));
    let older = Dissolve {
        seq: Seq::new(1).unwrap(),
        ..good.clone()
    };
    assert!(matches!(
        verify_dissolve(&sign(&older, &owner), &j.state),
        Err(ProtoError::Rollback)
    ));
    let fork = Dissolve {
        head: Hash32::from_bytes([4; 32]),
        ..good.clone()
    };
    assert!(matches!(
        verify_dissolve(&sign(&fork, &owner), &j.state),
        Err(ProtoError::Fork)
    ));
    let other_vault = Dissolve {
        vault_id: VaultId::from_bytes([2; 16]),
        ..good.clone()
    };
    assert!(matches!(
        verify_dissolve(&sign(&other_vault, &owner), &j.state),
        Err(ProtoError::Roster)
    ));
    let ahead = Dissolve {
        seq: Seq::new(99).unwrap(),
        ..good.clone()
    };
    assert!(verify_dissolve(&sign(&ahead, &owner), &j.state).is_ok());
    let mut private = j.state.clone();
    private.roster.kind = VaultKind::Private;
    assert!(matches!(
        verify_dissolve(&sign(&good, &owner), &private),
        Err(ProtoError::Roster)
    ));
}

#[test]
fn leave_requires_a_current_non_owner_member_signature() {
    let j = joined();
    let sign = |l: &LeaveRequest, p: &Person| Signed::sign(SigLabel::Leave, l, &p.signing).unwrap();
    let good = LeaveRequest {
        vault_id: j.state.roster.vault_id,
        account_id: AccountId::from_bytes([2; 16]),
        rver: j.state.rver,
        epoch: j.state.epoch,
    };
    assert!(verify_leave(&sign(&good, &Person::new(2)), &j.state).is_ok());
    assert!(matches!(
        verify_leave(&sign(&good, &Person::new(3)), &j.state),
        Err(ProtoError::Sig)
    ));
    let owner_leaves = LeaveRequest {
        account_id: AccountId::from_bytes([1; 16]),
        ..good.clone()
    };
    assert!(matches!(
        verify_leave(&sign(&owner_leaves, &Person::new(1)), &j.state),
        Err(ProtoError::Authz)
    ));
    let stranger = LeaveRequest {
        account_id: AccountId::from_bytes([3; 16]),
        ..good.clone()
    };
    assert!(matches!(
        verify_leave(&sign(&stranger, &Person::new(3)), &j.state),
        Err(ProtoError::Authz)
    ));
    let stale_rver = LeaveRequest {
        rver: Rver::new(1).unwrap(),
        ..good.clone()
    };
    assert!(matches!(
        verify_leave(&sign(&stale_rver, &Person::new(2)), &j.state),
        Err(ProtoError::Roster)
    ));
    let stale_epoch = LeaveRequest {
        epoch: Epoch::new(3).unwrap(),
        ..good.clone()
    };
    assert!(matches!(
        verify_leave(&sign(&stale_epoch, &Person::new(2)), &j.state),
        Err(ProtoError::Epoch)
    ));
    let other_vault = LeaveRequest {
        vault_id: VaultId::from_bytes([2; 16]),
        ..good
    };
    assert!(matches!(
        verify_leave(&sign(&other_vault, &Person::new(2)), &j.state),
        Err(ProtoError::Roster)
    ));
}

#[test]
fn members_helper_reads_owner_and_lookup() {
    let j = joined();
    assert_eq!(
        j.state.roster.owner().unwrap().account_id,
        AccountId::from_bytes([1; 16])
    );
    assert!(
        j.state
            .roster
            .member(&AccountId::from_bytes([2; 16]))
            .is_some()
    );
    assert!(
        j.state
            .roster
            .member(&AccountId::from_bytes([9; 16]))
            .is_none()
    );
    let _: Option<Member> = None;
}
