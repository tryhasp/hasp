use hasp_crypto::{SecretKey, hpke_open};
use hasp_proto::{
    Aad, AccountId, Commit, InviteCode, InviteId, OwnKeys, Pin, PinLevel, PinState, Role, Roster,
    SealedRaw, Share, ShareKey, SigLabel, Signed, VaultState, fingerprint, open_share, seal_share,
    verify_share,
};

use crate::double::{Check, DState, Verifier, directory_share, share_context};
use crate::harness::{
    ATTACKER, Chain, EDITOR, INVITEE, OWNER, Person, Session, clone_key, err_name, verified,
};
use crate::scenarios::attack;

struct Invited {
    session: Session,
    state: VaultState,
    share: Signed<Share>,
    invitee: Person,
    owner: Person,
}

impl Invited {
    fn new() -> Self {
        let mut session = Session::bare(INVITEE);
        let add = session.chain.add_member(INVITEE, Role::Editor);
        let state = session.verify(std::slice::from_ref(&add)).unwrap();
        Self {
            share: add.shares[0].clone(),
            invitee: Person::new(INVITEE),
            owner: Person::new(OWNER),
            session,
            state,
        }
    }

    fn roster(&self) -> (&Roster, &hasp_proto::Hash32) {
        (&self.state.roster, &self.state.roster_hash)
    }

    fn invite(&self) -> InviteCode {
        InviteCode {
            invite_id: InviteId::from_bytes([7; 16]),
            fp_owner: fingerprint(&self.owner.ik_pk, &self.owner.kem_pk),
            origin: "https://vault.example".into(),
        }
    }
}

#[derive(Clone, Copy)]
struct Case<'a> {
    own: &'a OwnKeys,
    roster: (&'a Roster, &'a hasp_proto::Hash32),
    share: &'a Signed<Share>,
    invite: Option<&'a InviteCode>,
    pins: &'a PinState,
}

fn verify_attack(case: &Case<'_>, expected: &str, skip: &[Check]) {
    let Case {
        own,
        roster,
        share,
        invite,
        pins,
    } = *case;
    let trusted = verified(roster.0, *roster.1);
    assert_eq!(
        err_name(verify_share(share, own, &trusted, invite, pins)),
        expected,
        "real verifier"
    );
    assert_eq!(
        err_name(Verifier::full().share(share, own, roster, invite, pins)),
        expected,
        "reference parity"
    );
    assert_eq!(
        err_name(Verifier::without(skip).share(share, own, roster, invite, pins)),
        "Ok",
        "vulnerable double {skip:?}"
    );
}

fn evil_vault_inviting(invitee: u8, owner_account: u8, owner_keys: u8) -> (Chain, Commit) {
    let mut evil = Chain::new(hasp_proto::VaultKind::Shared, owner_account);
    evil.owner_keys = owner_keys;
    evil.id = hasp_proto::VaultId::from_bytes([0xdd; 16]);
    evil.genesis();
    let add = evil.add_member(invitee, Role::Editor);
    (evil, add)
}

#[test]
fn honest_share_verifies_opens_and_matches_the_vk_commit_in_both_verifiers() {
    let fixture = Invited::new();
    let pins = PinState::new();
    let invite = fixture.invite();
    let trusted = verified(fixture.roster().0, *fixture.roster().1);
    let own = fixture.invitee.own();
    let verified_share =
        verify_share(&fixture.share, &own, &trusted, Some(&invite), &pins).unwrap();
    let vk = open_share(&verified_share, &fixture.invitee.kem, &trusted).unwrap();
    assert_eq!(vk.expose(), fixture.session.chain.vk().expose());
    let body = Verifier::full()
        .share(&fixture.share, &own, fixture.roster(), Some(&invite), &pins)
        .unwrap();
    let double_vk = Verifier::full()
        .open_share(&body, &fixture.invitee.kem, fixture.roster())
        .unwrap();
    assert_eq!(double_vk.expose(), vk.expose());
}

#[test]
fn e27_share_from_another_key_is_rejected_by_the_invite_fingerprint() {
    let fixture = Invited::new();
    let (evil, add) = evil_vault_inviting(INVITEE, ATTACKER, ATTACKER);
    let roster = evil.roster.clone().unwrap();
    verify_attack(
        &Case {
            own: &fixture.invitee.own(),
            roster: (&roster.0, &roster.1),
            share: &add.shares[0],
            invite: Some(&fixture.invite()),
            pins: &PinState::new(),
        },
        "Invite",
        &[Check::ShareInviteFingerprint],
    );
}

#[test]
fn e27_matching_pin_does_not_excuse_a_wrong_invite_fingerprint() {
    let fixture = Invited::new();
    let (evil, add) = evil_vault_inviting(INVITEE, ATTACKER, ATTACKER);
    let attacker = Person::new(ATTACKER);
    let mut pins = PinState::new();
    pins.insert(
        attacker.account,
        Pin::new(attacker.ik_pk, &attacker.kem_pk, PinLevel::Tofu),
    );
    let roster = evil.roster.clone().unwrap();
    verify_attack(
        &Case {
            own: &fixture.invitee.own(),
            roster: (&roster.0, &roster.1),
            share: &add.shares[0],
            invite: Some(&fixture.invite()),
            pins: &pins,
        },
        "Invite",
        &[Check::ShareInviteFingerprint],
    );
}

#[test]
fn e12_share_from_an_unknown_owner_without_an_invite_is_rejected() {
    let fixture = Invited::new();
    let (evil, add) = evil_vault_inviting(INVITEE, ATTACKER, ATTACKER);
    let roster = evil.roster.clone().unwrap();
    verify_attack(
        &Case {
            own: &fixture.invitee.own(),
            roster: (&roster.0, &roster.1),
            share: &add.shares[0],
            invite: None,
            pins: &PinState::new(),
        },
        "Invite",
        &[Check::SharePin],
    );
}

#[test]
fn e1_owner_keys_substituted_at_accept_time_are_a_pin_error() {
    let fixture = Invited::new();
    let owner = &fixture.owner;
    let mut pins = PinState::new();
    pins.insert(
        owner.account,
        Pin::new(owner.ik_pk, &owner.kem_pk, PinLevel::Verified),
    );
    let (evil, add) = evil_vault_inviting(INVITEE, OWNER, ATTACKER);
    let roster = evil.roster.clone().unwrap();
    verify_attack(
        &Case {
            own: &fixture.invitee.own(),
            roster: (&roster.0, &roster.1),
            share: &add.shares[0],
            invite: None,
            pins: &pins,
        },
        "Pin",
        &[Check::SharePin],
    );
}

#[test]
fn e1_owner_keys_substituted_in_the_roster_are_a_pin_error_before_any_share() {
    let mut fixture = Invited::new();
    let owner = &fixture.owner;
    fixture.session.pins.insert(
        owner.account,
        Pin::new(owner.ik_pk, &owner.kem_pk, PinLevel::Verified),
    );
    let mut evil = Chain::new(hasp_proto::VaultKind::Shared, OWNER);
    evil.owner_keys = ATTACKER;
    let genesis = evil.genesis();
    assert_eq!(
        err_name(hasp_proto::verify_genesis(
            &genesis,
            &fixture.invitee.own(),
            &fixture.session.pins
        )),
        "Pin"
    );
}

#[test]
fn e1_invitee_keys_substituted_at_invite_time_fail_the_own_key_check() {
    let mut session = Session::bare(INVITEE);
    session.chain.substitute.insert(INVITEE, ATTACKER);
    let add = session.chain.add_member(INVITEE, Role::Editor);
    attack(&session, &[add], "Roster", &[Check::RosterOwnKey]);
}

#[test]
fn e1_share_sealed_to_a_substituted_key_is_readable_only_by_the_attacker() {
    let mut session = Session::bare(INVITEE);
    session.chain.substitute.insert(INVITEE, ATTACKER);
    let add = session.chain.add_member(INVITEE, Role::Editor);
    let invitee = Person::new(INVITEE);
    let attacker = Person::new(ATTACKER);
    let roster = session.chain.roster.clone().unwrap();
    let share = add.shares[0].clone();
    verify_attack(
        &Case {
            own: &invitee.own(),
            roster: (&roster.0, &roster.1),
            share: &share,
            invite: None,
            pins: &PinState::new(),
        },
        "Roster",
        &[Check::ShareKemHash, Check::ShareBinding, Check::SharePin],
    );
    let body = share.unverified().unwrap();
    let verifier = Verifier::without(&[Check::ShareKemHash, Check::ShareBinding]);
    assert_eq!(
        err_name(verifier.open_share(&body, &invitee.kem, (&roster.0, &roster.1))),
        "Aead"
    );
    let stolen = verifier
        .open_share(&body, &attacker.kem, (&roster.0, &roster.1))
        .unwrap();
    assert_eq!(stolen.expose(), session.chain.vk().expose());
}

#[test]
fn e1_pinned_invitee_key_substitution_is_a_pin_error_on_the_inviter_side() {
    let mut session = Session::bare(OWNER);
    let invitee = Person::new(INVITEE);
    session.pins.insert(
        invitee.account,
        Pin::new(invitee.ik_pk, &invitee.kem_pk, PinLevel::Verified),
    );
    session.chain.substitute.insert(INVITEE, ATTACKER);
    let add = session.chain.add_member(INVITEE, Role::Editor);
    attack(&session, &[add], "Pin", &[Check::RosterPins]);
}

#[test]
fn e1_inviter_side_without_a_fingerprint_check_accepts_an_unpinned_key_as_tofu() {
    let mut session = Session::bare(OWNER);
    session.chain.substitute.insert(INVITEE, ATTACKER);
    let add = session.chain.add_member(INVITEE, Role::Editor);
    session.verify(std::slice::from_ref(&add)).unwrap();
    let attacker = Person::new(ATTACKER);
    let substituted = session.chain.roster.clone().unwrap().0;
    let member = substituted
        .member(&AccountId::from_bytes([INVITEE; 16]))
        .unwrap();
    assert_eq!(member.ik_pk, attacker.ik_pk);
    assert_eq!(
        hasp_proto::pin_check(
            &session.pins,
            &member.account_id,
            &member.ik_pk,
            &member.kem_pk
        ),
        hasp_proto::PinCheck::New
    );
}

fn owner_share(chain: &Chain, vk: &SecretKey, signer: &Person) -> Signed<Share> {
    let (roster, hash) = chain.roster.clone().unwrap();
    seal_share(
        &verified(&roster, hash),
        &ShareKey {
            owner_key: &signer.signing,
            vk,
            to: &AccountId::from_bytes([INVITEE; 16]),
        },
    )
    .unwrap()
}

#[test]
fn e2_share_substituted_by_the_server_with_a_chosen_vault_key_is_rejected() {
    let fixture = Invited::new();
    let chosen = SecretKey::from_bytes([0x66; 32]);
    let forged = owner_share(&fixture.session.chain, &chosen, &Person::new(ATTACKER));
    let invite = fixture.invite();
    let pins = PinState::new();
    let own = fixture.invitee.own();
    verify_attack(
        &Case {
            own: &own,
            roster: fixture.roster(),
            share: &forged,
            invite: Some(&invite),
            pins: &pins,
        },
        "Sig",
        &[Check::ShareSignature],
    );
    let body = forged.unverified().unwrap();
    assert_eq!(
        err_name(Verifier::without(&[Check::ShareSignature]).open_share(
            &body,
            &fixture.invitee.kem,
            fixture.roster()
        )),
        "Roster"
    );
    let accepted = Verifier::without(&[Check::ShareSignature, Check::ShareVkCommit])
        .open_share(&body, &fixture.invitee.kem, fixture.roster())
        .unwrap();
    assert_eq!(accepted.expose(), chosen.expose());
}

#[test]
fn e2_owner_signed_share_carrying_a_different_key_fails_the_vk_commit() {
    let fixture = Invited::new();
    let wrong = SecretKey::from_bytes([0x55; 32]);
    let share = owner_share(&fixture.session.chain, &wrong, &fixture.owner);
    let trusted = verified(fixture.roster().0, *fixture.roster().1);
    let own = fixture.invitee.own();
    let pins = PinState::new();
    let invite = fixture.invite();
    let body = verify_share(&share, &own, &trusted, Some(&invite), &pins).unwrap();
    assert_eq!(
        err_name(open_share(&body, &fixture.invitee.kem, &trusted)),
        "Roster"
    );
    let share_body = share.unverified().unwrap();
    assert_eq!(
        err_name(Verifier::full().open_share(&share_body, &fixture.invitee.kem, fixture.roster())),
        "Roster"
    );
    let vk = Verifier::without(&[Check::ShareVkCommit])
        .open_share(&share_body, &fixture.invitee.kem, fixture.roster())
        .unwrap();
    assert_eq!(vk.expose(), wrong.expose());
}

#[test]
fn e2_flipped_share_ciphertext_fails_the_signature_and_independently_the_aead() {
    let fixture = Invited::new();
    let mut body = fixture.share.unverified().unwrap();
    body.ct[0] ^= 1;
    let forged = Signed::sign(SigLabel::Share, &body, &Person::new(ATTACKER).signing).unwrap();
    let invite = fixture.invite();
    let own = fixture.invitee.own();
    let trusted = verified(fixture.roster().0, *fixture.roster().1);
    let pins = PinState::new();
    assert_eq!(
        err_name(verify_share(&forged, &own, &trusted, Some(&invite), &pins)),
        "Sig"
    );
    assert_eq!(
        err_name(Verifier::without(&[Check::ShareSignature]).open_share(
            &body,
            &fixture.invitee.kem,
            fixture.roster()
        )),
        "Aead"
    );
}

#[test]
fn e2_share_aimed_at_another_recipient_or_vault_is_rejected() {
    let fixture = Invited::new();
    let pins = PinState::new();
    let invite = fixture.invite();
    let bystander = Person::new(EDITOR);
    verify_attack(
        &Case {
            own: &bystander.own(),
            roster: fixture.roster(),
            share: &fixture.share,
            invite: Some(&invite),
            pins: &pins,
        },
        "Authz",
        &[Check::ShareTo, Check::ShareKemHash, Check::ShareBinding],
    );
}

#[test]
fn e2_self_wrap_swapped_between_vaults_fails_aead_unless_the_vault_is_left_out_of_the_aad() {
    let account = AccountId::from_bytes([OWNER; 16]);
    let vault_a = hasp_proto::VaultId::from_bytes([0xaa; 16]);
    let vault_b = hasp_proto::VaultId::from_bytes([0xbb; 16]);
    let epoch = hasp_proto::Epoch::new(0).unwrap();
    let k_self = SecretKey::from_bytes([3; 32]);
    let vk_b = SecretKey::from_bytes([0xb2; 32]);
    let wrap_b = SealedRaw::seal(
        &k_self,
        vk_b.expose(),
        &Aad::self_wrap(account, vault_b, epoch),
    )
    .unwrap();
    assert_eq!(
        err_name(wrap_b.open(&k_self, &Aad::self_wrap(account, vault_a, epoch))),
        "Aead"
    );
    let weak = |_vault| Aad::new(hasp_proto::Rtype::SelfWrap).account(account);
    let weak_b = SealedRaw::seal(&k_self, vk_b.expose(), &weak(vault_b)).unwrap();
    let opened = weak_b.open(&k_self, &weak(vault_a)).unwrap();
    assert_eq!(opened.expose(), vk_b.expose());
}

#[test]
fn e4_wrap_targets_come_from_the_signed_roster_not_from_a_server_directory() {
    let mut session = Session::owner();
    let attacker = Person::new(ATTACKER);
    let mut chain = session.chain.fork();
    let removal = chain.remove_member(crate::harness::VIEWER);
    session.advance(std::slice::from_ref(&removal));
    let roster = chain.roster.clone().unwrap();
    let editor = AccountId::from_bytes([EDITOR; 16]);
    let editor_person = Person::new(EDITOR);
    let owner = Person::new(OWNER);
    let share = &removal.shares[0];
    let body = share.unverified().unwrap();
    let roster_member = roster.0.member(&editor).unwrap();
    assert_eq!(body.to, editor);
    assert_eq!(
        body.kem_pk_hash,
        crate::double::kem_hash(&roster_member.kem_pk)
    );
    let (info, aad) = share_context(&body, &owner.ik_pk, &editor_person.ik_pk, &roster.1).unwrap();
    assert!(hpke_open(&attacker.kem, &body.enc, &info, &aad, &body.ct).is_err());
    let hijacked = directory_share(
        (&roster.0, &roster.1),
        &owner.signing,
        chain.vk(),
        &editor,
        &attacker.kem_pk,
    );
    let hijacked_body = hijacked.unverified().unwrap();
    let (info, aad) = share_context(
        &hijacked_body,
        &owner.ik_pk,
        &editor_person.ik_pk,
        &roster.1,
    )
    .unwrap();
    let leaked = hpke_open(
        &attacker.kem,
        &hijacked_body.enc,
        &info,
        &aad,
        &hijacked_body.ct,
    )
    .unwrap();
    assert_eq!(leaked.expose(), chain.vk().expose());
    let trusted = verified(&roster.0, roster.1);
    let pins = PinState::new();
    assert_eq!(
        err_name(verify_share(
            &hijacked,
            &editor_person.own(),
            &trusted,
            None,
            &pins
        )),
        "Roster"
    );
}

#[test]
fn e26_removal_verifies_under_empty_pins_and_stale_pins_only_block() {
    let session = Session::owner();
    let mut chain = session.chain.fork();
    let removal = chain.remove_member(crate::harness::VIEWER);
    let empty = PinState::new();
    let own = session.viewer.own();
    assert!(
        hasp_proto::verify_batch(&session.state, std::slice::from_ref(&removal), &own, &empty)
            .is_ok()
    );
    let editor = Person::new(EDITOR);
    let attacker = Person::new(ATTACKER);
    let mut stale = PinState::new();
    stale.insert(
        editor.account,
        Pin::new(attacker.ik_pk, &attacker.kem_pk, PinLevel::Tofu),
    );
    assert_eq!(
        err_name(hasp_proto::verify_batch(
            &session.state,
            std::slice::from_ref(&removal),
            &own,
            &stale
        )),
        "Pin"
    );
    for share in &removal.shares {
        let body = share.unverified().unwrap();
        let roster = chain.roster.clone().unwrap().0;
        let member = roster.member(&body.to).unwrap();
        assert_eq!(body.kem_pk_hash, crate::double::kem_hash(&member.kem_pk));
    }
    let own_state = DState::from_real(&session.state);
    assert_eq!(
        err_name(Verifier::without(&[Check::RosterPins]).batch(
            &own_state,
            &[removal],
            &own,
            &stale
        )),
        "Ok"
    );
}

#[test]
fn e30_invalid_encapsulation_key_is_rejected_at_construction_and_inside_a_roster() {
    let session = Session::owner();
    let mut bad = *Person::new(ATTACKER).kem_pk.as_bytes();
    bad[0] = 0xff;
    bad[1] = 0xff;
    assert!(hasp_crypto::KemPublicKey::from_bytes(bad).is_err());
    let length_only = |bytes: &[u8]| bytes.len() == hasp_crypto::XWING_PUBLIC_KEY_LEN;
    assert!(length_only(&bad));

    let mut chain = session.chain.fork();
    chain.rver = crate::harness::bump(chain.rver);
    chain.others.insert(ATTACKER, (Role::Editor, chain.rver));
    let roster = chain.roster_body(chain.rver, chain.epoch, &clone_key(chain.vk()));
    let good = Signed::sign(SigLabel::Roster, &roster, &chain.person(OWNER).signing).unwrap();
    let marker = *Person::new(ATTACKER).kem_pk.as_bytes();
    let at = good
        .body
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    let mut body = good.body.clone();
    body[at] = 0xff;
    body[at + 1] = 0xff;
    let owner = chain.person(OWNER);
    let mut message = SigLabel::Roster.name().as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(&body);
    let forged = Signed::<Roster>::from_parts(body, owner.ik_pk, owner.signing.sign(&message));
    assert_eq!(err_name(forged.unverified()), "Format");
}

fn resigned(share: &Signed<Share>, edit: impl FnOnce(&mut Share)) -> Signed<Share> {
    let mut body = share.unverified().unwrap();
    edit(&mut body);
    Signed::sign(SigLabel::Share, &body, &Person::new(OWNER).signing).unwrap()
}

#[test]
fn share_binding_fields_each_fail_on_their_own() {
    let fixture = Invited::new();
    let pins = PinState::new();
    let invite = fixture.invite();
    let own = fixture.invitee.own();
    let wrong_vault = resigned(&fixture.share, |s| {
        s.vault_id = hasp_proto::VaultId::from_bytes([0x21; 16]);
    });
    let wrong_rver = resigned(&fixture.share, |s| {
        s.rver = hasp_proto::Rver::new(s.rver.get() + 1).unwrap();
    });
    for forged in [&wrong_vault, &wrong_rver] {
        verify_attack(
            &Case {
                own: &own,
                roster: fixture.roster(),
                share: forged,
                invite: Some(&invite),
                pins: &pins,
            },
            "Roster",
            &[Check::ShareBinding],
        );
    }
    let (roster, hash) = fixture.roster();
    let mut private = roster.clone();
    private.kind = hasp_proto::VaultKind::Private;
    verify_attack(
        &Case {
            own: &own,
            roster: (&private, hash),
            share: &fixture.share,
            invite: Some(&invite),
            pins: &pins,
        },
        "Roster",
        &[Check::ShareBinding],
    );
}

#[test]
fn share_to_a_member_whose_identity_or_kem_key_differs_from_ours_is_rejected() {
    let fixture = Invited::new();
    let pins = PinState::new();
    let invite = fixture.invite();
    let attacker = Person::new(ATTACKER);
    let ik_mismatch = OwnKeys {
        ik_pk: attacker.ik_pk,
        ..fixture.invitee.own()
    };
    verify_attack(
        &Case {
            own: &ik_mismatch,
            roster: fixture.roster(),
            share: &fixture.share,
            invite: Some(&invite),
            pins: &pins,
        },
        "Roster",
        &[Check::ShareBinding],
    );
    let kem_mismatch = OwnKeys {
        kem_pk: attacker.kem_pk.clone(),
        ..fixture.invitee.own()
    };
    let aimed_at_attacker_kem = resigned(&fixture.share, |s| {
        s.kem_pk_hash = crate::double::kem_hash(&attacker.kem_pk);
    });
    verify_attack(
        &Case {
            own: &kem_mismatch,
            roster: fixture.roster(),
            share: &aimed_at_attacker_kem,
            invite: Some(&invite),
            pins: &pins,
        },
        "Roster",
        &[Check::ShareBinding],
    );
}
