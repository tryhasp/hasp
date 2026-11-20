use hasp_crypto::{OpaqueClientRegistration, OpaqueIdentities, SecretKey};
use hasp_proto::wire::{
    AccountGet, ErrorCode, NoticeKind, RcSet, RecoverAbort, RecoverComplete, RecoverFetch,
    RecoverRegisterStart, RecoverStart, RecoveryId, SessionToken,
};
use hasp_proto::{AccountStatus, Hash32, SigLabel, Signed, Uint53};

use super::vault::code;
use super::Harness;
use crate::fixture::{Client, ORIGIN, Person};

const HOUR: u64 = 3600;

fn enrol_recovery(h: &Harness, client: &mut Client) -> hasp_proto::wire::RcAuthKey {
    h.reauth(&client.person, &client.token).unwrap();
    let (auth, set) = client.person.recovery_material();
    h.call(Some(&client.token), &set).unwrap();
    client.person.adopt_record(set.account);
    auth
}

#[test]
fn setting_a_recovery_code_needs_reauth_and_a_consistent_enrolment() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let (_, set) = alice.person.recovery_material();
    assert_eq!(
        code(h.call(Some(&alice.token), &set)),
        ErrorCode::ReauthRequired
    );
    h.reauth(&alice.person, &alice.token).unwrap();

    let stale_gen = RcSet {
        account: alice.person.next_record(0, AccountStatus::Active),
        ..set.clone()
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &stale_gen)),
        ErrorCode::Rollback
    );

    let wrong_wrap_hash = RcSet {
        rc_wrap: alice.person.keyset().ak_wrap,
        ..set.clone()
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &wrong_wrap_hash)),
        ErrorCode::Rollback
    );

    let other = Person::new("mallory");
    let foreign = RcSet {
        rc: Signed::sign(
            SigLabel::Recovery,
            &set.rc.unverified().unwrap(),
            &other.signing,
        )
        .unwrap(),
        ..set.clone()
    };
    assert!(h.call(Some(&alice.token), &foreign).is_err());

    h.call(Some(&alice.token), &set).unwrap();
    assert_eq!(code(h.call(Some(&alice.token), &set)), ErrorCode::Format);
    let rgen = h
        .call(
            None,
            &hasp_proto::wire::RecoverPrelogin {
                login: "alice".to_owned(),
            },
        )
        .unwrap();
    assert_eq!(rgen.rgen.get(), 1);
}

#[test]
fn recovery_start_checks_the_hash_verifier_in_the_same_way_for_every_failure() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let ghost = RecoverStart {
        account_id: hasp_proto::AccountId::from_bytes([5; 16]),
        k_rc_auth: hasp_proto::wire::RcAuthKey::from_bytes([1; 32]),
    };
    assert_eq!(code(h.call(None, &ghost)), ErrorCode::Auth);
    let before_enrolment = RecoverStart {
        account_id: alice.person.account_id,
        k_rc_auth: hasp_proto::wire::RcAuthKey::from_bytes([1; 32]),
    };
    assert_eq!(code(h.call(None, &before_enrolment)), ErrorCode::Auth);
    let auth = enrol_recovery(&h, &mut alice);
    let wrong = RecoverStart {
        account_id: alice.person.account_id,
        k_rc_auth: hasp_proto::wire::RcAuthKey::from_bytes([2; 32]),
    };
    assert_eq!(code(h.call(None, &wrong)), ErrorCode::Auth);
    let started = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: auth,
            },
        )
        .unwrap();
    assert_eq!(started.release_at.get(), 1_000_000 + 24 * HOUR);
}

#[test]
fn recovery_waits_out_the_delay_and_other_devices_get_a_notice() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let started = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    let again = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    assert_eq!(again, started);
    let notices = h.pull(&alice, &[]).unwrap().notices;
    let notice = notices
        .iter()
        .find(|n| n.kind == NoticeKind::RecoveryStarted)
        .unwrap();
    assert_eq!(notice.at, Some(started.release_at));

    let fetch = RecoverFetch {
        recovery_id: started.recovery_id,
        k_rc_auth: auth,
    };
    h.clock.advance(23 * HOUR);
    let early = h.call(None, &fetch).unwrap_err();
    assert_eq!(early.code, ErrorCode::Pending);
    assert_eq!(early.retry_after.unwrap().get(), HOUR);
    h.clock.advance(HOUR);
    let fetched = h.call(None, &fetch).unwrap();
    assert_eq!(fetched.keyset.account_id, alice.person.account_id);
    assert_eq!(fetched.records.len(), 2);
    assert_eq!(fetched.enrolment.unverified().unwrap().rgen.get(), 1);
}

#[test]
fn a_normal_sign_in_or_an_explicit_abort_cancels_a_pending_recovery() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let start = || RecoverStart {
        account_id: alice.person.account_id,
        k_rc_auth: auth.clone(),
    };
    let first = h.call(None, &start()).unwrap();
    h.try_login(&alice.person).unwrap();
    h.clock.advance(25 * HOUR);
    let fetch = |id| RecoverFetch {
        recovery_id: id,
        k_rc_auth: auth.clone(),
    };
    assert_eq!(
        code(h.call(None, &fetch(first.recovery_id))),
        ErrorCode::Auth
    );
    let notices = h.pull(&alice, &[]).unwrap().notices;
    assert!(
        notices
            .iter()
            .any(|n| n.kind == NoticeKind::RecoveryAborted)
    );

    let second = h.call(None, &start()).unwrap();
    assert_ne!(second.recovery_id, first.recovery_id);
    h.call(Some(&alice.token), &RecoverAbort::by_session())
        .unwrap();
    h.clock.advance(25 * HOUR);
    assert_eq!(
        code(h.call(None, &fetch(second.recovery_id))),
        ErrorCode::Auth
    );
}

#[test]
fn recovery_is_rate_limited_per_account() {
    let limiter = std::sync::Arc::new(crate::WindowLimiter::new(crate::Limits::default()));
    let mut h = Harness::with_limiter(limiter);
    let alice = h.signup("alice");
    let attempt = RecoverStart {
        account_id: alice.person.account_id,
        k_rc_auth: hasp_proto::wire::RcAuthKey::from_bytes([2; 32]),
    };
    for _ in 0..3 {
        assert_eq!(code(h.call(None, &attempt)), ErrorCode::Auth);
    }
    assert_eq!(code(h.call(None, &attempt)), ErrorCode::RateLimited);
}

fn release(
    h: &Harness,
    client: &Client,
    auth: &hasp_proto::wire::RcAuthKey,
) -> (RecoveryId, SessionToken) {
    let started = h
        .call(
            None,
            &RecoverStart {
                account_id: client.person.account_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    h.clock.advance(25 * HOUR);
    let fetched = h
        .call(
            None,
            &RecoverFetch {
                recovery_id: started.recovery_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    (started.recovery_id, fetched.token)
}

fn new_credential(
    h: &Harness,
    client: &Client,
    id: RecoveryId,
    token: &SessionToken,
) -> (SecretKey, Vec<u8>) {
    let new_opk = SecretKey::random().unwrap();
    let (state, request) = OpaqueClientRegistration::start(&new_opk).unwrap();
    let response = h
        .call(
            Some(token),
            &RecoverRegisterStart {
                recovery_id: id,
                request: request.into(),
            },
        )
        .unwrap();
    let record = state
        .finish(
            response.response.as_slice(),
            &OpaqueIdentities {
                client: client.person.account_id.as_bytes(),
                server: ORIGIN.as_bytes(),
            },
        )
        .unwrap();
    (new_opk, record)
}

#[test]
fn recovery_registration_needs_the_released_recovery_token() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let (id, token) = release(&h, &alice, &auth);
    let probe = |token: Option<&SessionToken>| {
        code(h.call(
            token,
            &RecoverRegisterStart {
                recovery_id: id,
                request: vec![].into(),
            },
        ))
    };
    assert_eq!(probe(None), ErrorCode::Auth);
    assert_eq!(
        probe(Some(&SessionToken::from_bytes([1; 32]))),
        ErrorCode::Auth
    );
    assert_eq!(probe(Some(&alice.token)), ErrorCode::Auth);
    assert_ne!(probe(Some(&token)), ErrorCode::Auth);
    let wrong = h.call(
        Some(&token),
        &RecoverRegisterStart {
            recovery_id: RecoveryId::from_bytes([0xee; 16]),
            request: vec![].into(),
        },
    );
    assert_eq!(code(wrong), ErrorCode::Auth);
    h.call(Some(&alice.token), &AccountGet).unwrap();
}

#[test]
fn completing_recovery_replaces_the_credential_and_revokes_every_session() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let (recovery_id, recovery_token) = release(&h, &alice, &auth);
    let (new_opk, record) = new_credential(&h, &alice, recovery_id, &recovery_token);
    let (new_auth, set) = alice.person.recovery_material();
    let finish = RecoverComplete {
        recovery_id,
        record: record.into(),
        keyset: alice.person.keyset(),
        account: set.account.clone(),
        rc: set.rc.clone(),
        rc_wrap: set.rc_wrap.clone(),
        h_auth: set.h_auth,
        device: alice.person.device_info("recovered"),
    };
    let mut bad = finish.clone();
    bad.h_auth = Hash32::from_bytes([1; 32]);
    bad.rc_wrap = alice.person.keyset().ak_wrap;
    assert!(h.call(Some(&recovery_token), &bad).is_err());
    assert_eq!(code(h.call(None, &finish)), ErrorCode::Auth);
    let grant = h.call(Some(&recovery_token), &finish).unwrap();
    assert_eq!(
        code(h.call(Some(&recovery_token), &finish)),
        ErrorCode::Auth
    );

    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::Auth
    );
    let sessions = h
        .call(Some(&grant.token), &hasp_proto::wire::SessionList)
        .unwrap()
        .sessions;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].platform, "recovered");
    assert_eq!(code(h.try_login(&alice.person)), ErrorCode::Auth);
    alice.person.opk = new_opk;
    alice.person.adopt_record(set.account);
    h.try_login(&alice.person).unwrap();

    let rgen = h
        .call(
            None,
            &hasp_proto::wire::RecoverPrelogin {
                login: "alice".to_owned(),
            },
        )
        .unwrap();
    assert_eq!(rgen.rgen, Uint53::new(2).unwrap());
    let restarted = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: new_auth,
            },
        )
        .unwrap();
    assert!(restarted.release_at.get() > 0);
    let notices = h
        .call(
            Some(&grant.token),
            &hasp_proto::wire::Pull {
                vaults: Vec::new(),
                notices_after: Uint53::ZERO,
                limit: Uint53::ZERO,
            },
        )
        .unwrap()
        .notices;
    assert!(
        notices
            .iter()
            .any(|n| n.kind == NoticeKind::RecoveryCompleted)
    );
}

#[test]
fn a_released_recovery_token_expires() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let started = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    h.clock.advance(25 * HOUR);
    let fetched = h
        .call(
            None,
            &RecoverFetch {
                recovery_id: started.recovery_id,
                k_rc_auth: auth,
            },
        )
        .unwrap();
    h.clock.advance(HOUR + 1);
    assert_eq!(
        code(h.call(
            Some(&fetched.token),
            &RecoverRegisterStart {
                recovery_id: started.recovery_id,
                request: vec![].into()
            }
        )),
        ErrorCode::Auth
    );
}

#[test]
fn recover_prelogin_has_its_own_rate_class() {
    let limiter = std::sync::Arc::new(crate::WindowLimiter::new(crate::Limits::default()));
    let h = Harness::with_limiter(limiter);
    let peer = crate::Caller::anonymous().from_peer([10, 0, 0, 9].into());
    let recover = hasp_proto::wire::RecoverPrelogin {
        login: "x".to_owned(),
    };
    for _ in 0..10 {
        h.server.call(&peer, &recover).unwrap();
    }
    assert_eq!(
        h.server.call(&peer, &recover).unwrap_err().code,
        ErrorCode::RateLimited
    );
    let login = hasp_proto::wire::Prelogin {
        login: "x".to_owned(),
    };
    h.server.call(&peer, &login).unwrap();
}

#[test]
fn repeated_fetches_do_not_extend_the_recovery_window() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let started = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    let fetch = RecoverFetch {
        recovery_id: started.recovery_id,
        k_rc_auth: auth,
    };
    h.clock.advance(24 * HOUR);
    h.call(None, &fetch).unwrap();
    h.clock.advance(40 * 60);
    let last = h.call(None, &fetch).unwrap();
    h.clock.advance(30 * 60);
    let register = RecoverRegisterStart {
        recovery_id: started.recovery_id,
        request: hasp_proto::wire::Blob(Vec::new()),
    };
    assert_eq!(code(h.call(Some(&last.token), &register)), ErrorCode::Auth);
}

#[test]
fn a_recovery_code_alone_aborts_its_own_pending_recovery() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let auth = enrol_recovery(&h, &mut alice);
    let started = h
        .call(
            None,
            &RecoverStart {
                account_id: alice.person.account_id,
                k_rc_auth: auth.clone(),
            },
        )
        .unwrap();
    let wrong = hasp_proto::wire::RcAuthKey::from_bytes([9; 32]);
    assert_eq!(
        code(h.call(
            None,
            &RecoverAbort::by_recovery_code(started.recovery_id, wrong)
        )),
        ErrorCode::Auth
    );
    h.call(
        None,
        &RecoverAbort::by_recovery_code(started.recovery_id, auth.clone()),
    )
    .unwrap();
    h.clock.advance(25 * HOUR);
    assert_eq!(
        code(h.call(
            None,
            &RecoverFetch {
                recovery_id: started.recovery_id,
                k_rc_auth: auth,
            }
        )),
        ErrorCode::Auth
    );
    let notices = h.pull(&alice, &[]).unwrap().notices;
    assert!(
        notices
            .iter()
            .any(|n| n.kind == NoticeKind::RecoveryAborted)
    );
}
