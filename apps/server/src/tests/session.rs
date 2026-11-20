use hasp_proto::Esid;
use hasp_proto::wire::{
    AccountGet, Blob, EnrolAbort, EnrolApprove, EnrolMsgGet, EnrolMsgPut, EnrolOpen, EnrolSlot,
    ErrorCode, SessionList, SessionRevoke,
};

use super::vault::code;
use crate::fixture::Harness;

const DAY: u64 = 24 * 3600;

#[test]
fn sessions_slide_by_activity_and_expire_when_idle() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    h.clock.advance(29 * DAY);
    h.call(Some(&alice.token), &AccountGet).unwrap();
    h.clock.advance(29 * DAY);
    h.call(Some(&alice.token), &AccountGet).unwrap();
    h.clock.advance(31 * DAY);
    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::Auth
    );
    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::Auth
    );
}

#[test]
fn sessions_have_an_absolute_lifetime() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    for _ in 0..8 {
        h.clock.advance(10 * DAY);
        h.call(Some(&alice.token), &AccountGet).unwrap();
    }
    h.clock.advance(10 * DAY + 1);
    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::Auth
    );
}

#[test]
fn requests_without_or_with_unknown_tokens_are_unauthenticated() {
    let mut h = Harness::new();
    h.signup("alice");
    assert_eq!(code(h.call(None, &AccountGet)), ErrorCode::Auth);
    let forged = hasp_proto::wire::SessionToken::from_bytes([3; 32]);
    assert_eq!(code(h.call(Some(&forged), &AccountGet)), ErrorCode::Auth);
}

#[test]
fn sessions_are_listed_and_revoked_per_account() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let (second_id, second_token) = h.try_login(&alice.person).unwrap();
    let listed = h.call(Some(&alice.token), &SessionList).unwrap().sessions;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed.iter().filter(|s| s.current).count(), 1);
    assert!(listed.iter().all(|s| s.platform == "test"));

    let foreign = SessionRevoke {
        session_id: bob.session_id,
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &foreign)),
        ErrorCode::NotFound
    );
    h.call(
        Some(&alice.token),
        &SessionRevoke {
            session_id: second_id,
        },
    )
    .unwrap();
    assert_eq!(
        code(h.call(Some(&second_token), &AccountGet)),
        ErrorCode::Auth
    );
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &SessionRevoke {
                session_id: second_id
            }
        )),
        ErrorCode::NotFound
    );
    h.call(
        Some(&alice.token),
        &SessionRevoke {
            session_id: alice.session_id,
        },
    )
    .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::Auth
    );
}

#[test]
fn sweep_removes_expired_sessions_channels_and_pending_logins() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([4; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    h.clock.advance(31 * DAY);
    h.server.sweep().unwrap();
    let counts = h
        .server
        .with_store(|store| {
            use crate::store::Store;
            (
                store.sessions().len().unwrap(),
                store.session_tokens().len().unwrap(),
                store.enrol_channels().len().unwrap(),
            )
        })
        .unwrap();
    assert_eq!(counts, (0, 0, 0));
}

fn put(slot: EnrolSlot, esid: Esid, bytes: &[u8]) -> EnrolMsgPut {
    EnrolMsgPut {
        esid,
        slot,
        data: Blob(bytes.to_vec()),
    }
}

fn get(slot: EnrolSlot, esid: Esid) -> EnrolMsgGet {
    EnrolMsgGet { esid, slot }
}

#[test]
fn enrolment_relays_messages_and_mints_a_session_for_the_new_device() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([1; 16]);
    let opened = h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    assert_eq!(opened.expires.get(), 1_000_000 + 300);

    assert!(
        h.call(None, &get(EnrolSlot::Request, esid))
            .unwrap()
            .data
            .is_none()
    );
    h.call(None, &put(EnrolSlot::Request, esid, b"cB")).unwrap();
    assert_eq!(
        h.call(Some(&alice.token), &get(EnrolSlot::Request, esid))
            .unwrap()
            .data,
        Some(Blob(b"cB".to_vec()))
    );
    h.call(None, &put(EnrolSlot::Offer, esid, b"A")).unwrap();
    h.call(None, &put(EnrolSlot::Reveal, esid, b"B")).unwrap();
    assert_eq!(
        code(h.call(None, &put(EnrolSlot::Reveal, esid, b"B2"))),
        ErrorCode::Conflict
    );

    let device = hasp_proto::wire::DeviceInfo {
        device_id: hasp_proto::DeviceId::from_bytes([8; 16]),
        platform: "iphone".to_owned(),
        label: None,
    };
    let grant = h
        .call(
            Some(&alice.token),
            &EnrolApprove {
                esid,
                device: device.clone(),
            },
        )
        .unwrap();
    h.call(
        Some(&alice.token),
        &put(EnrolSlot::Payload, esid, b"sealed"),
    )
    .unwrap();
    assert_eq!(
        h.call(None, &get(EnrolSlot::Payload, esid)).unwrap().data,
        Some(Blob(b"sealed".to_vec()))
    );
    let account = h.call(Some(&grant.token), &AccountGet).unwrap();
    assert_eq!(account.records.len(), 1);
    let sessions = h.call(Some(&alice.token), &SessionList).unwrap().sessions;
    assert!(sessions.iter().any(|s| s.session_id == grant.session_id
        && s.platform == "iphone"
        && s.device_id == device.device_id));
    let again = EnrolApprove { esid, device };
    assert_eq!(code(h.call(Some(&alice.token), &again)), ErrorCode::Authz);
}

#[test]
fn enrolment_checks_ownership_expiry_and_abort() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let (_, second) = h.try_login(&alice.person).unwrap();
    let esid = Esid::from_bytes([2; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &EnrolOpen { esid })),
        ErrorCode::Conflict
    );
    let approve = EnrolApprove {
        esid,
        device: alice.person.device_info("x"),
    };
    assert_eq!(code(h.call(Some(&bob.token), &approve)), ErrorCode::Authz);
    assert_eq!(code(h.call(Some(&second), &approve)), ErrorCode::Authz);
    assert_eq!(code(h.call(None, &approve)), ErrorCode::Auth);
    h.call(Some(&alice.token), &EnrolAbort { esid }).unwrap();
    assert_eq!(
        code(h.call(None, &put(EnrolSlot::Request, esid, b"x"))),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(h.call(Some(&alice.token), &approve)),
        ErrorCode::NotFound
    );

    let late = Esid::from_bytes([3; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid: late })
        .unwrap();
    h.clock.advance(301);
    assert_eq!(
        code(h.call(None, &put(EnrolSlot::Request, late, b"x"))),
        ErrorCode::Expired
    );
    assert_eq!(
        code(h.call(
            Some(&alice.token),
            &EnrolApprove {
                esid: late,
                device: alice.person.device_info("x")
            }
        )),
        ErrorCode::Expired
    );
    assert_eq!(
        code(h.call(None, &get(EnrolSlot::Request, Esid::from_bytes([9; 16])))),
        ErrorCode::NotFound
    );
}

#[test]
fn enrolment_messages_are_bounded() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([5; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    assert_eq!(
        code(h.call(
            None,
            &put(EnrolSlot::Payload, esid, &vec![0; 1024 * 1024 + 1])
        )),
        ErrorCode::TooLarge
    );
}

#[test]
fn an_approved_device_session_is_a_full_session() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([6; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    let grant = h
        .call(
            Some(&alice.token),
            &EnrolApprove {
                esid,
                device: alice.person.device_info("extension"),
            },
        )
        .unwrap();
    h.call(
        Some(&grant.token),
        &SessionRevoke {
            session_id: grant.session_id,
        },
    )
    .unwrap();
    assert_eq!(
        code(h.call(Some(&grant.token), &AccountGet)),
        ErrorCode::Auth
    );
    h.call(Some(&alice.token), &AccountGet).unwrap();
}

#[test]
fn enrolment_slots_are_write_once_in_order_and_identical_repeats_succeed() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([7; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    assert_eq!(
        code(h.call(None, &put(EnrolSlot::Offer, esid, b"A"))),
        ErrorCode::Conflict
    );
    h.call(None, &put(EnrolSlot::Request, esid, b"cB")).unwrap();
    h.call(None, &put(EnrolSlot::Request, esid, b"cB")).unwrap();
    assert_eq!(
        code(h.call(None, &put(EnrolSlot::Request, esid, b"other"))),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(h.call(None, &put(EnrolSlot::Reveal, esid, b"B"))),
        ErrorCode::Conflict
    );
    h.call(None, &put(EnrolSlot::Offer, esid, b"A")).unwrap();
    h.call(None, &put(EnrolSlot::Reveal, esid, b"B")).unwrap();
    h.call(None, &put(EnrolSlot::Payload, esid, b"P")).unwrap();
    assert_eq!(
        h.call(None, &get(EnrolSlot::Request, esid)).unwrap().data,
        Some(Blob(b"cB".to_vec()))
    );
}

#[test]
fn identical_repeats_do_not_use_up_the_write_budget() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([8; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    for _ in 0..40 {
        h.call(None, &put(EnrolSlot::Request, esid, b"cB")).unwrap();
    }
    h.call(None, &put(EnrolSlot::Offer, esid, b"A")).unwrap();
}

#[test]
fn enrolment_abort_needs_only_the_esid_and_deletes_the_slots() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let esid = Esid::from_bytes([10; 16]);
    h.call(Some(&alice.token), &EnrolOpen { esid }).unwrap();
    h.call(None, &put(EnrolSlot::Request, esid, b"cB")).unwrap();
    h.call(None, &EnrolAbort { esid }).unwrap();
    assert_eq!(
        code(h.call(None, &get(EnrolSlot::Request, esid))),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(h.call(
            None,
            &EnrolAbort {
                esid: Esid::from_bytes([11; 16])
            }
        )),
        ErrorCode::NotFound
    );
}

#[test]
fn last_seen_is_written_at_most_once_a_minute() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let seen = |h: &Harness| {
        h.call(Some(&alice.token), &SessionList)
            .unwrap()
            .sessions
            .iter()
            .find(|s| s.current)
            .map(|s| s.last_seen.get())
            .unwrap()
    };
    let start = seen(&h);
    h.clock.advance(30);
    assert_eq!(seen(&h), start);
    h.clock.advance(31);
    h.call(Some(&alice.token), &AccountGet).unwrap();
    assert_eq!(seen(&h), start + 61);
}

#[test]
fn a_panic_inside_the_store_lock_does_not_brick_the_server() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let server = std::sync::Arc::clone(&h.server);
    let panicked = std::thread::spawn(move || {
        let _unused = server.with_store(|_| -> () { panic!("boom") });
    })
    .join();
    assert!(panicked.is_err());
    h.call(Some(&alice.token), &AccountGet).unwrap();
    assert!(h.server.writable());
}

#[test]
fn forged_tokens_never_spend_a_real_sessions_budget() {
    let limiter = std::sync::Arc::new(crate::WindowLimiter::new(crate::Limits {
        general_per_subject: 3,
        ..crate::Limits::default()
    }));
    let mut h = Harness::with_limiter(limiter);
    let alice = h.signup("alice");
    let forged = hasp_proto::wire::SessionToken::from_bytes([3; 32]);
    for _ in 0..10 {
        assert_eq!(code(h.call(Some(&forged), &AccountGet)), ErrorCode::Auth);
    }
    for _ in 0..3 {
        h.call(Some(&alice.token), &AccountGet).unwrap();
    }
    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::RateLimited
    );
}
