use std::sync::Arc;

use hasp_proto::wire::{
    AccountGet, ErrorCode, Health, OpaquePurpose, Prelogin, RecoverPrelogin, SignupToken, WireError,
};
use hasp_proto::{AccountStatus, KdfWire, Role, SigLabel, Signed, VaultKind, Wire};

use super::vault::code;
use super::Harness;
use crate::fixture::{ORIGIN, Person, VaultModel};
use crate::{Limits, WindowLimiter};

fn prelogin(h: &Harness, login: &str) -> Result<hasp_proto::wire::PreloginResponse, WireError> {
    h.call(
        None,
        &Prelogin {
            login: login.to_owned(),
        },
    )
}

#[test]
fn register_login_and_read_back_the_account() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let account = h.call(Some(&alice.token), &AccountGet).unwrap();
    assert_eq!(account.records.len(), 1);
    assert_eq!(account.keyset.account_id, alice.person.account_id);
    assert_eq!(account.keyset.generation.get(), 1);
    assert_eq!(account.memberships.len(), 1);
    assert_eq!(account.memberships[0].kind, VaultKind::Private);
    assert_eq!(account.memberships[0].role, Role::Owner);
}

#[test]
fn health_is_public() {
    let h = Harness::new();
    let health = h.call(None, &Health).unwrap();
    assert_eq!(health.min_protocol.get(), 1);
}

#[test]
fn prelogin_returns_the_real_record_for_a_known_login() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let response = prelogin(&h, "alice").unwrap();
    assert_eq!(response.account_id, alice.person.account_id);
    assert_eq!(response.kdf, crate::fixture::FLOOR_KDF);
    assert_eq!(response.cred_gen.get(), 1);
}

#[test]
fn prelogin_for_unknown_logins_is_stable_and_follows_the_real_distribution() {
    let mut h = Harness::new();
    let empty = prelogin(&h, "nobody").unwrap();
    assert_eq!(empty.kdf, crate::fixture::FLOOR_KDF);
    assert!((1..=3).contains(&empty.cred_gen.get()));

    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let first = prelogin(&h, "ghost").unwrap();
    assert_eq!(first, prelogin(&h, "ghost").unwrap());
    let other = prelogin(&h, "phantom").unwrap();
    assert_ne!(first.account_id, other.account_id);
    assert_ne!(first.account_id, alice.person.account_id);
    assert_ne!(first.account_id, bob.person.account_id);
    assert_eq!(first.kdf, crate::fixture::FLOOR_KDF);
    assert_eq!(first.v, prelogin(&h, "alice").unwrap().v);
    assert_eq!(
        first.to_cbor().unwrap().len(),
        prelogin(&h, "alice").unwrap().to_cbor().unwrap().len()
    );
}

#[test]
fn prelogin_pseudo_records_do_not_drift_as_accounts_are_added_or_tuned() {
    let mut h = Harness::new();
    let logins: Vec<String> = (0..20).map(|n| format!("ghost-{n}")).collect();
    let before: Vec<_> = logins.iter().map(|l| prelogin(&h, l).unwrap()).collect();
    let recover = |h: &Harness, login: &str| {
        h.call(
            None,
            &RecoverPrelogin {
                login: login.to_owned(),
            },
        )
        .unwrap()
    };
    let recover_before: Vec<_> = logins.iter().map(|l| recover(&h, l)).collect();
    h.signup("alice");
    let mut custom = Person::new("tuned");
    let tuned = KdfWire {
        m: 131_072,
        t: 4,
        p: 4,
    };
    let record = hasp_proto::AccountRecord {
        kdf: tuned,
        ..custom.record()
    };
    custom.head = Signed::sign(SigLabel::Account, &record, &custom.signing).unwrap();
    let token = h.signup_token();
    let mut vault = VaultModel::new(VaultKind::Private, &custom);
    h.try_register(&token, &custom, &mut vault).unwrap();
    h.signup("carol");
    for (login, expected) in logins.iter().zip(&before) {
        let fake = prelogin(&h, login).unwrap();
        assert_eq!(&fake, expected);
        assert_eq!(fake.kdf, crate::fixture::FLOOR_KDF);
        assert!((1..=3).contains(&fake.cred_gen.get()));
    }
    for (login, expected) in logins.iter().zip(&recover_before) {
        assert_eq!(&recover(&h, login), expected);
    }
}

#[test]
fn prelogin_rejects_malformed_logins() {
    let h = Harness::new();
    assert_eq!(code(prelogin(&h, "")), ErrorCode::Format);
    assert_eq!(code(prelogin(&h, " padded ")), ErrorCode::Format);
    assert_eq!(code(prelogin(&h, &"a".repeat(257))), ErrorCode::Format);
}

#[test]
fn recover_prelogin_is_uniform_too() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let known = h
        .call(
            None,
            &RecoverPrelogin {
                login: "alice".to_owned(),
            },
        )
        .unwrap();
    assert_eq!(known.account_id, alice.person.account_id);
    assert_eq!(known.rgen.get(), 0);
    let fake = h
        .call(
            None,
            &RecoverPrelogin {
                login: "ghost".to_owned(),
            },
        )
        .unwrap();
    assert_ne!(fake.account_id, alice.person.account_id);
    assert_eq!(
        fake,
        h.call(
            None,
            &RecoverPrelogin {
                login: "ghost".to_owned()
            }
        )
        .unwrap()
    );
}

#[test]
fn registration_needs_a_valid_unused_unexpired_token() {
    let mut h = Harness::new();
    let first = h.signup("alice");
    let token = h.signup_token();
    let bob = Person::new("bob");
    let mut vault = VaultModel::new(VaultKind::Private, &bob);
    let bogus = SignupToken::from_bytes([1; 20]);
    assert_eq!(
        code(h.try_register(&bogus, &bob, &mut vault)),
        ErrorCode::Auth
    );
    h.try_register(&token, &bob, &mut vault).unwrap();
    let carol = Person::new("carol");
    let mut vault = VaultModel::new(VaultKind::Private, &carol);
    assert_eq!(
        code(h.try_register(&token, &carol, &mut vault)),
        ErrorCode::Auth
    );
    let late = h.signup_token();
    h.clock.advance(8 * 24 * 3600);
    assert_eq!(
        code(h.try_register(&late, &carol, &mut vault)),
        ErrorCode::Auth
    );
    drop(first);
}

#[test]
fn registration_refuses_duplicate_logins_and_account_ids() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let token = h.signup_token();
    let same_login = Person::new("alice");
    let (start, _) = same_login.register_start(&token);
    assert_eq!(code(h.call(None, &start)), ErrorCode::Conflict);
    let mut same_id = Person::new("other");
    same_id.account_id = alice.person.account_id;
    let (start, _) = same_id.register_start(&token);
    assert_eq!(code(h.call(None, &start)), ErrorCode::Conflict);
}

#[test]
fn registration_validates_every_record() {
    let mut h = Harness::new();
    h.signup("alice");
    let token = h.signup_token();
    let person = Person::new("bob");

    let finish = |mutate: &dyn Fn(&mut hasp_proto::wire::RegisterFinish)| {
        let mut vault = VaultModel::new(VaultKind::Private, &person);
        let (start, state) = person.register_start(&token);
        let response = h.call(None, &start).unwrap();
        let mut request = person.register_finish(&token, state, &response, &mut vault);
        mutate(&mut request);
        h.call(None, &request)
    };

    let weak = hasp_proto::AccountRecord {
        kdf: KdfWire {
            m: 1024,
            t: 1,
            p: 1,
        },
        ..person.record()
    };
    let weak = Signed::sign(SigLabel::Account, &weak, &person.signing).unwrap();
    assert_eq!(
        code(finish(&|r| r.account = weak.clone())),
        ErrorCode::KdfParams
    );
    let other = Person::new("mallory");
    let foreign = Signed::sign(SigLabel::Account, &person.record(), &other.signing).unwrap();
    assert_eq!(
        code(finish(&|r| r.account = foreign.clone())),
        ErrorCode::Sig
    );
    assert_eq!(
        code(finish(&|r| r.keyset.account_id = other.account_id)),
        ErrorCode::Format
    );
    assert_eq!(
        code(finish(&|r| r.account_id = other.account_id)),
        ErrorCode::Format
    );
    assert_eq!(
        code(finish(&|r| r.record = vec![1, 2, 3].into())),
        ErrorCode::Format
    );
    let deleted = person.next_record(0, AccountStatus::Deleted);
    assert_eq!(
        code(finish(&|r| r.account = deleted.clone())),
        ErrorCode::Format
    );
    assert!(finish(&|_| {}).is_ok());
}

#[test]
fn a_vault_with_extra_members_or_a_foreign_owner_cannot_be_the_first_vault() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let token = h.signup_token();
    let bob = Person::new("bob");
    let mut vault = VaultModel::new(VaultKind::Shared, &bob);
    let (start, state) = bob.register_start(&token);
    let response = h.call(None, &start).unwrap();
    let request = bob.register_finish(&token, state, &response, &mut vault);
    assert_eq!(code(h.call(None, &request)), ErrorCode::Roster);
    drop(alice);
}

#[test]
fn bad_logins_for_known_and_unknown_accounts_fail_alike() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let known = h.garbage_login(alice.person.account_id).unwrap_err();
    let ghost = h
        .garbage_login(hasp_proto::AccountId::from_bytes([9; 16]))
        .unwrap_err();
    assert_eq!(known, ghost);
    assert_eq!(known.code, ErrorCode::Auth);
    let (start_known, _) = alice.person.login_start();
    let (start_ghost, _) = Person::new("ghost").login_start();
    let a = h.call(None, &start_known).unwrap();
    let b = h
        .call(
            None,
            &hasp_proto::wire::LoginStart {
                account_id: hasp_proto::AccountId::from_bytes([9; 16]),
                ..start_ghost
            },
        )
        .unwrap();
    assert_eq!(a.ke2.0.len(), b.ke2.0.len());
}

#[test]
fn login_handles_are_single_use_and_expire() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let (start, state) = alice.person.login_start();
    let response = h.call(None, &start).unwrap();
    let (finish, _) = alice
        .person
        .login_complete(ORIGIN, state, &response, "test")
        .unwrap();
    h.call(None, &finish).unwrap();
    assert_eq!(code(h.call(None, &finish)), ErrorCode::Auth);

    let (start, state) = alice.person.login_start();
    let response = h.call(None, &start).unwrap();
    let (finish, _) = alice
        .person
        .login_complete(ORIGIN, state, &response, "test")
        .unwrap();
    h.clock.advance(61);
    assert_eq!(code(h.call(None, &finish)), ErrorCode::Auth);
}

#[test]
fn login_and_reauth_handles_do_not_cross() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let (start, state) = alice.person.login_start();
    let response = h.call(None, &start).unwrap();
    let (handle, ke3, _) = alice
        .person
        .login_finish(ORIGIN, OpaquePurpose::Login, state, &response)
        .unwrap();
    let cross = hasp_proto::wire::ReauthFinish {
        handle,
        ke3: ke3.into(),
    };
    assert_eq!(code(h.call(Some(&alice.token), &cross)), ErrorCode::Auth);

    let (state, ke1) = hasp_crypto::OpaqueClientLogin::start(&alice.person.opk).unwrap();
    let response = h
        .call(
            Some(&alice.token),
            &hasp_proto::wire::ReauthStart { ke1: ke1.into() },
        )
        .unwrap();
    let (handle, ke3, _) = alice
        .person
        .login_finish(ORIGIN, OpaquePurpose::Reauth, state, &response)
        .unwrap();
    let cross = hasp_proto::wire::LoginFinish {
        handle,
        ke3: ke3.into(),
        device: alice.person.device_info("test"),
    };
    assert_eq!(code(h.call(None, &cross)), ErrorCode::Auth);
}

#[test]
fn failed_logins_back_off_and_a_success_clears_them() {
    let limiter = Arc::new(WindowLimiter::new(Limits {
        login_per_peer: 1000,
        ..Limits::default()
    }));
    let mut h = Harness::with_limiter(limiter);
    let alice = h.signup("alice");
    for _ in 0..5 {
        assert_eq!(
            code(h.garbage_login(alice.person.account_id)),
            ErrorCode::Auth
        );
    }
    let blocked = h.try_login(&alice.person).unwrap_err();
    assert_eq!(blocked.code, ErrorCode::RateLimited);
    assert!(blocked.retry_after.unwrap().get() >= 1);
    h.clock.advance(2);
    h.try_login(&alice.person).unwrap();
    h.try_login(&alice.person).unwrap();
}

#[test]
fn registration_is_rate_limited_per_peer() {
    let limiter = Arc::new(WindowLimiter::new(Limits {
        register_per_peer: 2,
        ..Limits::default()
    }));
    let mut h = Harness::with_limiter(limiter);
    let token = h.signup_token();
    let peer = crate::Caller::anonymous().from_peer([10, 0, 0, 9].into());
    let person = Person::new("p");
    let (start, _) = person.register_start(&token);
    assert!(h.server.call(&peer, &start).is_ok());
    assert!(h.server.call(&peer, &start).is_ok());
    let refused = h.server.call(&peer, &start).unwrap_err();
    assert_eq!(refused.code, ErrorCode::RateLimited);
    assert!(h.server.call(&crate::Caller::anonymous(), &start).is_ok());
}

#[test]
fn prelogin_is_rate_limited_per_peer() {
    let limiter = Arc::new(WindowLimiter::new(Limits::default()));
    let h = Harness::with_limiter(limiter);
    let peer = crate::Caller::anonymous().from_peer([10, 0, 0, 7].into());
    let request = Prelogin {
        login: "x".to_owned(),
    };
    for _ in 0..10 {
        h.server.call(&peer, &request).unwrap();
    }
    assert_eq!(
        h.server.call(&peer, &request).unwrap_err().code,
        ErrorCode::RateLimited
    );
}

#[test]
fn requests_that_do_not_decode_are_format_errors() {
    let h = Harness::new();
    let reply = h.server.handle(
        &crate::Caller::anonymous(),
        hasp_proto::wire::OpId::Prelogin,
        &[0xa0],
    );
    let decoded =
        hasp_proto::wire::decode_reply::<hasp_proto::wire::PreloginResponse>(&reply).unwrap();
    assert_eq!(decoded.unwrap_err().code, ErrorCode::Format);
}
