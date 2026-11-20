use hasp_proto::wire::{
    AccountDelete, AccountGet, AccountLookup, ChangeCredentialFinish, ChangeCredentialStart,
    ErrorCode, Prelogin, SessionList, WireError,
};
use hasp_proto::{AccountStatus, KdfWire, Role, SigLabel, Signed};

use super::vault::{code, shared_vault};
use super::Harness;
use crate::fixture::{ORIGIN, Person};

fn prelogin(h: &Harness, login: &str) -> Result<hasp_proto::wire::PreloginResponse, WireError> {
    h.call(
        None,
        &Prelogin {
            login: login.to_owned(),
        },
    )
}

#[test]
fn account_lookup_finds_records_by_login() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let found = h
        .call(
            Some(&bob.token),
            &AccountLookup {
                login: "alice".to_owned(),
            },
        )
        .unwrap();
    assert_eq!(found.account, Some(alice.person.head.clone()));
    let missing = h
        .call(
            Some(&bob.token),
            &AccountLookup {
                login: "carol".to_owned(),
            },
        )
        .unwrap();
    assert!(missing.account.is_none());
    assert_eq!(
        code(h.call(
            None,
            &AccountLookup {
                login: "alice".to_owned()
            }
        )),
        ErrorCode::Auth
    );
}

#[test]
fn changing_the_credential_needs_reauth_and_revokes_other_sessions() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let (other_id, other_token) = h.try_login(&alice.person).unwrap();
    let new_opk = hasp_crypto::SecretKey::random().unwrap();
    let (state, request) = hasp_crypto::OpaqueClientRegistration::start(&new_opk).unwrap();
    let start = ChangeCredentialStart {
        request: request.into(),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &start)),
        ErrorCode::ReauthRequired
    );
    h.reauth(&alice.person, &alice.token).unwrap();
    let response = h.call(Some(&alice.token), &start).unwrap();
    let record = state
        .finish(
            response.response.as_slice(),
            &hasp_crypto::OpaqueIdentities {
                client: alice.person.account_id.as_bytes(),
                server: ORIGIN.as_bytes(),
            },
        )
        .unwrap();

    let mut stale_keyset = alice.person.keyset();
    stale_keyset.generation = hasp_proto::Uint53::ZERO;
    let rollback = ChangeCredentialFinish {
        record: record.clone().into(),
        keyset: stale_keyset,
        account: None,
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &rollback)),
        ErrorCode::Rollback
    );

    let finish = ChangeCredentialFinish {
        record: record.into(),
        keyset: alice.person.keyset(),
        account: None,
    };
    h.call(Some(&alice.token), &finish).unwrap();
    assert!(h.call(Some(&alice.token), &AccountGet).is_ok());
    assert_eq!(
        code(h.call(Some(&other_token), &AccountGet)),
        ErrorCode::Auth
    );
    let sessions = h.call(Some(&alice.token), &SessionList).unwrap().sessions;
    assert!(sessions.iter().all(|s| s.session_id != other_id));
    assert_eq!(prelogin(&h, "alice").unwrap().cred_gen.get(), 2);

    assert_eq!(code(h.try_login(&alice.person)), ErrorCode::Auth);
    alice.person.opk = new_opk;
    h.try_login(&alice.person).unwrap();
}

#[test]
fn a_kdf_change_travels_as_the_next_account_record() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    h.reauth(&alice.person, &alice.token).unwrap();
    let stronger = hasp_proto::AccountRecord {
        kdf: KdfWire {
            m: 131_072,
            t: 4,
            p: 4,
        },
        seq: hasp_proto::Seq::new(2).unwrap(),
        prev: Some(alice.person.head.hash()),
        ..alice.person.record()
    };
    let next = Signed::sign(SigLabel::Account, &stronger, &alice.person.signing).unwrap();
    let new_opk = hasp_crypto::SecretKey::random().unwrap();
    let (state, request) = hasp_crypto::OpaqueClientRegistration::start(&new_opk).unwrap();
    let response = h
        .call(
            Some(&alice.token),
            &ChangeCredentialStart {
                request: request.into(),
            },
        )
        .unwrap();
    let record = state
        .finish(
            response.response.as_slice(),
            &hasp_crypto::OpaqueIdentities {
                client: alice.person.account_id.as_bytes(),
                server: ORIGIN.as_bytes(),
            },
        )
        .unwrap();
    let finish = |account: Option<Signed<hasp_proto::AccountRecord>>| ChangeCredentialFinish {
        record: record.clone().into(),
        keyset: alice.person.keyset(),
        account,
    };
    let unchained = Signed::sign(
        SigLabel::Account,
        &hasp_proto::AccountRecord {
            prev: None,
            ..stronger.clone()
        },
        &alice.person.signing,
    )
    .unwrap();
    assert!(
        h.call(Some(&alice.token), &finish(Some(unchained)))
            .is_err()
    );
    let weaker = Signed::sign(
        SigLabel::Account,
        &hasp_proto::AccountRecord {
            kdf: KdfWire {
                m: 1024,
                t: 1,
                p: 1,
            },
            ..stronger.clone()
        },
        &alice.person.signing,
    )
    .unwrap();
    assert_eq!(
        code(h.call(Some(&alice.token), &finish(Some(weaker)))),
        ErrorCode::KdfParams
    );
    h.call(Some(&alice.token), &finish(Some(next.clone())))
        .unwrap();
    alice.person.opk = new_opk;
    alice.person.head = next;
    assert_eq!(prelogin(&h, "alice").unwrap().kdf, stronger.kdf);
    let chain = h.call(Some(&alice.token), &AccountGet).unwrap().records;
    assert_eq!(chain.len(), 2);
}

#[test]
fn reauth_with_the_wrong_password_fails_and_the_mark_expires() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let mut wrong = Person::new("alice");
    wrong.account_id = alice.person.account_id;
    wrong.head = alice.person.head.clone();
    assert_eq!(code(h.reauth(&wrong, &alice.token)), ErrorCode::Auth);
    h.reauth(&alice.person, &alice.token).unwrap();
    let probe = || {
        h.call(
            Some(&alice.token),
            &ChangeCredentialStart {
                request: vec![].into(),
            },
        )
    };
    assert_ne!(code(probe()), ErrorCode::ReauthRequired);
    h.clock.advance(301);
    assert_eq!(code(probe()), ErrorCode::ReauthRequired);
}

#[test]
fn deleting_an_account_frees_the_login_and_removes_its_data() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let delete = AccountDelete {
        account: bob.person.next_record(0, AccountStatus::Deleted),
    };
    assert_eq!(
        code(h.call(Some(&bob.token), &delete)),
        ErrorCode::ReauthRequired
    );
    h.reauth(&bob.person, &bob.token).unwrap();
    let live = AccountDelete {
        account: bob.person.next_record(0, AccountStatus::Active),
    };
    assert_eq!(code(h.call(Some(&bob.token), &live)), ErrorCode::Format);
    h.call(Some(&bob.token), &delete).unwrap();
    assert_eq!(code(h.call(Some(&bob.token), &AccountGet)), ErrorCode::Auth);
    assert_eq!(code(h.try_login(&bob.person)), ErrorCode::Auth);
    let seen = h
        .call(
            Some(&alice.token),
            &AccountLookup {
                login: "bob".to_owned(),
            },
        )
        .unwrap();
    assert!(seen.account.is_none());
    let counts = h
        .server
        .with_store(|store| {
            use crate::store::Store;
            (
                store.vaults().len().unwrap(),
                store.accounts().len().unwrap(),
            )
        })
        .unwrap();
    assert_eq!(counts, (1, 1));
    let reused = h.signup("bob");
    assert_ne!(reused.person.account_id, bob.person.account_id);
}

#[test]
fn deletion_waits_for_owned_and_joined_shared_vaults() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let bob = h.signup("bob");
    let mut model = shared_vault(&h, &alice);
    super::members::invite_raw(&h, &alice, &bob.token, &model, Role::Editor);
    let bundle = model.add_member(&alice.person, &bob.person, Role::Editor);
    h.call(Some(&alice.token), &model.commit(bundle)).unwrap();
    h.reauth(&alice.person, &alice.token).unwrap();
    h.reauth(&bob.person, &bob.token).unwrap();
    let owner_delete = AccountDelete {
        account: alice.person.next_record(0, AccountStatus::Deleted),
    };
    assert_eq!(
        code(h.call(Some(&alice.token), &owner_delete)),
        ErrorCode::Conflict
    );
    let member_delete = AccountDelete {
        account: bob.person.next_record(0, AccountStatus::Deleted),
    };
    assert_eq!(
        code(h.call(Some(&bob.token), &member_delete)),
        ErrorCode::Conflict
    );
}
