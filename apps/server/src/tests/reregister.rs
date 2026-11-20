use hasp_crypto::{OpaqueClientRegistration, OpaqueIdentities, SecretKey};
use hasp_proto::wire::{
    AccountGet, ErrorCode, RegisterStart, ReregisterFinish, ReregisterStart, SignupToken,
};

use super::Harness;
use super::vault::code;
use crate::fixture::{Client, ORIGIN};
use crate::{Clock, ReregisterToken, issue_reregister_tokens};

const TTL: u64 = 3600;

fn issue(h: &Harness) -> Vec<ReregisterToken> {
    let now = h.clock.now();
    h.server
        .with_store(|store| issue_reregister_tokens(store, now, TTL))
        .unwrap()
        .unwrap()
}

fn token_of(tokens: &[ReregisterToken], client: &Client) -> SignupToken {
    tokens
        .iter()
        .find(|issued| issued.account_id == client.person.account_id)
        .unwrap()
        .token
        .clone()
}

fn credential(h: &Harness, client: &Client, token: &SignupToken) -> (SecretKey, Vec<u8>) {
    let opk = SecretKey::random().unwrap();
    let (state, request) = OpaqueClientRegistration::start(&opk).unwrap();
    let response = h
        .call(
            None,
            &ReregisterStart {
                token: token.clone(),
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
    (opk, record)
}

#[test]
fn a_reregister_token_replaces_the_credential_of_its_account_only_and_once() {
    let mut h = Harness::new();
    let mut alice = h.signup("alice");
    let bob = h.signup("bob");
    let tokens = issue(&h);
    assert_eq!(tokens.len(), 2);
    let token = token_of(&tokens, &alice);

    let (opk, record) = credential(&h, &alice, &token);
    let finish = ReregisterFinish {
        token: token.clone(),
        record: record.into(),
    };
    h.call(None, &finish).unwrap();
    assert_eq!(code(h.call(None, &finish)), ErrorCode::Auth);

    assert_eq!(
        code(h.call(Some(&alice.token), &AccountGet)),
        ErrorCode::Auth
    );
    assert_eq!(code(h.try_login(&alice.person)), ErrorCode::Auth);
    alice.person.opk = opk;
    h.try_login(&alice.person).unwrap();
    h.try_login(&bob.person).unwrap();
    h.call(Some(&bob.token), &AccountGet).unwrap();
}

#[test]
fn only_an_unspent_unexpired_reregister_token_of_the_right_kind_is_accepted() {
    let mut h = Harness::new();
    let alice = h.signup("alice");
    let signup = h.signup_token();
    let probe = |token: &SignupToken| {
        let (_, request) = OpaqueClientRegistration::start(&SecretKey::random().unwrap()).unwrap();
        code(h.call(
            None,
            &ReregisterStart {
                token: token.clone(),
                request: request.into(),
            },
        ))
    };
    assert_eq!(probe(&signup), ErrorCode::Auth);
    assert_eq!(probe(&SignupToken::random().unwrap()), ErrorCode::Auth);

    let tokens = issue(&h);
    let token = token_of(&tokens, &alice);
    let (_, request) = OpaqueClientRegistration::start(&SecretKey::random().unwrap()).unwrap();
    let as_signup = h.call(
        None,
        &RegisterStart {
            token: token.clone(),
            login: "mallory".to_owned(),
            account_id: hasp_proto::AccountId::from_bytes([9; 16]),
            request: request.into(),
        },
    );
    assert_eq!(code(as_signup), ErrorCode::Auth);

    h.clock.advance(TTL + 1);
    assert_eq!(probe(&token), ErrorCode::Auth);
}
