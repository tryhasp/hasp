use hasp_proto::VaultKind;
use hasp_proto::wire::{
    AccountGet, AdminAccountDelete, AdminAccountList, AdminAccountUpdate, AdminTokenCreate,
    ErrorCode, Prelogin, TokenKind, WireError,
};

use super::vault::code;
use super::Harness;
use crate::fixture::{Person, VaultModel};

fn prelogin(h: &Harness, login: &str) -> Result<hasp_proto::wire::PreloginResponse, WireError> {
    h.call(
        None,
        &Prelogin {
            login: login.to_owned(),
        },
    )
}

#[test]
fn admin_operations_are_admin_only_and_guard_self_harm() {
    let mut h = Harness::new();
    let admin = h.signup("admin");
    let member = h.signup("member");
    assert_eq!(
        code(h.call(Some(&member.token), &AdminAccountList)),
        ErrorCode::Authz
    );
    assert_eq!(
        code(h.call(
            Some(&member.token),
            &AdminTokenCreate {
                kind: TokenKind::Signup
            }
        )),
        ErrorCode::Authz
    );
    let listed = h.call(Some(&admin.token), &AdminAccountList).unwrap();
    assert_eq!(listed.accounts.len(), 2);
    assert!(
        listed
            .accounts
            .iter()
            .find(|a| a.login == "admin")
            .unwrap()
            .is_admin
    );
    assert!(
        !listed
            .accounts
            .iter()
            .find(|a| a.login == "member")
            .unwrap()
            .is_admin
    );
    assert_eq!(
        code(h.call(
            Some(&admin.token),
            &AdminTokenCreate {
                kind: TokenKind::Rehost
            }
        )),
        ErrorCode::Unsupported
    );
    let self_disable = AdminAccountUpdate {
        account_id: admin.person.account_id,
        disabled: true,
        is_admin: true,
    };
    assert_eq!(
        code(h.call(Some(&admin.token), &self_disable)),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(h.call(
            Some(&admin.token),
            &AdminAccountDelete {
                account_id: admin.person.account_id
            }
        )),
        ErrorCode::Conflict
    );
}

#[test]
fn disabling_an_account_revokes_its_sessions_and_blocks_login_until_enabled() {
    let mut h = Harness::new();
    let admin = h.signup("admin");
    let member = h.signup("member");
    let update = |disabled| AdminAccountUpdate {
        account_id: member.person.account_id,
        disabled,
        is_admin: false,
    };
    h.call(Some(&admin.token), &update(true)).unwrap();
    assert_eq!(
        code(h.call(Some(&member.token), &AccountGet)),
        ErrorCode::Auth
    );
    assert_eq!(code(h.try_login(&member.person)), ErrorCode::Auth);
    assert_eq!(
        prelogin(&h, "member").unwrap().account_id,
        member.person.account_id
    );
    h.call(Some(&admin.token), &update(false)).unwrap();
    h.try_login(&member.person).unwrap();
}

#[test]
fn admin_deletes_an_account_and_makes_tokens_that_register() {
    let mut h = Harness::new();
    let admin = h.signup("admin");
    let member = h.signup("member");
    h.call(
        Some(&admin.token),
        &AdminAccountDelete {
            account_id: member.person.account_id,
        },
    )
    .unwrap();
    assert_eq!(code(h.try_login(&member.person)), ErrorCode::Auth);
    let token = h
        .call(
            Some(&admin.token),
            &AdminTokenCreate {
                kind: TokenKind::Signup,
            },
        )
        .unwrap();
    assert!(token.expires.get() > 0);
    let person = Person::new("fresh");
    let mut vault = VaultModel::new(VaultKind::Private, &person);
    h.try_register(&token.token, &person, &mut vault).unwrap();
}

#[test]
fn the_bootstrap_token_is_one_time_and_makes_the_first_account_admin() {
    let mut h = Harness::new();
    let first = h.signup("first");
    assert!(h.server.issue_bootstrap_token().is_err());
    let listed = h.call(Some(&first.token), &AdminAccountList).unwrap();
    assert!(listed.accounts[0].is_admin);
    let second = h.signup("second");
    assert_eq!(
        code(h.call(Some(&second.token), &AdminAccountList)),
        ErrorCode::Authz
    );
}
