use hasp_core::CoreError;
use hasp_core::client::SignIn;
use hasp_core::testing::{login_item, password_of};
use hasp_crypto::sha256;
use hasp_server::ReregisterToken;
use hasp_testsupport::TEST_ORIGIN;
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use crate::gateway::{Live, PASSWORD};

const NEW_MASTER: [u8; 32] = [77; 32];

fn cancel() -> CancellationToken {
    CancellationToken::new()
}

fn fingerprint(live: &Live) -> [u8; 15] {
    let digest = sha256(&[&live.world.server.server_public_key()]);
    let mut out = [0_u8; 15];
    out.copy_from_slice(&digest[..15]);
    out
}

fn token_of(tokens: &[ReregisterToken], login: &str) -> String {
    tokens
        .iter()
        .find(|token| token.login == login)
        .unwrap()
        .token
        .to_text()
}

#[tokio::test]
async fn a_lost_server_secret_is_survived_by_reregistering_with_the_operator_token() {
    let mut live = Live::start().await;
    let (mut alice, secret_key) = live.signup("alice@example.com").await;
    let (_bob, _) = live.signup("bob@example.com").await;
    let private = alice.private_vault().unwrap();
    alice
        .create_item(&private, &login_item("Bank", "hunter2"))
        .unwrap();
    alice.sync(&cancel()).await.unwrap();
    let before = live.world.fingerprint();

    let tokens = live.lose_server_secret(NEW_MASTER).await;
    let after = fingerprint(&live);
    assert_ne!(before, after);

    let password = SecretString::from(PASSWORD);
    let mut stranger = live.client();
    let pinned = stranger
        .sign_in(
            &SignIn {
                origin: TEST_ORIGIN,
                login: "alice@example.com",
                secret_key: &secret_key,
                password: &password,
                kit_server_fp: Some(before),
            },
            &cancel(),
        )
        .await;
    assert!(matches!(pinned, Err(CoreError::ServerKey)), "{pinned:?}");

    alice.lock();

    let alice_token = token_of(&tokens, "alice@example.com");
    let wrong_fp = alice
        .reregister(&alice_token, &password, before, &cancel())
        .await;
    assert!(
        matches!(wrong_fp, Err(CoreError::ServerKey)),
        "{wrong_fp:?}"
    );

    let wrong_password = SecretString::from("not the password at all");
    let denied = alice
        .reregister(&alice_token, &wrong_password, after, &cancel())
        .await;
    assert!(matches!(denied, Err(CoreError::Credentials)), "{denied:?}");

    alice
        .reregister(&alice_token, &password, after, &cancel())
        .await
        .unwrap();
    assert!(alice.is_unlocked());
    alice.sync(&cancel()).await.unwrap();
    assert_eq!(
        password_of(
            &alice
                .item(&private, &alice.items(&private).unwrap()[0].item_id)
                .unwrap()
        ),
        "hunter2"
    );

    let spent = alice
        .reregister(&alice_token, &password, after, &cancel())
        .await;
    assert!(spent.is_err(), "a spent token must not work twice");

    let mut phone = live.sign_in("alice@example.com", &secret_key).await;
    phone.sync(&cancel()).await.unwrap();
    assert_eq!(phone.items(&private).unwrap().len(), 1);

    live.stop().await;
}
