#![expect(clippy::unwrap_used, reason = "integration test")]

use hasp_core::CoreError;
use hasp_core::client::{FingerprintCheck, NewAttachment, SignIn, SignUp};
use hasp_core::store::FileStore;
use hasp_core::testing::{login_item, password_of};
use hasp_proto::Role;
use hasp_testsupport::cancel;
use hasp_testsupport::{TEST_ORIGIN, World, block_on};
use tokio_util::sync::CancellationToken;

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

const PASSWORD: &str = "correct horse battery staple";

async fn shared_pair(
    world: &mut World,
) -> (
    hasp_testsupport::Device,
    hasp_testsupport::Device,
    hasp_proto::VaultId,
) {
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
    let vault = alice
        .client
        .create_vault("Shared", &cancel())
        .await
        .unwrap();
    let offer = alice
        .client
        .invite_create(&vault, Role::Viewer, &cancel())
        .await
        .unwrap();
    let accepted = bob
        .client
        .invite_accept(&offer.code, &cancel())
        .await
        .unwrap();
    alice
        .client
        .add_member(
            &vault,
            &offer.invite_id,
            &FingerprintCheck::Compared(accepted.my_fingerprint),
            &cancel(),
        )
        .await
        .unwrap();
    bob.client.sync(&cancel()).await.unwrap();
    (alice, bob, vault)
}

#[test]
fn pruned_server_history_does_not_break_a_device_that_was_offline_or_has_no_state() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(shared_pair(&mut world)).await;
        let item = alice
            .client
            .create_item(&vault, &login_item("Churn", "v0"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        for n in 1..=14 {
            alice
                .client
                .edit_item(&vault, &item, &login_item("Churn", &format!("v{n}")))
                .unwrap();
            alice.client.sync(&cancel()).await.unwrap();
        }
        let report = bob.client.sync(&cancel()).await.unwrap();
        assert!(
            report
                .vaults
                .iter()
                .all(|v| v.state == hasp_core::sync::VaultSyncState::UpToDate)
        );
        assert_eq!(password_of(&bob.client.item(&vault, &item).unwrap()), "v14");
        assert!(bob.client.events().unwrap().iter().any(|event| matches!(
            event.kind,
            hasp_core::store::EventKind::RetentionFallback { vault_id, .. } if vault_id == vault
        )));

        alice
            .client
            .change_password(
                &secret(PASSWORD),
                &secret("a second long password"),
                true,
                &cancel(),
            )
            .await
            .unwrap();
        let kit = alice
            .client
            .change_password(
                &secret("a second long password"),
                &secret(PASSWORD),
                true,
                &cancel(),
            )
            .await
            .unwrap()
            .unwrap();
        let mut fresh = world.device(true);
        fresh
            .client
            .sign_in(
                &SignIn {
                    origin: TEST_ORIGIN,
                    login: "alice@example.com",
                    secret_key: kit.secret_key(),
                    password: &secret(PASSWORD),
                    kit_server_fp: None,
                },
                &cancel(),
            )
            .await
            .unwrap();
        assert_eq!(
            password_of(&fresh.client.item(&vault, &item).unwrap()),
            "v14"
        );
    });
}

#[test]
fn a_cancelled_call_returns_cancelled_and_the_next_call_runs() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let token = CancellationToken::new();
        token.cancel();
        assert!(matches!(
            alice.client.sync(&token).await,
            Err(CoreError::Cancelled)
        ));
        alice.client.cancel();
        alice.client.sync(&cancel()).await.unwrap();
    });
}

#[test]
fn a_file_backed_cache_survives_a_restart_and_unlocks_offline() {
    block_on(async {
        let mut world = World::new();
        let dir = std::env::temp_dir().join(format!("hasp-e2e-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let token = world.token().await;
        let (mut client, _clock) =
            world.client_on(world.transport(), FileStore::open(&dir).unwrap(), true);
        Box::pin(client.sign_up(
            &SignUp {
                origin: TEST_ORIGIN,
                token: &token,
                login: "alice@example.com",
                password: &secret(PASSWORD),
            },
            &cancel(),
        ))
        .await
        .unwrap();
        let private = client.private_vault().unwrap();
        let id = client
            .create_item(&private, &login_item("Disk", "d"))
            .unwrap();
        client.sync(&cancel()).await.unwrap();
        let platform = client.platform_for_tests();
        drop(client);
        let reopened = hasp_core::client::Client::new(
            world.transport(),
            FileStore::open(&dir).unwrap(),
            platform,
            hasp_core::client::ClientConfig::new("macos"),
        );
        let mut client = reopened;
        assert_eq!(
            client.state().unwrap(),
            hasp_core::client::ClientState::Locked
        );
        client
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        assert_eq!(password_of(&client.item(&private, &id).unwrap()), "d");
        std::fs::remove_dir_all(&dir).ok();
    });
}

#[test]
fn a_promoted_viewer_writes_and_keeps_writing_across_an_epoch_bump() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(shared_pair(&mut world)).await;
        assert!(
            bob.client
                .create_item(&vault, &login_item("No", "n"))
                .is_err()
        );
        let bob_id = bob.client.account_id().unwrap();
        alice
            .client
            .change_role(&vault, &bob_id, Role::Editor, &cancel())
            .await
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        let theirs = bob
            .client
            .create_item(&vault, &login_item("Yes", "y"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            password_of(&alice.client.item(&vault, &theirs).unwrap()),
            "y"
        );

        alice.client.bump_epoch(&vault, &cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        let after = bob
            .client
            .create_item(&vault, &login_item("Post", "p"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            password_of(&alice.client.item(&vault, &after).unwrap()),
            "p"
        );
        assert_eq!(
            alice
                .client
                .vaults()
                .unwrap()
                .into_iter()
                .find(|v| v.vault_id == vault)
                .unwrap()
                .epoch,
            1
        );
    });
}

#[test]
fn an_item_with_an_attachment_moves_to_another_vault_and_keeps_its_file() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, _bob, vault) = Box::pin(shared_pair(&mut world)).await;
        let private = alice.client.private_vault().unwrap();
        let doc = alice
            .client
            .create_item(&vault, &login_item("Doc", "d"))
            .unwrap();
        alice
            .client
            .attach_file(
                &vault,
                &doc,
                &NewAttachment {
                    name: "a.txt",
                    mime: "text/plain",
                    data: b"hello attachment",
                },
                &cancel(),
            )
            .await
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let moved = alice
            .client
            .move_item(&vault, &doc, &private, &cancel())
            .await
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert!(alice.client.item(&vault, &doc).is_err());
        let item = alice.client.item(&private, &moved).unwrap();
        let att = hasp_proto::AttId::from_bytes(*item.details().attachments[0].att_id.as_bytes());
        let data = alice
            .client
            .download_attachment(&private, &moved, &att, &cancel())
            .await
            .unwrap();
        assert_eq!(data.as_slice(), b"hello attachment");
    });
}

#[test]
fn rehost_replays_the_verified_copy_into_an_account_on_another_server() {
    block_on(async {
        let mut old = World::new();
        let mut alice = old.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        alice
            .client
            .create_item(&private, &login_item("Move me", "m"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let mut new = World::with_config(|config| {
            config.server_master = hasp_crypto::SecretKey::from_bytes([5; 32]);
        });
        let token = new.token().await;
        let mut target = new.device(true);
        let kit = Box::pin(alice.client.rehost_to(
            &mut target.client,
            &SignUp {
                origin: TEST_ORIGIN,
                token: &token,
                login: "alice@example.com",
                password: &secret(PASSWORD),
            },
            &secret(PASSWORD),
            &cancel(),
        ))
        .await
        .unwrap();
        assert_ne!(kit.server_fingerprint_bytes(), old.fingerprint());
        let private = target.client.private_vault().unwrap();
        target.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            target.client.items(&private).unwrap()[0].overview.title,
            "Move me"
        );
    });
}
