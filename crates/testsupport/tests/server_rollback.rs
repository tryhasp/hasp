#![expect(clippy::unwrap_used, reason = "integration test")]

use hasp_core::CoreError;
use hasp_core::client::{FingerprintCheck, SignIn};
use hasp_core::store::EventKind;
use hasp_core::testing::{login_item, password_of};
use hasp_proto::{ProtoError, Role, VaultId};
use hasp_server::MemoryStore;
use hasp_testsupport::cancel;
use hasp_testsupport::{Device, TEST_ORIGIN, World, block_on};

const PASSWORD: &str = "correct horse battery staple";
const LOGIN: &str = "alice@example.com";

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

fn snapshot(world: &World) -> MemoryStore {
    world.server.with_store(|store| store.clone()).unwrap()
}

fn restore(world: &World, backup: &MemoryStore) {
    world
        .server
        .with_store(|store| *store = backup.clone())
        .unwrap();
}

async fn alice_with_kit(world: &mut World) -> (Device, String) {
    let mut alice = world.signup(LOGIN, PASSWORD, true).await;
    let kit = alice
        .client
        .change_password(&secret(PASSWORD), &secret(PASSWORD), true, &cancel())
        .await
        .unwrap()
        .unwrap();
    let key = kit.secret_key().to_owned();
    (alice, key)
}

async fn second_device(world: &World, secret_key: &str) -> Device {
    let mut device = world.device(true);
    device
        .client
        .sign_in(
            &SignIn {
                origin: TEST_ORIGIN,
                login: LOGIN,
                secret_key,
                password: &secret(PASSWORD),
                kit_server_fp: None,
            },
            &cancel(),
        )
        .await
        .unwrap();
    device.client.sync(&cancel()).await.unwrap();
    device
}

fn titles(device: &Device, vault: &VaultId) -> Vec<String> {
    let mut titles: Vec<String> = device
        .client
        .items(vault)
        .unwrap()
        .into_iter()
        .map(|item| item.overview.title)
        .collect();
    titles.sort();
    titles
}

fn password_for(device: &Device, vault: &VaultId, title: &str) -> String {
    let id = device
        .client
        .items(vault)
        .unwrap()
        .into_iter()
        .find(|item| item.overview.title == title)
        .unwrap()
        .item_id;
    password_of(&device.client.item(vault, &id).unwrap())
}

#[test]
fn a_restored_server_is_reported_as_behind_once_and_blocks_nothing_silently() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, _) = alice_with_kit(&mut world).await;
        let private = alice.client.private_vault().unwrap();
        alice
            .client
            .create_item(&private, &login_item("One", "1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let backup = snapshot(&world);
        alice
            .client
            .create_item(&private, &login_item("Two", "2"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let local_seq = alice.client.heads().unwrap()[0].seq;
        restore(&world, &backup);

        for _ in 0..2 {
            let error = alice.client.sync(&cancel()).await.unwrap_err();
            assert!(
                matches!(error, CoreError::Proto(ProtoError::Rollback)),
                "{error:?}"
            );
        }
        let behind = alice.client.server_behind(&private).unwrap().unwrap();
        assert!(behind < local_seq);
        let summary = alice
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == private)
            .unwrap();
        assert_eq!(summary.server_behind, Some(behind));
        let alarms = alice
            .client
            .events()
            .unwrap()
            .into_iter()
            .filter(|event| matches!(event.kind, EventKind::ServerBehind { .. }))
            .count();
        assert_eq!(alarms, 1);
        assert_eq!(titles(&alice, &private), ["One", "Two"]);
    });
}

#[test]
fn accepting_the_older_server_keeps_every_local_edit_and_pushes_it_as_ordinary_commits() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, key) = alice_with_kit(&mut world).await;
        let private = alice.client.private_vault().unwrap();
        let one = alice
            .client
            .create_item(&private, &login_item("One", "1"))
            .unwrap();
        alice
            .client
            .create_item(&private, &login_item("Gone", "g"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let backup = snapshot(&world);

        alice
            .client
            .edit_item(&private, &one, &login_item("One", "1-edited"))
            .unwrap();
        alice
            .client
            .create_item(&private, &login_item("Two", "2"))
            .unwrap();
        let gone = alice
            .client
            .items(&private)
            .unwrap()
            .into_iter()
            .find(|item| item.overview.title == "Gone")
            .unwrap()
            .item_id;
        alice.client.delete_item(&private, &gone).unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let before = alice.client.heads().unwrap()[0].seq;

        restore(&world, &backup);
        alice.client.sync(&cancel()).await.unwrap_err();

        let accepted = alice
            .client
            .accept_older_server_state(&private, &cancel())
            .await
            .unwrap();
        assert_eq!(accepted.from_seq, before);
        assert!(accepted.to_seq < before);
        assert_eq!(accepted.queued, 3);
        assert_eq!(alice.client.server_behind(&private).unwrap(), None);
        assert_eq!(titles(&alice, &private), ["One", "Two"]);
        assert_eq!(password_for(&alice, &private, "One"), "1-edited");
        assert!(
            alice
                .client
                .items(&private)
                .unwrap()
                .iter()
                .all(|item| item.pending || item.overview.title == "Gone")
        );

        alice.client.sync(&cancel()).await.unwrap();
        assert!(
            alice
                .client
                .items(&private)
                .unwrap()
                .iter()
                .all(|i| !i.pending)
        );
        assert_eq!(titles(&alice, &private), ["One", "Two"]);
        assert!(
            alice
                .client
                .events()
                .unwrap()
                .iter()
                .any(|event| matches!(event.kind, EventKind::RollbackAccepted { .. }))
        );

        let other = second_device(&world, &key).await;
        assert_eq!(titles(&other, &private), ["One", "Two"]);
        assert_eq!(password_for(&other, &private, "One"), "1-edited");
        let history = alice.client.history(&private, &one).unwrap();
        assert_eq!(history.len(), 2);
    });
}

#[test]
fn accepting_without_a_reported_rollback_is_refused() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, _) = alice_with_kit(&mut world).await;
        let private = alice.client.private_vault().unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let error = alice
            .client
            .accept_older_server_state(&private, &cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Refused(_)), "{error:?}");
    });
}

#[test]
fn a_server_that_catches_up_clears_the_report() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, _) = alice_with_kit(&mut world).await;
        let private = alice.client.private_vault().unwrap();
        alice
            .client
            .create_item(&private, &login_item("One", "1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let older = snapshot(&world);
        alice
            .client
            .create_item(&private, &login_item("Two", "2"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let newer = snapshot(&world);

        restore(&world, &older);
        alice.client.sync(&cancel()).await.unwrap_err();
        assert!(alice.client.server_behind(&private).unwrap().is_some());
        restore(&world, &newer);
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(alice.client.server_behind(&private).unwrap(), None);
    });
}

#[test]
fn a_restore_that_loses_a_member_is_not_accepted_and_changes_nothing() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup(LOGIN, PASSWORD, true).await;
        let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
        let vault = alice
            .client
            .create_vault("Shared", &cancel())
            .await
            .unwrap();
        let backup = snapshot(&world);
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
        let before = alice.client.heads().unwrap();

        restore(&world, &backup);
        let first = alice.client.sync(&cancel()).await.unwrap_err();
        assert!(
            matches!(first, CoreError::Proto(ProtoError::Rollback)),
            "{first:?}"
        );
        let error = alice
            .client
            .accept_older_server_state(&vault, &cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Refused(_)), "{error:?}");
        assert_eq!(alice.client.heads().unwrap(), before);
        assert!(alice.client.server_behind(&vault).unwrap().is_some());
    });
}

#[test]
fn a_second_device_whose_history_forked_from_the_restored_server_can_accept_it_too() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, key) = alice_with_kit(&mut world).await;
        let private = alice.client.private_vault().unwrap();
        alice
            .client
            .create_item(&private, &login_item("One", "1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let mut other = second_device(&world, &key).await;
        let backup = snapshot(&world);

        alice
            .client
            .create_item(&private, &login_item("Two", "2"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        other.client.sync(&cancel()).await.unwrap();
        restore(&world, &backup);

        alice.client.sync(&cancel()).await.unwrap_err();
        alice
            .client
            .accept_older_server_state(&private, &cancel())
            .await
            .unwrap();
        alice
            .client
            .create_item(&private, &login_item("Three", "3"))
            .unwrap();
        alice
            .client
            .create_item(&private, &login_item("Four", "4"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();

        other.client.sync(&cancel()).await.unwrap_err();
        assert!(other.client.server_behind(&private).unwrap().is_some());
        let accepted = other
            .client
            .accept_older_server_state(&private, &cancel())
            .await
            .unwrap();
        assert_eq!(other.client.server_behind(&private).unwrap(), None);
        assert_eq!(accepted.queued, 0, "alice already re-pushed the same edits");
        other.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let expected = ["Four", "One", "Three", "Two"];
        assert_eq!(titles(&other, &private), expected);
        assert_eq!(titles(&alice, &private), expected);
    });
}
