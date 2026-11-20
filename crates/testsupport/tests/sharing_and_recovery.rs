#![expect(clippy::unwrap_used, reason = "integration test")]

use hasp_core::testing::{login_item, password_of};
use hasp_testsupport::cancel;
use hasp_testsupport::{World, block_on};

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn signs_up_stores_an_item_and_reads_it_back_after_lock_and_unlock() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let client = &mut alice.client;
        let private = client.private_vault().unwrap();
        let id = client
            .create_item(&private, &login_item("Bank", "s3cret"))
            .unwrap();
        assert_eq!(password_of(&client.item(&private, &id).unwrap()), "s3cret");
        let report = client.sync(&cancel()).await.unwrap();
        assert!(
            report
                .vaults
                .iter()
                .all(|v| v.state == hasp_core::sync::VaultSyncState::UpToDate)
        );
        client.lock();
        client
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let items = client.items(&private).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(password_of(&client.item(&private, &id).unwrap()), "s3cret");
        client.lock();
        client.unlock_biometric(&cancel()).await.unwrap();
        assert_eq!(client.items(&private).unwrap()[0].overview.title, "Bank");
    });
}

#[test]
fn a_second_device_enrols_by_qr_with_commit_reveal_and_starts_confirmed() {
    block_on(async {
        let mut world = World::new();
        let mut first = world.signup("alice@example.com", PASSWORD, true).await;
        let private = first.client.private_vault().unwrap();
        let id = first
            .client
            .create_item(&private, &login_item("Mail", "pw1"))
            .unwrap();
        first.client.sync(&cancel()).await.unwrap();

        let mut second = world.device(true);
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second
            .client
            .enrol_join(&invite.qr, &cancel())
            .await
            .unwrap();
        let request = first
            .client
            .enrol_poll_request(&cancel())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.platform, "macos");
        let code = second.client.enrol_reveal(&cancel()).await.unwrap();
        assert!(
            first
                .client
                .enrol_confirm("000000x", &cancel())
                .await
                .is_err()
        );
        first.client.enrol_confirm(&code, &cancel()).await.unwrap();
        second.client.enrol_finish(None, &cancel()).await.unwrap();

        assert!(second.client.device_confirmed().unwrap());
        let items = second.client.items(&private).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            password_of(&second.client.item(&private, &id).unwrap()),
            "pw1"
        );
        let devices = second.client.devices(&cancel()).await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().filter(|d| d.recognised).count() >= 2);
    });
}

#[test]
fn a_wrong_qr_code_three_times_invalidates_the_channel() {
    block_on(async {
        let mut world = World::new();
        let mut first = world.signup("alice@example.com", PASSWORD, true).await;
        let mut second = world.device(true);
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        second
            .client
            .enrol_join(&invite.qr, &cancel())
            .await
            .unwrap();
        first
            .client
            .enrol_poll_request(&cancel())
            .await
            .unwrap()
            .unwrap();
        let code = second.client.enrol_reveal(&cancel()).await.unwrap();
        for _ in 0..3 {
            assert!(
                first
                    .client
                    .enrol_confirm("999999", &cancel())
                    .await
                    .is_err()
            );
        }
        assert!(first.client.enrol_confirm(&code, &cancel()).await.is_err());
        assert!(second.client.enrol_finish(None, &cancel()).await.is_err());
    });
}

async fn share_vault(
    world: &mut World,
) -> (
    hasp_testsupport::Device,
    hasp_testsupport::Device,
    hasp_proto::VaultId,
) {
    use hasp_core::client::FingerprintCheck;
    use hasp_proto::Role;
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
    let vault = alice
        .client
        .create_vault("Family", &cancel())
        .await
        .unwrap();
    let offer = alice
        .client
        .invite_create(&vault, Role::Editor, &cancel())
        .await
        .unwrap();
    let accepted = bob
        .client
        .invite_accept(&offer.code, &cancel())
        .await
        .unwrap();
    assert_eq!(accepted.vault_id, vault);
    let pending = alice
        .client
        .pending_invitees(&vault, &cancel())
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].fingerprint, accepted.my_fingerprint);
    alice
        .client
        .add_member(
            &vault,
            &offer.invite_id,
            &FingerprintCheck::Compared(accepted.my_fingerprint.clone()),
            &cancel(),
        )
        .await
        .unwrap();
    bob.client.sync(&cancel()).await.unwrap();
    (alice, bob, vault)
}

#[test]
fn two_accounts_share_a_vault_with_an_owner_pin_and_see_each_others_items() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(share_vault(&mut world)).await;
        let summary = bob
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == vault)
            .unwrap();
        assert_eq!(summary.name, "Family");
        assert_eq!(summary.members, 2);
        let a = alice
            .client
            .create_item(&vault, &login_item("Netflix", "n1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        assert_eq!(password_of(&bob.client.item(&vault, &a).unwrap()), "n1");
        let b = bob
            .client
            .create_item(&vault, &login_item("Disney", "d1"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(password_of(&alice.client.item(&vault, &b).unwrap()), "d1");
        assert_eq!(alice.client.items(&vault).unwrap().len(), 2);
        let (_, verified) = alice
            .client
            .trusted_key(&bob.client.account_id().unwrap())
            .unwrap()
            .unwrap();
        assert!(verified);
    });
}

#[test]
fn concurrent_edits_resolve_by_server_order_with_history_and_a_notice() {
    use hasp_core::store::EventKind;
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(share_vault(&mut world)).await;
        let x = alice
            .client
            .create_item(&vault, &login_item("Router", "v1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();

        alice
            .client
            .edit_item(&vault, &x, &login_item("Router", "alice-edit"))
            .unwrap();
        bob.client
            .edit_item(&vault, &x, &login_item("Router", "bob-edit"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();

        for client in [&alice.client, &bob.client] {
            assert_eq!(password_of(&client.item(&vault, &x).unwrap()), "bob-edit");
            let versions: Vec<u64> = client
                .history(&vault, &x)
                .unwrap()
                .into_iter()
                .map(|entry| entry.version)
                .collect();
            assert_eq!(versions, vec![3, 2, 1]);
        }
        let notice = bob
            .client
            .events()
            .unwrap()
            .into_iter()
            .find_map(|event| match event.kind {
                EventKind::Conflict {
                    replaced_ver,
                    resurrected,
                    ..
                } => Some((replaced_ver, resurrected)),
                _ => None,
            })
            .unwrap();
        assert_eq!(notice, (2, false));
        bob.client.restore_version(&vault, &x, 2).unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            password_of(&alice.client.item(&vault, &x).unwrap()),
            "alice-edit"
        );
    });
}

#[test]
fn an_edit_over_a_remote_delete_resurrects_the_item_with_a_notice() {
    use hasp_core::store::EventKind;
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(share_vault(&mut world)).await;
        let x = alice
            .client
            .create_item(&vault, &login_item("Old", "v1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.delete_item(&vault, &x).unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client
            .edit_item(&vault, &x, &login_item("Old", "bob"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(password_of(&alice.client.item(&vault, &x).unwrap()), "bob");
        assert!(bob.client.events().unwrap().iter().any(|e| matches!(
            e.kind,
            EventKind::Conflict {
                resurrected: true,
                ..
            }
        )));
    });
}

async fn add_viewer(
    world: &mut World,
    alice: &mut hasp_testsupport::Device,
    vault: &hasp_proto::VaultId,
) -> hasp_testsupport::Device {
    use hasp_core::client::FingerprintCheck;
    use hasp_proto::Role;
    let mut carol = world.signup("carol@example.com", PASSWORD, true).await;
    let offer = alice
        .client
        .invite_create(vault, Role::Viewer, &cancel())
        .await
        .unwrap();
    let accepted = carol
        .client
        .invite_accept(&offer.code, &cancel())
        .await
        .unwrap();
    alice
        .client
        .add_member(
            vault,
            &offer.invite_id,
            &FingerprintCheck::NotCompared,
            &cancel(),
        )
        .await
        .unwrap();
    carol.client.sync(&cancel()).await.unwrap();
    assert_eq!(accepted.role, Role::Viewer);
    carol
}

#[test]
fn removing_a_member_bumps_the_epoch_and_the_removed_member_cannot_read_new_items() {
    use hasp_core::sync::VaultSyncState;
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(share_vault(&mut world)).await;
        let mut carol = Box::pin(add_viewer(&mut world, &mut alice, &vault)).await;
        let old = alice
            .client
            .create_item(&vault, &login_item("Before", "b1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();

        alice
            .client
            .remove_member(&vault, &bob.client.account_id().unwrap(), &cancel())
            .await
            .unwrap();
        let fresh = alice
            .client
            .create_item(&vault, &login_item("After", "a1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();

        let report = bob.client.sync(&cancel()).await.unwrap();
        assert!(
            report
                .vaults
                .iter()
                .any(|v| v.state == VaultSyncState::Removed)
        );
        assert!(bob.client.item(&vault, &fresh).is_err());
        assert_eq!(password_of(&bob.client.item(&vault, &old).unwrap()), "b1");
        assert!(
            bob.client
                .edit_item(&vault, &old, &login_item("Before", "x"))
                .is_err()
        );

        carol.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            password_of(&carol.client.item(&vault, &fresh).unwrap()),
            "a1"
        );
        assert_eq!(password_of(&carol.client.item(&vault, &old).unwrap()), "b1");
        let summary = carol
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == vault)
            .unwrap();
        assert_eq!(summary.epoch, 1);
        assert_eq!(summary.members, 2);
        let carol_write = carol.client.create_item(&vault, &login_item("Nope", "n"));
        assert!(carol_write.is_err());
    });
}

#[test]
fn a_recovery_code_restores_the_account_on_a_new_device_after_the_delay() {
    use hasp_core::CoreError;
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        let id = alice
            .client
            .create_item(&private, &login_item("Vault", "keep"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let code = alice
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();

        let mut fresh = world.device(true);
        let ticket = fresh
            .client
            .recover_start(
                hasp_testsupport::TEST_ORIGIN,
                "alice@example.com",
                code.expose(),
            )
            .await
            .unwrap();
        assert!(matches!(
            fresh
                .client
                .recover_finish(&ticket, &secret("brand new password"), &cancel())
                .await,
            Err(CoreError::Pending { .. })
        ));
        let notified = alice.client.sync(&cancel()).await.unwrap();
        assert!(
            notified
                .events
                .iter()
                .any(|e| matches!(e.kind, hasp_core::store::EventKind::Server { kind: 1, .. }))
        );
        world.clock.advance(25 * 3600);
        let outcome = fresh
            .client
            .recover_finish(&ticket, &secret("brand new password"), &cancel())
            .await
            .unwrap();
        assert_eq!(
            password_of(&fresh.client.item(&private, &id).unwrap()),
            "keep"
        );
        assert!(!fresh.client.device_confirmed().unwrap());
        assert!(outcome.recovery_code.expose().starts_with("R1-"));
        assert!(matches!(
            alice.client.sync(&cancel()).await,
            Err(CoreError::SessionExpired)
        ));
        let mut again = world.device(true);
        again
            .client
            .sign_in(
                &hasp_core::client::SignIn {
                    origin: hasp_testsupport::TEST_ORIGIN,
                    login: "alice@example.com",
                    secret_key: outcome.kit.secret_key(),
                    password: &secret("brand new password"),
                    kit_server_fp: Some(world.fingerprint()),
                },
                &cancel(),
            )
            .await
            .unwrap();
        assert_eq!(again.client.items(&private).unwrap().len(), 1);
    });
}
