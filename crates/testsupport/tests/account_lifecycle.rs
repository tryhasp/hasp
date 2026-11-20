#![expect(clippy::unwrap_used, reason = "integration test")]

use hasp_core::CoreError;
use hasp_core::client::{FingerprintCheck, SignIn};
use hasp_core::export::Unlock;
use hasp_core::testing::{login_item, password_of};
use hasp_crypto::Argon2idParams;
use hasp_proto::Role;
use hasp_testsupport::cancel;
use hasp_testsupport::{Device, TEST_ORIGIN, World, block_on};

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

const PASSWORD: &str = "correct horse battery staple";

async fn pair(world: &mut World) -> (Device, Device, hasp_proto::VaultId) {
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
    let vault = alice
        .client
        .create_vault("Shared", &cancel())
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

async fn alice_with_a_large_attachment(world: &mut World) -> (Device, Vec<u8>) {
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    let private = alice.client.private_vault().unwrap();
    let id = alice
        .client
        .create_item(&private, &login_item("Docs", "d"))
        .unwrap();
    let data: Vec<u8> = (0..(1 << 20) + 17)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let info = alice
        .client
        .attach_file(
            &private,
            &id,
            &hasp_core::client::NewAttachment {
                name: "scan.bin",
                mime: "application/octet-stream",
                data: &data,
            },
            &cancel(),
        )
        .await
        .unwrap();
    alice.client.sync(&cancel()).await.unwrap();
    let downloaded = alice
        .client
        .download_attachment(&private, &id, &info.att_id, &cancel())
        .await
        .unwrap();
    assert_eq!(downloaded.as_slice(), data.as_slice());
    (alice, data)
}

#[test]
fn export_and_restore_carry_items_and_attachments_into_another_account() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, data) = alice_with_a_large_attachment(&mut world).await;
        let params = Argon2idParams::local(8, 1, 1).unwrap();
        let file = alice
            .client
            .export(
                &secret(PASSWORD),
                &secret("export phrase"),
                params,
                &cancel(),
            )
            .await
            .unwrap();
        assert!(
            alice
                .client
                .export(&secret("wrong password"), &secret("x"), params, &cancel())
                .await
                .is_err()
        );

        let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
        let report = bob
            .client
            .restore(
                &file,
                &Unlock::Passphrase(&secret("export phrase")),
                &cancel(),
            )
            .await
            .unwrap();
        assert_eq!((report.items, report.attachments), (1, 1));
        let bob_private = bob.client.private_vault().unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        let items = bob.client.items(&bob_private).unwrap();
        assert_eq!(items.len(), 1);
        let restored = bob.client.item(&bob_private, &items[0].item_id).unwrap();
        assert_eq!(password_of(&restored), "d");
        let att =
            hasp_proto::AttId::from_bytes(*restored.details().attachments[0].att_id.as_bytes());
        let again = bob
            .client
            .download_attachment(&bob_private, &items[0].item_id, &att, &cancel())
            .await
            .unwrap();
        assert_eq!(again.as_slice(), data.as_slice());
        assert!(matches!(
            bob.client
                .restore(&file, &Unlock::Passphrase(&secret("wrong")), &cancel())
                .await,
            Err(CoreError::Export(
                hasp_core::export::ExportError::WrongPassphrase
            ))
        ));
    });
}

async fn sign_in_with_kit(
    world: &mut World,
    kit: &hasp_core::client::EmergencyKit,
    vault: &hasp_proto::VaultId,
    item: &hasp_proto::ItemId,
) -> Device {
    let mut laptop = world.device(true);
    laptop
        .client
        .sign_in(
            &SignIn {
                origin: TEST_ORIGIN,
                login: "alice@example.com",
                secret_key: kit.secret_key(),
                password: &secret("another long password"),
                kit_server_fp: Some(kit.server_fingerprint_bytes()),
            },
            &cancel(),
        )
        .await
        .unwrap();
    assert!(!laptop.client.device_confirmed().unwrap());
    assert_eq!(password_of(&laptop.client.item(vault, item).unwrap()), "w");
    let edit = laptop
        .client
        .edit_item(vault, item, &login_item("Wifi", "w2"));
    assert!(matches!(edit, Err(CoreError::Unconfirmed)));
    let private = laptop.client.private_vault().unwrap();
    laptop
        .client
        .create_item(&private, &login_item("Own", "o"))
        .unwrap();
    laptop.client.sync(&cancel()).await.unwrap();
    laptop
}

#[test]
fn a_kit_sign_in_is_unconfirmed_until_the_head_codes_match() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, bob, vault) = Box::pin(pair(&mut world)).await;
        let item = alice
            .client
            .create_item(&vault, &login_item("Wifi", "w"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let kit = alice
            .client
            .change_password(
                &secret(PASSWORD),
                &secret("another long password"),
                true,
                &cancel(),
            )
            .await
            .unwrap()
            .unwrap();
        drop(bob);

        let mut laptop = Box::pin(sign_in_with_kit(&mut world, &kit, &vault, &item)).await;

        alice.client.sync(&cancel()).await.unwrap();
        let theirs = laptop.client.heads().unwrap();
        let ours = alice.client.heads().unwrap();
        let head = theirs.iter().find(|h| h.vault_id == vault).unwrap();
        let reference = ours.iter().find(|h| h.vault_id == vault).unwrap();
        assert!(matches!(
            laptop
                .client
                .confirm_head(vault, head.seq + 1, &reference.code)
                .unwrap(),
            hasp_core::client::Confirmation::NeedsSync { .. }
        ));
        assert!(
            laptop
                .client
                .confirm_head(vault, head.seq, "AAAA-AAAA")
                .is_err()
        );
        assert_eq!(
            laptop
                .client
                .confirm_head(vault, reference.seq, &reference.code)
                .unwrap(),
            hasp_core::client::Confirmation::Confirmed
        );
        laptop
            .client
            .edit_item(&vault, &item, &login_item("Wifi", "w2"))
            .unwrap();
        laptop.client.sync(&cancel()).await.unwrap();
    });
}

#[test]
fn a_leaving_member_is_removed_by_the_owner_and_can_be_invited_back() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(pair(&mut world)).await;
        let kept = alice
            .client
            .create_item(&vault, &login_item("Shared pw", "s"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        bob.client.leave_vault(&vault, &cancel()).await.unwrap();
        assert!(
            bob.client
                .create_item(&vault, &login_item("x", "x"))
                .is_err()
        );
        alice.client.sync(&cancel()).await.unwrap();
        let bob_id = bob.client.account_id().unwrap();
        assert_eq!(alice.client.pending_leaves(&vault).unwrap(), vec![bob_id]);
        alice
            .client
            .remove_member(&vault, &bob_id, &cancel())
            .await
            .unwrap();
        assert!(alice.client.pending_leaves(&vault).unwrap().is_empty());
        let secret_after = alice
            .client
            .create_item(&vault, &login_item("After", "a"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        assert!(bob.client.item(&vault, &secret_after).is_err());

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
        assert_eq!(
            password_of(&bob.client.item(&vault, &secret_after).unwrap()),
            "a"
        );
        assert_eq!(password_of(&bob.client.item(&vault, &kept).unwrap()), "s");
        bob.client
            .create_item(&vault, &login_item("Back", "b"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
    });
}

#[test]
fn dissolving_a_vault_leaves_members_a_read_only_local_copy() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, vault) = Box::pin(pair(&mut world)).await;
        let item = alice
            .client
            .create_item(&vault, &login_item("Last", "l"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        assert!(matches!(
            alice
                .client
                .dissolve_vault(&vault, "wrong name", &secret(PASSWORD), &cancel())
                .await,
            Err(CoreError::Refused(_))
        ));
        assert!(matches!(
            bob.client
                .dissolve_vault(&vault, "Shared", &secret(PASSWORD), &cancel())
                .await,
            Err(CoreError::Proto(hasp_proto::ProtoError::Authz))
        ));
        alice
            .client
            .dissolve_vault(&vault, "Shared", &secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let report = bob.client.sync(&cancel()).await.unwrap();
        assert!(
            report
                .vaults
                .iter()
                .any(|v| v.state == hasp_core::sync::VaultSyncState::Dissolved)
        );
        assert!(matches!(
            bob.client.create_item(&vault, &login_item("y", "y")),
            Err(CoreError::VaultInactive("dissolved"))
        ));
        assert_eq!(password_of(&bob.client.item(&vault, &item).unwrap()), "l");
    });
}

#[test]
fn password_only_platforms_unlock_with_the_password_and_throttle_failures() {
    block_on(async {
        let mut world = World::new();
        let mut linux = world.signup("alice@example.com", PASSWORD, false).await;
        let private = linux.client.private_vault().unwrap();
        linux
            .client
            .create_item(&private, &login_item("L", "l"))
            .unwrap();
        linux.client.lock();
        assert!(linux.client.unlock_biometric(&cancel()).await.is_err());
        for _ in 0..5 {
            assert!(matches!(
                linux
                    .client
                    .unlock_password(&secret("wrong password"), &cancel())
                    .await,
                Err(CoreError::Credentials)
            ));
        }
        assert!(matches!(
            linux
                .client
                .unlock_password(&secret(PASSWORD), &cancel())
                .await,
            Err(CoreError::Pending { .. })
        ));
        linux.clock.advance(3600);
        linux
            .client
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        assert_eq!(linux.client.items(&private).unwrap().len(), 1);
    });
}

#[test]
fn devices_are_listed_revoked_and_the_account_can_be_deleted() {
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
        first.client.enrol_confirm(&code, &cancel()).await.unwrap();
        second.client.enrol_finish(None, &cancel()).await.unwrap();

        let devices = first.client.devices(&cancel()).await.unwrap();
        let other = devices.iter().find(|d| !d.current).unwrap().clone();
        first
            .client
            .revoke_device(&other.session_id, &other.device_id, &cancel())
            .await
            .unwrap();
        let after = first.client.devices(&cancel()).await.unwrap();
        assert_eq!(after.len(), 1);
        assert!(matches!(
            second.client.sync(&cancel()).await,
            Err(CoreError::SessionExpired)
        ));

        first
            .client
            .delete_account(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        assert_eq!(
            first.client.state().unwrap(),
            hasp_core::client::ClientState::Empty
        );
        let mut again = world.device(true);
        assert!(
            again
                .client
                .sign_in(
                    &SignIn {
                        origin: TEST_ORIGIN,
                        login: "alice@example.com",
                        secret_key: "V1-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
                        password: &secret(PASSWORD),
                        kit_server_fp: None,
                    },
                    &cancel(),
                )
                .await
                .is_err()
        );
    });
}
