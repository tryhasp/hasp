use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::client::{Client, Confirmation};
use hasp_proto::wire::{OpId, Pull, PullResponse, VaultCursor};
use hasp_proto::{ProtoError, Role, Uint53};
use hasp_testsupport::World;

use super::lab::{PASSWORD, cancel, kit_device, login_item, phone, run, secret, share};
use super::mallory::{Mallory, Verdict, edit};

#[test]
fn e20_a_server_restored_from_an_older_backup_is_a_rollback_the_device_refuses() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice.add_login(&private, "One", "1");
        alice.client.sync(&cancel()).await.unwrap();
        let backup = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&backup);
        mallory.on_response(OpId::Pull, move |bytes| {
            *sink.lock().unwrap() = Some(bytes.clone());
        });
        alice.client.sync(&cancel()).await.unwrap();
        mallory.passthrough();
        alice.add_login(&private, "Two", "2");
        alice.client.sync(&cancel()).await.unwrap();
        assert_eq!(alice.client.items(&private).unwrap().len(), 2);

        let stale = backup.lock().unwrap().clone().unwrap();
        mallory.on_request(OpId::Pull, move |_| Verdict::Reply(stale.clone()));
        let error = alice.client.sync(&cancel()).await.unwrap_err();
        assert!(
            matches!(error, CoreError::Proto(ProtoError::Rollback)),
            "{error:?}"
        );
        assert_eq!(alice.client.items(&private).unwrap().len(), 2);
    });
}

#[test]
fn e20_a_device_restored_from_an_older_local_snapshot_catches_up_by_verifying_the_chain() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice.add_login(&private, "One", "1");
        alice.client.sync(&cancel()).await.unwrap();
        let snapshot = alice.store.dump();
        alice.add_login(&private, "Two", "2");
        alice.client.sync(&cancel()).await.unwrap();

        alice.store.load(&snapshot);
        let mut restored = Client::new(
            mallory.clone(),
            alice.store.clone(),
            alice.client.platform_for_tests(),
            hasp_core::client::ClientConfig::new("macos"),
        );
        restored
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        assert_eq!(restored.items(&private).unwrap().len(), 1);
        restored.sync(&cancel()).await.unwrap();
        assert_eq!(restored.items(&private).unwrap().len(), 2);
    });
}

#[test]
fn e5_reading_decrypted_items_makes_no_network_call() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        let id = alice
            .client
            .create_item(
                &private,
                &login_item("https://tracker.example/icon.png", "x"),
            )
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let mark = mallory.mark();
        alice.client.items(&private).unwrap();
        alice.client.item(&private, &id).unwrap();
        alice.client.vaults().unwrap();
        alice.client.history(&private, &id).unwrap();
        assert!(mallory.ops_since(mark).is_empty());
    });
}

#[test]
fn e23_an_unconfirmed_device_served_the_pre_removal_state_reads_it_but_cannot_write_shared() {
    run(async {
        let mut world = World::new();
        let mallory = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let mut bob = phone(&mut world, &mallory, "bob@example.com", true).await;
        let vault = share(&mut alice, &mut bob, "Family", Role::Editor).await;
        alice.add_login(&vault, "Wifi", "w");
        alice.client.sync(&cancel()).await.unwrap();

        let token = mallory.stolen_token();
        let stale_all = mallory
            .as_thief(
                &token,
                &Pull {
                    vaults: vec![VaultCursor {
                        vault_id: vault,
                        seq: hasp_proto::Seq::new(0).unwrap(),
                    }],
                    notices_after: Uint53::ZERO,
                    limit: Uint53::ZERO,
                },
            )
            .unwrap();
        let stale_page = stale_all.vaults[0].clone();
        let bob_id = bob.client.account_id().unwrap();
        alice
            .client
            .remove_member(&vault, &bob_id, &cancel())
            .await
            .unwrap();
        alice.add_login(&vault, "After removal", "a");
        alice.client.sync(&cancel()).await.unwrap();
        let alice_head = alice.heads_of(&vault);

        let link = Mallory::new(&world.server);
        link.on_response(OpId::Pull, move |bytes| {
            edit::<PullResponse>(bytes, |page| {
                for entry in &mut page.vaults {
                    if entry.vault_id == stale_page.vault_id {
                        *entry = stale_page.clone();
                    }
                }
            });
        });
        let mut laptop = kit_device(&world, &link, alice.kit(), "alice@example.com", PASSWORD)
            .await
            .unwrap();
        link.passthrough();
        assert!(!laptop.client.device_confirmed().unwrap());
        let stale_titles = laptop.client.items(&vault).unwrap();
        assert_eq!(stale_titles.len(), 1);
        let blocked = laptop.client.create_item(&vault, &login_item("x", "x"));
        assert!(
            matches!(blocked, Err(CoreError::Unconfirmed)),
            "{blocked:?}"
        );
        laptop.add_login(&laptop.private(), "private ok", "p");

        let mine = laptop.heads_of(&vault);
        assert!(mine.seq < alice_head.seq);
        assert_ne!(mine.code, alice_head.code);
        let behind = laptop
            .client
            .confirm_head(vault, alice_head.seq, &alice_head.code)
            .unwrap();
        assert!(
            matches!(behind, Confirmation::NeedsSync { .. }),
            "{behind:?}"
        );
        let fork = laptop
            .client
            .confirm_head(vault, mine.seq, &alice_head.code);
        assert!(
            matches!(fork, Err(CoreError::Proto(ProtoError::Fork))),
            "{fork:?}"
        );
        assert!(!laptop.client.device_confirmed().unwrap());

        laptop.client.sync(&cancel()).await.unwrap();
        let current = laptop.heads_of(&vault);
        assert_eq!(current.code, alice_head.code);
        assert_eq!(
            laptop
                .client
                .confirm_head(vault, alice_head.seq, &alice_head.code)
                .unwrap(),
            Confirmation::Confirmed
        );
        assert_eq!(laptop.client.items(&vault).unwrap().len(), 2);
    });
}
