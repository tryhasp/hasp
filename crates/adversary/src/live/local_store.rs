use hasp_core::CoreError;
use hasp_core::client::{Client, ClientConfig};
use hasp_core::store::StoreError;
use hasp_proto::ProtoError;
use hasp_proto::wire::{OpId, PullResponse};
use hasp_testsupport::World;

use super::lab::{PASSWORD, SharedStore, cancel, phone, run, secret};
use super::mallory::{Mallory, edit};

fn head_seq(store: &SharedStore, vault: &hasp_proto::VaultId) -> u64 {
    store
        .cache()
        .vault(vault)
        .unwrap()
        .unwrap()
        .head
        .unwrap()
        .seq
        .get()
}

#[test]
fn a_second_process_with_an_older_view_cannot_lower_the_stored_head() {
    run(async {
        let mut world = World::new();
        let link = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &link, "alice@example.com", true).await;
        let private = alice.private();
        alice.add_login(&private, "One", "1");
        alice.client.sync(&cancel()).await.unwrap();
        let older = alice.store.dump();
        let base = head_seq(&alice.store, &private);
        for title in ["Two", "Three"] {
            alice.add_login(&private, title, "x");
            alice.client.sync(&cancel()).await.unwrap();
        }
        let newer = alice.store.dump();
        assert_eq!(head_seq(&alice.store, &private), base + 2);

        alice.store.load(&older);
        let process_link = Mallory::new(&world.server);
        let mut other = Client::new(
            process_link.clone(),
            alice.store.clone(),
            alice.client.platform_for_tests(),
            ClientConfig::new("macos"),
        );
        other
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let store = alice.store.clone();
        process_link.on_response(OpId::Pull, move |bytes| {
            store.load(&newer);
            edit::<PullResponse>(bytes, |page| {
                for entry in &mut page.vaults {
                    entry.commits.truncate(1);
                    let first = entry.commits[0].manifest.clone();
                    entry.head_seq = first.unverified().unwrap().seq;
                    entry.head_hash = Some(first.hash());
                    entry.has_more = false;
                }
            });
        });
        let outcome = other.sync(&cancel()).await;
        assert!(
            matches!(
                outcome,
                Err(CoreError::Proto(ProtoError::Rollback) | CoreError::Store(StoreError::Stale))
            ),
            "{outcome:?}"
        );
        assert_eq!(head_seq(&alice.store, &private), base + 2);
    });
}
