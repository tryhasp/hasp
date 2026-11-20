use hasp_core::CoreError;
use hasp_proto::wire::{AccountGetResponse, OpId};
use hasp_proto::{PinState, ProtoError, Uint53, Wire, verify_account_record};
use hasp_testsupport::World;

use super::lab::{PASSWORD, SharedStore, cancel, phone, run, secret};
use super::mallory::{Mallory, Verdict, edit};

struct Aged {
    world: World,
    link: Mallory,
    alice: super::lab::Phone,
    stale: Vec<u8>,
}

async fn aged() -> Aged {
    let mut world = World::new();
    let link = Mallory::new(&world.server);
    let mut alice = phone(&mut world, &link, "alice@example.com", true).await;
    alice.client.sync(&cancel()).await.unwrap();
    let stale = link
        .seen_op(OpId::AccountGet)
        .pop()
        .unwrap()
        .response
        .unwrap();
    alice
        .client
        .create_recovery_code(&secret(PASSWORD), &cancel())
        .await
        .unwrap();
    alice.client.sync(&cancel()).await.unwrap();
    Aged {
        world,
        link,
        alice,
        stale,
    }
}

#[test]
fn an_older_account_record_chain_is_a_rollback_for_a_device_that_holds_a_newer_one() {
    run(async {
        let mut aged = Box::pin(aged()).await;
        let stale = aged.stale.clone();
        aged.link
            .on_request(OpId::AccountGet, move |_| Verdict::Reply(stale.clone()));
        let outcome = aged.alice.client.sync(&cancel()).await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Rollback))),
            "{outcome:?}"
        );

        let old = AccountGetResponse::from_cbor(&aged.stale).unwrap();
        assert!(verify_account_record(&old.records[0], None, &PinState::new()).is_ok());
    });
}

#[test]
fn a_lower_keyset_generation_is_a_rollback() {
    run(async {
        let mut aged = Box::pin(aged()).await;
        aged.link.on_response(OpId::AccountGet, |bytes| {
            edit::<AccountGetResponse>(bytes, |reply| reply.keyset.generation = Uint53::ZERO);
        });
        let outcome = aged.alice.client.sync(&cancel()).await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Rollback))),
            "{outcome:?}"
        );
    });
}

#[test]
fn a_device_enrolled_from_a_newer_snapshot_refuses_the_older_record_chain() {
    run(async {
        let mut aged = Box::pin(aged()).await;
        let link = Mallory::new(&aged.world.server);
        let (mut second, _) = aged
            .world
            .client_on(link.clone(), SharedStore::default(), true);
        let invite = aged.alice.client.enrol_open(&cancel()).await.unwrap();
        second.enrol_join(&invite.qr, &cancel()).await.unwrap();
        aged.alice
            .client
            .enrol_poll_request(&cancel())
            .await
            .unwrap();
        let code = second.enrol_reveal(&cancel()).await.unwrap();
        aged.alice
            .client
            .enrol_confirm(&code, &cancel())
            .await
            .unwrap();
        let stale = aged.stale.clone();
        link.on_request(OpId::AccountGet, move |_| Verdict::Reply(stale.clone()));
        let outcome = second.enrol_finish(None, &cancel()).await;
        assert!(
            matches!(outcome, Err(CoreError::Proto(ProtoError::Rollback))),
            "{outcome:?}"
        );
        assert!(!second.is_unlocked());
    });
}
