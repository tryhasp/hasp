mod account_rollback;
mod attachments;
mod enrol_model;
mod enrolment;
mod enumeration;
mod escrow;
mod extension;
mod extension_channel;
mod history;
mod lab;
mod lair;
mod local_store;
mod mallory;
mod pages;
mod recovery;
mod removal;
mod rogue;
mod roles;
mod rollback;
mod server_key;
mod session_key;
mod sessions;

#[test]
fn a_client_signs_up_and_syncs_through_the_forwarding_transport() {
    use lab::{login_item, phone, run};
    run(async {
        let mut world = hasp_testsupport::World::new();
        let mallory = mallory::Mallory::new(&world.server);
        let mut alice = phone(&mut world, &mallory, "alice@example.com", true).await;
        let private = alice.private();
        alice
            .client
            .create_item(&private, &login_item("Mail", "pw"))
            .unwrap();
        alice.client.sync(&lab::cancel()).await.unwrap();
        assert!(mallory.head(&private).is_some());
        assert!(!mallory.seen_op(hasp_proto::wire::OpId::Commit).is_empty());
    });
}
