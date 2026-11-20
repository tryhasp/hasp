use hasp_core::CoreError;
use hasp_core::client::SignIn;
use hasp_crypto::{OpaqueIdentities, SecretKey, sha256};
use hasp_proto::wire::{OpId, OpaquePurpose, ServerKeyResponse, opaque_context};
use hasp_server::fixture::Person;
use hasp_testsupport::World;

use super::lab::{ORIGIN, PASSWORD, SharedStore, cancel, phone, run, secret};
use super::mallory::{Mallory, edit};

fn swap_key(mallory: &Mallory) {
    mallory.on_response(OpId::ServerKey, |bytes| {
        edit::<ServerKeyResponse>(bytes, |r| r.public_key.0[0] ^= 1);
    });
}

#[test]
fn e19_a_swapped_server_key_or_origin_is_refused_before_any_login() {
    run(async {
        let mut world = World::new();
        let honest = Mallory::new(&world.server);
        let alice = phone(&mut world, &honest, "alice@example.com", true).await;
        for tamper in [0, 1] {
            let link = Mallory::new(&world.server);
            if tamper == 0 {
                swap_key(&link);
            } else {
                link.on_response(OpId::ServerKey, |bytes| {
                    edit::<ServerKeyResponse>(bytes, |r| r.origin = "https://evil.test".to_owned());
                });
            }
            let (mut laptop, _) = world.client_on(link.clone(), SharedStore::default(), true);
            let result = laptop
                .sign_in(
                    &SignIn {
                        origin: ORIGIN,
                        login: "alice@example.com",
                        secret_key: alice.kit().secret_key(),
                        password: &secret(PASSWORD),
                        kit_server_fp: Some(alice.kit().server_fingerprint_bytes()),
                    },
                    &cancel(),
                )
                .await;
            assert!(matches!(result, Err(CoreError::ServerKey)), "{result:?}");
            assert_eq!(link.ops(), vec![OpId::ServerKey]);
        }
    });
}

#[test]
fn e19_qr_enrolment_refuses_a_swapped_server_key_before_posting_anything() {
    run(async {
        let mut world = World::new();
        let honest = Mallory::new(&world.server);
        let mut alice = phone(&mut world, &honest, "alice@example.com", true).await;
        let invite = alice.client.enrol_open(&cancel()).await.unwrap();
        let link = Mallory::new(&world.server);
        swap_key(&link);
        let (mut laptop, _) = world.client_on(link.clone(), SharedStore::default(), true);
        let result = laptop.enrol_join(&invite.qr, &cancel()).await;
        assert!(matches!(result, Err(CoreError::ServerKey)), "{result:?}");
        assert_eq!(link.ops(), vec![OpId::ServerKey]);
    });
}

#[test]
fn e19_a_pinned_key_that_changes_after_first_contact_blocks_the_relogin() {
    run(async {
        let mut world = World::new();
        let honest = Mallory::new(&world.server);
        let alice = phone(&mut world, &honest, "alice@example.com", true).await;
        let link = Mallory::new(&world.server);
        let (mut laptop, _) = world.client_on(link.clone(), SharedStore::default(), true);
        laptop
            .sign_in(
                &SignIn {
                    origin: ORIGIN,
                    login: "alice@example.com",
                    secret_key: alice.kit().secret_key(),
                    password: &secret(PASSWORD),
                    kit_server_fp: None,
                },
                &cancel(),
            )
            .await
            .unwrap();
        world.clock.advance(31 * 24 * 3600);
        swap_key(&link);
        let mark = link.mark();
        laptop.lock();
        let result = laptop.unlock_password(&secret(PASSWORD), &cancel()).await;
        assert!(matches!(result, Err(CoreError::ServerKey)), "{result:?}");
        assert!(!link.ops_since(mark).contains(&OpId::LoginStart));
    });
}

#[test]
fn e19_the_opaque_server_key_differs_per_server_so_a_pin_comparison_catches_a_restored_secret() {
    run(async {
        let first = World::new();
        let second = World::with_config(|c| c.server_master = SecretKey::from_bytes([42; 32]));
        let person = Person::new("dana@example.com");
        let mut keys = Vec::new();
        for world in [&first, &second] {
            let mallory = Mallory::new(&world.server);
            let token = world.server.issue_bootstrap_token().unwrap();
            let mut model =
                hasp_server::fixture::VaultModel::new(hasp_proto::VaultKind::Private, &person);
            let (start, state) = person.register_start(&token);
            let response = mallory.anonymous(&start).unwrap();
            let finish = person.register_finish(&token, state, &response, &mut model);
            mallory.anonymous(&finish).unwrap();
            let (login, state) = person.login_start();
            let reply = mallory.anonymous(&login).unwrap();
            let context = opaque_context(
                OpaquePurpose::Login,
                &person.account_id,
                &person.record().kdf,
            )
            .unwrap();
            let (_, _, server_key) = state
                .finish_with_server_key(
                    reply.ke2.as_slice(),
                    &context,
                    &OpaqueIdentities {
                        client: person.account_id.as_bytes(),
                        server: ORIGIN.as_bytes(),
                    },
                )
                .unwrap();
            keys.push(sha256(&[&server_key])[..15].to_vec());
        }
        assert_ne!(keys[0], keys[1]);
    });
}
