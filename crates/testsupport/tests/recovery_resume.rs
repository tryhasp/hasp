use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::store::{Batch, Entry, MemoryStore, Store, StoreError};
use hasp_core::testing::{login_item, password_of};
use hasp_testsupport::{World, block_on, cancel};

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a brand new password";

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

#[derive(Clone, Default)]
struct Disk(Arc<Mutex<MemoryStore>>);

impl Store for Disk {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.lock().map_err(|_| StoreError::Io)?.get(key)
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StoreError> {
        self.0.lock().map_err(|_| StoreError::Io)?.scan(prefix)
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), StoreError> {
        self.0.lock().map_err(|_| StoreError::Io)?.apply(batch)
    }
}

#[test]
fn a_started_recovery_survives_a_restart_and_finishes_after_the_delay() {
    block_on(Box::pin(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        let id = alice
            .client
            .create_item(&private, &login_item("Bank", "keep"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let code = alice
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();

        let disk = Disk::default();
        let (mut first, _) = world.client_on(world.transport(), disk.clone(), true);
        assert!(!first.has_recovery_ticket().unwrap());
        let ticket = first
            .recover_start(
                hasp_testsupport::TEST_ORIGIN,
                "alice@example.com",
                code.expose(),
            )
            .await
            .unwrap();
        first
            .save_recovery_ticket(&ticket, &secret(NEW_PASSWORD))
            .unwrap();
        drop(first);

        let at_rest = disk.scan(&[]).unwrap();
        assert!(!at_rest.is_empty());
        for (key, value) in at_rest {
            for plain in [code.expose().as_bytes(), b"alice@example.com".as_slice()] {
                assert!(!value.windows(plain.len()).any(|window| window == plain));
                assert!(!key.windows(plain.len()).any(|window| window == plain));
            }
        }

        let (mut second, _) = world.client_on(world.transport(), disk.clone(), true);
        assert!(second.has_recovery_ticket().unwrap());
        assert!(matches!(
            second.load_recovery_ticket(&secret("some other password")),
            Err(CoreError::Credentials)
        ));
        let resumed = second
            .load_recovery_ticket(&secret(NEW_PASSWORD))
            .unwrap()
            .unwrap();
        assert_eq!(resumed.recovery_id, ticket.recovery_id);
        assert_eq!(resumed.release_at, ticket.release_at);
        let early = second
            .recover_finish(&resumed, &secret(NEW_PASSWORD), &cancel())
            .await;
        assert!(matches!(early, Err(CoreError::Pending { .. })), "{early:?}");
        assert!(second.has_recovery_ticket().unwrap());

        world.clock.advance(25 * 3600);
        second
            .recover_finish(&resumed, &secret(NEW_PASSWORD), &cancel())
            .await
            .unwrap();
        assert!(!second.has_recovery_ticket().unwrap());
        assert_eq!(password_of(&second.item(&private, &id).unwrap()), "keep");
    }));
}

#[test]
fn the_emergency_kit_needs_the_last_secret_key_group_and_reproduces_the_signup_kit() {
    block_on(Box::pin(async {
        let mut world = World::new();
        let token = world.token().await;
        let mut device = world.device(true);
        let signup = Box::pin(device.client.sign_up(
            &hasp_core::client::SignUp {
                origin: hasp_testsupport::TEST_ORIGIN,
                token: &token,
                login: "alice@example.com",
                password: &secret(PASSWORD),
            },
            &cancel(),
        ))
        .await
        .unwrap();
        let last = signup.secret_key().rsplit('-').next().unwrap().to_owned();

        let wrong = device.client.emergency_kit("ZZZZ");
        assert!(matches!(wrong, Err(CoreError::Refused(_))), "{wrong:?}");
        let kit = device.client.emergency_kit(&last).unwrap();
        assert!(kit.text.contains(signup.secret_key()));
        assert!(kit.text.contains(&signup.server_fingerprint));
        assert!(kit.pdf.starts_with(b"%PDF-1.4"));

        device.client.lock();
        assert!(matches!(
            device.client.emergency_kit(&last),
            Err(CoreError::Locked)
        ));
    }));
}
