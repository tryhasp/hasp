use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::client::SignUp;
use hasp_core::store::{Batch, Entry, MemoryStore, Store, StoreError, UnlockClass};
use hasp_core::testing::{login_item, password_of};
use hasp_testsupport::{TEST_ORIGIN, World, block_on, cancel};

const PASSWORD: &str = "correct horse battery staple";

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
fn a_password_only_device_moves_to_the_hardware_class_when_the_platform_can_gate() {
    block_on(Box::pin(async {
        let mut world = World::new();
        let token = world.token().await;
        let disk = Disk::default();
        let (mut passwordless, _) = world.client_on(world.transport(), disk.clone(), false);
        passwordless
            .sign_up(
                &SignUp {
                    origin: TEST_ORIGIN,
                    token: &token,
                    login: "alice@example.com",
                    password: &secret(PASSWORD),
                },
                &cancel(),
            )
            .await
            .unwrap();
        let private = passwordless.private_vault().unwrap();
        let id = passwordless
            .create_item(&private, &login_item("Bank", "keep"))
            .unwrap();
        assert_eq!(
            passwordless.unlock_class().unwrap(),
            Some(UnlockClass::PasswordOnly)
        );
        assert!(matches!(
            passwordless.enable_hardware_unlock(&secret(PASSWORD), &cancel()),
            Err(CoreError::Refused(_))
        ));
        drop(passwordless);

        let (mut gated, _) = world.client_on(world.transport(), disk.clone(), true);
        assert!(!gated.biometric_ready());
        assert!(matches!(
            gated.enable_hardware_unlock(&secret("wrong password"), &cancel()),
            Err(CoreError::Credentials)
        ));
        gated
            .enable_hardware_unlock(&secret(PASSWORD), &cancel())
            .unwrap();
        assert_eq!(gated.unlock_class().unwrap(), Some(UnlockClass::Hardware));
        assert!(gated.biometric_ready());
        assert!(matches!(
            gated.enable_hardware_unlock(&secret(PASSWORD), &cancel()),
            Err(CoreError::Refused(_))
        ));

        gated.lock();
        gated.unlock_biometric(&cancel()).await.unwrap();
        assert_eq!(password_of(&gated.item(&private, &id).unwrap()), "keep");
        gated.lock();
        gated
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        assert_eq!(password_of(&gated.item(&private, &id).unwrap()), "keep");
    }));
}
