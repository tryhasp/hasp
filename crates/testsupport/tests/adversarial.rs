#![expect(clippy::unwrap_used, reason = "integration test")]

use std::future::Future;
use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::client::{Channel, ChannelError, FingerprintCheck, SignUp};
use hasp_core::testing::{login_item, password_of};
use hasp_core::transport::{Transport, TransportError};
use hasp_crypto::SecretKey;
use hasp_proto::wire::{OpId, Operation, SessionToken};
use hasp_proto::{ProtoError, Role, Wire};
use hasp_testsupport::cancel;
use hasp_testsupport::{InProcess, TEST_ORIGIN, World, block_on};

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

const PASSWORD: &str = "correct horse battery staple";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Pass,
    Record,
    Replay,
    BreakSignatures,
}

#[derive(Debug)]
struct Mitm {
    inner: InProcess<hasp_server::MemoryStore>,
    mode: Arc<Mutex<Mode>>,
    recorded: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Transport for Mitm {
    async fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        let mode = *self.mode.lock().unwrap();
        if O::ID == OpId::Pull {
            if mode == Mode::Replay {
                let bytes = self.recorded.lock().unwrap().clone().unwrap();
                return Ok(O::Response::from_cbor(&bytes)?);
            }
            let reply = self.inner.call(token, request).await?;
            if mode == Mode::Record {
                *self.recorded.lock().unwrap() = Some(reply.to_cbor()?);
            }
            if mode == Mode::BreakSignatures {
                let mut page = hasp_proto::wire::PullResponse::from_cbor(&reply.to_cbor()?)?;
                for vault in &mut page.vaults {
                    for commit in &mut vault.commits {
                        let mut sig = *commit.manifest.sig.as_bytes();
                        sig[0] ^= 1;
                        commit.manifest.sig = hasp_crypto::Signature::from_bytes(sig);
                    }
                }
                return Ok(O::Response::from_cbor(&page.to_cbor()?)?);
            }
            return Ok(reply);
        }
        self.inner.call(token, request).await
    }
}

#[test]
fn a_replayed_older_pull_is_a_rollback_and_changes_nothing() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        let mode = Arc::new(Mutex::new(Mode::Pass));
        let recorded = Arc::new(Mutex::new(None));
        let mitm = Mitm {
            inner: world.transport(),
            mode: Arc::clone(&mode),
            recorded: Arc::clone(&recorded),
        };
        let (mut phone, _) = world.client_with(mitm, true);
        let kit = alice
            .client
            .change_password(&secret(PASSWORD), &secret(PASSWORD), true, &cancel())
            .await
            .unwrap()
            .unwrap();
        phone
            .sign_in(
                &hasp_core::client::SignIn {
                    origin: TEST_ORIGIN,
                    login: "alice@example.com",
                    secret_key: kit.secret_key(),
                    password: &secret(PASSWORD),
                    kit_server_fp: None,
                },
                &cancel(),
            )
            .await
            .unwrap();
        *mode.lock().unwrap() = Mode::Record;
        phone.sync(&cancel()).await.unwrap();
        *mode.lock().unwrap() = Mode::Pass;
        alice
            .client
            .create_item(&private, &login_item("Later", "l"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        phone.sync(&cancel()).await.unwrap();
        assert_eq!(phone.items(&private).unwrap().len(), 1);
        *mode.lock().unwrap() = Mode::Replay;
        let error = phone.sync(&cancel()).await.unwrap_err();
        assert!(
            matches!(error, CoreError::Proto(ProtoError::Rollback)),
            "{error:?}"
        );
        assert_eq!(phone.items(&private).unwrap().len(), 1);
    });
}

struct Pipe {
    tx: Mutex<std::sync::mpsc::Sender<Vec<u8>>>,
    rx: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
}

impl Channel for Pipe {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        std::future::ready(
            self.tx
                .lock()
                .unwrap()
                .send(message)
                .map_err(|_| ChannelError::Closed),
        )
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        std::future::ready(
            self.rx
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| ChannelError::Closed),
        )
    }
}

#[test]
fn an_extension_pairs_through_the_desktop_channel_and_unlocks_with_k_ext() {
    let mut world = World::new();
    let (mut desktop, mut extension) = block_on(async {
        let mut desktop = world.signup("alice@example.com", PASSWORD, true).await;
        let private = desktop.client.private_vault().unwrap();
        desktop
            .client
            .create_item(&private, &login_item("Site", "s"))
            .unwrap();
        desktop.client.sync(&cancel()).await.unwrap();
        (desktop, world.device(false))
    });
    let (to_ext, from_desktop) = std::sync::mpsc::channel();
    let (to_desktop, from_ext) = std::sync::mpsc::channel();
    let desktop_side = Pipe {
        tx: Mutex::new(to_ext),
        rx: Mutex::new(from_ext),
    };
    let ext_side = Pipe {
        tx: Mutex::new(to_desktop),
        rx: Mutex::new(from_desktop),
    };
    let k_ext: SecretKey = std::thread::scope(|scope| {
        let served = scope.spawn(|| {
            block_on(
                desktop
                    .client
                    .serve_extension_pairing(&desktop_side, &cancel()),
            )
            .unwrap();
        });
        let paired = scope
            .spawn(|| {
                block_on(
                    extension
                        .client
                        .pair_with_desktop(&ext_side, "chrome", &cancel()),
                )
                .unwrap()
            })
            .join()
            .unwrap();
        served.join().unwrap();
        paired
    });
    block_on(async {
        let private = extension.client.private_vault().unwrap();
        assert_eq!(extension.client.items(&private).unwrap().len(), 1);
        extension.client.lock();
        assert!(
            extension
                .client
                .unlock_password(&secret(PASSWORD), &cancel())
                .await
                .is_err()
        );
        let wrong = SecretKey::from_bytes([1; 32]);
        assert!(
            extension
                .client
                .unlock_extension(&wrong, &cancel())
                .await
                .is_err()
        );
        extension
            .client
            .unlock_extension(&k_ext, &cancel())
            .await
            .unwrap();
        assert_eq!(
            extension.client.items(&private).unwrap()[0].overview.title,
            "Site"
        );
        assert!(extension.client.device_confirmed().unwrap());
    });
}

#[test]
fn family_recovery_stores_the_current_code_in_a_shared_vault_the_organizer_can_read() {
    block_on(async {
        let mut world = World::new();
        let mut member = world.signup("member@example.com", PASSWORD, true).await;
        let mut organizer = world.signup("organizer@example.com", PASSWORD, true).await;
        let code = member
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let (vault, item) = member
            .client
            .family_recovery_setup(code.expose(), &cancel())
            .await
            .unwrap();
        let offer = member
            .client
            .invite_create(&vault, Role::Viewer, &cancel())
            .await
            .unwrap();
        let accepted = organizer
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        member
            .client
            .add_member(
                &vault,
                &offer.invite_id,
                &FingerprintCheck::Compared(accepted.my_fingerprint),
                &cancel(),
            )
            .await
            .unwrap();
        organizer.client.sync(&cancel()).await.unwrap();
        let read = organizer.client.item(&vault, &item).unwrap();
        assert_eq!(password_of(&read), code.expose());
        let newer = member
            .client
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        member
            .client
            .family_recovery_update(&vault, &item, newer.expose(), &cancel())
            .await
            .unwrap();
        organizer.client.sync(&cancel()).await.unwrap();
        assert_eq!(
            password_of(&organizer.client.item(&vault, &item).unwrap()),
            newer.expose()
        );
        assert!(
            organizer
                .client
                .create_item(&vault, &login_item("x", "x"))
                .is_err()
        );
    });
}

#[test]
fn scheduled_backups_restore_with_the_passphrase_alone() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        alice
            .client
            .create_item(&private, &login_item("Keep", "k"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let params = hasp_crypto::Argon2idParams::local(8, 1, 1).unwrap();
        alice
            .client
            .enable_backup(&secret("backup phrase"), params)
            .unwrap();
        let file = alice
            .client
            .backup(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let other = alice
            .client
            .backup(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        assert_ne!(file, other);
        let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
        let report = bob
            .client
            .restore(
                &file,
                &hasp_core::export::Unlock::Passphrase(&secret("backup phrase")),
                &cancel(),
            )
            .await
            .unwrap();
        assert_eq!(report.items, 1);
        let linux = world.signup("carol@example.com", PASSWORD, false).await;
        let mut linux = linux;
        assert!(linux.client.enable_backup(&secret("x"), params).is_err());
    });
}

#[test]
fn sign_up_requires_a_valid_token_and_strong_enough_kdf_parameters() {
    block_on(async {
        let world = World::new();
        let mut device = world.device(true);
        let bad = hasp_proto::wire::SignupToken::from_bytes([3; 20]).to_text();
        let result = device
            .client
            .sign_up(
                &SignUp {
                    origin: TEST_ORIGIN,
                    token: &bad,
                    login: "x@example.com",
                    password: &secret(PASSWORD),
                },
                &cancel(),
            )
            .await;
        assert!(result.is_err());
    });
}

async fn quarantine_setup(
    world: &mut World,
) -> (
    hasp_testsupport::Device,
    hasp_core::client::Client<Mitm, hasp_core::store::MemoryStore>,
    Arc<Mutex<Mode>>,
    hasp_proto::VaultId,
) {
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    let mode = Arc::new(Mutex::new(Mode::Pass));
    let mitm = Mitm {
        inner: world.transport(),
        mode: Arc::clone(&mode),
        recorded: Arc::new(Mutex::new(None)),
    };
    let (mut bob, _) = world.client_with(mitm, true);
    let token = world.token().await;
    bob.sign_up(
        &SignUp {
            origin: TEST_ORIGIN,
            token: &token,
            login: "bob@example.com",
            password: &secret(PASSWORD),
        },
        &cancel(),
    )
    .await
    .unwrap();
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
    let accepted = bob.invite_accept(&offer.code, &cancel()).await.unwrap();
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
    bob.sync(&cancel()).await.unwrap();
    (alice, bob, mode, vault)
}

#[test]
fn a_commit_with_a_broken_signature_quarantines_the_vault_and_blocks_writes() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, mut bob, mode, vault) = Box::pin(quarantine_setup(&mut world)).await;
        alice
            .client
            .create_item(&vault, &login_item("Fine", "f"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        *mode.lock().unwrap() = Mode::BreakSignatures;
        let report = bob.sync(&cancel()).await.unwrap();
        let state = &report
            .vaults
            .iter()
            .find(|v| v.vault_id == vault)
            .unwrap()
            .state;
        assert_eq!(
            state,
            &hasp_core::sync::VaultSyncState::Quarantined("Sig".to_owned())
        );
        assert!(bob.items(&vault).unwrap().is_empty());
        let write = bob.create_item(&vault, &login_item("Nope", "n"));
        assert!(matches!(write, Err(CoreError::Quarantined { .. })));
        assert!(
            bob.vaults()
                .unwrap()
                .iter()
                .any(|v| v.vault_id == vault && v.quarantined)
        );
        *mode.lock().unwrap() = Mode::Pass;
        let again = bob.sync(&cancel()).await.unwrap();
        assert!(again.vaults.iter().all(|v| v.vault_id != vault));
    });
}

#[test]
fn the_owner_can_prepare_and_apply_a_repair_after_confirming() {
    block_on(async {
        let mut world = World::new();
        let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
        let mode = Arc::new(Mutex::new(Mode::Pass));
        let mitm = Mitm {
            inner: world.transport(),
            mode: Arc::clone(&mode),
            recorded: Arc::new(Mutex::new(None)),
        };
        let (mut alice, _) = world.client_with(mitm, true);
        let token = world.token().await;
        alice
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
        let vault = alice.create_vault("Shared", &cancel()).await.unwrap();
        let offer = alice
            .invite_create(&vault, Role::Editor, &cancel())
            .await
            .unwrap();
        let accepted = bob
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        alice
            .add_member(
                &vault,
                &offer.invite_id,
                &FingerprintCheck::Compared(accepted.my_fingerprint),
                &cancel(),
            )
            .await
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        bob.client
            .create_item(&vault, &login_item("Bad", "b"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        *mode.lock().unwrap() = Mode::BreakSignatures;
        let report = alice.sync(&cancel()).await.unwrap();
        assert!(matches!(
            report
                .vaults
                .iter()
                .find(|v| v.vault_id == vault)
                .unwrap()
                .state,
            hasp_core::sync::VaultSyncState::Quarantined(_)
        ));
        let repair = alice.repair_prepare(&vault).unwrap();
        assert!(alice.repair_apply(&vault, &repair, false).is_err());
        alice.repair_apply(&vault, &repair, true).unwrap();
        assert!(alice.vaults().unwrap().iter().all(|v| !v.quarantined));
    });
}
