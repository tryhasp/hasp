#![expect(clippy::unwrap_used, reason = "integration test")]

use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::client::{FingerprintCheck, SignIn, SignUp};
use hasp_core::sync::VaultSyncState;
use hasp_core::testing::{login_item, password_of};
use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{OpId, Operation, ServerKeyResponse, SessionToken};
use hasp_proto::{Role, Wire};
use hasp_testsupport::cancel;
use hasp_testsupport::{Device, InProcess, TEST_ORIGIN, World, block_on};

const PASSWORD: &str = "correct horse battery staple";

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

#[derive(Debug)]
struct Watch {
    inner: InProcess<hasp_server::MemoryStore>,
    seen: Arc<Mutex<Vec<OpId>>>,
    break_pulls: Arc<Mutex<bool>>,
    swap_server_key: bool,
}

impl Watch {
    fn new(world: &World) -> Self {
        Self {
            inner: world.transport(),
            seen: Arc::new(Mutex::new(Vec::new())),
            break_pulls: Arc::new(Mutex::new(false)),
            swap_server_key: false,
        }
    }
}

impl Transport for Watch {
    async fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        self.seen.lock().unwrap().push(O::ID);
        let reply = self.inner.call(token, request).await?;
        if self.swap_server_key && O::ID == OpId::ServerKey {
            let mut body = ServerKeyResponse::from_cbor(&reply.to_cbor()?)?;
            body.public_key.0[0] ^= 1;
            return Ok(O::Response::from_cbor(&body.to_cbor()?)?);
        }
        if O::ID == OpId::Pull && *self.break_pulls.lock().unwrap() {
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
        Ok(reply)
    }
}

type WatchedClient = hasp_core::client::Client<Watch, hasp_core::store::MemoryStore>;

async fn watched_owner(world: &mut World) -> (WatchedClient, Arc<Mutex<bool>>) {
    let transport = Watch::new(world);
    let breaker = Arc::clone(&transport.break_pulls);
    let (mut alice, _) = world.client_with(transport, true);
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
    (alice, breaker)
}

async fn add_editor(
    world: &mut World,
    owner: &mut WatchedClient,
    vault: &hasp_proto::VaultId,
    login: &str,
) -> Device {
    let mut member = world.signup(login, PASSWORD, true).await;
    let offer = owner
        .invite_create(vault, Role::Editor, &cancel())
        .await
        .unwrap();
    let accepted = member
        .client
        .invite_accept(&offer.code, &cancel())
        .await
        .unwrap();
    owner
        .add_member(
            vault,
            &offer.invite_id,
            &FingerprintCheck::Compared(accepted.my_fingerprint),
            &cancel(),
        )
        .await
        .unwrap();
    member.client.sync(&cancel()).await.unwrap();
    member
}

fn titles(client: &impl ItemTitles, vault: &hasp_proto::VaultId) -> Vec<String> {
    client.titles(vault)
}

trait ItemTitles {
    fn titles(&self, vault: &hasp_proto::VaultId) -> Vec<String>;
}

impl<T: Transport, S: hasp_core::store::Store> ItemTitles for hasp_core::client::Client<T, S> {
    fn titles(&self, vault: &hasp_proto::VaultId) -> Vec<String> {
        let mut out: Vec<String> = self
            .items(vault)
            .unwrap()
            .into_iter()
            .map(|item| item.overview.title)
            .collect();
        out.sort();
        out
    }
}

async fn quarantine_and_repair(
    alice: &mut WatchedClient,
    breaker: &Arc<Mutex<bool>>,
    vault: &hasp_proto::VaultId,
) {
    *breaker.lock().unwrap() = true;
    alice.sync(&cancel()).await.unwrap();
    assert!(alice.vaults().unwrap().iter().any(|v| v.quarantined));
    *breaker.lock().unwrap() = false;

    assert!(alice.repair_publish(vault, false, &cancel()).await.is_err());
    alice.repair_publish(vault, true, &cancel()).await.unwrap();
    assert!(alice.vaults().unwrap().iter().all(|v| !v.quarantined));
    assert!(titles(alice, vault).is_empty());
}

async fn confirm_repair(carol: &mut Device, vault: &hasp_proto::VaultId) {
    let report = carol.client.sync(&cancel()).await.unwrap();
    let state = &report
        .vaults
        .iter()
        .find(|v| v.vault_id == *vault)
        .unwrap()
        .state;
    assert_eq!(state, &VaultSyncState::RepairPending);
    let pending = carol.client.pending_repairs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].vault_id, *vault);
    assert!(
        carol
            .client
            .vaults()
            .unwrap()
            .iter()
            .any(|v| v.vault_id == *vault && v.repair_pending)
    );
    assert!(matches!(
        carol.client.create_item(vault, &login_item("Early", "e")),
        Err(CoreError::RepairPending { .. })
    ));
    assert!(carol.client.repair_confirm(vault, false).is_err());
    assert_eq!(carol.client.pending_repairs().unwrap().len(), 1);
    carol.client.repair_confirm(vault, true).unwrap();
    assert!(carol.client.pending_repairs().unwrap().is_empty());
    assert!(titles(&carol.client, vault).is_empty());
}

#[test]
fn an_owner_repair_reaches_members_who_confirm_it_before_writing_again() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, breaker) = Box::pin(watched_owner(&mut world)).await;
        let vault = alice.create_vault("Shared", &cancel()).await.unwrap();
        let mut bob = Box::pin(add_editor(
            &mut world,
            &mut alice,
            &vault,
            "bob@example.com",
        ))
        .await;
        let mut carol = Box::pin(add_editor(
            &mut world,
            &mut alice,
            &vault,
            "carol@example.com",
        ))
        .await;
        bob.client.sync(&cancel()).await.unwrap();
        alice.sync(&cancel()).await.unwrap();

        bob.client
            .create_item(&vault, &login_item("Bad", "b"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();
        quarantine_and_repair(&mut alice, &breaker, &vault).await;
        confirm_repair(&mut carol, &vault).await;

        let later = carol
            .client
            .create_item(&vault, &login_item("Later", "l"))
            .unwrap();
        carol.client.sync(&cancel()).await.unwrap();
        alice.sync(&cancel()).await.unwrap();
        assert_eq!(titles(&alice, &vault), vec!["Later".to_owned()]);
        assert_eq!(password_of(&alice.item(&vault, &later).unwrap()), "l");
        let behind = bob.client.sync(&cancel()).await.unwrap();
        assert!(matches!(
            behind
                .vaults
                .iter()
                .find(|v| v.vault_id == vault)
                .unwrap()
                .state,
            VaultSyncState::Quarantined(_)
        ));
    });
}

#[test]
fn a_quarantined_vault_is_retried_from_the_last_good_head() {
    block_on(async {
        let mut world = World::new();
        let (mut alice, breaker) = Box::pin(watched_owner(&mut world)).await;
        let vault = alice.create_vault("Shared", &cancel()).await.unwrap();
        let mut bob = Box::pin(add_editor(
            &mut world,
            &mut alice,
            &vault,
            "bob@example.com",
        ))
        .await;
        bob.client
            .create_item(&vault, &login_item("Fine", "f"))
            .unwrap();
        bob.client.sync(&cancel()).await.unwrap();

        *breaker.lock().unwrap() = true;
        alice.sync(&cancel()).await.unwrap();
        assert!(alice.vaults().unwrap().iter().any(|v| v.quarantined));
        assert!(matches!(
            alice.quarantine_retry(&vault, &cancel()).await,
            Err(CoreError::Quarantined { .. })
        ));
        assert!(alice.vaults().unwrap().iter().any(|v| v.quarantined));

        *breaker.lock().unwrap() = false;
        let retried = alice.quarantine_retry(&vault, &cancel()).await.unwrap();
        assert_eq!(retried.state, VaultSyncState::UpToDate);
        assert!(alice.vaults().unwrap().iter().all(|v| !v.quarantined));
        assert_eq!(titles(&alice, &vault), vec!["Fine".to_owned()]);
        assert!(matches!(
            alice.quarantine_retry(&vault, &cancel()).await,
            Err(CoreError::NotFound(_))
        ));
    });
}

async fn kit_for(world: &mut World) -> hasp_core::client::EmergencyKit {
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    alice
        .client
        .change_password(
            &secret(PASSWORD),
            &secret("another long password"),
            true,
            &cancel(),
        )
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn a_kit_sign_in_refuses_a_wrong_server_key_before_any_login() {
    block_on(async {
        let mut world = World::new();
        let kit = kit_for(&mut world).await;
        let transport = Watch::new(&world);
        let seen = Arc::clone(&transport.seen);
        let (mut laptop, _) = world.client_with(transport, true);
        let mut wrong = kit.server_fingerprint_bytes();
        wrong[0] ^= 1;
        let result = laptop
            .sign_in(
                &SignIn {
                    origin: TEST_ORIGIN,
                    login: "alice@example.com",
                    secret_key: kit.secret_key(),
                    password: &secret("another long password"),
                    kit_server_fp: Some(wrong),
                },
                &cancel(),
            )
            .await;
        assert!(matches!(result, Err(CoreError::ServerKey)));
        assert_eq!(*seen.lock().unwrap(), vec![OpId::ServerKey]);
    });
}

#[test]
fn a_server_that_swaps_its_key_is_refused_by_sign_in_and_by_qr_enrolment() {
    block_on(async {
        let mut world = World::new();
        let kit = kit_for(&mut world).await;
        let mut transport = Watch::new(&world);
        transport.swap_server_key = true;
        let seen = Arc::clone(&transport.seen);
        let (mut laptop, _) = world.client_with(transport, true);
        let result = laptop
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
            .await;
        assert!(matches!(result, Err(CoreError::ServerKey)));
        assert!(!seen.lock().unwrap().contains(&OpId::LoginStart));

        let mut first = world.device(true);
        first
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
        let invite = first.client.enrol_open(&cancel()).await.unwrap();
        let mut tampered = Watch::new(&world);
        tampered.swap_server_key = true;
        let seen = Arc::clone(&tampered.seen);
        let (mut second, _) = world.client_with(tampered, true);
        let joined = second.enrol_join(&invite.qr, &cancel()).await;
        assert!(matches!(joined, Err(CoreError::ServerKey)));
        assert!(!seen.lock().unwrap().contains(&OpId::EnrolMsgPut));
    });
}
