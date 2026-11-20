#![expect(clippy::unwrap_used, reason = "integration test")]

use std::sync::{Arc, Mutex};

use hasp_core::CoreError;
use hasp_core::client::{Client, ClientState, FingerprintCheck, SignIn, SignUp};
use hasp_core::store::MemoryStore as ClientStore;
use hasp_core::sync::VaultSyncState;
use hasp_core::testing::{login_item, password_of};
use hasp_core::transport::{Transport, TransportError};
use hasp_proto::wire::{
    AccountGetResponse, InviteListResponse, OpId, Operation, PullResponse, SessionToken,
};
use hasp_proto::{Role, VaultId, Wire};
use hasp_testsupport::cancel;
use hasp_testsupport::{Device, InProcess, TEST_ORIGIN, World, block_on};

const PASSWORD: &str = "correct horse battery staple";

fn secret(text: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(text)
}

type PullHook = Box<dyn FnMut(&mut PullResponse) + Send>;
type InviteHook = Box<dyn FnMut(&mut InviteListResponse) + Send>;
type AccountHook = Box<dyn FnMut(&mut AccountGetResponse) + Send>;

#[derive(Default)]
struct Hooks {
    pull: Option<PullHook>,
    invites: Option<InviteHook>,
    account: Option<AccountHook>,
}

struct Mallory {
    inner: InProcess<hasp_server::MemoryStore>,
    hooks: Arc<Mutex<Hooks>>,
}

impl std::fmt::Debug for Mallory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mallory(..)")
    }
}

fn mallory(world: &World) -> (Mallory, Arc<Mutex<Hooks>>) {
    let hooks = Arc::new(Mutex::new(Hooks::default()));
    (
        Mallory {
            inner: world.transport(),
            hooks: Arc::clone(&hooks),
        },
        hooks,
    )
}

impl Transport for Mallory {
    async fn call<O: Operation + Sync>(
        &self,
        token: Option<&SessionToken>,
        request: &O,
    ) -> Result<O::Response, TransportError> {
        let reply = self.inner.call(token, request).await?;
        let mut hooks = self.hooks.lock().unwrap();
        let bytes = reply.to_cbor()?;
        let rewritten = match O::ID {
            OpId::Pull if hooks.pull.is_some() => {
                let mut page = PullResponse::from_cbor(&bytes)?;
                (hooks.pull.as_mut().unwrap())(&mut page);
                page.to_cbor()?
            }
            OpId::InviteList if hooks.invites.is_some() => {
                let mut list = InviteListResponse::from_cbor(&bytes)?;
                (hooks.invites.as_mut().unwrap())(&mut list);
                list.to_cbor()?
            }
            OpId::AccountGet if hooks.account.is_some() => {
                let mut account = AccountGetResponse::from_cbor(&bytes)?;
                (hooks.account.as_mut().unwrap())(&mut account);
                account.to_cbor()?
            }
            _ => return Ok(reply),
        };
        Ok(O::Response::from_cbor(&rewritten)?)
    }
}

async fn signup_via<T: Transport>(
    world: &mut World,
    transport: T,
    login: &str,
) -> Client<T, ClientStore> {
    let token = world.token().await;
    let (mut client, _) = world.client_with(transport, true);
    Box::pin(client.sign_up(
        &SignUp {
            origin: TEST_ORIGIN,
            token: &token,
            login,
            password: &secret(PASSWORD),
        },
        &cancel(),
    ))
    .await
    .unwrap();
    client
}

async fn share<T: Transport>(
    alice: &mut Device,
    bob: &mut Client<T, ClientStore>,
    role: Role,
) -> VaultId {
    let vault = alice
        .client
        .create_vault("Shared", &cancel())
        .await
        .unwrap();
    let offer = alice
        .client
        .invite_create(&vault, role, &cancel())
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
    vault
}

fn state_of(report: &hasp_core::sync::SyncReport, vault: VaultId) -> VaultSyncState {
    report
        .vaults
        .iter()
        .find(|v| v.vault_id == vault)
        .unwrap()
        .state
        .clone()
}

fn head_of<T: Transport>(client: &Client<T, ClientStore>, vault: VaultId) -> u64 {
    client
        .heads()
        .unwrap()
        .into_iter()
        .find(|h| h.vault_id == vault)
        .unwrap()
        .seq
}

#[test]
fn has_more_never_decides_the_head_and_a_dropped_op_is_a_root_error_not_a_stale_leaf_set() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let (link, hooks) = mallory(&world);
        let mut bob = signup_via(&mut world, link, "bob@example.com").await;
        let vault = share(&mut alice, &mut bob, Role::Viewer).await;
        let item = alice
            .client
            .create_item(&vault, &login_item("Site", "old"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.sync(&cancel()).await.unwrap();
        let held = head_of(&bob, vault);
        alice
            .client
            .edit_item(&vault, &item, &login_item("Site", "new"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();

        hooks.lock().unwrap().pull = Some(Box::new(|page| {
            for vault in &mut page.vaults {
                vault.has_more = !vault.commits.is_empty();
                for commit in &mut vault.commits {
                    commit.ops.clear();
                }
            }
        }));
        let report = bob.sync(&cancel()).await.unwrap();
        assert!(
            matches!(state_of(&report, vault), VaultSyncState::Quarantined(ref check) if check == "Root"),
            "{:?}",
            state_of(&report, vault)
        );
        assert_eq!(head_of(&bob, vault), held);
        assert_eq!(password_of(&bob.item(&vault, &item).unwrap()), "old");
    });
}

#[test]
fn a_failing_strict_batch_quarantines_instead_of_falling_back_to_the_weak_replay() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let (link, hooks) = mallory(&world);
        let mut bob = signup_via(&mut world, link, "bob@example.com").await;
        let vault = share(&mut alice, &mut bob, Role::Viewer).await;
        let item = alice
            .client
            .create_item(&vault, &login_item("Site", "v1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        bob.sync(&cancel()).await.unwrap();
        for text in ["v2", "v3"] {
            alice
                .client
                .edit_item(&vault, &item, &login_item("Site", text))
                .unwrap();
            alice.client.sync(&cancel()).await.unwrap();
        }
        let held = head_of(&bob, vault);

        hooks.lock().unwrap().pull = Some(Box::new(|page| {
            for vault in &mut page.vaults {
                if let Some(first) = vault.commits.first_mut() {
                    first.ops.clear();
                }
            }
        }));
        let report = bob.sync(&cancel()).await.unwrap();
        assert!(
            matches!(state_of(&report, vault), VaultSyncState::Quarantined(ref check) if check == "Root"),
            "{:?}",
            state_of(&report, vault)
        );
        assert_eq!(head_of(&bob, vault), held);
        assert_eq!(password_of(&bob.item(&vault, &item).unwrap()), "v1");
    });
}

#[test]
fn the_role_of_an_invitee_comes_from_the_owner_and_not_from_the_server_reply() {
    block_on(async {
        let mut world = World::new();
        let (link, hooks) = mallory(&world);
        let mut alice = signup_via(&mut world, link, "alice@example.com").await;
        let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
        let vault = alice.create_vault("Shared", &cancel()).await.unwrap();
        let offer = alice
            .invite_create(&vault, Role::Viewer, &cancel())
            .await
            .unwrap();
        let accepted = bob
            .client
            .invite_accept(&offer.code, &cancel())
            .await
            .unwrap();
        hooks.lock().unwrap().invites = Some(Box::new(|list| {
            for entry in &mut list.invites {
                entry.role = Role::Editor;
            }
        }));
        let listed = alice.pending_invitees(&vault, &cancel()).await.unwrap();
        assert_eq!(listed[0].role, Role::Viewer);
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
        let summary = bob
            .client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.vault_id == vault)
            .unwrap();
        assert_eq!(summary.role, Role::Viewer);
        assert!(
            bob.client
                .create_item(&vault, &login_item("Nope", "n"))
                .is_err()
        );
    });
}

#[test]
fn an_older_account_record_served_after_a_newer_one_is_a_rollback() {
    block_on(async {
        let mut world = World::new();
        let (link, hooks) = mallory(&world);
        let mut alice = signup_via(&mut world, link, "alice@example.com").await;
        let first = Arc::new(Mutex::new(None::<Vec<u8>>));
        let recorded = Arc::clone(&first);
        hooks.lock().unwrap().account = Some(Box::new(move |reply| {
            let mut held = recorded.lock().unwrap();
            match held.as_ref() {
                None => *held = Some(reply.to_cbor().unwrap()),
                Some(bytes) => *reply = AccountGetResponse::from_cbor(bytes).unwrap(),
            }
        }));
        alice.sync(&cancel()).await.unwrap();
        alice
            .create_recovery_code(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let error = alice.sync(&cancel()).await.unwrap_err();
        assert!(
            matches!(error, CoreError::Proto(hasp_proto::ProtoError::Rollback)),
            "{error:?}"
        );
    });
}

#[test]
fn a_revoked_device_that_reaches_its_own_revocation_erases_its_local_data() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        alice
            .client
            .create_item(&private, &login_item("Bank", "keep"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        let kit = alice
            .client
            .change_password(&secret(PASSWORD), &secret(PASSWORD), true, &cancel())
            .await
            .unwrap()
            .unwrap();
        let mut second = world.device(true);
        second
            .client
            .sign_in(
                &SignIn {
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
        alice.client.sync(&cancel()).await.unwrap();
        let listed = alice.client.devices(&cancel()).await.unwrap();
        let victim = listed.iter().find(|d| !d.current).unwrap();
        alice
            .client
            .revoke_device(&victim.session_id, &victim.device_id, &cancel())
            .await
            .unwrap();

        second.client.lock();
        second
            .client
            .unlock_password(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let error = second.client.sync(&cancel()).await.unwrap_err();
        assert!(matches!(error, CoreError::DeviceRevoked), "{error:?}");
        assert_eq!(second.client.state().unwrap(), ClientState::Empty);
        assert!(!second.client.is_unlocked());
        assert!(second.client.private_vault().is_err());
    });
}

#[test]
fn an_export_carries_each_item_with_its_authenticated_history() {
    block_on(async {
        let mut world = World::new();
        let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
        let private = alice.client.private_vault().unwrap();
        let item = alice
            .client
            .create_item(&private, &login_item("Site", "v1"))
            .unwrap();
        alice.client.sync(&cancel()).await.unwrap();
        for text in ["v2", "v3"] {
            alice
                .client
                .edit_item(&private, &item, &login_item("Site", text))
                .unwrap();
            alice.client.sync(&cancel()).await.unwrap();
        }
        assert_eq!(alice.client.history(&private, &item).unwrap().len(), 3);
        let content = alice
            .client
            .export_content(&secret(PASSWORD), &cancel())
            .await
            .unwrap();
        let exported = content
            .items
            .iter()
            .find(|entry| entry.item_id.as_bytes() == item.as_bytes())
            .unwrap();
        assert_eq!(exported.history.len(), 2);
        assert_eq!(password_of(&exported.item), "v3");
    });
}
