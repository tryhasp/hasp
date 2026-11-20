#![expect(clippy::unwrap_used, reason = "integration test")]

use std::collections::{BTreeMap, BTreeSet};

use hasp_core::client::FingerprintCheck;
use hasp_core::testing::{login_item, password_of};
use hasp_proto::{ItemId, Role};
use hasp_testsupport::cancel;
use hasp_testsupport::{Device, World, block_on};
use proptest::prelude::*;

const PASSWORD: &str = "correct horse battery staple";

#[derive(Clone, Debug)]
enum Action {
    Edit { who: usize, item: usize },
    Delete { who: usize, item: usize },
    Create { who: usize },
    Sync { who: usize },
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        (0..2_usize, 0..3_usize).prop_map(|(who, item)| Action::Edit { who, item }),
        (0..2_usize, 0..3_usize).prop_map(|(who, item)| Action::Delete { who, item }),
        (0..2_usize).prop_map(|who| Action::Create { who }),
        (0..2_usize).prop_map(|who| Action::Sync { who }),
        (0..2_usize).prop_map(|who| Action::Sync { who }),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Queued {
    Put(String),
    Delete,
}

async fn world_with_two_clients() -> (World, Device, Device, hasp_proto::VaultId) {
    let mut world = World::new();
    let mut alice = world.signup("alice@example.com", PASSWORD, true).await;
    let mut bob = world.signup("bob@example.com", PASSWORD, true).await;
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
    let accepted = bob
        .client
        .invite_accept(&offer.code, &cancel())
        .await
        .unwrap();
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
    bob.client.sync(&cancel()).await.unwrap();
    (world, alice, bob, vault)
}

fn view(device: &Device, vault: &hasp_proto::VaultId) -> BTreeMap<ItemId, (String, String)> {
    device
        .client
        .items(vault)
        .unwrap()
        .into_iter()
        .map(|summary| {
            let item = device.client.item(vault, &summary.item_id).unwrap();
            (
                summary.item_id,
                (summary.overview.title, password_of(&item)),
            )
        })
        .collect()
}

type Pending = BTreeMap<ItemId, Queued>;
type Committed = BTreeMap<ItemId, BTreeSet<String>>;

struct Scenario {
    _world: World,
    devices: [Device; 2],
    vault: hasp_proto::VaultId,
    items: Vec<ItemId>,
    queued: [Pending; 2],
    committed: Committed,
}

impl Scenario {
    async fn start() -> Self {
        let (world, alice, bob, vault) = Box::pin(world_with_two_clients()).await;
        let mut devices = [alice, bob];
        let mut items = Vec::new();
        let mut committed = Committed::new();
        for n in 0..3 {
            let title = format!("base-{n}");
            let id = devices[0]
                .client
                .create_item(&vault, &login_item(&title, "pw"))
                .unwrap();
            items.push(id);
            committed.entry(id).or_default().insert(title);
        }
        devices[0].client.sync(&cancel()).await.unwrap();
        devices[1].client.sync(&cancel()).await.unwrap();
        Self {
            _world: world,
            devices,
            vault,
            items,
            queued: [Pending::new(), Pending::new()],
            committed,
        }
    }

    async fn sync(&mut self, who: usize) {
        self.devices[who].client.sync(&cancel()).await.unwrap();
        for (id, op) in std::mem::take(&mut self.queued[who]) {
            if let Queued::Put(title) = op {
                self.committed.entry(id).or_default().insert(title);
            }
        }
    }

    async fn apply(&mut self, action: &Action, counter: u32) {
        let vault = self.vault;
        match action {
            Action::Edit { who, item } => {
                let Some(id) = self.items.get(*item).copied() else {
                    return;
                };
                let title = format!("edit-{who}-{counter}");
                let edited =
                    self.devices[*who]
                        .client
                        .edit_item(&vault, &id, &login_item(&title, "pw"));
                if edited.is_ok() {
                    self.queued[*who].insert(id, Queued::Put(title));
                }
            }
            Action::Delete { who, item } => {
                let Some(id) = self.items.get(*item).copied() else {
                    return;
                };
                if self.devices[*who].client.delete_item(&vault, &id).is_ok() {
                    self.queued[*who].insert(id, Queued::Delete);
                }
            }
            Action::Create { who } => {
                let title = format!("new-{who}-{counter}");
                let id = self.devices[*who]
                    .client
                    .create_item(&vault, &login_item(&title, "pw"))
                    .unwrap();
                self.items.push(id);
                self.queued[*who].insert(id, Queued::Put(title));
            }
            Action::Sync { who } => self.sync(*who).await,
        }
    }

    fn history_titles(&self, who: usize, id: &ItemId) -> BTreeSet<String> {
        self.devices[who]
            .client
            .history(&self.vault, id)
            .unwrap()
            .into_iter()
            .map(|entry| entry.title)
            .collect()
    }

    fn head_code(&self, who: usize) -> String {
        self.devices[who]
            .client
            .heads()
            .unwrap()
            .into_iter()
            .find(|h| h.vault_id == self.vault)
            .unwrap()
            .code
    }
}

async fn replay(actions: &[Action]) -> Result<(), TestCaseError> {
    let mut scenario = Box::pin(Scenario::start()).await;
    for (counter, action) in (1_u32..).zip(actions) {
        scenario.apply(action, counter).await;
    }
    for _ in 0..2 {
        for who in 0..2 {
            scenario.sync(who).await;
        }
    }
    let vault = scenario.vault;
    prop_assert_eq!(
        view(&scenario.devices[0], &vault),
        view(&scenario.devices[1], &vault)
    );
    prop_assert_eq!(scenario.head_code(0), scenario.head_code(1));
    for (id, titles) in &scenario.committed {
        let alice = scenario.history_titles(0, id);
        let bob = scenario.history_titles(1, id);
        for title in titles {
            prop_assert!(alice.contains(title), "alice lost {title}");
            prop_assert!(bob.contains(title), "bob lost {title}");
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn random_interleavings_of_two_clients_converge_and_keep_every_committed_version(
        actions in prop::collection::vec(action(), 1..10)
    ) {
        block_on(replay(&actions))?;
    }
}
