use std::future::Future;
use std::sync::{Arc, Mutex};

use hasp_core::client::{Client, EmergencyKit, SignIn, SignUp};
use hasp_core::model::field::{Field, FieldValue, Purpose, Section};
use hasp_core::model::id::Id;
use hasp_core::model::item::{Item, ItemParts, ItemState};
use hasp_core::store::{Batch, Cache, Entry, MemoryStore, Store, StoreError};
use hasp_core::sync::VaultSyncState;
use hasp_proto::{ItemId, OwnKeys, VaultId, VaultState};
use hasp_testsupport::{TEST_ORIGIN, World, block_on};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use super::mallory::Mallory;

pub(crate) const PASSWORD: &str = "correct horse battery staple";
pub(crate) const ORIGIN: &str = TEST_ORIGIN;

pub(crate) fn secret(text: &str) -> SecretString {
    SecretString::from(text)
}

pub(crate) fn cancel() -> CancellationToken {
    CancellationToken::new()
}

pub(crate) fn run<F: Future>(future: F) -> F::Output {
    block_on(Box::pin(future))
}

pub(crate) fn login_item(title: &str, password: &str) -> Item {
    let password_field = Field::new(
        Id::from_bytes([200; 16]),
        "password",
        FieldValue::Concealed(SecretString::from(password)),
    )
    .unwrap()
    .with_purpose(Purpose::Password)
    .unwrap()
    .with_concealed(true);
    let section = Section::new(Id::from_bytes([7; 16]), "", vec![password_field]).unwrap();
    Item::new(ItemParts {
        kind: "login".to_owned(),
        title: title.to_owned(),
        subtitle: String::new(),
        tags: Vec::new(),
        favourite: None,
        state: ItemState::Active,
        sections: vec![section],
        notes: None,
        urls: Vec::new(),
        apps: Vec::new(),
        passkeys: Vec::new(),
        attachments: Vec::new(),
        password_history: Vec::new(),
        client_modified: 10,
        created: 10,
        expires_at: None,
    })
    .unwrap()
}

pub(crate) fn password_of(item: &Item) -> String {
    item.details()
        .sections
        .iter()
        .flat_map(|section| section.fields().iter())
        .find_map(|field| match field.value() {
            FieldValue::Concealed(value) => Some(value.expose_secret().to_owned()),
            _ => None,
        })
        .unwrap()
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SharedStore(Arc<Mutex<MemoryStore>>);

impl SharedStore {
    pub(crate) fn cache(&self) -> Cache<Self> {
        Cache::new(self.clone())
    }

    pub(crate) fn dump(&self) -> Vec<Entry> {
        self.0.lock().unwrap().scan(&[]).unwrap()
    }

    pub(crate) fn load(&self, entries: &[Entry]) {
        let mut batch = Batch::new();
        batch.delete_prefix(Vec::new());
        for (key, value) in entries {
            batch.put(key.clone(), value.clone());
        }
        self.0.lock().unwrap().apply(&batch).unwrap();
    }
}

impl Store for SharedStore {
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

pub(crate) type Victim = Client<Mallory, SharedStore>;

pub(crate) struct Phone {
    pub(crate) client: Victim,
    pub(crate) store: SharedStore,
    pub(crate) kit: Option<EmergencyKit>,
}

impl std::fmt::Debug for Phone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Phone(..)")
    }
}

impl Phone {
    pub(crate) fn kit(&self) -> &EmergencyKit {
        self.kit.as_ref().unwrap()
    }

    pub(crate) fn private(&self) -> VaultId {
        self.client.private_vault().unwrap()
    }

    pub(crate) fn add_login(&mut self, vault: &VaultId, title: &str, password: &str) -> ItemId {
        self.client
            .create_item(vault, &login_item(title, password))
            .unwrap()
    }

    pub(crate) fn state_of(&self, vault: &VaultId) -> VaultState {
        self.store
            .cache()
            .vault(vault)
            .unwrap()
            .unwrap()
            .state()
            .unwrap()
            .unwrap()
    }

    pub(crate) fn own_keys(&self) -> OwnKeys {
        let record = self
            .store
            .cache()
            .account()
            .unwrap()
            .unwrap()
            .record
            .unverified()
            .unwrap();
        OwnKeys {
            account_id: record.account_id,
            ik_pk: record.ik_pk,
            kem_pk: record.kem_pk,
            retired_kem_pk_hashes: Vec::new(),
        }
    }

    pub(crate) async fn sync_state(
        &mut self,
        vault: &VaultId,
    ) -> Result<VaultSyncState, hasp_core::CoreError> {
        let report = self.client.sync(&cancel()).await?;
        Ok(report
            .vaults
            .into_iter()
            .find(|sync| sync.vault_id == *vault)
            .unwrap()
            .state)
    }

    pub(crate) fn heads_of(&self, vault: &VaultId) -> hasp_core::client::HeadInfo {
        self.client
            .heads()
            .unwrap()
            .into_iter()
            .find(|head| head.vault_id == *vault)
            .unwrap()
    }
}

pub(crate) async fn phone(
    world: &mut World,
    mallory: &Mallory,
    login: &str,
    hardware: bool,
) -> Phone {
    let store = SharedStore::default();
    let (mut client, _) = world.client_on(mallory.clone(), store.clone(), hardware);
    let token = world.token().await;
    let kit = client
        .sign_up(
            &SignUp {
                origin: ORIGIN,
                token: &token,
                login,
                password: &secret(PASSWORD),
            },
            &cancel(),
        )
        .await
        .unwrap();
    Phone {
        client,
        store,
        kit: Some(kit),
    }
}

pub(crate) type Pending<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + 'a>>;

pub(crate) fn kit_device<'a>(
    world: &'a World,
    mallory: &'a Mallory,
    kit: &'a EmergencyKit,
    login: &'a str,
    password: &'a str,
) -> Pending<'a, Result<Phone, hasp_core::CoreError>> {
    Box::pin(async move {
        let store = SharedStore::default();
        let (mut client, _) = world.client_on(mallory.clone(), store.clone(), true);
        client
            .sign_in(
                &SignIn {
                    origin: ORIGIN,
                    login,
                    secret_key: kit.secret_key(),
                    password: &secret(password),
                    kit_server_fp: Some(kit.server_fingerprint_bytes()),
                },
                &cancel(),
            )
            .await?;
        Ok(Phone {
            client,
            store,
            kit: None,
        })
    })
}

pub(crate) async fn share(
    owner: &mut Phone,
    member: &mut Phone,
    name: &str,
    role: hasp_proto::Role,
) -> VaultId {
    let vault = owner.client.create_vault(name, &cancel()).await.unwrap();
    invite(owner, member, &vault, role).await;
    vault
}

pub(crate) async fn invite(
    owner: &mut Phone,
    member: &mut Phone,
    vault: &VaultId,
    role: hasp_proto::Role,
) {
    let offer = owner
        .client
        .invite_create(vault, role, &cancel())
        .await
        .unwrap();
    let accepted = member
        .client
        .invite_accept(&offer.code, &cancel())
        .await
        .unwrap();
    owner
        .client
        .add_member(
            vault,
            &offer.invite_id,
            &hasp_core::client::FingerprintCheck::Compared(accepted.my_fingerprint),
            &cancel(),
        )
        .await
        .unwrap();
    member.client.sync(&cancel()).await.unwrap();
}
