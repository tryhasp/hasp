use std::path::Path;
use std::sync::Arc;

use hasp_crypto::{Argon2idParams, SecretKey};
use hasp_proto::wire::TokenKind;
use hasp_proto::{AccountId, AttId, Epoch, Hash32, Rver, Seq, VaultId, VaultKind};

use crate::fixture::{HarnessOf, Scratch, TestStore};
use crate::{
    AccountRow, AccountState, AttachmentRow, AttachmentState, DataLayout, Durability, MemoryStore,
    PersistError, RestoreOptions, SqliteStore, Store, Unlimited, VaultPhase, VaultRow,
    create_snapshot, export_server_key, generate_server_key, import_server_key, install_server_key,
    issue_reregister_tokens, list_snapshots, load_server_key, prune_snapshots, restore_snapshot,
    server_fingerprint, staleness, verify_snapshot,
};
use crate::{KeyOrigin, Staleness, load_or_generate_server_key};

mod backup;
mod migration;
mod server_key;

const V1_FIXTURE: &str = include_str!("../../fixtures/schema-v1.sql");

fn layout(scratch: &Scratch) -> DataLayout {
    DataLayout::new(scratch.path().join("data"))
}

fn open(layout: &DataLayout) -> SqliteStore {
    SqliteStore::open_with(layout, Durability::Full).expect("open store")
}

fn run_sql(db: &Path, script: &str) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut conn = crate::store::connect(db, true, Durability::Full)
            .await
            .unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(script.to_owned()))
            .execute(&mut conn)
            .await
            .unwrap();
    });
}

fn vault_row(seq: u64) -> VaultRow {
    VaultRow {
        kind: VaultKind::Private,
        owner: AccountId::from_bytes([9; 16]),
        head_seq: Seq::new(seq).unwrap(),
        head_hash: Hash32::from_bytes([u8::try_from(seq % 250).unwrap(); 32]),
        rver: Rver::ZERO,
        epoch: Epoch::ZERO,
        state: VaultPhase::Active,
        dissolve: None,
        created: 1,
    }
}

fn attachment_row() -> AttachmentRow {
    AttachmentRow {
        vault_id: VaultId::from_bytes([1; 16]),
        size: 6,
        chunks: 2,
        state: AttachmentState::Complete,
        created: 1,
        refs: 1,
    }
}

fn commit_log_hash(n: u8) -> Hash32 {
    Hash32::from_bytes([n; 32])
}

fn exercise(store: &mut dyn Store) {
    let vault = VaultId::from_bytes([1; 16]);
    let seq = |n: u64| (vault, Seq::new(n).unwrap());
    store.vaults().put(vault, vault_row(1)).unwrap();
    store.commit_log().put(seq(1), commit_log_hash(1)).unwrap();
    store.begin().unwrap();
    store.commit_log().put(seq(2), commit_log_hash(2)).unwrap();
    store.rollback().unwrap();
    assert_eq!(store.commit_log().len().unwrap(), 1);
    assert!(store.commit_log().get(&seq(2)).unwrap().is_none());
    store.begin().unwrap();
    for n in 2..=5 {
        store
            .commit_log()
            .put(seq(n), commit_log_hash(u8::try_from(n).unwrap()))
            .unwrap();
    }
    store.commit().unwrap();
    store.rollback().unwrap();
    let range = store.commit_log().range(&seq(2), &seq(4)).unwrap();
    let seqs: Vec<u64> = range.iter().map(|(k, _)| k.1.get()).collect();
    assert_eq!(seqs, [2, 3, 4]);
    assert_eq!(
        store
            .commit_log()
            .last_in(&seq(1), &seq(4))
            .unwrap()
            .unwrap()
            .0
            .1
            .get(),
        4
    );
    assert!(
        store
            .commit_log()
            .range(&seq(4), &seq(2))
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .commit_log()
            .last_in(&seq(4), &seq(2))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.commit_log().remove(&seq(3)).unwrap(),
        Some(commit_log_hash(3))
    );
    assert_eq!(store.commit_log().remove(&seq(3)).unwrap(), None);
    store.commit_log().put(seq(4), commit_log_hash(44)).unwrap();
    assert_eq!(
        store.commit_log().get(&seq(4)).unwrap(),
        Some(commit_log_hash(44))
    );
    assert_eq!(store.commit_log().len().unwrap(), 4);
    let id = AccountId::from_bytes([3; 16]);
    store
        .accounts()
        .put(
            id,
            AccountRow {
                account_id: id,
                login: "café".to_owned(),
                notify_email: None,
                is_admin: true,
                state: AccountState::Disabled,
                cred_gen: 7,
                created: 11,
            },
        )
        .unwrap();
    let back = store.accounts().get(&id).unwrap().unwrap();
    assert_eq!(back.login, "café");
    assert!(back.is_admin);
    assert_eq!(back.state, AccountState::Disabled);
    store.logins().put("café".to_owned(), id).unwrap();
    store.logins().put("cafe".to_owned(), id).unwrap();
    let logins = store
        .logins()
        .range(&String::new(), &"zzz".to_owned())
        .unwrap();
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[0].0, "cafe");
    store.memberships().put((id, vault), ()).unwrap();
    store.memberships().put((id, vault), ()).unwrap();
    assert_eq!(store.memberships().len().unwrap(), 1);
    assert_eq!(store.memberships().get(&(id, vault)).unwrap(), Some(()));
    assert_eq!(store.memberships().remove(&(id, vault)).unwrap(), Some(()));
}

#[test]
fn memory_store_follows_the_table_contract() {
    exercise(&mut MemoryStore::new());
}

#[test]
fn sqlite_store_follows_the_table_contract() {
    let (mut store, _scratch) = SqliteStore::fresh();
    exercise(&mut store);
}

#[test]
fn committed_rows_survive_a_reopen_and_rolled_back_ones_do_not() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let vault = VaultId::from_bytes([1; 16]);
    {
        let mut store = open(&layout);
        store.begin().unwrap();
        store.vaults().put(vault, vault_row(2)).unwrap();
        store.commit().unwrap();
        store.begin().unwrap();
        store.vaults().put(vault, vault_row(3)).unwrap();
        store.rollback().unwrap();
    }
    let mut store = open(&layout);
    assert_eq!(
        store.vaults().get(&vault).unwrap().unwrap().head_seq.get(),
        2
    );
}

#[test]
fn a_dropped_transaction_commits_nothing() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let vault = VaultId::from_bytes([1; 16]);
    let att = AttId::from_bytes([5; 16]);
    {
        let mut store = open(&layout);
        store.vaults().put(vault, vault_row(1)).unwrap();
        store.begin().unwrap();
        store.vaults().put(vault, vault_row(9)).unwrap();
        store.attachments().put(att, attachment_row()).unwrap();
        store
            .attachment_chunks()
            .put((att, 0), Arc::new(b"abc".to_vec()))
            .unwrap();
    }
    let mut store = open(&layout);
    assert_eq!(
        store.vaults().get(&vault).unwrap().unwrap().head_seq.get(),
        1
    );
    assert!(store.attachments().get(&att).unwrap().is_none());
    assert!(store.attachment_chunks().get(&(att, 0)).unwrap().is_none());
    assert_eq!(store.sweep_blobs().unwrap(), Some(1));
    assert!(!layout.blob_path(&att, 0).exists());
}

#[test]
fn a_crash_image_taken_mid_write_recovers_only_committed_state() {
    let scratch = Scratch::new();
    let live = layout(&scratch);
    let vault = VaultId::from_bytes([1; 16]);
    let mut store = open(&live);
    store.begin().unwrap();
    store.vaults().put(vault, vault_row(4)).unwrap();
    store.commit().unwrap();
    store.begin().unwrap();
    store.vaults().put(vault, vault_row(5)).unwrap();
    let image = DataLayout::new(scratch.path().join("image"));
    std::fs::create_dir_all(image.root()).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let mut from = live.db_path().into_os_string();
        from.push(suffix);
        let mut to = image.db_path().into_os_string();
        to.push(suffix);
        if Path::new(&from).exists() {
            std::fs::copy(&from, &to).unwrap();
        }
    }
    let mut recovered = open(&image);
    assert_eq!(
        recovered
            .vaults()
            .get(&vault)
            .unwrap()
            .unwrap()
            .head_seq
            .get(),
        4
    );
    store.rollback().unwrap();
}

#[test]
fn rolling_back_removes_new_chunk_files_and_restores_replaced_ones() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let mut store = open(&layout);
    let att = AttId::from_bytes([6; 16]);
    store.attachments().put(att, attachment_row()).unwrap();
    store
        .attachment_chunks()
        .put((att, 0), Arc::new(b"old".to_vec()))
        .unwrap();
    store.begin().unwrap();
    store
        .attachment_chunks()
        .put((att, 0), Arc::new(b"new".to_vec()))
        .unwrap();
    store
        .attachment_chunks()
        .put((att, 1), Arc::new(b"extra".to_vec()))
        .unwrap();
    assert_eq!(std::fs::read(layout.blob_path(&att, 0)).unwrap(), b"new");
    store.rollback().unwrap();
    assert_eq!(std::fs::read(layout.blob_path(&att, 0)).unwrap(), b"old");
    assert!(!layout.blob_path(&att, 1).exists());
    assert_eq!(
        store
            .attachment_chunks()
            .get(&(att, 0))
            .unwrap()
            .unwrap()
            .as_slice(),
        b"old"
    );
}

#[test]
fn sweeping_deletes_unreferenced_chunk_files_and_keeps_live_ones() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let mut store = open(&layout);
    let att = AttId::from_bytes([7; 16]);
    store.attachments().put(att, attachment_row()).unwrap();
    for idx in 0..2 {
        store
            .attachment_chunks()
            .put((att, idx), Arc::new(vec![1; 4]))
            .unwrap();
    }
    assert_eq!(store.sweep_blobs().unwrap(), Some(0));
    store.attachment_chunks().remove(&(att, 1)).unwrap();
    assert_eq!(store.sweep_blobs().unwrap(), Some(1));
    assert!(layout.blob_path(&att, 0).exists());
    assert!(!layout.blob_path(&att, 1).exists());
    store.begin().unwrap();
    assert!(matches!(store.sweep_blobs(), Err(PersistError::Busy)));
    store.rollback().unwrap();
}

#[test]
fn a_damaged_chunk_file_is_an_error_never_wrong_bytes() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let mut store = open(&layout);
    let att = AttId::from_bytes([8; 16]);
    store.attachments().put(att, attachment_row()).unwrap();
    store
        .attachment_chunks()
        .put((att, 0), Arc::new(b"payload".to_vec()))
        .unwrap();
    std::fs::write(layout.blob_path(&att, 0), b"payloaD").unwrap();
    assert!(store.attachment_chunks().get(&(att, 0)).is_err());
}

#[test]
fn two_stores_committing_to_one_vault_serialise() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    drop(open(&layout));
    let vault = VaultId::from_bytes([1; 16]);
    let writers: Vec<_> = (0..4_u8)
        .map(|writer| {
            let layout = layout.clone();
            std::thread::spawn(move || {
                let mut store = SqliteStore::open_unlocked(&layout).unwrap();
                for _ in 0..15 {
                    store.begin().unwrap();
                    let head = store
                        .vaults()
                        .get(&vault)
                        .unwrap()
                        .map_or(0, |row| row.head_seq.get());
                    let next = head + 1;
                    store.vaults().put(vault, vault_row(next)).unwrap();
                    store
                        .commit_log()
                        .put(
                            (vault, Seq::new(next).unwrap()),
                            Hash32::from_bytes([writer; 32]),
                        )
                        .unwrap();
                    store.commit().unwrap();
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let mut store = open(&layout);
    assert_eq!(
        store.vaults().get(&vault).unwrap().unwrap().head_seq.get(),
        60
    );
    assert_eq!(store.commit_log().len().unwrap(), 60);
}
