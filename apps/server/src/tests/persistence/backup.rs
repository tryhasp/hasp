use super::*;

type Alice = (HarnessOf<SqliteStore>, crate::fixture::Client);

fn served(layout: &DataLayout) -> Alice {
    let store = open(layout);
    let mut h = HarnessOf::<SqliteStore>::over(store, Box::new(()), Arc::new(Unlimited));
    let alice = h.signup("alice");
    (h, alice)
}

fn commit_item(h: &HarnessOf<SqliteStore>, alice: &mut crate::fixture::Client, n: u8) -> u64 {
    let bundle = alice.vault.put_item(&alice.person, n, b"data");
    let commit = alice.vault.commit(bundle);
    h.call(Some(&alice.token), &commit).unwrap().head_seq.get()
}

fn head_of(layout: &DataLayout, vault: VaultId) -> u64 {
    let mut store = open(layout);
    store.vaults().get(&vault).unwrap().unwrap().head_seq.get()
}

#[test]
fn a_snapshot_is_consistent_hashed_and_excludes_uncommitted_writes() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    generate_server_key(layout.key_path()).unwrap();
    let mut store = open(&layout);
    let vault = VaultId::from_bytes([1; 16]);
    let att = AttId::from_bytes([4; 16]);
    store.vaults().put(vault, vault_row(2)).unwrap();
    store.attachments().put(att, attachment_row()).unwrap();
    store
        .attachment_chunks()
        .put((att, 0), Arc::new(b"chunk".to_vec()))
        .unwrap();
    store.begin().unwrap();
    store
        .vaults()
        .put(VaultId::from_bytes([2; 16]), vault_row(7))
        .unwrap();
    let info = create_snapshot(&layout, &layout.backups_dir(), 100, true).unwrap();
    store.rollback().unwrap();
    assert_eq!(info.manifest.vaults.len(), 1);
    assert_eq!(info.manifest.vaults[0].head_seq, 2);
    assert_eq!(info.manifest.blobs.len(), 1);
    assert!(info.manifest.key.is_some());
    assert_eq!(info.manifest.schema_version, crate::store::latest_schema());
    let verified = verify_snapshot(&info.dir).unwrap();
    assert_eq!(verified, info.manifest);
    std::fs::write(info.dir.join("haspd.sqlite3"), b"damaged").unwrap();
    assert!(matches!(
        verify_snapshot(&info.dir),
        Err(PersistError::HashMismatch(_))
    ));
}

#[test]
fn restore_drill_from_a_snapshot_into_an_empty_directory() {
    let scratch = Scratch::new();
    let source = layout(&scratch);
    generate_server_key(source.key_path()).unwrap();
    let (h, mut alice) = served(&source);
    assert_eq!(commit_item(&h, &mut alice, 1), 2);
    let vault = alice.vault.id;
    let att = AttId::from_bytes([4; 16]);
    h.server
        .with_store(|store| {
            store.attachments().put(att, attachment_row()).unwrap();
            store
                .attachment_chunks()
                .put((att, 0), Arc::new(b"file bytes".to_vec()))
                .unwrap();
        })
        .unwrap();
    let snapshot = create_snapshot(&source, &source.backups_dir(), 1_000, true).unwrap();
    assert_eq!(commit_item(&h, &mut alice, 2), 3);
    drop(h);
    let target = DataLayout::new(scratch.path().join("rebuilt"));
    let report = restore_snapshot(
        &snapshot.dir,
        &target,
        RestoreOptions {
            acknowledge_rollback: false,
        },
    )
    .unwrap();
    assert!(report.rolled_back.is_empty());
    assert!(report.previous.is_none());
    assert_eq!(
        load_server_key(target.key_path()).unwrap().expose(),
        load_server_key(source.key_path()).unwrap().expose()
    );
    let mut store = open(&target);
    assert_eq!(
        store.vaults().get(&vault).unwrap().unwrap().head_seq.get(),
        2
    );
    assert_eq!(
        store
            .attachment_chunks()
            .get(&(att, 0))
            .unwrap()
            .unwrap()
            .as_slice(),
        b"file bytes"
    );
    assert_eq!(store.sessions().len().unwrap(), 0);
    let h = HarnessOf::<SqliteStore>::over(store, Box::new(()), Arc::new(Unlimited));
    assert!(h.pull(&alice, &[(vault, 3)]).is_err());
}

#[test]
fn restore_refuses_to_roll_back_seen_state_unless_acknowledged() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    generate_server_key(layout.key_path()).unwrap();
    let (h, mut alice) = served(&layout);
    commit_item(&h, &mut alice, 1);
    let vault = alice.vault.id;
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    commit_item(&h, &mut alice, 2);
    drop(h);
    let refused = restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: false,
        },
    )
    .unwrap_err();
    let PersistError::RollbackRefused(vaults) = refused else {
        panic!("expected a refusal");
    };
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].vault_id, vault);
    assert_eq!(vaults[0].seen_seq, 3);
    assert_eq!(vaults[0].restored_seq, Some(2));
    assert_eq!(head_of(&layout, vault), 3);
    let report = restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: true,
        },
    )
    .unwrap();
    assert_eq!(report.rolled_back.len(), 1);
    let previous = report.previous.unwrap();
    assert!(previous.join("haspd.sqlite3").exists());
    assert_eq!(head_of(&layout, vault), 2);
}

#[test]
fn a_tampered_snapshot_is_refused_before_anything_changes() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let (h, mut alice) = served(&layout);
    commit_item(&h, &mut alice, 1);
    let vault = alice.vault.id;
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    commit_item(&h, &mut alice, 2);
    drop(h);
    let mut bytes = std::fs::read(snapshot.dir.join("haspd.sqlite3")).unwrap();
    bytes.push(0);
    std::fs::write(snapshot.dir.join("haspd.sqlite3"), bytes).unwrap();
    let error = restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: true,
        },
    )
    .unwrap_err();
    assert!(matches!(error, PersistError::HashMismatch(_)));
    assert_eq!(head_of(&layout, vault), 3);
}

#[test]
fn restore_refuses_while_a_server_holds_the_data_directory() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let store = open(&layout);
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    let error = restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: true,
        },
    )
    .unwrap_err();
    assert!(matches!(error, PersistError::Busy));
    assert!(matches!(
        SqliteStore::open(&layout),
        Err(PersistError::Busy)
    ));
    drop(store);
}

#[test]
fn pruning_keeps_the_newest_snapshots_and_staleness_follows_the_newest() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    drop(open(&layout));
    let root = layout.backups_dir();
    assert_eq!(staleness(&root, 100).unwrap(), Staleness::Never);
    for created in [10, 20, 30, 40] {
        create_snapshot(&layout, &root, created, false).unwrap();
    }
    std::fs::create_dir_all(root.join(".hasp-backup-00000000000000000099.partial")).unwrap();
    let removed = prune_snapshots(&root, 2).unwrap();
    assert_eq!(removed.len(), 3);
    let kept: Vec<u64> = list_snapshots(&root)
        .unwrap()
        .iter()
        .map(|(_, m)| m.created)
        .collect();
    assert_eq!(kept, [30, 40]);
    assert_eq!(list_snapshots(&root).unwrap().len(), 2);
    assert_eq!(prune_snapshots(&root, 0).unwrap().len(), 1);
    assert_eq!(list_snapshots(&root).unwrap().len(), 1);
    assert_eq!(staleness(&root, 50).unwrap(), Staleness::Fresh { age: 10 });
    assert_eq!(
        staleness(&root, 40 + 7 * 24 * 3600 + 1).unwrap(),
        Staleness::Stale {
            age: 7 * 24 * 3600 + 1
        }
    );
}

#[test]
fn a_default_snapshot_leaves_server_key_out_and_restore_keeps_the_live_key() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    generate_server_key(layout.key_path()).unwrap();
    drop(open(&layout));
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    assert!(snapshot.manifest.key.is_none());
    assert!(!snapshot.dir.join("secrets").exists());
    let before = load_server_key(layout.key_path()).unwrap();
    restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: false,
        },
    )
    .unwrap();
    assert_eq!(
        load_server_key(layout.key_path()).unwrap().expose(),
        before.expose()
    );
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn data_directory_database_and_snapshots_are_private() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    generate_server_key(layout.key_path()).unwrap();
    let mut store = open(&layout);
    store.begin().unwrap();
    store
        .vaults()
        .put(VaultId::from_bytes([1; 16]), vault_row(1))
        .unwrap();
    store.commit().unwrap();
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, true).unwrap();
    assert_eq!(mode_of(layout.root()), 0o700);
    assert_eq!(mode_of(&layout.blobs_dir()), 0o700);
    assert_eq!(mode_of(&layout.backups_dir()), 0o700);
    assert_eq!(mode_of(&layout.db_path()), 0o600);
    for suffix in ["-wal", "-shm"] {
        let mut name = layout.db_path().into_os_string();
        name.push(suffix);
        let path = std::path::PathBuf::from(name);
        if path.exists() {
            assert_eq!(mode_of(&path), 0o600, "{suffix}");
        }
    }
    assert_eq!(mode_of(&snapshot.dir), 0o700);
    assert_eq!(mode_of(&snapshot.dir.join("haspd.sqlite3")), 0o600);
    assert_eq!(mode_of(&snapshot.dir.join("secrets/server.key")), 0o600);
    assert_eq!(mode_of(&snapshot.dir.join("manifest.json")), 0o600);
}

#[test]
fn restore_checks_heads_against_the_snapshot_database_not_the_manifest() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let (h, mut alice) = served(&layout);
    commit_item(&h, &mut alice, 1);
    let vault = alice.vault.id;
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    commit_item(&h, &mut alice, 2);
    drop(h);
    let manifest_path = snapshot.dir.join("manifest.json");
    let edited = std::fs::read_to_string(&manifest_path)
        .unwrap()
        .replace("\"head_seq\": 2", "\"head_seq\": 9");
    std::fs::write(&manifest_path, edited).unwrap();
    let error = restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: true,
        },
    )
    .unwrap_err();
    assert!(matches!(error, PersistError::Manifest(_)));
    assert_eq!(head_of(&layout, vault), 3);
    assert!(!layout.restore_marker().exists());
}

#[test]
fn restore_fails_closed_when_the_live_database_cannot_be_read() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    drop(open(&layout));
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    std::fs::write(layout.db_path(), b"this is not a database").unwrap();
    let options = |acknowledge_rollback| RestoreOptions {
        acknowledge_rollback,
    };
    assert!(matches!(
        restore_snapshot(&snapshot.dir, &layout, options(false)),
        Err(PersistError::LiveUnreadable)
    ));
    restore_snapshot(&snapshot.dir, &layout, options(true)).unwrap();
    drop(open(&layout));
}

#[test]
fn restore_revokes_sessions_and_expires_unused_tokens() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let (h, alice) = served(&layout);
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    let _ = &alice;
    drop(h);
    let mut store = open(&layout);
    store.begin().unwrap();
    store
        .signup_tokens()
        .put(
            Hash32::from_bytes([9; 32]),
            crate::TokenRow {
                creator: None,
                target: None,
                expires: 4_000_000_000,
                used_by: None,
                kind: TokenKind::Signup,
                makes_admin: false,
            },
        )
        .unwrap();
    store.commit().unwrap();
    drop(store);
    let source_tokens = {
        let mut store = open(&layout);
        let sessions = store.sessions().len().unwrap();
        drop(store);
        sessions
    };
    assert!(source_tokens > 0);
    restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: true,
        },
    )
    .unwrap();
    let mut store = open(&layout);
    assert_eq!(store.sessions().len().unwrap(), 0);
    assert_eq!(store.session_tokens().len().unwrap(), 0);
    assert_eq!(store.enrol_channels().len().unwrap(), 0);
    assert_eq!(store.recovery_sessions().len().unwrap(), 0);
    let all = store
        .signup_tokens()
        .range(
            &Hash32::from_bytes([0; 32]),
            &Hash32::from_bytes([0xff; 32]),
        )
        .unwrap();
    assert!(
        all.iter()
            .all(|(_, row)| row.used_by.is_some() || row.expires == 0)
    );
}

#[test]
fn an_interrupted_restore_blocks_startup_until_it_is_run_again() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    let (h, mut alice) = served(&layout);
    commit_item(&h, &mut alice, 1);
    let vault = alice.vault.id;
    let snapshot = create_snapshot(&layout, &layout.backups_dir(), 5, false).unwrap();
    drop(h);
    std::fs::rename(layout.db_path(), scratch.path().join("moved-away.sqlite3")).unwrap();
    std::fs::write(layout.restore_marker(), b"crashed").unwrap();
    assert!(matches!(
        SqliteStore::open(&layout),
        Err(PersistError::RestoreInterrupted(_))
    ));
    assert!(matches!(
        SqliteStore::open_shared(&layout),
        Err(PersistError::RestoreInterrupted(_))
    ));
    assert!(!layout.db_path().exists());
    restore_snapshot(
        &snapshot.dir,
        &layout,
        RestoreOptions {
            acknowledge_rollback: false,
        },
    )
    .unwrap();
    assert!(!layout.restore_marker().exists());
    assert_eq!(head_of(&layout, vault), 2);
}
