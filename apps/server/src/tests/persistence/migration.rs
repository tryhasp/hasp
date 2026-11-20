use super::*;

#[test]
fn a_fresh_database_is_at_the_latest_schema() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    drop(open(&layout));
    let status = status_of(&layout);
    assert!(status.is_current());
    assert!(!status.is_newer());
}

fn status_of(layout: &DataLayout) -> crate::SchemaStatus {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut conn = crate::store::connect_read_only(&layout.db_path())
            .await
            .unwrap();
        crate::store::schema_status(&mut conn).await.unwrap()
    })
}

#[test]
fn a_v1_database_migrates_to_the_latest_keeping_its_data_after_a_backup() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    std::fs::create_dir_all(layout.root()).unwrap();
    run_sql(&layout.db_path(), V1_FIXTURE);
    let mut store = open(&layout);
    let account = AccountId::from_bytes([0x11; 16]);
    let row = store.accounts().get(&account).unwrap().unwrap();
    assert_eq!(row.login, "alice");
    assert_eq!(row.notify_email.as_deref(), Some("alice@example.test"));
    assert_eq!(row.cred_gen, 3);
    let vault = VaultId::from_bytes([0x22; 16]);
    assert_eq!(
        store.vaults().get(&vault).unwrap().unwrap().head_seq.get(),
        5
    );
    assert_eq!(store.memberships().len().unwrap(), 1);
    assert_eq!(store.signup_tokens().len().unwrap(), 1);
    assert_eq!(
        store.logins().get(&"alice".to_owned()).unwrap(),
        Some(account)
    );
    drop(store);
    assert!(status_of(&layout).is_current());
    let backup = layout.backups_dir().join(format!(
        "pre-migrate-v1-to-v{}.sqlite3",
        crate::store::latest_schema()
    ));
    assert!(backup.exists());
    let backup_status = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut conn = crate::store::connect_read_only(&backup).await.unwrap();
            crate::store::schema_status(&mut conn).await.unwrap()
        })
    };
    assert_eq!(backup_status.applied, Some(1));
}

#[test]
fn a_database_from_a_newer_binary_is_refused_untouched() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    drop(open(&layout));
    run_sql(
        &layout.db_path(),
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (9999, 'future', 1, X'00', 1);",
    );
    let error = SqliteStore::open(&layout).unwrap_err();
    assert!(matches!(
        error,
        PersistError::SchemaNewer { found: 9999, .. }
    ));
}

#[test]
fn an_edited_applied_migration_is_refused() {
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    std::fs::create_dir_all(layout.root()).unwrap();
    let (head, tail) = V1_FIXTURE
        .split_once("INSERT INTO _sqlx_migrations")
        .unwrap();
    let tampered = format!(
        "{head}INSERT INTO _sqlx_migrations{}",
        tail.replacen("X'", "X'00", 1)
    );
    run_sql(&layout.db_path(), &tampered);
    assert!(matches!(
        SqliteStore::open(&layout),
        Err(PersistError::Migrate(_))
    ));
}
