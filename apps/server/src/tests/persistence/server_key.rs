use super::*;

#[test]
fn the_server_key_is_generated_once_private_and_reloadable() {
    let scratch = Scratch::new();
    let path = scratch.path().join("secrets").join("server.key");
    let (key, origin) = load_or_generate_server_key(&path).unwrap();
    assert_eq!(origin, KeyOrigin::Generated);
    let (again, origin) = load_or_generate_server_key(&path).unwrap();
    assert_eq!(origin, KeyOrigin::Loaded);
    assert_eq!(key.expose(), again.expose());
    assert!(matches!(
        generate_server_key(&path),
        Err(PersistError::KeyExists)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    std::fs::write(&path, b"short").unwrap();
    assert!(matches!(
        load_server_key(&path),
        Err(PersistError::KeyFormat)
    ));
}

#[test]
fn an_exported_key_imports_only_with_the_passphrase_and_untampered() {
    let key = SecretKey::random().unwrap();
    let params = Argon2idParams::local(64, 1, 1).unwrap();
    let export = export_server_key(&key, b"correct horse", params).unwrap();
    assert!(!export.windows(32).any(|w| w == key.expose()));
    let back = import_server_key(&export, b"correct horse").unwrap();
    assert_eq!(back.expose(), key.expose());
    assert!(matches!(
        import_server_key(&export, b"wrong"),
        Err(PersistError::Passphrase)
    ));
    let mut tampered = export.clone();
    tampered[7] ^= 1;
    assert!(import_server_key(&tampered, b"correct horse").is_err());
    let mut truncated = export.clone();
    truncated.truncate(30);
    assert!(matches!(
        import_server_key(&truncated, b"correct horse"),
        Err(PersistError::KeyFormat)
    ));
    let mut hostile = export;
    hostile[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        import_server_key(&hostile, b"correct horse"),
        Err(PersistError::KdfParams)
    ));
}

#[test]
fn installing_a_key_never_overwrites_one() {
    let scratch = Scratch::new();
    let path = scratch.path().join("server.key");
    let first = SecretKey::random().unwrap();
    let second = SecretKey::random().unwrap();
    install_server_key(&path, &first).unwrap();
    assert!(matches!(
        install_server_key(&path, &second),
        Err(PersistError::KeyExists)
    ));
    assert_eq!(load_server_key(&path).unwrap().expose(), first.expose());
    assert!(!scratch.path().join("server.key.previous").exists());
}

#[test]
fn the_fingerprint_is_stable_per_key_and_differs_between_keys() {
    let key = SecretKey::from_bytes([1; 32]);
    let print = server_fingerprint(&key).unwrap();
    assert_eq!(print, server_fingerprint(&key).unwrap());
    assert_ne!(
        print,
        server_fingerprint(&SecretKey::from_bytes([2; 32])).unwrap()
    );
    assert_eq!(hasp_proto::parse_fingerprint(&print).unwrap().len(), 15);
}

fn reregister_for(store: &mut dyn Store) {
    for (n, state) in [
        (1_u8, AccountState::Active),
        (2, AccountState::Disabled),
        (3, AccountState::Active),
    ] {
        let id = AccountId::from_bytes([n; 16]);
        store
            .accounts()
            .put(
                id,
                AccountRow {
                    account_id: id,
                    login: format!("user{n}"),
                    notify_email: None,
                    is_admin: false,
                    state,
                    cred_gen: 1,
                    created: 1,
                },
            )
            .unwrap();
    }
    let tokens = issue_reregister_tokens(store, 100, 50).unwrap();
    assert_eq!(tokens.len(), 2);
    assert!(tokens.iter().all(|t| t.expires == 150));
    for issued in &tokens {
        let row = store
            .signup_tokens()
            .get(&issued.token.hash())
            .unwrap()
            .unwrap();
        assert_eq!(row.kind, TokenKind::Reregister);
        assert_eq!(row.target, Some(issued.account_id));
        assert_eq!(row.creator, None);
        assert_eq!(row.used_by, None);
    }
    assert_eq!(store.signup_tokens().len().unwrap(), 2);
}

#[test]
fn server_secret_loss_issues_one_reregister_token_per_active_account() {
    reregister_for(&mut MemoryStore::new());
    let (mut store, _scratch) = SqliteStore::fresh();
    reregister_for(&mut store);
}

#[cfg(unix)]
#[test]
fn a_server_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let layout = layout(&scratch);
    generate_server_key(layout.key_path()).unwrap();
    std::fs::set_permissions(layout.key_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        load_server_key(layout.key_path()),
        Err(PersistError::KeyPermissions)
    ));
}
