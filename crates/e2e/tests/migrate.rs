#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use hasp_e2e::{Device, Haspd, PASSWORD, query_strings, repo_root, run_sql};

fn v1_database(server: &Haspd) -> std::path::PathBuf {
    let script =
        std::fs::read_to_string(repo_root().join("apps/server/fixtures/schema-v1.sql")).unwrap();
    std::fs::create_dir_all(server.data_dir()).unwrap();
    let db = server.data_dir().join("haspd.sqlite3");
    run_sql(&db, &script);
    db
}

fn exercise(server: &Haspd, code: &str) {
    server.fingerprint();
    let first = Device::new(&server.origin, "bob@example.com", PASSWORD);
    let secret_key = first.signup(code).ok().text("secret_key");
    first
        .run(
            &[
                "item",
                "create",
                "--title",
                "After migration",
                "--field-stdin",
                "password",
            ],
            &["migrated-secret"],
        )
        .ok();
    let second = Device::new(&server.origin, "bob@example.com", PASSWORD);
    second.signin_with_kit(&secret_key, None).ok();
    assert_eq!(
        second.data(&["read", "hasp://Private/After migration/password"])["value"],
        "migrated-secret"
    );
    second
        .run(&["item", "create", "--title", "From second device"], &[])
        .ok();
    first.run(&["sync"], &[]).ok();
    assert_eq!(first.data(&["item", "list"]).as_array().unwrap().len(), 2);
    first
        .run(&["--reveal", "account", "recovery-code", "create"], &[])
        .ok();
}

#[test]
fn migrate_command_upgrades_the_v1_schema_and_clients_keep_working() {
    let mut server = Haspd::new();
    let db = v1_database(&server);
    let versions = "SELECT CAST(version AS TEXT) FROM _sqlx_migrations ORDER BY version";
    assert_eq!(query_strings(&db, versions), ["1"]);
    let migrated = server.run(&["migrate"], "").ok();
    assert!(
        migrated.stdout.contains("schema is at version 4"),
        "{}",
        migrated.stdout
    );
    assert_eq!(query_strings(&db, versions), ["1", "2", "3", "4"]);
    let backup = server
        .data_dir()
        .join("backups")
        .join("pre-migrate-v1-to-v4.sqlite3");
    assert!(
        backup.exists(),
        "a copy of the v1 database is kept before migrating"
    );
    assert_eq!(
        query_strings(&db, "SELECT login FROM accounts ORDER BY login"),
        ["alice"],
        "existing accounts survive"
    );
    let again = server.run(&["migrate"], "").ok();
    assert!(
        again.stdout.contains("schema is at version 4"),
        "{}",
        again.stdout
    );

    let init = server.run(&["init"], "").ok();
    assert!(
        init.stdout.contains("already has accounts"),
        "{}",
        init.stdout
    );
    server.start();
    let code = server.signup_code();
    exercise(&server, &code);
    server.stop();
    assert_eq!(
        query_strings(&db, "SELECT login FROM accounts ORDER BY login").len(),
        2
    );
}

#[test]
fn serve_migrates_the_v1_schema_on_start() {
    let mut server = Haspd::new();
    let db = v1_database(&server);
    server.start();
    assert!(
        server
            .data_dir()
            .join("backups")
            .join("pre-migrate-v1-to-v4.sqlite3")
            .exists()
    );
    let code = server.signup_code();
    exercise(&server, &code);
    assert_eq!(
        query_strings(&db, "SELECT login FROM accounts ORDER BY login"),
        ["alice", "bob@example.com"]
    );
}
