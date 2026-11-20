use std::path::Path;

use super::{CliError, Context, run};
use crate::Store;
use crate::persist::PersistError;

struct Outcome {
    result: Result<(), CliError>,
    out: String,
}

fn haspd(dir: &Path, args: &[&str], stdin: &str) -> Outcome {
    let data = dir.join("data");
    let data = data.to_str().unwrap().to_owned();
    let backups = dir.join("backups").to_str().unwrap().to_owned();
    let env = move |key: &str| match key {
        "HASP_DATA_DIR" => Some(data.clone()),
        "HASP_BACKUP_DIR" => Some(backups.clone()),
        "HASP_PUBLIC_URL" => Some("https://hasp.example.com".to_owned()),
        _ => None,
    };
    let mut input = std::io::Cursor::new(stdin.as_bytes().to_vec());
    let mut out = Vec::new();
    let result = run(
        std::iter::once("haspd").chain(args.iter().copied()),
        &mut Context {
            env: &env,
            input: &mut input,
            out: &mut out,
        },
    );
    Outcome {
        result,
        out: String::from_utf8_lossy(&out).into_owned(),
    }
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let outcome = haspd(dir, args, "");
    outcome.result.unwrap();
    outcome.out
}

#[test]
fn init_creates_the_key_and_database_and_is_repeatable() {
    let dir = tempfile::tempdir().unwrap();
    let first = ok(dir.path(), &["init"]);
    assert!(first.contains("server key created"));
    let code = first
        .lines()
        .find_map(|line| line.strip_prefix("first signup code (makes you the admin): "))
        .unwrap();
    assert!(hasp_proto::wire::SignupToken::parse(code).is_ok());
    assert!(dir.path().join("data/secrets/server.key").exists());
    assert!(dir.path().join("data/haspd.sqlite3").exists());
    let second = ok(dir.path(), &["init"]);
    assert!(second.contains("server key kept"));
    let fingerprint = ok(dir.path(), &["fingerprint"]);
    assert!(first.contains(fingerprint.trim()));
    assert_eq!(fingerprint.trim().len(), 29);
}

#[test]
fn migrate_reports_the_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    assert!(ok(dir.path(), &["migrate"]).contains("schema is at version"));
}

#[test]
fn signup_codes_are_parseable_and_distinct() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let first = ok(dir.path(), &["admin", "signup-code"]);
    let second = ok(dir.path(), &["admin", "token", "--admin"]);
    for text in [&first, &second] {
        assert!(hasp_proto::wire::SignupToken::parse(text.trim()).is_ok());
    }
    assert_ne!(first, second);
}

#[test]
fn reregister_lists_the_fingerprint_and_one_parseable_code_per_active_account() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let listing = ok(dir.path(), &["admin", "reregister"]);
    let mut lines = listing.lines();
    let fingerprint = ok(dir.path(), &["fingerprint"]);
    assert_eq!(
        lines.next().unwrap(),
        format!("server fingerprint: {}", fingerprint.trim())
    );
    assert_eq!(lines.next(), None);
}

#[test]
fn backup_and_restore_round_trip_and_prune() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let output = ok(dir.path(), &["backup"]);
    let snapshot = output.lines().next().unwrap();
    assert!(Path::new(snapshot).join("manifest.json").exists());
    assert!(!Path::new(snapshot).join("secrets/server.key").exists());
    assert!(output.contains("does not contain server.key"));
    let restored = ok(dir.path(), &["restore", "--from", snapshot]);
    assert!(restored.contains("restored"));
    let fingerprint = ok(dir.path(), &["fingerprint"]);
    assert_eq!(fingerprint.trim().len(), 29);
}

#[test]
fn restore_of_a_missing_snapshot_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let outcome = haspd(
        dir.path(),
        &["restore", "--from", "/nonexistent/snapshot"],
        "",
    );
    assert!(matches!(outcome.result, Err(CliError::Persist(_))));
}

#[test]
fn key_export_and_import_move_the_key_under_a_passphrase() {
    let source = tempfile::tempdir().unwrap();
    ok(source.path(), &["init"]);
    let export = source.path().join("server.key.export");
    let target = export.to_str().unwrap();
    let phrase = "correct horse battery staple\n";
    haspd(source.path(), &["key", "export", "--to", target], phrase)
        .result
        .unwrap();
    let bytes = std::fs::read(&export).unwrap();
    let raw = std::fs::read(source.path().join("data/secrets/server.key")).unwrap();
    assert!(
        !bytes
            .windows(raw.len())
            .any(|window| window == raw.as_slice())
    );

    let fresh = tempfile::tempdir().unwrap();
    let wrong = haspd(
        fresh.path(),
        &["key", "import", "--from", target],
        "another long passphrase\n",
    );
    assert!(matches!(
        wrong.result,
        Err(CliError::Persist(PersistError::Passphrase))
    ));
    let imported = haspd(fresh.path(), &["key", "import", "--from", target], phrase);
    imported.result.unwrap();
    assert_eq!(
        ok(fresh.path(), &["fingerprint"]),
        ok(source.path(), &["fingerprint"])
    );
    let again = haspd(fresh.path(), &["key", "import", "--from", target], phrase);
    assert!(matches!(
        again.result,
        Err(CliError::Persist(PersistError::KeyExists))
    ));
}

#[test]
fn short_passphrases_are_refused_and_never_echoed() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let export = dir.path().join("out");
    let outcome = haspd(
        dir.path(),
        &["key", "export", "--to", export.to_str().unwrap()],
        "short\n",
    );
    let Err(error) = outcome.result else {
        panic!("expected a refusal");
    };
    assert!(!error.to_string().contains("short\n"));
    assert!(!export.exists());
}

#[test]
fn fingerprint_without_a_key_names_the_problem() {
    let dir = tempfile::tempdir().unwrap();
    let outcome = haspd(dir.path(), &["fingerprint"], "");
    assert!(matches!(
        outcome.result,
        Err(CliError::Persist(PersistError::KeyMissing))
    ));
}

#[test]
fn bad_arguments_and_help_do_not_run_anything() {
    let dir = tempfile::tempdir().unwrap();
    assert!(haspd(dir.path(), &["--help"], "").result.is_ok());
    assert!(haspd(dir.path(), &["no-such-command"], "").result.is_err());
    assert!(!dir.path().join("data").exists());
}

#[test]
fn a_running_gateway_answers_the_container_healthcheck() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let layout = crate::persist::DataLayout::new(dir.path().join("data"));
    let key = crate::load_server_key(layout.key_path()).unwrap();
    let store = crate::SqliteStore::open(&layout).unwrap();
    let server = std::sync::Arc::new(
        crate::Server::new(
            crate::ServerConfig::new("https://hasp.example.com", key),
            store,
            std::sync::Arc::new(crate::SystemClock),
            std::sync::Arc::new(crate::Unlimited),
        )
        .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, signal) = tokio::sync::oneshot::channel::<()>();
    let gateway = crate::Gateway::new(server, crate::HttpOptions::default());
    let task = runtime.spawn(gateway.run(listener, async move {
        let _fired = signal.await;
    }));
    let probe = std::thread::spawn(move || super::healthcheck::check(address));
    probe.join().unwrap().unwrap();
    stop.send(()).unwrap();
    runtime.block_on(task).unwrap().unwrap();
    assert!(super::healthcheck::check(address).is_err());
}

#[test]
fn admin_commands_share_the_database_with_a_running_server() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let layout = crate::persist::DataLayout::new(dir.path().join("data"));
    let key = crate::load_server_key(layout.key_path()).unwrap();
    let store = crate::SqliteStore::open(&layout).unwrap();
    let server = std::sync::Arc::new(
        crate::Server::new(
            crate::ServerConfig::new("https://hasp.example.com", key),
            store,
            std::sync::Arc::new(crate::SystemClock),
            std::sync::Arc::new(crate::Unlimited),
        )
        .unwrap(),
    );
    let writer = {
        let server = std::sync::Arc::clone(&server);
        std::thread::spawn(move || {
            for _ in 0..40 {
                server.issue_bootstrap_token().unwrap();
            }
        })
    };
    let mut last = String::new();
    for _ in 0..15 {
        last = ok(dir.path(), &["admin", "signup-code", "--admin"]);
    }
    writer.join().unwrap();
    let token = hasp_proto::wire::SignupToken::parse(last.trim()).unwrap();
    let person = crate::fixture::Person::new("dana@example.com");
    let (start, _state) = person.register_start(&token);
    server.call(&crate::Caller::anonymous(), &start).unwrap();
    assert!(ok(dir.path(), &["admin", "reregister"]).starts_with("server fingerprint: "));
    assert!(matches!(
        haspd(dir.path(), &["init"], "").result,
        Err(CliError::Persist(PersistError::Busy))
    ));
}

#[test]
fn admin_commands_refuse_a_database_that_was_never_initialised() {
    let dir = tempfile::tempdir().unwrap();
    let outcome = haspd(dir.path(), &["admin", "signup-code"], "");
    assert!(outcome.result.is_err());
    assert!(!dir.path().join("data/haspd.sqlite3").exists());
}

#[test]
fn backup_keeps_the_configured_number_of_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let root = dir.path().join("backups");
    let layout = crate::persist::DataLayout::new(dir.path().join("data"));
    for second in 1..=9 {
        crate::create_snapshot(&layout, &root, 1_700_000_000 + second, false).unwrap();
    }
    assert_eq!(crate::list_snapshots(&root).unwrap().len(), 9);
    ok(dir.path(), &["backup"]);
    assert_eq!(crate::list_snapshots(&root).unwrap().len(), 7);

    let other = tempfile::tempdir().unwrap();
    ok(other.path(), &["init"]);
    let other_root = other.path().join("backups");
    let other_layout = crate::persist::DataLayout::new(other.path().join("data"));
    for second in 1..=4 {
        crate::create_snapshot(&other_layout, &other_root, 1_700_000_000 + second, false).unwrap();
    }
    ok(other.path(), &["backup", "--keep", "2"]);
    assert_eq!(crate::list_snapshots(&other_root).unwrap().len(), 2);
}

#[test]
fn include_key_adds_the_key_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let output = ok(dir.path(), &["backup", "--include-key"]);
    let snapshot = output.lines().next().unwrap();
    assert!(Path::new(snapshot).join("secrets/server.key").exists());
    assert!(output.contains("WARNING"));
}

#[test]
fn the_key_export_refuses_the_backups_directory_and_can_go_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let phrase = "correct horse battery staple\n";
    let inside = dir.path().join("backups").join("server.key.enc");
    let refused = haspd(
        dir.path(),
        &["key", "export", "--to", inside.to_str().unwrap()],
        phrase,
    );
    assert!(matches!(refused.result, Err(CliError::Failed(_))));
    assert!(!inside.exists());
    let streamed = haspd(dir.path(), &["key", "export", "--to", "-"], phrase);
    streamed.result.unwrap();
    assert!(streamed.out.starts_with("HSK1"));
}

#[test]
fn a_passphrase_under_twenty_characters_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init"]);
    let export = dir.path().join("out");
    let outcome = haspd(
        dir.path(),
        &["key", "export", "--to", export.to_str().unwrap()],
        "nineteen characters\n",
    );
    assert!(outcome.result.is_err());
}

#[test]
fn init_replaces_an_unused_bootstrap_code() {
    let dir = tempfile::tempdir().unwrap();
    let first = ok(dir.path(), &["init"]);
    let second = ok(dir.path(), &["init"]);
    let code = |text: &str| {
        text.lines()
            .find_map(|l| l.split(": ").nth(1).filter(|c| c.starts_with("SGN1")))
            .unwrap()
            .to_owned()
    };
    assert_ne!(code(&first), code(&second));
    let layout = crate::DataLayout::new(dir.path().join("data"));
    let mut store = crate::SqliteStore::open(&layout).unwrap();
    let bootstrap = store
        .signup_tokens()
        .range(
            &hasp_proto::Hash32::from_bytes([0; 32]),
            &hasp_proto::Hash32::from_bytes([0xff; 32]),
        )
        .unwrap();
    assert_eq!(bootstrap.len(), 1);
}
