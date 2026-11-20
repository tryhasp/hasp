#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use hasp_e2e::{Device, Haspd, PASSWORD};

const KEY_PASSPHRASE: &str = "server key passphrase 123";

fn titles(device: &Device) -> Vec<String> {
    let mut titles: Vec<String> = device
        .data(&["item", "list"])
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap().to_owned())
        .collect();
    titles.sort();
    titles
}

fn kit_device(server: &Haspd, login: &str, secret_key: &str, fingerprint: &str) -> Device {
    let device = Device::new(&server.origin, login, PASSWORD);
    device.signin_with_kit(secret_key, Some(fingerprint)).ok();
    device
}

#[test]
fn snapshot_restore_drill_detects_rollback_and_accepts_older_server_state() {
    let (mut server, init) = Haspd::boot();
    let first = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let secret_key = first.signup(&init.code).ok().text("secret_key");
    first
        .run(&["item", "create", "--title", "Before"], &[])
        .ok();
    let second = kit_device(&server, "ada@example.com", &secret_key, &init.fingerprint);

    let backup = server
        .run(
            &["backup", "--to", server.backups_dir().to_str().unwrap()],
            "",
        )
        .ok();
    let snapshot = backup.stdout.lines().next().unwrap().trim().to_owned();
    assert!(std::path::Path::new(&snapshot).is_dir());

    first
        .run(&["item", "create", "--title", "After one"], &[])
        .ok();
    first
        .run(&["item", "create", "--title", "After two"], &[])
        .ok();
    second.run(&["sync"], &[]).ok();
    assert_eq!(titles(&second), ["After one", "After two", "Before"]);

    server.stop();
    let refused = server.run(&["restore", "--from", &snapshot], "");
    assert_eq!(refused.code, 1);
    assert!(
        refused.stdout.contains("would roll back vault"),
        "{}",
        refused.stdout
    );
    assert!(
        refused.stderr.contains("--acknowledge-rollback"),
        "{}",
        refused.stderr
    );
    let restored = server
        .run(
            &["restore", "--from", &snapshot, "--acknowledge-rollback"],
            "",
        )
        .ok();
    assert!(
        restored.stdout.contains("rolled back vault"),
        "{}",
        restored.stdout
    );
    server.start();

    let detected = first.run(&["sync"], &[]);
    assert_eq!(detected.code, 9, "{}", detected.stdout);
    assert_eq!(detected.error()["code"], "E_ROLLBACK");
    assert!(
        detected.stderr.contains("accept-rollback"),
        "{}",
        detected.stderr
    );
    let local = first.run(&["item", "list"], &[]).ok();
    assert!(local.stderr.contains("accept-rollback"), "{}", local.stderr);
    assert_eq!(
        titles(&first),
        ["After one", "After two", "Before"],
        "nothing is silently dropped"
    );
    let behind = first.data(&["vault", "list"]);
    assert_eq!(behind[0]["name"], "Private");

    let unconfirmed = first.run(&["vault", "accept-rollback", "Private"], &[]);
    assert_eq!(unconfirmed.code, 2, "accepting needs --yes");
    let accepted = first.data(&["vault", "accept-rollback", "Private", "--yes"]);
    assert!(
        accepted["accepted"].as_str().unwrap().contains("queued: 2"),
        "{accepted}"
    );
    first.run(&["sync"], &[]).ok();
    let fine = first.run(&["sync"], &[]).ok();
    assert!(fine.stderr.is_empty(), "{}", fine.stderr);
    assert_eq!(titles(&first), ["After one", "After two", "Before"]);

    let third = kit_device(&server, "ada@example.com", &secret_key, &init.fingerprint);
    assert_eq!(
        titles(&third),
        ["After one", "After two", "Before"],
        "the server holds the re-queued writes again"
    );
    let stale = second.run(&["sync"], &[]);
    assert_eq!(
        stale.code, 9,
        "the other device also notices the divergent server"
    );
    assert!(stale.stderr.contains("accept-rollback"), "{}", stale.stderr);
    second.data(&["vault", "accept-rollback", "Private", "--yes"]);
    second.run(&["sync"], &[]).ok();
    assert_eq!(titles(&second), ["After one", "After two", "Before"]);
}

#[test]
fn server_secret_loss_drill_reregisters_accounts() {
    let (mut server, init) = Haspd::boot();
    let ada = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let secret_key = ada.signup(&init.code).ok().text("secret_key");
    ada.run(
        &[
            "item",
            "create",
            "--title",
            "Kept",
            "--field-stdin",
            "password",
        ],
        &["kept-secret"],
    )
    .ok();
    let account_fingerprint = ada.data(&["whoami"])["fingerprint"].clone();

    server.stop();
    std::fs::remove_file(server.key_path()).unwrap();
    server.start();
    let new_fingerprint = server.fingerprint();
    assert_ne!(
        new_fingerprint, init.fingerprint,
        "a new server.key was generated"
    );

    let blocked =
        Device::new(&server.origin, "ada@example.com", PASSWORD).signin_with_kit(&secret_key, None);
    assert_ne!(
        blocked.code, 0,
        "without the old server.key no password verifies"
    );

    let issued = server.run(&["admin", "reregister"], "").ok();
    assert!(
        issued.stdout.contains(&new_fingerprint),
        "{}",
        issued.stdout
    );
    let code = issued
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("ada@example.com\t"))
        .unwrap()
        .trim()
        .to_owned();
    let wrong_server = ada.run(
        &[
            "account",
            "reregister",
            "--code",
            &code,
            "--server-fingerprint",
            &init.fingerprint,
        ],
        &[],
    );
    assert_ne!(
        wrong_server.code, 0,
        "the operator's fingerprint is compared"
    );
    let done = ada
        .run(
            &[
                "account",
                "reregister",
                "--code",
                &code,
                "--server-fingerprint",
                &new_fingerprint,
            ],
            &[],
        )
        .ok()
        .data();
    assert_eq!(done["reregistered"], true);
    assert_eq!(
        ada.data(&["whoami"])["fingerprint"],
        account_fingerprint,
        "the account identity is unchanged"
    );
    assert_eq!(
        ada.data(&["read", "hasp://Private/Kept/password"])["value"],
        "kept-secret"
    );

    let fresh = kit_device(&server, "ada@example.com", &secret_key, &new_fingerprint);
    assert_eq!(titles(&fresh), ["Kept"]);
    let reused = ada.run(
        &[
            "account",
            "reregister",
            "--code",
            &code,
            "--server-fingerprint",
            &new_fingerprint,
        ],
        &[],
    );
    assert_ne!(reused.code, 0, "a re-registration code is single use");
}

#[test]
fn server_key_export_and_import_restores_without_reregistering() {
    let (mut server, init) = Haspd::boot();
    let ada = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let secret_key = ada.signup(&init.code).ok().text("secret_key");
    ada.run(&["item", "create", "--title", "Kept"], &[]).ok();

    let exported = server.scratch().join("server-key.export");
    server
        .run(
            &["key", "export", "--to", exported.to_str().unwrap()],
            &format!("{KEY_PASSPHRASE}\n"),
        )
        .ok();
    let short = server.run(
        &[
            "key",
            "export",
            "--to",
            server.scratch().join("x").to_str().unwrap(),
        ],
        "short\n",
    );
    assert_ne!(short.code, 0, "a short passphrase is refused");

    server.stop();
    std::fs::remove_file(server.key_path()).unwrap();
    let wrong = server.run(
        &["key", "import", "--from", exported.to_str().unwrap()],
        "not the right passphrase\n",
    );
    assert_ne!(wrong.code, 0);
    let imported = server
        .run(
            &["key", "import", "--from", exported.to_str().unwrap()],
            &format!("{KEY_PASSPHRASE}\n"),
        )
        .ok();
    assert!(
        imported.stdout.contains(&init.fingerprint),
        "{}",
        imported.stdout
    );
    server.start();
    let fresh = kit_device(&server, "ada@example.com", &secret_key, &init.fingerprint);
    assert_eq!(titles(&fresh), ["Kept"]);
}
