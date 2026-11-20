#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hasp_e2e::{
    Device, Haspd, bitwarden_secrets, csv_secrets, item_count, onepux_data, onepux_items,
    onepux_secrets, repo_root, vault_secret_hashes,
};

fn fixture(name: &str) -> PathBuf {
    repo_root().join("testvectors/import").join(name)
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

struct Imported {
    preview: serde_json::Value,
    committed: serde_json::Value,
}

fn import(device: &Device, kind: &str, file: &Path) -> Imported {
    let report_out = device.file(&format!("{kind}.report.json"));
    let before = item_count(device);
    let preview = device
        .run(
            &[
                "import",
                kind,
                path_str(file),
                "--dry-run",
                "--report-out",
                path_str(&report_out),
            ],
            &[],
        )
        .ok()
        .data();
    assert_eq!(item_count(device), before, "a dry run writes nothing");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_out).unwrap()).unwrap();
    assert_eq!(
        report["items"].as_array().unwrap().len() as u64,
        preview["items"].as_u64().unwrap() + preview["skipped"].as_u64().unwrap(),
        "every source item has a line in the migration report"
    );
    let refused = device.run(&["import", kind, path_str(file)], &[]);
    assert_eq!(
        refused.code, 2,
        "an import without --yes or --dry-run is a usage error"
    );
    let committed = device
        .run(&["import", kind, path_str(file), "--yes"], &[])
        .ok()
        .data();
    Imported { preview, committed }
}

fn fresh_account(server: &Haspd, admin: &Device, login: &str) -> Device {
    let code = admin.data(&["admin", "token", "create"])["signup_code"]
        .as_str()
        .unwrap()
        .to_owned();
    server.account(login, &code)
}

fn assert_secrets_equal(label: &str, oracle: &BTreeSet<String>, vault: &BTreeSet<String>) {
    assert!(!oracle.is_empty(), "{label}: the fixture has secrets");
    let missing: Vec<_> = oracle.difference(vault).collect();
    let extra: Vec<_> = vault.difference(oracle).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{label}: secret hashes differ, {} missing from the vault, {} unexpected in it",
        missing.len(),
        extra.len()
    );
}

fn check_onepux(server: &Haspd, admin: &Device, login: &str, file: &Path) {
    let account = fresh_account(server, admin, login);
    let data = onepux_data(file);
    let expected = onepux_items(&data).len();
    let imported = import(&account, "1pux", file);
    let items = usize::try_from(imported.committed["imported"].as_u64().unwrap()).unwrap();
    let skipped = usize::try_from(imported.committed["skipped"].as_u64().unwrap()).unwrap();
    assert_eq!(items + skipped, expected, "count equality with the 1PUX");
    assert_eq!(item_count(&account), items);
    assert_secrets_equal(
        "1pux",
        &onepux_secrets(&data),
        &vault_secret_hashes(&account),
    );

    let reports = account.data(&["import", "report", "list"]);
    let id = reports[0]["id"].as_str().unwrap().to_owned();
    let report = account
        .run(&["import", "report", "show", &id], &[])
        .ok()
        .data();
    assert_eq!(report["items"].as_array().unwrap().len(), expected);
    assert_eq!(
        reports[0]["with_loss"].as_u64().unwrap(),
        imported.committed["with_loss"].as_u64().unwrap()
    );
    assert!(
        report["notes"].as_array().is_some(),
        "the report carries its notes"
    );

    let again = account
        .run(&["import", "1pux", path_str(file), "--yes"], &[])
        .ok()
        .data();
    assert_eq!(again["imported"], 0, "a second import adds nothing");
    assert_eq!(again["already_imported"], items);
    assert_eq!(item_count(&account), items);
}

#[test]
fn onepux_import_matches_count_and_secret_hashes() {
    let (server, init) = Haspd::boot();
    let admin = server.account("admin@example.com", &init.code);
    check_onepux(
        &server,
        &admin,
        "onepux@example.com",
        &fixture("onepux-basic.1pux"),
    );
    let preview_account = fresh_account(&server, &admin, "preview@example.com");
    let imported = import(&preview_account, "1pux", &fixture("onepux-basic.1pux"));
    assert_eq!(imported.preview["source"], "1password");
    assert_eq!(imported.preview["vaults"], 2);
    assert!(imported.preview["with_loss"].as_u64().unwrap() >= 1);
    assert!(imported.preview["categories"]["login"].as_u64().unwrap() >= 1);
    let vaults = preview_account.data(&["vault", "list"]);
    assert!(
        vaults
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["name"] == "Family"),
        "a shared 1Password vault becomes a vault: {vaults}"
    );
}

#[test]
#[ignore = "pending the author's real 1PUX: set HASP_REAL_1PUX to its path"]
fn authors_real_onepux_matches_count_and_secret_hashes() {
    let path = std::env::var_os("HASP_REAL_1PUX")
        .map(PathBuf::from)
        .expect("HASP_REAL_1PUX names the author's 1PUX export");
    let (server, init) = Haspd::boot();
    let admin = server.account("admin@example.com", &init.code);
    check_onepux(&server, &admin, "author@example.com", &path);
}

#[test]
fn bitwarden_import_matches_count_and_secret_hashes() {
    let (server, init) = Haspd::boot();
    let admin = server.account("admin@example.com", &init.code);
    let account = fresh_account(&server, &admin, "bw@example.com");
    let file = fixture("bitwarden-individual.json");
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let expected = data["items"].as_array().unwrap().len();
    let imported = import(&account, "bitwarden", &file);
    assert_eq!(
        imported.committed["imported"].as_u64().unwrap()
            + imported.committed["skipped"].as_u64().unwrap(),
        expected as u64
    );
    assert_eq!(item_count(&account), expected);
    assert_eq!(imported.committed["categories"]["credit-card"], 1);
    assert_secrets_equal(
        "bitwarden",
        &bitwarden_secrets(&data),
        &vault_secret_hashes(&account),
    );
    let trashed = account.data(&["item", "list", "--trashed"]);
    assert_eq!(
        trashed.as_array().unwrap().len(),
        1,
        "the source's trash stays in the trash"
    );
    let again = account
        .run(&["import", "bitwarden", path_str(&file), "--yes"], &[])
        .ok()
        .data();
    assert_eq!(again["imported"], 0);
}

#[test]
fn csv_imports_from_two_exports_both_land() {
    let (server, init) = Haspd::boot();
    let admin = server.account("admin@example.com", &init.code);
    let account = fresh_account(&server, &admin, "csv@example.com");
    let chrome = fixture("csv-chrome.csv");
    let bitwarden = fixture("csv-bitwarden.csv");
    let first = import(&account, "csv", &chrome);
    assert_eq!(first.committed["imported"], 2);
    let second = import(&account, "csv", &bitwarden);
    assert_eq!(
        second.committed["imported"], 2,
        "a second CSV file is not mistaken for the first: {}",
        second.committed
    );
    assert_eq!(item_count(&account), 4);
    let mut expected = csv_secrets(&chrome, &["password"]);
    expected.extend(csv_secrets(&bitwarden, &["login_password", "login_totp"]));
    assert_secrets_equal("csv", &expected, &vault_secret_hashes(&account));
    let again = account
        .run(&["import", "csv", path_str(&chrome), "--yes"], &[])
        .ok()
        .data();
    assert_eq!(again["imported"], 0);
    assert_eq!(again["already_imported"], 2);
}
