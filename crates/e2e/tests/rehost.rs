#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "tests assert by unwrapping and scenarios read top to bottom"
)]

use hasp_e2e::{Device, Haspd, vault_secret_hashes};

const PASSPHRASE: &str = "an export passphrase that is long";

fn listing(device: &Device) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = device
        .data(&["item", "list"])
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["vault"].as_str().unwrap().to_owned(),
                item["title"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn restore(device: &Device, file: &std::path::Path, passphrase: &str) -> hasp_e2e::Out {
    device.run(
        &["restore", file.to_str().unwrap(), "--passphrase-stdin"],
        &[passphrase],
    )
}

#[test]
fn rehost_through_a_haspx_export_into_a_new_account_on_a_second_server() {
    let (first_server, init) = Haspd::boot();
    let ada = first_server.account("ada@example.com", &init.code);
    ada.run(
        &[
            "item",
            "create",
            "--title",
            "Bank",
            "--url",
            "https://bank.example",
            "--field",
            "username=ada",
            "--field-stdin",
            "password",
        ],
        &["bank-secret"],
    )
    .ok();
    ada.run(
        &[
            "item",
            "create",
            "--title",
            "Passport",
            "--category",
            "document",
        ],
        &[],
    )
    .ok();
    let scan: Vec<u8> = (0..400_000_u32)
        .map(|n| n.to_le_bytes()[0] ^ 0x5a)
        .collect();
    let scan_path = ada.file("scan.bin");
    std::fs::write(&scan_path, &scan).unwrap();
    ada.data(&["file", "put", "Passport", scan_path.to_str().unwrap()]);
    ada.data(&["vault", "create", "Family"]);
    ada.run(
        &[
            "item",
            "create",
            "--vault",
            "Family",
            "--title",
            "Wifi",
            "--field-stdin",
            "password",
        ],
        &["wifi-secret"],
    )
    .ok();
    ada.run(&["sync"], &[]).ok();

    let export = ada.file("rehost.haspx");
    let written = ada
        .run(
            &[
                "export",
                "--out",
                export.to_str().unwrap(),
                "--passphrase-stdin",
            ],
            &[PASSPHRASE],
        )
        .ok()
        .data();
    assert!(written["bytes"].as_u64().unwrap() > 400_000);
    let raw = std::fs::read(&export).unwrap();
    assert!(
        !raw.windows(11).any(|w| w == b"bank-secret"),
        "the export is encrypted"
    );

    let (second_server, second_init) = Haspd::boot();
    assert_ne!(second_server.origin, first_server.origin);
    let moved = second_server.account("ada@example.com", &second_init.code);

    let wrong = restore(&moved, &export, "definitely the wrong passphrase");
    assert_ne!(wrong.code, 0);
    assert_eq!(moved.data(&["item", "list"]).as_array().unwrap().len(), 0);

    let report = restore(&moved, &export, PASSPHRASE).ok().data();
    assert_eq!(report["items"], 3);
    assert_eq!(report["attachments"], 1);
    assert!(report["vaults"].as_u64().unwrap() >= 2);

    let vault_names = |device: &Device| -> Vec<String> {
        let mut names: Vec<String> = device
            .data(&["vault", "list"])
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    };
    assert_eq!(vault_names(&moved), vault_names(&ada));
    assert_eq!(listing(&moved), listing(&ada));
    assert_eq!(vault_secret_hashes(&moved), vault_secret_hashes(&ada));
    assert_eq!(
        moved.data(&["read", "hasp://Private/Bank/password"])["value"],
        "bank-secret"
    );
    let copy = moved.file("scan.copy");
    moved.data(&[
        "file",
        "get",
        "Passport",
        "scan.bin",
        "--out",
        copy.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&copy).unwrap(), scan);

    let backup = ada.file("account.haspx");
    let refused = ada.run(&["backup", "now", "--out", backup.to_str().unwrap()], &[]);
    assert_ne!(refused.code, 0, "backups are opt-in");
    assert!(!backup.exists());
}
