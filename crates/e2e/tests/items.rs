#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests assert by unwrapping and scenarios read top to bottom"
)]

use hasp_e2e::{Device, Haspd, PASSWORD};
use serde_json::Value;

fn titles(device: &Device, extra: &[&str]) -> Vec<String> {
    let mut args = vec!["item", "list"];
    args.extend_from_slice(extra);
    let mut titles: Vec<String> = device
        .data(&args)
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap().to_owned())
        .collect();
    titles.sort();
    titles
}

fn field<'a>(item: &'a Value, label: &str) -> &'a Value {
    item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .unwrap_or_else(|| panic!("no field {label} in {item}"))
}

fn second_device(server: &Haspd, first: &Device, secret_key: &str, fingerprint: &str) -> Device {
    let device = Device::new(&server.origin, &first.login, PASSWORD);
    device.signin_with_kit(secret_key, Some(fingerprint)).ok();
    device
}

fn patterned(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

#[test]
fn item_crud_history_and_attachments() {
    let (server, init) = Haspd::boot();
    let ada = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let kit = ada.signup(&init.code).ok().data();
    let secret_key = kit["secret_key"].as_str().unwrap().to_owned();

    let created = ada
        .run(
            &[
                "item",
                "create",
                "--title",
                "GitHub",
                "--url",
                "https://github.com/login",
                "--tag",
                "dev",
                "--notes",
                "work account",
                "--field",
                "username=ada",
                "--field-stdin",
                "password",
            ],
            &["first-password"],
        )
        .ok()
        .data();
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["title"], "GitHub");
    let shown = ada.data(&["--reveal", "item", "get", "GitHub"]);
    assert_eq!(shown["category"], "login");
    assert_eq!(shown["notes"], "work account");
    assert_eq!(shown["urls"][0], "https://github.com/login");
    assert_eq!(field(&shown, "username")["value"], "ada");
    let password = field(&shown, "password");
    assert_eq!(password["value"], "first-password");
    assert_eq!(password["concealed"], true);
    let hidden = ada.data(&["item", "get", &id]);
    assert_eq!(field(&hidden, "password")["value"], "<concealed>");

    ada.run(
        &[
            "item",
            "edit",
            "GitHub",
            "--title",
            "GitHub work",
            "--field-stdin",
            "password",
        ],
        &["second-password"],
    )
    .ok();
    assert_eq!(titles(&ada, &[]), ["GitHub work"]);
    assert_eq!(
        ada.data(&["read", "hasp://Private/GitHub work/password"])["value"],
        "second-password"
    );
    let history = ada.data(&["item", "history", "GitHub work"]);
    let versions = history.as_array().unwrap();
    assert!(versions.len() >= 2, "{history}");
    assert!(versions.iter().any(|v| v["title"] == "GitHub"));
    let first = versions
        .iter()
        .map(|v| v["version"].as_u64().unwrap())
        .min()
        .unwrap();
    ada.data(&[
        "item",
        "history",
        "GitHub work",
        "--restore",
        &first.to_string(),
    ]);
    assert_eq!(
        ada.data(&["read", "hasp://Private/GitHub/password"])["value"],
        "first-password"
    );

    assert_eq!(titles(&ada, &["--tag", "dev"]), ["GitHub"]);
    assert!(titles(&ada, &["--tag", "other"]).is_empty());
    ada.data(&["item", "archive", "GitHub"]);
    assert!(titles(&ada, &[]).is_empty());
    assert_eq!(titles(&ada, &["--archived"]), ["GitHub"]);
    ada.data(&["item", "restore", "GitHub"]);
    ada.data(&["item", "delete", "GitHub"]);
    assert_eq!(titles(&ada, &["--trashed"]), ["GitHub"]);
    ada.data(&["item", "restore", "GitHub"]);
    assert_eq!(titles(&ada, &[]), ["GitHub"]);

    let bytes = patterned(2_400_000);
    let source = ada.file("scan.bin");
    std::fs::write(&source, &bytes).unwrap();
    let put = ada.data(&["file", "put", "GitHub", source.to_str().unwrap()]);
    assert_eq!(put["name"], "scan.bin");
    assert_eq!(put["size"], 2_400_000);
    let listed = ada.data(&["file", "list", "GitHub"]);
    assert_eq!(listed[0]["size"], 2_400_000);
    let out = ada.file("scan.out");
    ada.data(&[
        "file",
        "get",
        "GitHub",
        "scan.bin",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), bytes);
    assert_eq!(
        ada.data(&["read", "hasp://Private/GitHub/scan.bin?attribute=size"])["value"],
        "2400000"
    );

    let laptop = second_device(&server, &ada, &secret_key, &init.fingerprint);
    let remote = laptop.file("remote.bin");
    laptop.data(&[
        "file",
        "get",
        "GitHub",
        "scan.bin",
        "--out",
        remote.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read(&remote).unwrap(),
        bytes,
        "the second device downloads the same bytes"
    );

    ada.data(&["file", "rm", "GitHub", "scan.bin"]);
    assert!(
        ada.data(&["file", "list", "GitHub"])
            .as_array()
            .unwrap()
            .is_empty()
    );
    laptop.run(&["sync"], &[]).ok();
    assert!(
        laptop
            .data(&["file", "list", "GitHub"])
            .as_array()
            .unwrap()
            .is_empty()
    );

    ada.data(&["item", "delete", "GitHub", "--permanent"]);
    assert!(titles(&ada, &[]).is_empty());
    assert!(titles(&ada, &["--trashed"]).is_empty());
    laptop.run(&["sync"], &[]).ok();
    assert!(titles(&laptop, &[]).is_empty());

    let generated = ada.data(&["generate", "--length", "24"]);
    assert_eq!(generated["password"].as_str().unwrap().chars().count(), 24);
}

#[test]
fn offline_queue_survives_a_stopped_server() {
    let (mut server, init) = Haspd::boot();
    let ada = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let kit = ada.signup(&init.code).ok().data();
    let secret_key = kit["secret_key"].as_str().unwrap().to_owned();
    ada.run(&["item", "create", "--title", "Online"], &[]).ok();
    let laptop = second_device(&server, &ada, &secret_key, &init.fingerprint);
    assert_eq!(titles(&laptop, &[]), ["Online"]);

    server.stop();
    let queued = ada
        .run(&["item", "create", "--title", "Queued while down"], &[])
        .ok();
    assert!(queued.stderr.contains("queued"), "{}", queued.stderr);
    ada.run(&["item", "edit", "Online", "--title", "Online edited"], &[])
        .ok();
    ada.run(
        &[
            "--offline",
            "item",
            "create",
            "--title",
            "Queued offline flag",
        ],
        &[],
    )
    .ok();
    let local = ada.data(&["--offline", "item", "list"]);
    let local = local.as_array().unwrap();
    assert_eq!(local.len(), 3, "{local:?}");
    assert!(
        local.iter().all(|item| item["pending"] == true),
        "{local:?}"
    );
    let down = ada.run(&["sync"], &[]);
    assert_eq!(down.code, 7, "{}", down.stdout);
    assert_eq!(down.error()["exit"], 7);

    server.start();
    let synced = ada.run(&["sync"], &[]).ok().data();
    assert!(
        synced
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["commits"].as_u64().unwrap_or(0) > 0 || v["head_seq"].as_u64().unwrap() > 2),
        "{synced}"
    );
    assert!(
        ada.data(&["item", "list"])
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["pending"] == false)
    );
    laptop.run(&["sync"], &[]).ok();
    assert_eq!(
        titles(&laptop, &[]),
        ["Online edited", "Queued offline flag", "Queued while down"]
    );
}

#[test]
fn whole_item_last_writer_wins_between_two_devices() {
    let (server, init) = Haspd::boot();
    let first = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let kit = first.signup(&init.code).ok().data();
    let secret_key = kit["secret_key"].as_str().unwrap().to_owned();
    first
        .run(
            &[
                "item",
                "create",
                "--title",
                "Shared note",
                "--notes",
                "original",
            ],
            &[],
        )
        .ok();
    let second = second_device(&server, &first, &secret_key, &init.fingerprint);
    assert_eq!(titles(&second, &[]), ["Shared note"]);

    first
        .run(
            &[
                "--offline",
                "item",
                "edit",
                "Shared note",
                "--title",
                "First device edit",
                "--notes",
                "from first",
            ],
            &[],
        )
        .ok();
    second
        .run(
            &[
                "item",
                "edit",
                "Shared note",
                "--title",
                "Second device edit",
                "--notes",
                "from second",
            ],
            &[],
        )
        .ok();

    let synced = first.run(&["sync"], &[]).ok();
    assert!(
        synced.stderr.contains("conflict on item"),
        "the later writer is told what it replaced: {}",
        synced.stderr
    );
    assert_eq!(titles(&first, &[]), ["First device edit"]);
    let winner = first.data(&["item", "get", "First device edit"]);
    assert_eq!(winner["notes"], "from first", "no per-field merge");

    second.run(&["sync"], &[]).ok();
    assert_eq!(titles(&second, &[]), ["First device edit"]);
    assert_eq!(
        second.data(&["item", "get", "First device edit"])["notes"],
        "from first"
    );
    let history = second.data(&["item", "history", "First device edit"]);
    assert!(
        history
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["title"] == "Second device edit"),
        "the replaced version stays in history: {history}"
    );
}
