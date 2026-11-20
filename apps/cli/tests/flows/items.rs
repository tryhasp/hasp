use super::*;

#[test]
fn item_lifecycle_with_history_trash_and_restore() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let id = create_login(&device, "GitHub", "first-password-1");

    let listed = unlocked(&device, &["item", "list"]).ok().data();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["title"], "GitHub");

    let concealed = unlocked(&device, &["item", "get", "GitHub"]).ok().data();
    let password = concealed["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "Password" || f["purpose"] == "password")
        .unwrap()
        .clone();
    assert_eq!(password["value"], "<concealed>");

    let revealed = device
        .run(
            &["--password-stdin", "--reveal", "item", "get", &id],
            &[PASSWORD],
        )
        .ok()
        .data();
    let shown: Vec<&Value> = revealed["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["value"] == "first-password-1")
        .collect();
    assert_eq!(shown.len(), 1);

    device
        .run(
            &[
                "--password-stdin",
                "item",
                "edit",
                &id,
                "--field-stdin",
                "password",
                "--tag",
                "work",
            ],
            &[PASSWORD, "second-password-2"],
        )
        .ok();
    let history = unlocked(&device, &["item", "history", &id]).ok().data();
    assert!(history.as_array().unwrap().len() >= 2);

    unlocked(&device, &["item", "delete", &id]).ok();
    assert_eq!(
        unlocked(&device, &["item", "list"])
            .ok()
            .data()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let trashed = unlocked(&device, &["item", "list", "--trashed"])
        .ok()
        .data();
    assert_eq!(trashed.as_array().unwrap().len(), 1);
    unlocked(&device, &["item", "restore", &id]).ok();
    let back = unlocked(&device, &["item", "list", "--tag", "work"])
        .ok()
        .data();
    assert_eq!(back.as_array().unwrap().len(), 1);
}

#[test]
fn read_resolves_secret_references_and_attributes() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "GitHub", "pw-for-reading-1");
    let read = device
        .run(
            &[
                "--password-stdin",
                "--format",
                "table",
                "read",
                "hasp://Private/GitHub/password",
            ],
            &[PASSWORD],
        )
        .ok();
    assert_eq!(read.out, "pw-for-reading-1");
    let newline = device
        .run(
            &[
                "--password-stdin",
                "--format",
                "table",
                "read",
                "--newline",
                "hasp://Private/GitHub/password",
            ],
            &[PASSWORD],
        )
        .ok();
    assert_eq!(newline.out, "pw-for-reading-1\n");
    let kind = device
        .run(
            &[
                "--password-stdin",
                "--format",
                "table",
                "read",
                "hasp://Private/GitHub/username?attribute=type",
            ],
            &[PASSWORD],
        )
        .ok();
    assert_eq!(kind.out, "text");
    let missing = unlocked(&device, &["read", "hasp://Private/GitHub/nothing"]);
    assert_eq!(missing.code, 4);
    let bad = unlocked(&device, &["read", "https://Private/GitHub/password"]);
    assert_eq!(bad.code, 2);
}

#[test]
fn totp_item_produces_a_code() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    device
        .run(
            &[
                "--password-stdin",
                "item",
                "create",
                "--title",
                "Mail",
                "--field",
                "totp=JBSWY3DPEHPK3PXP",
            ],
            &[PASSWORD],
        )
        .ok();
    let code = unlocked(&device, &["otp", "Mail"]).ok().data();
    assert_eq!(code["code"].as_str().unwrap().len(), 6);
    let via_read = device
        .run(
            &[
                "--password-stdin",
                "--format",
                "table",
                "read",
                "hasp://Private/Mail/totp?attribute=otp",
            ],
            &[PASSWORD],
        )
        .ok();
    assert_eq!(via_read.out.len(), 6);
}

#[test]
fn ambiguous_and_missing_names_exit_four() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "Twin", "twin-password-1");
    create_login(&device, "Twin", "twin-password-2");
    let ambiguous = unlocked(&device, &["item", "get", "Twin"]);
    assert_eq!(ambiguous.code, 4);
    assert!(ambiguous.err.contains("ambiguous"));
    assert_eq!(
        ambiguous.json()["error"]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(unlocked(&device, &["item", "get", "Ghost"]).code, 4);
}

#[test]
fn json_output_is_versioned_and_conceals_secrets() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "GitHub", "hunter2hunter2");
    let got = unlocked(&device, &["item", "get", "GitHub"]);
    let document = got.json();
    assert_eq!(document["schema_version"], 1);
    assert!(!got.out.contains("hunter2hunter2"));
    let concealed_fields = document["data"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["concealed"] == true)
        .count();
    assert!(concealed_fields >= 1);
    assert!(got.out.contains("<concealed>"));
}

#[test]
fn table_output_matches_the_golden_files() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "GitHub", "hunter2hunter2");
    let list = unlocked(&device, &["--format", "table", "item", "list"]).ok();
    assert_golden("item-list-table", &list.out);
    let get = unlocked(&device, &["--format", "table", "item", "get", "GitHub"]).ok();
    assert_golden("item-get-table", &get.out);
    let vaults = unlocked(&device, &["--format", "table", "vault", "list"]).ok();
    assert_golden("vault-list-table", &vaults.out);
    let templates = device
        .run(
            &["--format", "table", "item", "template", "get", "login"],
            &[],
        )
        .ok();
    assert_golden("template-get-table", &templates.out);
}

#[test]
fn json_output_matches_the_golden_files() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "GitHub", "hunter2hunter2");
    let list = unlocked(&device, &["item", "list"]).ok();
    assert_golden("item-list-json", &list.out);
    let error = unlocked(&device, &["item", "get", "Ghost"]);
    assert_golden("error-not-found-json", &error.out);
}

#[test]
fn generate_supports_each_mode() {
    let world = World::new();
    let device = Device::new(&world, false);
    let random = device
        .run(&["--format", "table", "generate", "--length", "24"], &[])
        .ok();
    assert_eq!(random.out.trim_end().chars().count(), 24);
    let pin = device
        .run(
            &["--format", "table", "generate", "--pin", "--length", "8"],
            &[],
        )
        .ok();
    assert!(pin.out.trim_end().chars().all(|c| c.is_ascii_digit()));
    assert_eq!(pin.out.trim_end().len(), 8);
    let words = device
        .run(
            &[
                "--format",
                "table",
                "generate",
                "--memorable",
                "--length",
                "4",
            ],
            &[],
        )
        .ok();
    assert_eq!(words.out.trim_end().split('-').count(), 4);
    let rules = device
        .run(
            &[
                "--format",
                "table",
                "generate",
                "--rules",
                "minlength: 12; required: lower, upper, digit; allowed: lower, upper, digit",
            ],
            &[],
        )
        .ok();
    assert!(rules.out.trim_end().len() >= 12);
    let json = device.run(&["generate"], &[]).ok().data();
    assert!(json["password"].as_str().unwrap().len() >= 20);
    assert_eq!(
        device.run(&["generate", "--pin", "--memorable"], &[]).code,
        2
    );
}

#[test]
fn attachments_round_trip_through_files() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let id = create_login(&device, "Docs", "docs-password-1");
    let source = device.dir.path().join("note.txt");
    std::fs::write(&source, b"attachment body").unwrap();
    unlocked(&device, &["file", "put", &id, source.to_str().unwrap()]).ok();
    let files = unlocked(&device, &["file", "list", &id]).ok().data();
    assert_eq!(files[0]["name"], "note.txt");
    assert_eq!(files[0]["size"], 15);
    let out = device.dir.path().join("copy.txt");
    unlocked(
        &device,
        &[
            "file",
            "get",
            &id,
            "note.txt",
            "--out",
            out.to_str().unwrap(),
        ],
    )
    .ok();
    assert_eq!(std::fs::read(&out).unwrap(), b"attachment body");
    let via_read = device
        .run(
            &[
                "--password-stdin",
                "--format",
                "table",
                "read",
                "hasp://Private/Docs/note.txt?attribute=content",
            ],
            &[PASSWORD],
        )
        .ok();
    assert_eq!(via_read.out, "attachment body");
    unlocked(&device, &["file", "rm", &id, "note.txt"]).ok();
    assert_eq!(
        unlocked(&device, &["file", "list", &id])
            .ok()
            .data()
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn templates_and_generated_passwords_build_items() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let json = r#"{"category":"login","title":"Mail","urls":["https://mail.test"],"tags":["personal"],"fields":[{"key":"username","value":"ada@mail.test"},{"key":"recovery email","value":"ada@home.test","section":"Extra"}]}"#;
    let shared = device.run(
        &["--password-stdin", "item", "create", "--template", "-"],
        &[PASSWORD, json],
    );
    assert_eq!(
        shared.code, 2,
        "a template cannot share stdin with the password"
    );

    let hardware = signed_up(&mut world, "bob", true);
    hardware
        .run(
            &["item", "create", "--template", "-", "--generate-password"],
            &[json],
        )
        .ok();
    let got = hardware
        .run(&["--reveal", "item", "get", "Mail"], &[])
        .ok()
        .data();
    let fields = got["fields"].as_array().unwrap();
    let password = fields.iter().find(|f| f["purpose"] == "password").unwrap();
    assert_eq!(password["value"].as_str().unwrap().len(), 20);
    assert!(
        fields
            .iter()
            .any(|f| f["label"] == "recovery email" && f["section"] == "Extra")
    );
    assert_eq!(got["tags"][0], "personal");
}
