use super::*;

#[test]
fn imports_report_losses_skip_repeats_and_flag_changes() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let file = device.dir.path().join("logins.csv");
    std::fs::write(
        &file,
        "name,url,username,password,notes\nGitHub,https://github.com,ada,pw-one-1,\nBank,https://bank.test,ada,pw-two-2,main\n",
    )
    .unwrap();
    let path = file.to_str().unwrap();
    let preview = unlocked(&device, &["import", "csv", path, "--dry-run"])
        .ok()
        .data();
    assert_eq!(preview["items"], 2);
    assert_eq!(
        unlocked(&device, &["item", "list"])
            .ok()
            .data()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(unlocked(&device, &["import", "csv", path]).code, 2);

    let done = unlocked(&device, &["import", "csv", path, "--yes"])
        .ok()
        .data();
    assert_eq!(done["imported"], 2);
    let listed = unlocked(&device, &["item", "list"]).ok().data();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert!(
        listed[0]["tags"][0]
            .as_str()
            .unwrap()
            .starts_with("imported/csv/")
    );

    let again = unlocked(&device, &["import", "csv", path, "--yes"])
        .ok()
        .data();
    assert_eq!(again["imported"], 0);
    assert_eq!(again["already_imported"], 2);

    std::fs::write(
        &file,
        "name,url,username,password,notes\nGitHub,https://github.com,ada,changed-pw-3,\nBank,https://bank.test,ada,pw-two-2,main\n",
    )
    .unwrap();
    let changed = unlocked(&device, &["import", "csv", path, "--yes"])
        .ok()
        .data();
    assert_eq!(changed["changed_since_import"][0], "GitHub");
    let secret = device
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
    assert_eq!(secret.out, "pw-one-1");

    let reports = unlocked(&device, &["import", "report", "list"]).ok().data();
    assert!(!reports.as_array().unwrap().is_empty());
    let id = reports[0]["id"].as_str().unwrap().to_owned();
    let shown = unlocked(&device, &["import", "report", "show", &id]).ok();
    assert_eq!(shown.json()["data"]["source"], "csv");
}

#[test]
fn bitwarden_import_maps_logins_and_reports_attachments() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let file = device.dir.path().join("bw.json");
    std::fs::write(
        &file,
        r#"{"encrypted":false,"folders":[{"id":"f1","name":"Work"}],"items":[{"id":"i1","folderId":"f1","type":1,"name":"Jira","notes":null,"favorite":true,"login":{"username":"ada","password":"jira-pw-1","totp":null,"uris":[{"match":null,"uri":"https://jira.test"}]},"fields":[]}]}"#,
    )
    .unwrap();
    let done = unlocked(
        &device,
        &[
            "import",
            "bitwarden",
            file.to_str().unwrap(),
            "--yes",
            "--delete-source",
        ],
    )
    .ok()
    .data();
    assert_eq!(done["imported"], 1);
    assert!(!file.exists());
    let listed = unlocked(&device, &["item", "list", "--favorite"])
        .ok()
        .data();
    assert_eq!(listed[0]["title"], "Jira");
}

#[test]
fn export_then_restore_into_a_fresh_account() {
    let mut world = World::new();
    let source = signed_up(&mut world, "ada", false);
    create_login(&source, "GitHub", "export-me-1234");
    let file = source.dir.path().join("vault.haspx");
    let exported = source.run(
        &[
            "--password-stdin",
            "export",
            "--out",
            file.to_str().unwrap(),
            "--passphrase-stdin",
        ],
        &[PASSWORD, "backup passphrase"],
    );
    assert_eq!(exported.code, 0, "{}", exported.err);
    assert!(std::fs::metadata(&file).unwrap().len() > 0);

    let target = signed_up(&mut world, "bob", false);
    let wrong = target.run(
        &[
            "--password-stdin",
            "restore",
            file.to_str().unwrap(),
            "--passphrase-stdin",
        ],
        &[PASSWORD, "not the passphrase"],
    );
    assert_ne!(wrong.code, 0);
    let restored = target.run(
        &[
            "--password-stdin",
            "restore",
            file.to_str().unwrap(),
            "--passphrase-stdin",
        ],
        &[PASSWORD, "backup passphrase"],
    );
    assert_eq!(restored.code, 0, "{}", restored.err);
    assert_eq!(restored.data()["items"], 1);
    let secret = target
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
    assert_eq!(secret.out, "export-me-1234");
}

#[test]
fn imported_titles_and_values_are_not_readable_on_disk() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    let outside = tempfile::tempdir().unwrap();
    let file = outside.path().join("logins.csv");
    std::fs::write(
        &file,
        "name,url,username,password,notes\nQuiteUniqueTitle,https://bank.test,ada,pin-4821-xq,\n",
    )
    .unwrap();
    unlocked(&device, &["import", "csv", file.to_str().unwrap(), "--yes"]).ok();
    assert!(!device.dir.path().join("imports").exists());
    assert!(!device.dir.path().join("reports").exists());
    let mut stack = vec![device.dir.path().to_path_buf()];
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        for needle in ["QuiteUniqueTitle", "pin-4821-xq"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{} holds {needle}",
                path.display()
            );
        }
    }
    let reports = unlocked(&device, &["import", "report", "list"]).ok().data();
    assert_eq!(reports.as_array().unwrap().len(), 1);
}
