use super::*;

#[test]
fn unattended_backup_needs_a_hardware_gated_device() {
    let mut world = World::new();
    let software = signed_up(&mut world, "ada", false);
    let refused = software.run(
        &["--password-stdin", "backup", "enable", "--passphrase-stdin"],
        &[PASSWORD, "backup phrase"],
    );
    assert_ne!(refused.code, 0);

    let hardware = signed_up(&mut world, "bob", true);
    hardware
        .run(
            &["backup", "enable", "--passphrase-stdin"],
            &["backup phrase"],
        )
        .ok();
    let file = hardware.dir.path().join("auto.haspx");
    hardware
        .run(
            &[
                "--password-stdin",
                "backup",
                "now",
                "--out",
                file.to_str().unwrap(),
            ],
            &[PASSWORD],
        )
        .ok();
    assert!(file.exists());
}

#[test]
fn recovery_code_restores_access_after_the_delay() {
    let mut world = World::with_config(|config| config.set_recovery_delay(0));
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "GitHub", "recover-me-1234");
    let created = device
        .run(
            &[
                "--password-stdin",
                "account",
                "recovery-code",
                "create",
                "--reveal",
            ],
            &[PASSWORD],
        )
        .ok();
    let code = created.data()["recovery_code"].as_str().unwrap().to_owned();

    let fresh = Device::new(&world, false);
    let used = fresh.run(
        &[
            "--password-stdin",
            "account",
            "recovery-code",
            "use",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--code-stdin",
            "--reveal",
        ],
        &[&code, "a brand new password"],
    );
    assert_eq!(used.code, 0, "{}", used.err);
    let listed = fresh.run(
        &["--password-stdin", "item", "list"],
        &["a brand new password"],
    );
    assert_eq!(listed.code, 0, "{}", listed.err);
    assert_eq!(listed.data().as_array().unwrap().len(), 1);
}

#[test]
fn recovery_code_use_starts_exits_and_resumes_after_the_delay() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    create_login(&device, "GitHub", "recover-me-1234");
    let created = device
        .run(
            &[
                "--password-stdin",
                "account",
                "recovery-code",
                "create",
                "--reveal",
            ],
            &[PASSWORD],
        )
        .ok();
    let code = created.data()["recovery_code"].as_str().unwrap().to_owned();

    let fresh = Device::new(&world, false);
    let use_args = [
        "--password-stdin",
        "account",
        "recovery-code",
        "use",
        "--origin",
        ORIGIN,
        "--login",
        "ada",
        "--code-stdin",
        "--reveal",
    ];
    let started = fresh.run(&use_args, &[&code, "a brand new password"]).ok();
    assert_eq!(started.data()["recovered"], false);
    assert!(started.err.contains("Recovery started"));
    assert!(!started.out.contains(&code));

    let early = fresh.run(&use_args, &["a brand new password"]).ok();
    assert_eq!(early.data()["recovered"], false);
    assert!(early.data()["retry_after_s"].as_u64().unwrap() > 0);

    let wrong = fresh.run(&use_args, &["not the new password"]);
    assert_eq!(wrong.code, 8, "{}", wrong.err);

    world.clock.advance(25 * 3600);
    let done = fresh.run(&use_args, &["a brand new password"]).ok();
    assert_eq!(done.data()["recovered"], true);
    let listed = fresh
        .run(
            &["--password-stdin", "item", "list"],
            &["a brand new password"],
        )
        .ok();
    assert_eq!(listed.data().as_array().unwrap().len(), 1);

    let again = fresh.run(&use_args, &[&code, "a brand new password"]);
    assert_ne!(again.code, 0);
}

#[test]
fn emergency_kit_needs_the_last_group_and_writes_private_files() {
    let mut world = World::new();
    let device = Device::new(&world, false);
    let signup = signup_code(&mut world);
    let signed = device.run(
        &[
            "--password-stdin",
            "signup",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--code-stdin",
            "--server-fingerprint",
            &fingerprint(&world),
            "--reveal",
        ],
        &[&signup, PASSWORD],
    );
    let secret_key = signed.ok().data()["secret_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let last = secret_key.rsplit('-').next().unwrap().to_owned();
    let pdf = device.dir.path().join("kit.pdf");
    let text = device.dir.path().join("kit.txt");
    let args = [
        "--password-stdin",
        "account",
        "emergency-kit",
        "--last-group-stdin",
        "--pdf-out",
        pdf.to_str().unwrap(),
        "--text-out",
        text.to_str().unwrap(),
    ];
    let wrong = device.run(&args, &[PASSWORD, "ZZZZ"]);
    assert_ne!(wrong.code, 0);
    assert!(!pdf.exists());

    device.run(&args, &[PASSWORD, &last]).ok();
    let bytes = std::fs::read(&pdf).unwrap();
    assert!(bytes.starts_with(b"%PDF-1.4"));
    assert!(
        std::fs::read_to_string(&text)
            .unwrap()
            .contains(&secret_key)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&pdf).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let refused = device.run(
        &[
            "--password-stdin",
            "account",
            "emergency-kit",
            "--last-group-stdin",
        ],
        &[PASSWORD, &last],
    );
    assert_eq!(refused.code, 2);
}
