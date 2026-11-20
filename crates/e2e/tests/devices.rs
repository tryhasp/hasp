#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

use std::time::Duration;

use hasp_e2e::{Device, Haspd, PASSWORD};

const WAIT: Duration = Duration::from_secs(60);

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

fn enrol_by_qr(existing: &Device, joining: &Device) -> String {
    let mut inviter = existing.start(&["account", "enrol", "--code-stdin"], &[]);
    let line = inviter.wait_stderr("ENR1-", WAIT);
    let code = line.trim().to_owned();
    assert!(code.starts_with("ENR1-"), "{code}");
    assert!(
        inviter.stderr_so_far().lines().count() > 5,
        "the QR text is shown above the typed code: {}",
        inviter.stderr_so_far()
    );
    let mut joiner = joining.start_raw(
        &[
            "--password-stdin",
            "signin",
            "--origin",
            &joining.origin,
            "--enrol-stdin",
        ],
        &format!("{code}\n{PASSWORD}\n"),
    );
    let shown = joiner.wait_stderr("Type this code on the signed-in device:", WAIT);
    let typed = shown.rsplit(": ").next().unwrap().trim().to_owned();
    inviter.write(&format!("{typed}\n"));
    let approved = inviter.finish().ok();
    assert_eq!(approved.data()["enrolled"], true);
    joiner.finish().ok().data()["login"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn second_device_by_qr_and_by_emergency_kit() {
    let (server, init) = Haspd::boot();
    let phone = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let kit = phone.signup(&init.code).ok().data();
    let secret_key = kit["secret_key"].as_str().unwrap().to_owned();
    phone
        .run(
            &[
                "item",
                "create",
                "--title",
                "Bank",
                "--field",
                "username=ada",
                "--field-stdin",
                "password",
            ],
            &["bank-secret-1"],
        )
        .ok();

    let laptop = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let login = enrol_by_qr(&phone, &laptop);
    assert_eq!(login, "ada@example.com");
    assert_eq!(titles(&laptop), ["Bank"]);
    let secret = laptop
        .run(&["read", "hasp://Private/Bank/password"], &[])
        .ok()
        .data()["value"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(secret, "bank-secret-1");

    let desktop = Device::new(&server.origin, "ada@example.com", PASSWORD);
    desktop
        .signin_with_kit(&secret_key, Some(&init.fingerprint))
        .ok();
    assert_eq!(titles(&desktop), ["Bank"]);
    desktop
        .run(&["item", "create", "--title", "From desktop"], &[])
        .ok();
    laptop.run(&["sync"], &[]).ok();
    assert_eq!(titles(&laptop), ["Bank", "From desktop"]);
    assert_eq!(titles(&phone), ["Bank", "From desktop"]);

    let devices = phone.data(&["devices", "list"]);
    let devices = devices.as_array().unwrap();
    assert_eq!(devices.len(), 3, "{devices:?}");
    assert_eq!(devices.iter().filter(|d| d["current"] == true).count(), 1);

    let laptop_device = laptop.data(&["devices", "list"]);
    let laptop_device = laptop_device
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["current"] == true)
        .unwrap()["device"]
        .as_str()
        .unwrap()
        .to_owned();
    let revoked = phone.data(&["devices", "revoke", &laptop_device]);
    assert_eq!(revoked["revoked"], laptop_device.as_str());
    let after = laptop.run(&["item", "list"], &[]);
    assert_ne!(
        after.code, 0,
        "a revoked device cannot sync: {}",
        after.stdout
    );
    after.error();

    let wrong_fingerprint = Device::new(&server.origin, "ada@example.com", PASSWORD)
        .signin_with_kit(&secret_key, Some("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"));
    assert_ne!(
        wrong_fingerprint.code, 0,
        "the kit's server fingerprint is checked"
    );
}

#[test]
fn a_wrong_typed_code_does_not_enrol() {
    let (server, init) = Haspd::boot();
    let phone = server.account("ada@example.com", &init.code);
    let laptop = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let mut inviter = phone.start(&["account", "enrol", "--code-stdin"], &[]);
    let code = inviter.wait_stderr("ENR1-", WAIT).trim().to_owned();
    let mut joiner = laptop.start_raw(
        &[
            "--password-stdin",
            "signin",
            "--origin",
            &laptop.origin,
            "--enrol-stdin",
        ],
        &format!("{code}\n{PASSWORD}\n"),
    );
    joiner.wait_stderr("Type this code on the signed-in device:", WAIT);
    inviter.write("000000\n");
    let refused = inviter.finish();
    assert_ne!(refused.code, 0, "{}", refused.stdout);
    refused.error();
    let started = std::time::Instant::now();
    let abandoned = joiner.finish();
    assert_ne!(abandoned.code, 0, "{}", abandoned.stdout);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the joiner stops polling once the code is refused"
    );
    assert!(
        !abandoned.stderr.contains("enrolled"),
        "{}",
        abandoned.stderr
    );
    let nothing = laptop.run(&["item", "list"], &[]);
    assert_eq!(nothing.code, 3, "the laptop holds no account");
}
