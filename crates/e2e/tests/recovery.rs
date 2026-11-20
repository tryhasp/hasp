#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "tests assert by unwrapping and scenarios read top to bottom"
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hasp_e2e::{Device, Haspd, PASSWORD};

const NEW_PASSWORD: &str = "a different long passphrase";
const DELAY: u64 = 4;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn recovery_by_code_resumes_across_invocations() {
    let mut server = Haspd::new().recovery_delay(DELAY);
    let init = server.init();
    server.start();
    let ada = server.account("ada@example.com", &init.code);
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
    let code = ada
        .run(&["--reveal", "account", "recovery-code", "create"], &[])
        .ok()
        .text("recovery_code");

    let lost = Device::new(&server.origin, "ada@example.com", NEW_PASSWORD);
    let args = [
        "--password-stdin",
        "account",
        "recovery-code",
        "use",
        "--origin",
        &server.origin,
        "--login",
        "ada@example.com",
        "--code-stdin",
    ];
    let started = lost
        .raw(&args, &format!("{code}\n{NEW_PASSWORD}\n"))
        .ok()
        .data();
    assert_eq!(started["recovered"], false);
    let release_at = started["release_at"].as_u64().unwrap();
    assert!(
        release_at >= now(),
        "the delay has not passed yet: {started}"
    );
    assert!(release_at <= now() + DELAY + 2, "{started}");

    let early = lost.raw(
        &[
            "--password-stdin",
            "account",
            "recovery-code",
            "use",
            "--origin",
            &server.origin,
            "--login",
            "ada@example.com",
        ],
        &format!("{NEW_PASSWORD}\n"),
    );
    assert_eq!(early.ok().data()["recovered"], false, "still waiting");

    let notice = ada.run(&["sync"], &[]).ok();
    assert!(
        notice
            .stderr
            .contains("a recovery of this account was started"),
        "the signed-in device is alerted: {}",
        notice.stderr
    );

    while now() <= release_at {
        hasp_e2e::pause(Duration::from_millis(200));
    }
    let done = lost
        .raw(
            &[
                "--password-stdin",
                "--reveal",
                "account",
                "recovery-code",
                "use",
                "--origin",
                &server.origin,
                "--login",
                "ada@example.com",
            ],
            &format!("{NEW_PASSWORD}\n"),
        )
        .ok()
        .data();
    assert_eq!(done["recovered"], true, "{done}");
    let new_key = done["secret_key"].as_str().unwrap().to_owned();
    assert!(new_key.starts_with("V1-"));
    assert_ne!(
        done["recovery_code"].as_str().unwrap(),
        code,
        "recovery rotates the recovery code"
    );

    let items = lost.data(&["item", "list"]);
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(
        lost.data(&["read", "hasp://Private/Kept/password"])["value"],
        "kept-secret"
    );

    let fresh = Device::new(&server.origin, "ada@example.com", NEW_PASSWORD);
    fresh
        .signin_with_kit(&new_key, Some(&init.fingerprint))
        .ok();
    assert_eq!(fresh.data(&["item", "list"]).as_array().unwrap().len(), 1);

    let stale = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let old = stale.signin_with_kit(&new_key, None);
    assert_ne!(old.code, 0, "the old password no longer opens the account");
}

#[test]
fn restart_drops_a_saved_recovery_and_begins_again() {
    let mut server = Haspd::new().recovery_delay(DELAY);
    let init = server.init();
    server.start();
    let ada = server.account("ada@example.com", &init.code);
    let code = ada
        .run(&["--reveal", "account", "recovery-code", "create"], &[])
        .ok()
        .text("recovery_code");
    let lost = Device::new(&server.origin, "ada@example.com", NEW_PASSWORD);
    let started = lost
        .raw(
            &[
                "--password-stdin",
                "account",
                "recovery-code",
                "use",
                "--origin",
                &server.origin,
                "--login",
                "ada@example.com",
                "--code-stdin",
            ],
            &format!("{code}\n{NEW_PASSWORD}\n"),
        )
        .ok()
        .data();
    assert_eq!(started["recovered"], false);
    let again = lost.raw(
        &[
            "--password-stdin",
            "account",
            "recovery-code",
            "use",
            "--origin",
            &server.origin,
            "--login",
            "ada@example.com",
            "--restart",
            "--code-stdin",
        ],
        &format!("{code}\n{NEW_PASSWORD}\n"),
    );
    assert_eq!(again.ok().data()["recovered"], false);
}
