use super::*;

#[test]
fn signup_prints_the_kit_once_and_signin_needs_the_secret_key() {
    let mut world = World::new();
    let first = signed_up(&mut world, "ada", false);
    let who = first.run(&["whoami"], &[]).ok().data();
    assert_eq!(who["login"], "ada");
    assert_eq!(who["origin"], ORIGIN);
    let status = first.run(&["status"], &[]).ok().data();
    assert_eq!(status["signed_in"], true);
    assert_eq!(status["unlock"], "password");
}

#[test]
fn signup_in_json_mode_refuses_to_hide_the_secret_key() {
    let mut world = World::new();
    let device = Device::new(&world, false);
    let code = signup_code(&mut world);
    let refused = device.run(
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
        ],
        &[&code, PASSWORD],
    );
    assert_eq!(refused.code, 2);
    assert!(refused.err.contains("--kit-out"));
    let kit = device.dir.path().join("kit.txt");
    let done = device.run(
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
            "--kit-out",
            kit.to_str().unwrap(),
        ],
        &[&code, PASSWORD],
    );
    assert_eq!(done.code, 0, "{}", done.err);
    assert_eq!(done.data()["secret_key"], "<concealed>");
    let text = std::fs::read_to_string(&kit).unwrap();
    assert!(text.contains("Secret Key: V1-"));
}

#[test]
fn signin_on_a_second_device_with_the_kit() {
    let mut world = World::new();
    let first = signed_up(&mut world, "ada", false);
    let created = create_login(&first, "GitHub", "hunter2hunter2");
    let kit = first.run(
        &[
            "--password-stdin",
            "account",
            "password",
            "--new-password-stdin",
            "--new-secret-key",
            "--reveal",
        ],
        &[PASSWORD, "the new account password"],
    );
    assert_eq!(kit.code, 0, "{}", kit.err);
    let secret_key = kit.data()["secret_key"].as_str().unwrap().to_owned();
    assert!(!created.is_empty());

    let second = Device::new(&world, false);
    let signin = second.run(
        &[
            "--password-stdin",
            "signin",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--secret-key-stdin",
            "--server-fingerprint",
            &fingerprint(&world),
        ],
        &[&secret_key, "the new account password"],
    );
    assert_eq!(signin.code, 0, "{}", signin.err);
    let listed = second.run(
        &["--password-stdin", "item", "list"],
        &["the new account password"],
    );
    assert_eq!(listed.code, 0, "{}", listed.err);
    assert_eq!(listed.data().as_array().unwrap().len(), 1);
}

#[test]
fn exit_codes_follow_the_contract() {
    let mut world = World::new();
    let nobody = Device::new(&world, false);
    assert_eq!(nobody.run(&["item", "list"], &[]).code, 3);
    assert_eq!(nobody.run(&["no-such-command"], &[]).code, 2);
    assert_eq!(nobody.run(&["item", "get"], &[]).code, 2);

    let device = signed_up(&mut world, "ada", false);
    let wrong = device.run(&["--password-stdin", "item", "list"], &["not the password"]);
    assert_eq!(wrong.code, 8);
    let no_input = device.run(&["--no-input", "item", "list"], &[]);
    assert_eq!(no_input.code, 2);
    let down = device.run_down(&["--password-stdin", "sync"], &[PASSWORD]);
    assert_eq!(down.code, 7);
    let help = nobody.run(&["--help"], &[]);
    assert_eq!(help.code, 0);
}

#[test]
fn failed_passwords_lock_out_locally() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", false);
    for _ in 0..5 {
        let wrong = device.run(&["--password-stdin", "unlock"], &["bad password here"]);
        assert_eq!(wrong.code, 8);
    }
    let locked_out = device.run(&["--password-stdin", "unlock"], &[PASSWORD]);
    assert_eq!(locked_out.code, 8);
    assert!(locked_out.json()["error"]["retry_after"].as_u64().unwrap() > 0);
    device.clock.advance(3600);
    unlocked(&device, &["unlock"]).ok();
}

#[test]
fn hardware_devices_unlock_without_the_password_until_it_is_due() {
    let mut world = World::new();
    let device = signed_up(&mut world, "ada", true);
    assert_eq!(
        device.run(&["status"], &[]).ok().data()["unlock"],
        "device key"
    );
    assert_eq!(
        device
            .run(&["item", "list"], &[])
            .ok()
            .data()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    device.clock.advance(15 * 24 * 3600);
    let due = device.run(&["item", "list"], &[]);
    assert_eq!(due.code, 2, "the password is required again after 14 days");
    unlocked(&device, &["item", "list"]).ok();
}

#[test]
fn signup_and_signin_require_the_server_fingerprint() {
    let mut world = World::new();
    let device = Device::new(&world, false);
    let code = signup_code(&mut world);
    let missing = device.run(
        &[
            "--password-stdin",
            "signup",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--code-stdin",
            "--reveal",
        ],
        &[&code, PASSWORD],
    );
    assert_eq!(missing.code, 2, "{}", missing.err);
    assert!(missing.err.contains("--server-fingerprint"));
    let wrong = device.run(
        &[
            "--password-stdin",
            "signup",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--code-stdin",
            "--server-fingerprint",
            "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
            "--reveal",
        ],
        &[&code, PASSWORD],
    );
    assert_ne!(wrong.code, 0, "{}", wrong.err);
    assert_eq!(device.run(&["status"], &[]).data()["signed_in"], false);
    let right = device.run(
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
        &[&code, PASSWORD],
    );
    assert_eq!(
        right.code, 0,
        "the code survived the refused attempts: {}",
        right.err
    );

    let other = Device::new(&world, false);
    let no_fingerprint = other.run(
        &[
            "--password-stdin",
            "signin",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--secret-key-stdin",
        ],
        &[right.data()["secret_key"].as_str().unwrap(), PASSWORD],
    );
    assert_eq!(no_fingerprint.code, 2, "{}", no_fingerprint.err);
}

#[test]
fn a_code_in_argv_is_accepted_with_a_warning() {
    let mut world = World::new();
    let device = Device::new(&world, false);
    let code = signup_code(&mut world);
    let done = device.run(
        &[
            "--password-stdin",
            "signup",
            "--origin",
            ORIGIN,
            "--login",
            "ada",
            "--code",
            &code,
            "--server-fingerprint",
            &fingerprint(&world),
            "--reveal",
        ],
        &[PASSWORD],
    );
    assert_eq!(done.code, 0, "{}", done.err);
    assert!(done.err.contains("process list"), "{}", done.err);
}
