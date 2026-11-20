use std::time::Instant;

use hasp_e2e::{Device, Haspd, PASSWORD, bins};

#[test]
fn bootstrap_signup_and_register() {
    let mut server = Haspd::new();
    let init = server.init();
    assert!(init.code.starts_with("SGN1-"), "{}", init.code);
    assert!(
        init.output
            .contains("without it every account password is void"),
        "{}",
        init.output
    );
    let again = server.run(&["init"], "").ok();
    assert!(again.stdout.contains("server key kept"), "{}", again.stdout);
    assert!(
        again.stdout.contains("already has accounts") || again.stdout.contains("first signup code"),
        "{}",
        again.stdout
    );
    assert_eq!(server.fingerprint(), init.fingerprint);
    server.start();
    server.run(&["healthcheck"], "").ok();

    let ada = Device::new(&server.origin, "ada@example.com", PASSWORD);
    let code = again
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("first signup code (makes you the admin): "))
        .map_or_else(|| init.code.clone(), |code| code.trim().to_owned());
    let signup = ada.signup(&code).ok();
    let data = signup.data();
    assert!(data["secret_key"].as_str().unwrap().starts_with("V1-"));
    assert_eq!(data["login"], "ada@example.com");
    assert_eq!(data["origin"], server.origin);
    assert_eq!(data["server_fingerprint"], init.fingerprint);

    let whoami = ada.data(&["whoami"]);
    assert_eq!(whoami["login"], "ada@example.com");
    assert_eq!(whoami["origin"], server.origin);
    assert!(
        whoami["fingerprint"]
            .as_str()
            .is_some_and(|fp| fp.len() >= 20)
    );
    let status = ada.data(&["status"]);
    assert_eq!(status["signed_in"], true);

    let vaults = ada.data(&["vault", "list"]);
    let vaults = vaults.as_array().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0]["kind"], "private");
    assert_eq!(vaults[0]["role"], "owner");

    let reuse = Device::new(&server.origin, "mallory@example.com", PASSWORD).signup(&code);
    assert_ne!(reuse.code, 0, "a signup code is single use");
    reuse.error();

    let admin_code = ada.data(&["admin", "token", "create"])["signup_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob = Device::new(&server.origin, "bob@example.com", PASSWORD);
    bob.signup(&admin_code).ok();
    let denied = bob.run(&["admin", "token", "create"], &[]);
    assert_ne!(denied.code, 0, "only the bootstrap account is an admin");
    denied.error();

    let wrong = ada.raw(&["--password-stdin", "item", "list"], "not the password\n");
    assert_eq!(wrong.code, 8);
    assert_eq!(wrong.error()["exit"], 8);

    let signed_out = Device::new(&server.origin, "x", PASSWORD).run(&["item", "list"], &[]);
    assert_eq!(signed_out.code, 3);
    signed_out.error();
}

#[test]
fn first_login_with_production_limits_is_fast() {
    bins();
    let started = Instant::now();
    let mut server = Haspd::new().production_limits();
    let init = server.init();
    server.start();
    let device = Device::new(&server.origin, "me@example.com", PASSWORD);
    device.signup(&init.code).ok();
    let whoami = device.data(&["whoami"]);
    let elapsed = started.elapsed();
    assert_eq!(whoami["login"], "me@example.com");
    assert!(
        elapsed.as_secs() <= 60,
        "init, serve and signup on a built binary took {elapsed:?}"
    );
}
