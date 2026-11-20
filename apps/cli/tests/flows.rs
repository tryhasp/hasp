#![expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]

#[path = "support/harness.rs"]
mod harness;

use harness::{Device, ORIGIN, PASSWORD, assert_golden, fingerprint, signed_up, signup_code};
use hasp_testsupport::World;
use serde_json::Value;

#[path = "flows/account.rs"]
mod account;
#[path = "flows/devices.rs"]
mod devices;
#[path = "flows/items.rs"]
mod items;
#[path = "flows/recovery.rs"]
mod recovery;
#[path = "flows/transfer.rs"]
mod transfer;
#[path = "flows/vaults.rs"]
mod vaults;

fn create_login(device: &Device, title: &str, password: &str) -> String {
    let created = device
        .run(
            &[
                "--password-stdin",
                "item",
                "create",
                "--title",
                title,
                "--url",
                "https://example.com",
                "--field",
                "username=ada",
                "--field-stdin",
                "password",
            ],
            &[PASSWORD, password],
        )
        .ok();
    created.data()["id"].as_str().unwrap().to_owned()
}

fn unlocked(device: &Device, args: &[&str]) -> harness::Outcome {
    device.run(&[&["--password-stdin"], args].concat(), &[PASSWORD])
}
