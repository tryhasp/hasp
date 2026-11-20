use super::*;

#[test]
fn sharing_a_vault_adds_and_removes_members() {
    let mut world = World::new();
    let owner = signed_up(&mut world, "ada", false);
    let guest = signed_up(&mut world, "bob", false);
    unlocked(&owner, &["vault", "create", "Family"]).ok();
    let share = unlocked(&owner, &["vault", "share", "Family", "--role", "editor"])
        .ok()
        .data();
    let code = share["code"].as_str().unwrap().to_owned();
    let invite = share["invite_id"].as_str().unwrap().to_owned();
    assert!(code.starts_with("INV1-"));

    let joined = unlocked(&guest, &["vault", "join", &code]).ok().data();
    let fingerprint = joined["your_fingerprint"].as_str().unwrap().to_owned();

    let pending = unlocked(&owner, &["vault", "members", "pending", "Family"])
        .ok()
        .data();
    assert_eq!(pending[0]["fingerprint"], fingerprint.as_str());
    let refused = unlocked(&owner, &["vault", "members", "add", "Family", &invite]);
    assert_eq!(refused.code, 2);
    unlocked(
        &owner,
        &[
            "vault",
            "members",
            "add",
            "Family",
            &invite,
            "--fingerprint",
            &fingerprint,
        ],
    )
    .ok();

    let members = unlocked(&owner, &["vault", "members", "list", "Family"])
        .ok()
        .data();
    assert_eq!(members.as_array().unwrap().len(), 2);
    let guest_view = unlocked(&guest, &["vault", "list"]).ok().data();
    assert!(
        guest_view
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["name"] == "Family")
    );

    guest
        .run(
            &[
                "--password-stdin",
                "item",
                "create",
                "--vault",
                "Family",
                "--title",
                "Wifi",
                "--category",
                "password",
                "--field-stdin",
                "password",
            ],
            &[PASSWORD, "wifi-secret-one"],
        )
        .ok();
    let seen = unlocked(&owner, &["item", "list", "--vault", "Family"])
        .ok()
        .data();
    assert_eq!(seen[0]["title"], "Wifi");

    let bob = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["self"] == false)
        .unwrap()["account"]
        .as_str()
        .unwrap()
        .to_owned();
    unlocked(
        &owner,
        &["vault", "members", "set-role", "Family", &bob, "viewer"],
    )
    .ok();
    unlocked(&owner, &["vault", "members", "remove", "Family", &bob]).ok();
    let after = unlocked(&owner, &["vault", "members", "list", "Family"])
        .ok()
        .data();
    assert_eq!(after.as_array().unwrap().len(), 1);
}

#[test]
fn leaving_and_dissolving_vaults() {
    let mut world = World::new();
    let owner = signed_up(&mut world, "ada", false);
    let guest = signed_up(&mut world, "bob", false);
    unlocked(&owner, &["vault", "create", "Team"]).ok();
    let share = unlocked(&owner, &["vault", "share", "Team"]).ok().data();
    let joined = unlocked(&guest, &["vault", "join", share["code"].as_str().unwrap()])
        .ok()
        .data();
    unlocked(
        &owner,
        &[
            "vault",
            "members",
            "add",
            "Team",
            share["invite_id"].as_str().unwrap(),
            "--fingerprint",
            joined["your_fingerprint"].as_str().unwrap(),
        ],
    )
    .ok();
    unlocked(&guest, &["vault", "leave", "Team"]).ok();
    let wrong_name = unlocked(&owner, &["vault", "dissolve", "Team", "--confirm", "Nope"]);
    assert_ne!(wrong_name.code, 0);
    device_runs_dissolve(&owner);
    let remaining = unlocked(&owner, &["vault", "list"]).ok().data();
    assert!(
        remaining
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["name"] != "Team")
    );
}

fn device_runs_dissolve(owner: &Device) {
    owner
        .run(
            &[
                "--password-stdin",
                "vault",
                "dissolve",
                "Team",
                "--confirm",
                "Team",
            ],
            &[PASSWORD],
        )
        .ok();
}
