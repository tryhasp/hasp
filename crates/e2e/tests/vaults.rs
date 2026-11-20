#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "tests assert by unwrapping and scenarios read top to bottom"
)]

use hasp_e2e::{Device, Haspd};
use serde_json::Value;

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap().to_owned()
}

fn vault_named(device: &Device, name: &str) -> Option<Value> {
    let vaults = device.data(&["vault", "list"]);
    vaults
        .as_array()
        .into_iter()
        .flatten()
        .find(|v| v["name"] == name)
        .cloned()
}

fn titles(device: &Device, vault: &str) -> Vec<String> {
    let mut titles: Vec<String> = device
        .data(&["item", "list", "--vault", vault])
        .as_array()
        .unwrap()
        .iter()
        .map(|item| text(item, "title"))
        .collect();
    titles.sort();
    titles
}

fn share(owner: &Device, member: &Device, name: &str, role: &str) -> String {
    let id = text(&owner.data(&["vault", "create", name]), "id");
    let offer = owner.data(&["vault", "share", name, "--role", role]);
    let joined = member.data(&["vault", "join", &text(&offer, "code")]);
    assert_eq!(joined["role"], role);
    let fingerprint = text(&joined, "your_fingerprint");
    let pending = owner.data(&["vault", "members", "pending", name]);
    let pending = pending.as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["fingerprint"], fingerprint.as_str());
    assert_eq!(pending[0]["invite"], offer["invite_id"]);
    let added = owner.data(&[
        "vault",
        "members",
        "add",
        name,
        &text(&offer, "invite_id"),
        "--fingerprint",
        &fingerprint,
    ]);
    assert_eq!(added["added"], offer["invite_id"]);
    member.data(&["sync"]);
    id
}

fn other_member(owner: &Device, vault: &str) -> String {
    let members = owner.data(&["vault", "members", "list", vault]);
    let others: Vec<_> = members
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["self"] == false)
        .collect();
    assert_eq!(others.len(), 1, "{members}");
    text(others[0], "account")
}

#[test]
fn share_remove_with_epoch_bump_leave_and_dissolve() {
    let (server, init) = Haspd::boot();
    let owner = server.account("owner@example.com", &init.code);
    let code = text(&owner.data(&["admin", "token", "create"]), "signup_code");
    let member = server.account("member@example.com", &code);

    let family = share(&owner, &member, "Family", "editor");
    assert_eq!(
        vault_named(&member, "Family").unwrap()["id"],
        family.as_str()
    );
    assert_eq!(vault_named(&member, "Family").unwrap()["role"], "editor");
    assert_eq!(
        owner
            .data(&["vault", "members", "list", "Family"])
            .as_array()
            .unwrap()
            .len(),
        2
    );
    owner
        .run(
            &[
                "item",
                "create",
                "--vault",
                "Family",
                "--title",
                "Wifi",
                "--field-stdin",
                "password",
            ],
            &["wifi-secret-1"],
        )
        .ok();
    member.run(&["sync"], &[]).ok();
    let read = member.data(&["read", "hasp://Family/Wifi/password"]);
    assert_eq!(read["value"], "wifi-secret-1");
    member
        .run(
            &[
                "item",
                "create",
                "--vault",
                "Family",
                "--title",
                "From member",
            ],
            &[],
        )
        .ok();
    owner.run(&["sync"], &[]).ok();
    assert_eq!(titles(&owner, "Family"), ["From member", "Wifi"]);

    let epoch_before = owner.data(&["vault", "get", "Family"])["epoch"]
        .as_u64()
        .unwrap();
    let account = other_member(&owner, "Family");
    let removed = owner.data(&["vault", "members", "remove", "Family", &account]);
    assert_eq!(removed["removed"], account.as_str());
    let after = owner.data(&["vault", "get", "Family"]);
    assert!(after["epoch"].as_u64().unwrap() > epoch_before, "{after}");
    assert_eq!(after["members"], 1);
    owner
        .run(
            &[
                "item",
                "create",
                "--vault",
                "Family",
                "--title",
                "After removal",
                "--field-stdin",
                "password",
            ],
            &["new-secret-2"],
        )
        .ok();

    let synced = member.data(&["sync"]);
    let states: Vec<&str> = synced
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["state"].as_str().unwrap())
        .collect();
    assert!(states.contains(&"removed"), "{synced}");
    assert!(vault_named(&member, "Family").is_none());
    let blocked = member.run(&["read", "hasp://Family/After removal/password"], &[]);
    assert_ne!(blocked.code, 0, "{}", blocked.stdout);
    assert!(!blocked.stdout.contains("new-secret-2"));
    let listed = member.run(&["item", "list"], &[]).ok();
    assert!(
        !listed.stdout.contains("After removal"),
        "{}",
        listed.stdout
    );

    let club = share(&owner, &member, "Club", "viewer");
    assert_eq!(vault_named(&member, "Club").unwrap()["role"], "viewer");
    let denied = member.run(
        &[
            "item",
            "create",
            "--vault",
            "Club",
            "--title",
            "Not allowed",
        ],
        &[],
    );
    assert_ne!(denied.code, 0, "a viewer cannot write: {}", denied.stdout);
    let left = member.data(&["vault", "leave", "Club"]);
    assert_eq!(left["left"], club.as_str());
    assert!(vault_named(&member, "Club").is_none());
    owner.run(&["sync"], &[]).ok();

    let temp = share(&owner, &member, "Temp", "editor");
    owner
        .run(
            &["item", "create", "--vault", "Temp", "--title", "Doomed"],
            &[],
        )
        .ok();
    let wrong_name = owner.run(&["vault", "dissolve", "Temp", "--confirm", "Nope"], &[]);
    assert_ne!(wrong_name.code, 0);
    let dissolved = owner.data(&["vault", "dissolve", "Temp", "--confirm", "Temp"]);
    assert_eq!(dissolved["dissolved"], temp.as_str());
    assert!(vault_named(&owner, "Temp").is_none());
    let synced = member.data(&["sync"]);
    assert!(
        synced
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["state"] == "dissolved"),
        "{synced}"
    );
    assert!(vault_named(&member, "Temp").is_none());
}
