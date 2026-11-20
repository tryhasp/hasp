use super::*;

pub(super) fn item_fixture() -> (Vault, Vec<Commit>, ItemOp, ItemOp) {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let mut commits = vec![vault.genesis()];
    let live = vault.put(1, 7, b"overview of seven");
    let other = vault.put(1, 8, b"overview of eight");
    let tomb = vault.delete(1, 8);
    let (live_op, tomb_op) = (live.ops[0].clone(), tomb.ops[0].clone());
    commits.extend([live, other, tomb]);
    (vault, commits, live_op, tomb_op)
}

pub(super) fn item_case(
    name: &str,
    commits: &[Commit],
    wire: &ItemOp,
    bytes: &[u8],
    vk: &SecretKey,
) -> Value {
    let mut case = json!({
        "kind": "item",
        "name": name,
        "commits": commits.iter().map(commit_json).collect::<Vec<_>>(),
        "wire": hex(bytes),
        "vk": hex(vk.expose()),
    });
    let _ = wire;
    case["expect"] = expected(replay_item_inputs(&case));
    case
}

#[expect(clippy::unwrap_in_result, reason = "replay reads trusted fixtures")]
pub(super) fn replay_item_inputs(case: &Value) -> Result<Value, ProtoError> {
    let commits: Vec<Commit> = field(case, "commits")
        .as_array()
        .unwrap()
        .iter()
        .map(commit_from)
        .collect();
    let state = run_chain(&own_json(&Person::new(1)), &json!([]), &commits).unwrap();
    let bytes = bytes_of(case, "wire");
    let item = crate::ItemWire::from_cbor(&bytes)?;
    let vk = SecretKey::from_bytes(array32(case, "vk"));
    open_item(&item, &bytes, &state, &vk).map(|opened| match opened {
        OpenedItem::Live {
            overview,
            details,
            ver,
            ..
        } => json!({
            "overview": hex(overview.expose()),
            "details": hex(details.expose()),
            "ver": ver.get(),
        }),
        OpenedItem::Tombstone { ver, .. } => json!({ "tombstone": true, "ver": ver.get() }),
    })
}

pub(super) fn item_cases() -> Vec<Value> {
    let (vault, commits, live, tomb) = item_fixture();
    let wire = live.wire().to_cbor().unwrap();
    let wrong_key = SecretKey::from_bytes([0x11; 32]);
    let mut tampered = wire.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    let older = crate::ItemWire {
        ver: Version::new(9).unwrap(),
        ..live.wire().clone()
    }
    .to_cbor()
    .unwrap();
    let swapped = {
        let other = commits[2].ops[0].wire();
        let (crate::ItemBody::Live { ov, .. }, crate::ItemBody::Live { wrap, det, .. }) =
            (&live.wire().body, &other.body)
        else {
            panic!("live items expected");
        };
        crate::ItemWire {
            body: crate::ItemBody::Live {
                wrap: wrap.clone(),
                ov: ov.clone(),
                det: det.clone(),
            },
            ..other.clone()
        }
        .to_cbor()
        .unwrap()
    };
    vec![
        item_case("live_item_opens", &commits, &live, &wire, vault.vk()),
        item_case(
            "tombstone_reported",
            &commits,
            &tomb,
            &tomb.wire().to_cbor().unwrap(),
            vault.vk(),
        ),
        item_case("wrong_vault_key", &commits, &live, &wire, &wrong_key),
        item_case(
            "wire_bytes_tampered",
            &commits,
            &live,
            &tampered,
            vault.vk(),
        ),
        item_case(
            "version_not_in_leaf_set",
            &commits,
            &live,
            &older,
            vault.vk(),
        ),
        item_case(
            "overview_swapped_between_items",
            &commits,
            &live,
            &swapped,
            vault.vk(),
        ),
    ]
}

pub(super) fn replay_item(case: &Value) {
    check_outcome(
        replay_item_inputs(case),
        field(case, "expect"),
        |ok, expect| assert_eq!(ok, expect),
    );
}
