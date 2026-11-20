use super::*;

pub(super) fn own_json(p: &Person) -> Value {
    json!({
        "account_id": hex(p.account.as_bytes()),
        "ik_pk": hex(p.ik_pk.as_bytes()),
        "kem_pk": hex(p.kem_pk.as_bytes()),
    })
}

pub(super) fn pins_json(pins: &[&Person]) -> Value {
    Value::Array(pins.iter().map(|p| own_json(p)).collect())
}

pub(super) fn own_from(value: &Value) -> crate::OwnKeys {
    crate::OwnKeys {
        account_id: AccountId::from_bytes(array16(value, "account_id")),
        ik_pk: VerifyingKey::from_bytes(array32(value, "ik_pk")).unwrap(),
        kem_pk: KemPublicKey::from_bytes(bytes_of(value, "kem_pk").try_into().unwrap()).unwrap(),
        retired_kem_pk_hashes: Vec::new(),
    }
}

pub(super) fn pins_from(value: &Value) -> PinState {
    let mut pins = PinState::new();
    for pin in value.as_array().unwrap() {
        let own = own_from(pin);
        pins.insert(
            own.account_id,
            Pin::new(own.ik_pk, &own.kem_pk, PinLevel::Verified),
        );
    }
    pins
}

pub(super) fn commit_json(commit: &Commit) -> Value {
    json!({
        "manifest": hex(&commit.manifest.to_cbor().unwrap()),
        "roster": commit.roster.as_ref().map(|r| hex(&r.to_cbor().unwrap())),
        "ops": commit.ops.iter().map(|op| hex(&op.wire().to_cbor().unwrap())).collect::<Vec<_>>(),
        "shares": commit.shares.iter().map(|s| hex(&s.to_cbor().unwrap())).collect::<Vec<_>>(),
    })
}

pub(super) fn commit_from(value: &Value) -> Commit {
    let hexes = |key: &str| -> Vec<Vec<u8>> {
        field(value, key)
            .as_array()
            .unwrap()
            .iter()
            .map(|v| unhex(v.as_str().unwrap()))
            .collect()
    };
    Commit {
        manifest: Signed::from_cbor(&bytes_of(value, "manifest")).unwrap(),
        roster: field(value, "roster")
            .as_str()
            .map(|r| Signed::from_cbor(&unhex(r)).unwrap()),
        ops: hexes("ops")
            .iter()
            .map(|b| ItemOp::from_wire_bytes(b).unwrap())
            .collect(),
        shares: hexes("shares")
            .iter()
            .map(|b| Signed::from_cbor(b).unwrap())
            .collect(),
    }
}

pub(super) fn state_json(state: &VaultState) -> Value {
    json!({
        "seq": state.seq.get(),
        "hash": hex(state.hash.as_bytes()),
        "rver": state.rver.get(),
        "epoch": state.epoch.get(),
        "roster_hash": hex(state.roster_hash.as_bytes()),
        "leaf_count": state.leafset.len(),
        "root": hex(leafset_root(&state.leafset).unwrap().as_bytes()),
    })
}

pub(super) fn check_state(state: &VaultState, expected: &Value) {
    assert_eq!(&state_json(state), expected);
}

pub(super) fn check_outcome<T>(
    result: Result<T, ProtoError>,
    expect: &Value,
    on_ok: impl FnOnce(&T, &Value),
) {
    match (result, expect.get("ok"), expect.get("err")) {
        (Ok(value), Some(ok), None) => on_ok(&value, ok),
        (Err(error), None, Some(name)) => assert_eq!(error.name(), name.as_str().unwrap()),
        (Ok(_), None, Some(name)) => panic!("expected error {name}, got Ok"),
        (Err(error), Some(_), None) => panic!("expected Ok, got {error:?}"),
        _ => panic!("malformed expectation"),
    }
}

pub(super) fn expected(result: Result<Value, ProtoError>) -> Value {
    match result {
        Ok(ok) => json!({ "ok": ok }),
        Err(error) => json!({ "err": error.name() }),
    }
}

pub(super) fn run_chain(
    own: &Value,
    pins: &Value,
    commits: &[Commit],
) -> Result<VaultState, ProtoError> {
    let (own, pins) = (own_from(own), pins_from(pins));
    let (first, rest) = commits.split_first().ok_or(ProtoError::Format)?;
    let state = verify_genesis(first, &own, &pins)?;
    verify_batch(&state, rest, &own, &pins)
}

pub(super) fn chain_case(name: &str, own: &Person, pins: &[&Person], commits: &[Commit]) -> Value {
    let (own_value, pins_value) = (own_json(own), pins_json(pins));
    let outcome = run_chain(&own_value, &pins_value, commits).map(|state| state_json(&state));
    json!({
        "kind": "chain",
        "name": name,
        "own": own_value,
        "pins": pins_value,
        "commits": commits.iter().map(commit_json).collect::<Vec<_>>(),
        "expect": expected(outcome),
    })
}

pub(super) fn replay_chain(case: &Value) {
    let commits: Vec<Commit> = field(case, "commits")
        .as_array()
        .unwrap()
        .iter()
        .map(commit_from)
        .collect();
    let result = run_chain(field(case, "own"), field(case, "pins"), &commits);
    check_outcome(result, field(case, "expect"), check_state);
}

pub(super) fn base() -> (Vault, Vec<Commit>) {
    let mut vault = Vault::new(VaultKind::Shared, 1);
    let commits = vec![
        vault.genesis(),
        vault.put(1, 7, b"first"),
        vault.add_member(2, Role::Editor),
    ];
    (vault, commits)
}

pub(super) fn verify_prefix(commits: &[Commit]) -> VaultState {
    let owner = Person::new(1);
    let pins = PinState::new();
    let state = verify_genesis(&commits[0], &owner.own(), &pins).unwrap();
    verify_batch(&state, &commits[1..], &owner.own(), &pins).unwrap()
}
