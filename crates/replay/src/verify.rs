use hasp_crypto::{KemPublicKey, KemSecretKey, SecretKey, VerifyingKey};
use hasp_proto::{
    AccountId, AccountRecord, AccountSeen, Commit, Dissolve, Hash32, InviteCode, ItemOp, ItemWire,
    LeaveRequest, OpenedItem, OwnKeys, Pin, PinLevel, PinState, ProtoError, Seq, Share, Signed,
    VaultState, Wire, leafset_root, open_item, open_share, verify_account_record, verify_batch,
    verify_dissolve, verify_genesis, verify_leave, verify_repair, verify_share,
};
use serde_json::{Value, json};

use crate::Outcome;
use crate::ReplayError;
use crate::json::{
    Replay, bytes, field, fixed, hex, hex_items, list, named, num, outcome, settle, text,
};

const OWNER_CASE: &str = "ok_lifecycle_owner_view";

fn own_from(value: &Value) -> Replay<OwnKeys> {
    Ok(OwnKeys {
        account_id: AccountId::from_bytes(fixed(value, "account_id")?),
        ik_pk: VerifyingKey::from_bytes(fixed(value, "ik_pk")?)?,
        kem_pk: KemPublicKey::from_bytes(fixed(value, "kem_pk")?)?,
        retired_kem_pk_hashes: Vec::new(),
    })
}

fn pins_from(value: &Value) -> Replay<PinState> {
    let mut pins = PinState::new();
    for pin in value.as_array().ok_or(ReplayError::Vector("pins"))? {
        let own = own_from(pin)?;
        pins.insert(
            own.account_id,
            Pin::new(own.ik_pk, &own.kem_pk, PinLevel::Verified),
        );
    }
    Ok(pins)
}

fn commit_from(value: &Value) -> Replay<Commit> {
    let roster = match field(value, "roster")?.as_str() {
        Some(text) => Some(Signed::from_cbor(&crate::json::unhex(text)?)?),
        None => None,
    };
    let ops = hex_items(value, "ops")?
        .iter()
        .map(|wire| ItemOp::from_wire_bytes(wire).map_err(ReplayError::from))
        .collect::<Replay<Vec<_>>>()?;
    let shares = hex_items(value, "shares")?
        .iter()
        .map(|wire| Signed::from_cbor(wire).map_err(ReplayError::from))
        .collect::<Replay<Vec<_>>>()?;
    Ok(Commit {
        manifest: Signed::from_cbor(&bytes(value, "manifest")?)?,
        roster,
        ops,
        shares,
    })
}

fn commits_from(value: &Value) -> Replay<Vec<Commit>> {
    list(value, "commits")?.iter().map(commit_from).collect()
}

fn state_json(state: &VaultState) -> Result<Value, ProtoError> {
    Ok(json!({
        "seq": state.seq.get(),
        "hash": hex(state.hash.as_bytes()),
        "rver": state.rver.get(),
        "epoch": state.epoch.get(),
        "roster_hash": hex(state.roster_hash.as_bytes()),
        "leaf_count": state.leafset.len(),
        "root": hex(leafset_root(&state.leafset)?.as_bytes()),
    }))
}

fn run_chain(
    own: &Value,
    pins: &Value,
    commits: &[Commit],
) -> Replay<Result<VaultState, ProtoError>> {
    let (own, pins) = (own_from(own)?, pins_from(pins)?);
    let (first, rest) = commits
        .split_first()
        .ok_or(ReplayError::Vector("no commits"))?;
    Ok(
        verify_genesis(first, &own, &pins)
            .and_then(|state| verify_batch(&state, rest, &own, &pins)),
    )
}

fn settled_state(result: Result<VaultState, ProtoError>) -> Value {
    settle(result.and_then(|state| state_json(&state)))
}

fn replay_case(case: &Value, owner: &Value) -> Replay<Value> {
    let kind = text(case, "kind")?;
    let pins = case.get("pins").cloned().unwrap_or_else(|| json!([]));
    let own = case.get("own").unwrap_or(owner);
    Ok(match kind {
        "chain" => settled_state(run_chain(own, &pins, &commits_from(case)?)?),
        "repair" => {
            let state = run_chain(own, &pins, &commits_from(case)?)?;
            let quarantined = match field(case, "quarantined")? {
                value if value.is_object() => Some(commit_from(value)?),
                _ => None,
            };
            let repair = commit_from(field(case, "repair")?)?;
            settled_state(
                state.and_then(|state| verify_repair(&state, quarantined.as_ref(), &repair)),
            )
        }
        "account" => account(case, &pins)?,
        "share" => share(case, own, &pins)?,
        "item" => item(case, own)?,
        "dissolve" | "leave" => lifecycle(case, kind, own)?,
        _ => return Err(ReplayError::Vector("unknown kind")),
    })
}

fn account(case: &Value, pins: &Value) -> Replay<Value> {
    let signed = Signed::<AccountRecord>::from_cbor(&bytes(case, "record")?)?;
    let seen = match field(case, "seen")? {
        value if value.is_object() => Some(AccountSeen {
            seq: Seq::new(num(value, "seq")?)?,
            hash: Hash32::from_bytes(fixed(value, "hash")?),
        }),
        _ => None,
    };
    Ok(settle(
        verify_account_record(&signed, seen.as_ref(), &pins_from(pins)?).map(
            |record| json!({ "account_id": hex(record.account_id.as_bytes()), "seq": record.seq.get() }),
        ),
    ))
}

fn trusted(case: &Value, own: &Value) -> Replay<Result<VaultState, ProtoError>> {
    run_chain(own, &json!([]), &commits_from(case)?)
}

fn share(case: &Value, own: &Value, pins: &Value) -> Replay<Value> {
    let state = match trusted(case, own)? {
        Ok(state) => state,
        Err(error) => return Ok(crate::json::failed(&error)),
    };
    let signed = Signed::<Share>::from_cbor(&bytes(case, "share")?)?;
    let invite = match field(case, "invite")?.as_str() {
        Some(code) => Some(InviteCode::parse(code)?),
        None => None,
    };
    let own_keys = own_from(own)?;
    let roster = state.verified_roster();
    let kem = KemSecretKey::from_seed(&SecretKey::from_bytes(fixed(case, "kem_seed")?))?;
    let opened = verify_share(
        &signed,
        &own_keys,
        &roster,
        invite.as_ref(),
        &pins_from(pins)?,
    )
    .and_then(|verified| open_share(&verified, &kem, &roster));
    Ok(settle(opened.map(|vk| json!({ "vk": hex(vk.expose()) }))))
}

fn item(case: &Value, own: &Value) -> Replay<Value> {
    let state = match trusted(case, own)? {
        Ok(state) => state,
        Err(error) => return Ok(crate::json::failed(&error)),
    };
    let wire = bytes(case, "wire")?;
    let vk = SecretKey::from_bytes(fixed(case, "vk")?);
    let opened = ItemWire::from_cbor(&wire).and_then(|item| open_item(&item, &wire, &state, &vk));
    Ok(settle(opened.map(|opened| match opened {
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
    })))
}

fn lifecycle(case: &Value, kind: &str, own: &Value) -> Replay<Value> {
    let state = match trusted(case, own)? {
        Ok(state) => state,
        Err(error) => return Ok(crate::json::failed(&error)),
    };
    let record = bytes(case, "record")?;
    let result = if kind == "dissolve" {
        Signed::<Dissolve>::from_cbor(&record)
            .and_then(|signed| verify_dissolve(&signed, &state))
            .map(|d| json!({ "seq": d.seq.get(), "head": hex(d.head.as_bytes()) }))
    } else {
        Signed::<LeaveRequest>::from_cbor(&record)
            .and_then(|signed| verify_leave(&signed, &state))
            .map(|l| json!({ "account_id": hex(l.account_id.as_bytes()), "rver": l.rver.get() }))
    };
    Ok(settle(result))
}

pub(crate) fn replay(value: &Value) -> Replay<Vec<Outcome>> {
    let cases = list(value, "cases")?;
    let owner = cases
        .iter()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(OWNER_CASE))
        .and_then(|case| case.get("own"))
        .ok_or(ReplayError::Vector("owner case missing"))?;
    cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            Ok(outcome(
                named(case, "verify", index),
                field(case, "expect")?,
                &replay_case(case, owner)?,
            ))
        })
        .collect()
}
