use hasp_proto::ProtoError;
use serde_json::{Value, json};

use crate::{Outcome, ReplayError};

pub(crate) type Replay<T> = Result<T, ReplayError>;

pub(crate) fn field<'a>(value: &'a Value, key: &str) -> Replay<&'a Value> {
    value.get(key).ok_or(ReplayError::Vector("missing field"))
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Replay<&'a str> {
    field(value, key)?
        .as_str()
        .ok_or(ReplayError::Vector("field is not text"))
}

pub(crate) fn num(value: &Value, key: &str) -> Replay<u64> {
    field(value, key)?
        .as_u64()
        .ok_or(ReplayError::Vector("field is not a number"))
}

pub(crate) fn list<'a>(value: &'a Value, key: &str) -> Replay<&'a [Value]> {
    field(value, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or(ReplayError::Vector("field is not a list"))
}

pub(crate) use hasp_crypto::to_hex as hex;

pub(crate) fn unhex(text: &str) -> Replay<Vec<u8>> {
    hasp_crypto::from_hex(text).ok_or(ReplayError::Vector("bad hex"))
}

pub(crate) fn bytes(value: &Value, key: &str) -> Replay<Vec<u8>> {
    unhex(text(value, key)?)
}

pub(crate) fn fixed<const N: usize>(value: &Value, key: &str) -> Replay<[u8; N]> {
    bytes(value, key)?
        .try_into()
        .map_err(|_| ReplayError::Vector("bad length"))
}

pub(crate) fn hex_items(value: &Value, key: &str) -> Replay<Vec<Vec<u8>>> {
    list(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or(ReplayError::Vector("item is not text"))
                .and_then(unhex)
        })
        .collect()
}

pub(crate) fn failed(error: &ProtoError) -> Value {
    json!({ "err": error.name() })
}

pub(crate) fn settle(result: Result<Value, ProtoError>) -> Value {
    match result {
        Ok(value) => json!({ "ok": value }),
        Err(error) => failed(&error),
    }
}

pub(crate) fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        json!(key),
                        map.get(key).map_or_else(String::new, canonical)
                    )
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", body.join(","))
        }
        other => other.to_string(),
    }
}

pub(crate) fn outcome(name: String, expected: &Value, actual: &Value) -> Outcome {
    Outcome {
        name,
        expected: canonical(expected),
        actual: canonical(actual),
    }
}

pub(crate) fn named(case: &Value, group: &str, index: usize) -> String {
    case.get("name").and_then(Value::as_str).map_or_else(
        || format!("{group}[{index}]"),
        |name| format!("{group}:{name}"),
    )
}
