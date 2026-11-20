use hasp_proto::ProtoError;
use serde_json::{Value, json};

use crate::Outcome;
use crate::ReplayError;
use crate::json::{Replay, failed, hex, list, named, outcome, text};

pub fn normalise_password(input: &str) -> String {
    hasp_core::normalise_password(input).to_string()
}

pub fn normalise_login(input: &str) -> Result<String, ProtoError> {
    hasp_core::normalise_login(input).map_err(|_| ProtoError::Format)
}

fn scalars(case: &Value) -> Replay<String> {
    list(case, "scalars")?
        .iter()
        .map(|scalar| {
            scalar
                .as_u64()
                .and_then(|code| u32::try_from(code).ok())
                .and_then(char::from_u32)
                .ok_or(ReplayError::Vector("scalar"))
        })
        .collect()
}

pub(crate) fn replay(
    value: &Value,
    rule: fn(&str) -> Result<String, ProtoError>,
) -> Replay<Vec<Outcome>> {
    list(value, "cases")?
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let input = scalars(case)?;
            let expected = match case.get("err") {
                Some(_) => json!({ "err": text(case, "err")? }),
                None => json!({ "utf8": text(case, "utf8")? }),
            };
            let actual = match rule(&input) {
                Ok(output) => json!({ "utf8": hex(output.as_bytes()) }),
                Err(error) => failed(&error),
            };
            Ok(outcome(named(case, "text", index), &expected, &actual))
        })
        .collect::<Result<_, ReplayError>>()
}
