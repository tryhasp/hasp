use serde::Serialize;
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::HaspError;
use crate::error::{exported, thrown};

#[derive(Clone, Debug, Serialize, Tsify)]
pub struct ReplayOutcome {
    pub name: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, Serialize, Tsify)]
pub struct ReplayReport {
    pub outcomes: Vec<ReplayOutcome>,
}

#[wasm_bindgen(js_name = vectorGroups)]
pub fn vector_groups() -> Vec<String> {
    hasp_replay::GROUPS
        .iter()
        .map(|group| (*group).to_owned())
        .collect()
}

#[wasm_bindgen(js_name = replayVectors)]
pub fn replay_vectors(group: &str, vectors: &str) -> Result<Ts<ReplayReport>, Ts<HaspError>> {
    let outcomes = hasp_replay::replay(group, vectors)
        .map_err(thrown)?
        .into_iter()
        .map(|outcome| ReplayOutcome {
            name: outcome.name,
            expected: outcome.expected,
            actual: outcome.actual,
        })
        .collect();
    exported(&ReplayReport { outcomes })
}

#[wasm_bindgen(js_name = normalisePassword)]
pub fn normalise_password(input: &str) -> String {
    hasp_replay::normalise_password(input)
}

#[wasm_bindgen(js_name = normaliseLogin)]
pub fn normalise_login(input: &str) -> Result<String, Ts<HaspError>> {
    hasp_replay::normalise_login(input).map_err(thrown)
}
