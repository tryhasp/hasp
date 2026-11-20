use crate::HaspError;

#[derive(Clone, Debug, uniffi::Record)]
pub struct ReplayOutcome {
    pub name: String,
    pub expected: String,
    pub actual: String,
}

#[uniffi::export]
pub fn vector_groups() -> Vec<String> {
    hasp_replay::GROUPS
        .iter()
        .map(|group| (*group).to_owned())
        .collect()
}

#[uniffi::export]
pub fn replay_vectors(group: &str, vectors: &str) -> Result<Vec<ReplayOutcome>, HaspError> {
    Ok(hasp_replay::replay(group, vectors)?
        .into_iter()
        .map(|outcome| ReplayOutcome {
            name: outcome.name,
            expected: outcome.expected,
            actual: outcome.actual,
        })
        .collect())
}

#[uniffi::export]
pub fn normalise_password(input: &str) -> String {
    hasp_replay::normalise_password(input)
}

#[uniffi::export]
pub fn normalise_login(input: &str) -> Result<String, HaspError> {
    hasp_replay::normalise_login(input).map_err(HaspError::from)
}
