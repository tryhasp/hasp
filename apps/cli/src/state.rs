use std::path::{Path, PathBuf};

use crate::error::CliError;
use crate::fsx;

const FILE: &str = "state.json";
const FAILURES_BEFORE_DELAY: u32 = 5;
const DELAY_BASE_S: u64 = 2;
const DELAY_CAP_S: u64 = 3600;
pub(crate) const FULL_PASSWORD_EVERY_S: u64 = 14 * 24 * 60 * 60;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct State {
    pub(crate) origin: Option<String>,
    pub(crate) last_password_at: u64,
    pub(crate) failures: u32,
    pub(crate) locked_until: u64,
}

#[derive(Debug)]
pub(crate) struct StateFile {
    path: PathBuf,
}

impl State {
    pub(crate) fn lockout_remaining(&self, now: u64) -> Option<u64> {
        (self.failures >= FAILURES_BEFORE_DELAY && now < self.locked_until)
            .then(|| self.locked_until.saturating_sub(now))
    }

    pub(crate) fn note_failure(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= FAILURES_BEFORE_DELAY {
            let doublings = self.failures.saturating_sub(FAILURES_BEFORE_DELAY).min(20);
            let delay = DELAY_BASE_S
                .saturating_mul(1_u64 << doublings)
                .min(DELAY_CAP_S);
            self.locked_until = now.saturating_add(delay);
        }
    }

    pub(crate) fn note_password(&mut self, now: u64) {
        self.failures = 0;
        self.locked_until = 0;
        self.last_password_at = now;
    }

    pub(crate) fn password_due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_password_at) >= FULL_PASSWORD_EVERY_S
    }

    pub(crate) fn password_due_in(&self, now: u64) -> u64 {
        FULL_PASSWORD_EVERY_S.saturating_sub(now.saturating_sub(self.last_password_at))
    }
}

impl StateFile {
    pub(crate) fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(FILE),
        }
    }

    pub(crate) fn load(&self) -> Result<State, CliError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn save(&self, state: &State) -> Result<(), CliError> {
        fsx::replace_private(&self.path, &serde_json::to_vec_pretty(state)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_failures_start_an_exponential_delay() {
        let mut state = State::default();
        for _ in 0..4 {
            state.note_failure(100);
        }
        assert_eq!(state.lockout_remaining(100), None);
        state.note_failure(100);
        assert_eq!(state.lockout_remaining(100), Some(2));
        state.note_failure(100);
        assert_eq!(state.lockout_remaining(100), Some(4));
        assert_eq!(state.lockout_remaining(104), None);
    }

    #[test]
    fn the_delay_is_capped() {
        let mut state = State::default();
        for _ in 0..40 {
            state.note_failure(0);
        }
        assert_eq!(state.lockout_remaining(0), Some(DELAY_CAP_S));
    }

    #[test]
    fn a_password_resets_failures_and_the_fourteen_day_clock() {
        let mut state = State::default();
        state.note_failure(10);
        state.note_password(1_000);
        assert_eq!(state.failures, 0);
        assert!(!state.password_due(1_000 + FULL_PASSWORD_EVERY_S - 1));
        assert!(state.password_due(1_000 + FULL_PASSWORD_EVERY_S));
    }

    #[test]
    fn state_survives_a_round_trip_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let file = StateFile::new(dir.path());
        assert_eq!(file.load().unwrap(), State::default());
        let state = State {
            origin: Some("https://vault.example".to_owned()),
            last_password_at: 7,
            failures: 2,
            locked_until: 0,
        };
        file.save(&state).unwrap();
        assert_eq!(file.load().unwrap(), state);
    }
}
