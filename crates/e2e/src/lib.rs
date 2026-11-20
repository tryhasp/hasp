#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness aborts on a broken fixture"
)]

use std::time::Duration;

mod bins;
mod device;
mod haspd;
mod oracle;
mod secrets;
mod sqlite;

pub use bins::{Bins, bins, repo_root};
pub use device::{Device, Out, Running};
pub use haspd::{Haspd, Init, PASSWORD, free_port};
pub use oracle::{bitwarden_secrets, csv_secrets, onepux_data, onepux_items, onepux_secrets};
pub use secrets::{hash_hex, item_count, vault_secret_hashes};
pub use sqlite::{query_strings, run_sql};

#[expect(
    clippy::disallowed_methods,
    reason = "end-to-end tests wait on real processes and the real clock"
)]
pub fn pause(duration: Duration) {
    std::thread::sleep(duration);
}
