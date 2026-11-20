#![deny(deprecated)]

mod engine;
mod error;
mod fetch;
mod js;
#[cfg(feature = "replay")]
mod replay;
mod secret;
mod types;

pub use engine::{
    Client, extension_pairing_code, extension_unlock_code, parse_kit_qr, registrable_domain,
};
pub use error::HaspError;
#[cfg(feature = "replay")]
pub use replay::{
    ReplayOutcome, ReplayReport, normalise_login, normalise_password, replay_vectors, vector_groups,
};
pub use types::*;
