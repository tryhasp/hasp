mod bridge;
mod engine;
mod error;
mod platform;
#[cfg(feature = "replay")]
mod replay;
mod secret;
mod types;

pub use bridge::{
    BridgeConfig, BridgeDelegate, BrowserFillOutcome, ExtensionBridge, PeerCheck,
    bridge_group_container,
};
pub use engine::{Client, parse_kit_qr, registrable_domain};
pub use error::HaspError;
pub use platform::{BreachRange, EventListener, PairingChannel, PlatformBiometric, PlatformStore};
#[cfg(feature = "replay")]
pub use replay::{
    ReplayOutcome, normalise_login, normalise_password, replay_vectors, vector_groups,
};
pub use types::*;

uniffi::setup_scaffolding!();
