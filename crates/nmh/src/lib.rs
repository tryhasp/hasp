pub mod desktop;
#[cfg(any(test, feature = "test-double"))]
pub mod double;
pub mod framing;
pub mod host;
pub mod identity;
pub mod ipc;
pub mod manifest;
pub mod message;
pub mod origin;
pub mod peer;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(test)]
mod relay_tests;
