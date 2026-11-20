use std::sync::Arc;

use hasp_core::client::{Channel, ChannelError};
use hasp_core::platform::{Biometric, PlatformError, SecureStore};
use hasp_core::watchtower::WatchtowerError;
use hasp_core::watchtower::pwned::{Prefix, RangeClient};
use hasp_crypto::SecretBytes;

use crate::HaspError;

#[uniffi::export(with_foreign)]
pub trait PlatformStore: Send + Sync {
    fn hardware_gated(&self) -> bool;
    fn put(&self, label: String, secret: Vec<u8>) -> Result<(), HaspError>;
    fn get(&self, label: String) -> Result<Vec<u8>, HaspError>;
    fn delete(&self, label: String) -> Result<(), HaspError>;
}

#[uniffi::export(with_foreign)]
pub trait PlatformBiometric: Send + Sync {
    fn available(&self) -> bool;
    fn authenticate(&self, reason: String) -> Result<(), HaspError>;
}

#[uniffi::export(with_foreign)]
pub trait PairingChannel: Send + Sync {
    fn send(&self, message: Vec<u8>) -> Result<(), HaspError>;
    fn recv(&self) -> Result<Vec<u8>, HaspError>;
}

#[uniffi::export(with_foreign)]
pub trait BreachRange: Send + Sync {
    fn range(&self, prefix: String) -> Result<String, HaspError>;
}

#[uniffi::export(with_foreign)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: crate::types::EngineEvent);
}

fn platform_error(error: HaspError) -> PlatformError {
    match error {
        HaspError::Cancelled | HaspError::Authz => PlatformError::Denied,
        HaspError::NotFound => PlatformError::Missing,
        _ => PlatformError::Store,
    }
}

pub(crate) struct ForeignStore(pub(crate) Arc<dyn PlatformStore>);

impl SecureStore for ForeignStore {
    fn hardware_gated(&self) -> bool {
        self.0.hardware_gated()
    }

    fn put(&self, label: &str, secret: &[u8]) -> Result<(), PlatformError> {
        self.0
            .put(label.to_owned(), secret.to_vec())
            .map_err(platform_error)
    }

    fn get(&self, label: &str) -> Result<SecretBytes, PlatformError> {
        self.0
            .get(label.to_owned())
            .map(SecretBytes::from_vec)
            .map_err(platform_error)
    }

    fn delete(&self, label: &str) -> Result<(), PlatformError> {
        self.0.delete(label.to_owned()).map_err(platform_error)
    }
}

pub(crate) struct ForeignBiometric(pub(crate) Arc<dyn PlatformBiometric>);

impl Biometric for ForeignBiometric {
    fn available(&self) -> bool {
        self.0.available()
    }

    fn authenticate(&self, reason: &str) -> Result<(), PlatformError> {
        self.0
            .authenticate(reason.to_owned())
            .map_err(platform_error)
    }
}

pub(crate) struct ForeignChannel(pub(crate) Arc<dyn PairingChannel>);

impl Channel for ForeignChannel {
    async fn send(&self, message: Vec<u8>) -> Result<(), ChannelError> {
        let channel = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || channel.send(message))
            .await
            .map_err(|_| ChannelError::Closed)?
            .map_err(|_| ChannelError::Closed)
    }

    async fn recv(&self) -> Result<Vec<u8>, ChannelError> {
        let channel = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || channel.recv())
            .await
            .map_err(|_| ChannelError::Closed)?
            .map_err(|error| match error {
                HaspError::Authz => ChannelError::Peer,
                _ => ChannelError::Closed,
            })
    }
}

pub(crate) struct ForeignRange(pub(crate) Arc<dyn BreachRange>);

impl RangeClient for ForeignRange {
    async fn range(&self, prefix: &Prefix) -> Result<String, WatchtowerError> {
        let fetcher = Arc::clone(&self.0);
        let prefix = prefix.as_str().to_owned();
        tokio::task::spawn_blocking(move || fetcher.range(prefix))
            .await
            .map_err(|_| WatchtowerError::Network)?
            .map_err(|_| WatchtowerError::Network)
    }
}
