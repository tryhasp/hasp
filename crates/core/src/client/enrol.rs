use std::future::Future;

use hasp_crypto::{SecretKey, X25519Secret};
use hasp_proto::{AccountId, DeviceId, Esid, Hash32};

mod codec;
mod device;
mod extension;

pub use extension::{UNLOCK_NONCE_LEN, pairing_code, pairing_code_of_request, unlock_code};

pub(super) const QR_VERSION: u64 = 1;
pub(super) const EXPIRY_S: u64 = 300;
pub(super) const MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolInvite {
    pub esid: Esid,
    pub qr: Vec<u8>,
    pub expires: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolRequest {
    pub platform: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("the channel closed")]
    Closed,
    #[error("the peer failed verification")]
    Peer,
}

/// A local channel whose peer the host verified before it handed it over (protocol 7.2 C step 1).
/// The channel is not cryptographic.
pub trait Channel: Send + Sync {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send;
    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send;
}

pub(crate) enum EnrolState {
    Initiator(Initiator),
    Joiner(Box<Joiner>),
}

pub(crate) struct Initiator {
    esid: Esid,
    e: SecretKey,
    expires: u64,
    c_b: Option<Hash32>,
    device: Option<(DeviceId, String)>,
    a: Option<X25519Secret>,
    a_pub: Option<[u8; 32]>,
    attempts: u8,
}

pub(crate) struct Joiner {
    origin: String,
    account_id: AccountId,
    esid: Esid,
    e: SecretKey,
    fp: [u8; 15],
    sf: [u8; 15],
    b: X25519Secret,
    b_pub: [u8; 32],
    c_b: Hash32,
    device_id: DeviceId,
    k_ch: Option<(SecretKey, Hash32)>,
}

impl std::fmt::Debug for EnrolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrolState(..)")
    }
}
