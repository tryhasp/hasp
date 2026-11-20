mod account;
mod attach;
mod auth;
mod enrol;
mod facade;
mod kit;
mod localnote;
mod members;
mod provider;
mod signin;
mod signup;
mod unlock;
mod vaults;

use std::sync::{Arc, Mutex};

use hasp_proto::KdfWire;
use tokio_util::sync::CancellationToken;

use crate::CoreError;
use crate::platform::Platform;
use crate::session::{Cancel, Session};
use crate::store::{Cache, Store};
use crate::transport::Transport;

pub use account::{DeviceEntry, RecoveryOutcome, RecoveryTicket, RestoreReport};
pub use attach::{AttachmentInfo, NewAttachment};
pub use enrol::{
    Channel, ChannelError, EnrolInvite, EnrolRequest, UNLOCK_NONCE_LEN, pairing_code,
    pairing_code_of_request, unlock_code,
};
pub use kit::KitDocument;
pub use members::{
    AcceptedInvite, Admission, FingerprintCheck, InviteOffer, MemberInfo, PendingInvitee,
};
pub use signin::SignIn;
pub use signup::{EmergencyKit, SignUp};
pub use unlock::{Confirmation, HeadInfo};
pub use vaults::{HistoryEntry, ItemSummary, VaultSummary};

macro_rules! ctx {
    ($client:ident, $cancel:expr) => {
        $crate::sync::Ctx {
            transport: &$client.transport,
            cache: &mut $client.cache,
            session: $client.session.as_mut().ok_or($crate::CoreError::Locked)?,
            platform: &$client.platform,
            cancel: $cancel,
        }
    };
}
pub(crate) use ctx;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub platform_name: String,
    pub max_kdf_m_kib: u32,
    pub account_kdf: KdfWire,
    pub local_kdf: KdfWire,
}

impl ClientConfig {
    pub fn new(platform_name: &str) -> Self {
        let floor = KdfWire {
            m: 65_536,
            t: 3,
            p: 4,
        };
        Self {
            platform_name: platform_name.to_owned(),
            max_kdf_m_kib: 524_288,
            account_kdf: floor,
            local_kdf: floor,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeviceDescription {
    pub label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    Empty,
    Locked,
    Unlocked,
}

#[derive(Clone, Debug)]
pub struct CancelHandle(Arc<Mutex<CancellationToken>>);

impl CancelHandle {
    pub fn cancel(&self) {
        if let Ok(token) = self.0.lock() {
            token.cancel();
        }
    }
}

pub struct Client<T: Transport, S: Store> {
    transport: T,
    cache: Cache<S>,
    platform: Platform,
    config: ClientConfig,
    session: Option<Session>,
    cancel: CancelHandle,
    enrol: Option<enrol::EnrolState>,
    failed_unlocks: u32,
    locked_until: u64,
    staged: std::collections::BTreeMap<hasp_proto::AttId, attach::Staged>,
    opened: std::sync::atomic::AtomicU64,
}

impl<T: Transport, S: Store> std::fmt::Debug for Client<T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client(..)")
    }
}

impl<T: Transport, S: Store> Client<T, S> {
    pub fn new(transport: T, store: S, platform: Platform, config: ClientConfig) -> Self {
        Self {
            transport,
            cache: Cache::new(store),
            platform,
            config,
            session: None,
            cancel: CancelHandle(Arc::new(Mutex::new(CancellationToken::new()))),
            enrol: None,
            failed_unlocks: 0,
            locked_until: 0,
            staged: std::collections::BTreeMap::new(),
            opened: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> Result<ClientState, CoreError> {
        Ok(if self.session.is_some() {
            ClientState::Unlocked
        } else if self.cache.account()?.is_some() {
            ClientState::Locked
        } else {
            ClientState::Empty
        })
    }

    /// A handle a host keeps to stop the call in flight. Cancelling returns `Cancelled` at the next
    /// await of the running call; the next call starts with a fresh token.
    pub fn cancel_handle(&self) -> CancelHandle {
        self.cancel.clone()
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// The bearer token of this unlocked session, for the transport's hint socket.
    /// It must never be displayed, logged or stored.
    pub fn session_token(&self) -> Result<hasp_proto::wire::SessionToken, CoreError> {
        Ok(self.unlocked()?.token.clone())
    }

    pub fn login(&self) -> Result<String, CoreError> {
        Ok(self.cache.account()?.ok_or(CoreError::Locked)?.login)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn platform_for_tests(&self) -> Platform {
        self.platform.clone()
    }

    pub fn into_store(self) -> S {
        self.cache.into_store()
    }

    pub fn account_id(&self) -> Result<hasp_proto::AccountId, CoreError> {
        Ok(self.cache.account()?.ok_or(CoreError::Locked)?.account_id)
    }

    pub fn fingerprint(&self) -> Result<String, CoreError> {
        let account = self.cache.account()?.ok_or(CoreError::Locked)?;
        let record = account.record.unverified()?;
        Ok(hasp_proto::format_fingerprint(&hasp_proto::fingerprint(
            &record.ik_pk,
            &record.kem_pk,
        )))
    }

    fn begin(&self, call: &CancellationToken) -> Cancel {
        let client = match self.cancel.0.lock() {
            Ok(mut guard) => {
                if guard.is_cancelled() {
                    *guard = CancellationToken::new();
                }
                guard.clone()
            }
            Err(_) => CancellationToken::new(),
        };
        Cancel {
            client,
            call: call.clone(),
        }
    }

    fn unlocked(&self) -> Result<&Session, CoreError> {
        self.session.as_ref().ok_or(CoreError::Locked)
    }
}

#[cfg(any(test, feature = "testing"))]
impl<T: Transport, S: Store> Client<T, S> {
    /// How many items this client decrypted so far, for tests that prove a call stays small.
    pub fn items_opened(&self) -> u64 {
        self.opened.load(std::sync::atomic::Ordering::Relaxed)
    }
}
