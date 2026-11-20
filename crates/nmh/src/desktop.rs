use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hasp_core::CoreError;
use hasp_core::client::{Channel, ChannelError, Client};
use hasp_core::store::Store;
use hasp_core::transport::Transport;
use hasp_crypto::SecretKey;
use hasp_proto::{DeviceId, Reader, Wire, Writer, base64url};
use tokio_util::sync::CancellationToken;

use crate::framing::{FrameError, MAX_HELLO, read_frame};
use crate::ipc::{ADMIT_TIMEOUT, FramedLink};
use crate::message::{
    Browser, DesktopMessage, ErrorCode, ExtensionMessage, FillOutcome, Hello, SecretText,
};
use crate::origin::{ExtensionAllowlist, ExtensionOrigin, OriginError};
use crate::peer::{CodeVerifier, PeerError, Requirement};

const EXTENSION_PLATFORM: &str = "extension";
const ENROL_REQUEST: &str = "enrol_request";

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("the link closed or failed: {0}")]
    Io(#[from] io::Error),
    #[error("malformed message")]
    Malformed,
}

/// One verified conversation with an extension. A socket from `hasp-nmh` implements it
/// (`FramedLink`); the Safari handler inside the app implements it over `sendNativeMessage`
/// and `beginRequest`, where being inside the app bundle is the verification (protocol 7.2 C
/// step 1).
pub trait Link: Send {
    fn recv(&mut self) -> Result<Option<ExtensionMessage>, LinkError>;
    fn send(&mut self, message: &DesktopMessage) -> Result<(), LinkError>;

    /// A second handle that only writes, so another thread can push while this one blocks in
    /// `recv`. A link that cannot split returns `None` and has no `Pusher`.
    fn writer(&self) -> Option<Box<dyn LinkWriter>> {
        None
    }
}

pub trait LinkWriter: Send + std::fmt::Debug {
    fn send(&mut self, message: &DesktopMessage) -> Result<(), LinkError>;
}

#[derive(Debug)]
pub struct UnlockRequest {
    pub device_id: DeviceId,
    pub nonce: [u8; 16],
    pub browser: Browser,
    pub origin: String,
}

#[derive(Debug)]
pub struct Release {
    pub k_ext: SecretKey,
    pub valid_until: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    Declined,
    Revoked,
    Locked,
    Unknown,
}

/// The app side of protocol 7.16. `release` decides: it requires user presence, checks that
/// `device_id` is a paired extension that has not been revoked or unpaired, and returns that
/// device's `K_ext` from the sealed `ext_key`. It never returns anything else.
pub trait ExtensionKeys {
    fn release(&self, request: &UnlockRequest) -> Result<Release, Denial>;

    /// Called once after pairing succeeded, with the `K_ext` the core made. The app seals it
    /// as `ext_key` under the device unlock key (protocol 4.6, rtype 11 field 8).
    fn remember(&self, paired: Paired);

    /// Whether `device` is still a paired extension of exactly this browser and extension id.
    /// Asked before every desktop-initiated request (`fill_request`, `page_query`); the default
    /// refuses, so an implementation that does not answer can never be pushed to.
    fn is_paired(&self, _device: DeviceId, _browser: Browser, _origin: &str) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct Paired {
    pub device_id: DeviceId,
    pub browser: Browser,
    pub origin: String,
    pub k_ext: SecretKey,
}

#[derive(Debug)]
pub struct DesktopPolicy {
    pub host: Requirement,
    pub host_path: PathBuf,
    pub allowlist: ExtensionAllowlist,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("the socket peer is not the signed host: {0}")]
    Peer(PeerError),
    #[error("the socket peer is a different binary than this app's own host")]
    NotOurHost,
    #[error("hello: {0}")]
    Hello(String),
    #[error("origin: {0}")]
    Origin(#[from] OriginError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Served {
    Paired(DeviceId),
    Unlocked,
    Replied,
    Refused(ErrorCode),
    Closed,
}

#[derive(Debug)]
pub struct Session<L: Link> {
    link: L,
    browser: Browser,
    origin: String,
    shared: Arc<Mutex<Shared>>,
    writer: Option<Arc<Mutex<Box<dyn LinkWriter>>>>,
    denials: u8,
}

const MAX_DENIALS: u8 = 3;

/// What one extension reports for a `page_query`: the host of its active tab and whether its
/// browser window is the one the user is looking at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageState {
    pub host: Option<String>,
    pub focused: bool,
}

#[derive(Debug)]
enum Reply {
    Page(PageState),
    Fill(FillOutcome),
}

#[derive(Debug, Default)]
struct Shared {
    device: Option<DeviceId>,
    next_id: u64,
    pending: BTreeMap<u64, Sender<Reply>>,
}

const MAX_PENDING: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    #[error("this connection is not a paired extension")]
    NotPaired,
    #[error("the extension did not answer in time")]
    Timeout,
    #[error("the link is closed or busy")]
    Closed,
}

/// The write side of one verified connection, for requests the desktop starts (Quick Access to
/// the extension). Every request is refused unless the connection completed pairing or unlock
/// for a device that `ExtensionKeys::is_paired` still confirms for this browser and extension
/// id. Requests carry item references only; the extension re-runs matching and step-up itself.
#[derive(Clone, Debug)]
pub struct Pusher {
    writer: Arc<Mutex<Box<dyn LinkWriter>>>,
    shared: Arc<Mutex<Shared>>,
    browser: Browser,
    origin: String,
}

#[derive(Debug)]
pub enum Request {
    Enrol {
        id: u64,
        data: String,
    },
    Unlock {
        id: u64,
        device_id: DeviceId,
        nonce: [u8; 16],
    },
    Replied,
}

/// Admits a connection from `hasp-nmh`. The signing check of the socket peer runs first and
/// nothing is read before it passes; then the app checks that the binary is the one inside its
/// own bundle and that the origin the host attests is allowed for the browser it attests.
pub fn admit<V: CodeVerifier>(
    verifier: &V,
    policy: &DesktopPolicy,
    stream: UnixStream,
) -> Result<Session<FramedLink>, AdmitError> {
    let target = verifier.peer_of(&stream).map_err(AdmitError::Peer)?;
    let signed = verifier
        .verify(&target, &policy.host)
        .map_err(AdmitError::Peer)?;
    if signed.path != policy.host_path {
        return Err(AdmitError::NotOurHost);
    }
    let mut link = FramedLink::new(stream);
    link.set_timeout(Some(ADMIT_TIMEOUT))?;
    let frame = match read_frame(link.stream(), MAX_HELLO) {
        Ok(Some(frame)) => frame,
        Ok(None) => return Err(AdmitError::Hello("closed".to_owned())),
        Err(FrameError::Io(e)) => return Err(AdmitError::Io(e)),
        Err(other) => return Err(AdmitError::Hello(other.to_string())),
    };
    let hello = Hello::decode(&frame).map_err(|e| AdmitError::Hello(e.to_string()))?;
    let origin = match hello.browser.family() {
        crate::message::Family::Chromium => ExtensionOrigin::Chromium(hello.origin.clone()),
        crate::message::Family::Gecko => ExtensionOrigin::Gecko(hello.origin.clone()),
        crate::message::Family::WebKit => {
            return Err(AdmitError::Hello("safari does not use the host".to_owned()));
        }
    };
    policy.allowlist.admit(&origin, hello.browser)?;
    link.set_timeout(None)?;
    Ok(Session::new(link, hello.browser, hello.origin))
}

impl<L: Link> Session<L> {
    pub fn new(link: L, browser: Browser, origin: String) -> Self {
        let writer = link.writer().map(|w| Arc::new(Mutex::new(w)));
        Self {
            link,
            browser,
            origin,
            shared: Arc::new(Mutex::new(Shared::default())),
            writer,
            denials: 0,
        }
    }

    pub fn pusher(&self) -> Option<Pusher> {
        Some(Pusher {
            writer: Arc::clone(self.writer.as_ref()?),
            shared: Arc::clone(&self.shared),
            browser: self.browser,
            origin: self.origin.clone(),
        })
    }

    pub fn device(&self) -> Option<DeviceId> {
        lock(&self.shared).device
    }

    /// Records that this connection completed pairing or unlock for `device`.
    pub fn mark_paired(&self, device: DeviceId) {
        lock(&self.shared).device = Some(device);
    }

    /// Reads the next message. A reply to a desktop request is delivered to its waiter and
    /// reported as `Replied`; a reply nobody asked for is `Malformed`, which ends the link.
    pub fn recv_request(&mut self) -> Result<Option<Request>, LinkError> {
        let Some(message) = self.link.recv()? else {
            return Ok(None);
        };
        let id = message.id();
        match message {
            ExtensionMessage::EnrolRequest { data, .. } => Ok(Some(Request::Enrol { id, data })),
            ExtensionMessage::Unlock { .. } => {
                let device_id = message.device_id().ok_or(LinkError::Malformed)?;
                let nonce = message.nonce().ok_or(LinkError::Malformed)?;
                Ok(Some(Request::Unlock {
                    id,
                    device_id,
                    nonce,
                }))
            }
            ExtensionMessage::PageReply { host, focused, .. } => {
                self.deliver(id, Reply::Page(PageState { host, focused }))?;
                Ok(Some(Request::Replied))
            }
            ExtensionMessage::FillReply { outcome, .. } => {
                self.deliver(id, Reply::Fill(outcome))?;
                Ok(Some(Request::Replied))
            }
        }
    }

    fn deliver(&self, id: u64, reply: Reply) -> Result<(), LinkError> {
        let waiter = lock(&self.shared).pending.remove(&id);
        match waiter {
            Some(waiter) => {
                waiter.send(reply).ok();
                Ok(())
            }
            None => Err(LinkError::Malformed),
        }
    }

    pub fn pairing_channel(&mut self, id: u64, data: String) -> impl Channel + '_ {
        PairingChannel::new(&mut self.link, id, self.browser, data)
    }

    pub fn refuse(&mut self, id: u64, code: ErrorCode) -> Result<(), LinkError> {
        self.link
            .send(&DesktopMessage::Error { id: Some(id), code })
    }

    /// Asks `keys` to release `K_ext` for one `unlock`. After `MAX_DENIALS` refusals on this
    /// connection it refuses without asking, so a process that keeps asking cannot keep the user's
    /// prompt open: the connection ends.
    pub fn serve_unlock<K: ExtensionKeys>(
        &mut self,
        keys: &K,
        id: u64,
        device_id: DeviceId,
        nonce: [u8; 16],
    ) -> Result<Served, LinkError> {
        if self.denials >= MAX_DENIALS {
            self.refuse(id, ErrorCode::Declined)?;
            return Ok(Served::Closed);
        }
        let released = keys.release(&UnlockRequest {
            device_id,
            nonce,
            browser: self.browser,
            origin: self.origin.clone(),
        });
        self.answer_unlock(id, device_id, released)
    }

    pub fn answer_unlock(
        &mut self,
        id: u64,
        device: DeviceId,
        released: Result<Release, Denial>,
    ) -> Result<Served, LinkError> {
        match released {
            Ok(release) => {
                self.link.send(&DesktopMessage::UnlockReply {
                    id,
                    k_ext: SecretText::new(base64url::encode(release.k_ext.expose())),
                    valid_until: release.valid_until,
                })?;
                self.mark_paired(device);
                Ok(Served::Unlocked)
            }
            Err(denial) => {
                self.denials = self.denials.saturating_add(1);
                let code = match denial {
                    Denial::Declined => ErrorCode::Declined,
                    Denial::Revoked => ErrorCode::Revoked,
                    Denial::Locked => ErrorCode::Locked,
                    Denial::Unknown => ErrorCode::Refused,
                };
                self.refuse(id, code)?;
                Ok(Served::Refused(code))
            }
        }
    }

    pub fn browser(&self) -> Browser {
        self.browser
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn push_lock(&mut self) -> Result<(), LinkError> {
        self.link.send(&DesktopMessage::Lock)
    }

    /// Serves one request. Pairing runs the core's `serve_extension_pairing` (7.2 C steps 2 to
    /// 4) over this link; unlock asks `keys` (7.16). Blocks the calling thread while it waits
    /// for the extension.
    pub async fn serve_one<T: Transport, S: Store, K: ExtensionKeys>(
        &mut self,
        client: &mut Client<T, S>,
        keys: &K,
        call: &CancellationToken,
    ) -> Result<Served, LinkError> {
        match self.recv_request()? {
            None => Ok(Served::Closed),
            Some(Request::Replied) => Ok(Served::Replied),
            Some(Request::Enrol { id, data }) => {
                let browser = self.browser;
                let paired = {
                    let channel = PairingChannel::new(&mut self.link, id, browser, data);
                    client.serve_extension_pairing(&channel, call).await
                };
                match paired {
                    Ok((device_id, k_ext)) => {
                        keys.remember(Paired {
                            device_id,
                            browser,
                            origin: self.origin.clone(),
                            k_ext,
                        });
                        self.mark_paired(device_id);
                        Ok(Served::Paired(device_id))
                    }
                    Err(error) => {
                        let code = code_of(&error);
                        self.refuse(id, code)?;
                        Ok(Served::Refused(code))
                    }
                }
            }
            Some(Request::Unlock {
                id,
                device_id,
                nonce,
            }) => self.serve_unlock(keys, id, device_id, nonce),
        }
    }
}

impl Pusher {
    pub fn browser(&self) -> Browser {
        self.browser
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn push_lock(&self) -> Result<(), PushError> {
        self.send(&DesktopMessage::Lock)
    }

    pub fn page_host<K: ExtensionKeys + ?Sized>(
        &self,
        keys: &K,
        timeout: Duration,
    ) -> Result<PageState, PushError> {
        self.authorize(keys)?;
        match self.ask(|id| DesktopMessage::PageQuery { id }, timeout)? {
            Reply::Page(state) => Ok(state),
            Reply::Fill(_) => Err(PushError::Closed),
        }
    }

    pub fn request_fill<K: ExtensionKeys + ?Sized>(
        &self,
        keys: &K,
        vault: &str,
        item: &str,
        timeout: Duration,
    ) -> Result<FillOutcome, PushError> {
        self.authorize(keys)?;
        let message = |id| DesktopMessage::FillRequest {
            id,
            vault: vault.to_owned(),
            item: item.to_owned(),
        };
        match self.ask(message, timeout)? {
            Reply::Fill(outcome) => Ok(outcome),
            Reply::Page(_) => Err(PushError::Closed),
        }
    }

    pub fn is_paired<K: ExtensionKeys + ?Sized>(&self, keys: &K) -> bool {
        self.authorize(keys).is_ok()
    }

    fn authorize<K: ExtensionKeys + ?Sized>(&self, keys: &K) -> Result<(), PushError> {
        let device = lock(&self.shared).device.ok_or(PushError::NotPaired)?;
        if keys.is_paired(device, self.browser, &self.origin) {
            Ok(())
        } else {
            Err(PushError::NotPaired)
        }
    }

    fn send(&self, message: &DesktopMessage) -> Result<(), PushError> {
        self.writer
            .lock()
            .map_err(|_| PushError::Closed)?
            .send(message)
            .map_err(|_| PushError::Closed)
    }

    fn ask(
        &self,
        build: impl FnOnce(u64) -> DesktopMessage,
        timeout: Duration,
    ) -> Result<Reply, PushError> {
        let (sender, receiver) = mpsc::channel();
        let id = {
            let mut shared = lock(&self.shared);
            if shared.pending.len() >= MAX_PENDING {
                return Err(PushError::Closed);
            }
            shared.next_id = shared.next_id.saturating_add(1);
            let id = shared.next_id;
            shared.pending.insert(id, sender);
            id
        };
        if let Err(error) = self.send(&build(id)) {
            lock(&self.shared).pending.remove(&id);
            return Err(error);
        }
        receiver.recv_timeout(timeout).map_err(|_| {
            lock(&self.shared).pending.remove(&id);
            PushError::Timeout
        })
    }
}

fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

fn code_of(error: &CoreError) -> ErrorCode {
    match error {
        CoreError::Platform(_) => ErrorCode::Declined,
        CoreError::Locked => ErrorCode::Locked,
        CoreError::DeviceRevoked => ErrorCode::Revoked,
        _ => ErrorCode::Refused,
    }
}

pub(crate) struct PairingChannel<'a, L: Link> {
    link: Mutex<&'a mut L>,
    id: u64,
    browser: Browser,
    first: Mutex<Option<String>>,
}

impl<'a, L: Link> PairingChannel<'a, L> {
    fn new(link: &'a mut L, id: u64, browser: Browser, first: String) -> Self {
        Self {
            link: Mutex::new(link),
            id,
            browser,
            first: Mutex::new(Some(first)),
        }
    }
}

impl<L: Link> Channel for PairingChannel<'_, L> {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        let reply = DesktopMessage::EnrolReply {
            id: self.id,
            data: SecretText::new(base64url::encode(&message)),
        };
        let sent = self
            .link
            .lock()
            .map_err(|_| ChannelError::Closed)
            .and_then(|mut link| link.send(&reply).map_err(|_| ChannelError::Closed));
        std::future::ready(sent)
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        let taken = self.first.lock().ok().and_then(|mut slot| slot.take());
        let request = taken
            .and_then(|data| base64url::decode(&data))
            .and_then(|cbor| attest(&cbor, self.browser))
            .ok_or(ChannelError::Peer);
        std::future::ready(request)
    }
}

/// Rebuilds the `enrol_request` with the browser the host attested and the fixed platform, so a
/// page-controlled extension cannot choose the name the approval prompt shows.
fn attest(cbor: &[u8], browser: Browser) -> Option<Vec<u8>> {
    let mut reader = Reader::new(cbor);
    let device_id = reader
        .map(|r, n| {
            if n != 4 {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(0)?;
            if r.text()? != ENROL_REQUEST {
                return Err(hasp_proto::ProtoError::Format);
            }
            r.key(1)?;
            let device_id: DeviceId = r.value()?;
            r.key(2)?;
            r.text()?;
            r.key(3)?;
            r.text()?;
            Ok(device_id)
        })
        .ok()?;
    reader.finish().ok()?;
    let mut w = Writer::new();
    w.map(4).ok()?;
    w.key(0).ok()?;
    w.text(ENROL_REQUEST).ok()?;
    w.key(1).ok()?;
    device_id.encode(&mut w).ok()?;
    w.key(2).ok()?;
    w.text(EXTENSION_PLATFORM).ok()?;
    w.key(3).ok()?;
    w.text(browser.name()).ok()?;
    Some(w.into_bytes())
}
