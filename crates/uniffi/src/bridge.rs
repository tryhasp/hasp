#![expect(
    clippy::needless_pass_by_value,
    reason = "UniFFI hands every argument over by value"
)]

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hasp_core::CoreError;
use hasp_nmh::desktop::{
    AdmitError, Denial, DesktopPolicy, ExtensionKeys, PageState, Paired, PushError, Pusher,
    Release, Request, Served, UnlockRequest, admit,
};
use hasp_nmh::identity;
use hasp_nmh::ipc::{AppListener, IpcError, group_container_dir, home_owner_uid};
use hasp_nmh::message::{Browser, ErrorCode, FillOutcome};
use hasp_nmh::origin::ExtensionAllowlist;
use hasp_nmh::peer::{PeerError, Requirement, Signing};
use tokio::runtime::Handle;

use crate::HaspError;
use crate::engine::{Client, Core};

const PUSH_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_CONNECTIONS: usize = 16;

#[derive(Clone, Debug, uniffi::Record)]
pub struct BridgeConfig {
    pub directory: String,
    pub helper_path: String,
    pub team_id: String,
    pub chromium_ids: Vec<String>,
    pub gecko_ids: Vec<String>,
    pub any_team_certificate: bool,
}

/// Why a connection was refused before a single message was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PeerCheck {
    OtherUser,
    NotSignedHost,
    WrongBinary,
    BadHello,
    OriginRefused,
    IoFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BrowserFillOutcome {
    Filled,
    NeedsConfirmation,
    NoMatchingPage,
    Locked,
    Unavailable,
}

#[uniffi::export(with_foreign)]
pub trait BridgeDelegate: Send + Sync {
    fn peer_refused(&self, check: PeerCheck);
    fn connected(&self, browser: String, origin: String);
    fn paired(&self, browser: String, origin: String, device: String);
    fn disconnected(&self, browser: String, origin: String);
}

#[cfg(target_os = "macos")]
const VERIFIER: hasp_nmh::macos::SystemVerifier = hasp_nmh::macos::SystemVerifier;

#[cfg(not(target_os = "macos"))]
const VERIFIER: unsupported::Verifier = unsupported::Verifier;

#[cfg(not(target_os = "macos"))]
mod unsupported {
    use std::os::unix::net::UnixStream;

    use hasp_nmh::peer::{CodeTarget, CodeVerifier, PeerError, Requirement, VerifiedCode};

    #[derive(Clone, Copy, Debug)]
    pub(super) struct Verifier;

    impl CodeVerifier for Verifier {
        fn peer_of(&self, _: &UnixStream) -> Result<CodeTarget, PeerError> {
            Err(PeerError::Unsupported)
        }

        fn parent(&self) -> Result<CodeTarget, PeerError> {
            Err(PeerError::Unsupported)
        }

        fn verify(&self, _: &CodeTarget, _: &Requirement) -> Result<VerifiedCode, PeerError> {
            Err(PeerError::Unsupported)
        }
    }
}

fn browser_of(name: &str) -> Option<Browser> {
    [
        Browser::Chrome,
        Browser::Edge,
        Browser::Brave,
        Browser::Firefox,
        Browser::Safari,
    ]
    .into_iter()
    .find(|browser| browser.name() == name)
}

fn peer_string(browser: Browser, origin: &str) -> String {
    format!("{}:{origin}", browser.name())
}

fn check_of(error: &AdmitError) -> PeerCheck {
    match error {
        AdmitError::Peer(PeerError::OtherUser) => PeerCheck::OtherUser,
        AdmitError::Peer(_) => PeerCheck::NotSignedHost,
        AdmitError::NotOurHost => PeerCheck::WrongBinary,
        AdmitError::Hello(_) => PeerCheck::BadHello,
        AdmitError::Origin(_) => PeerCheck::OriginRefused,
        AdmitError::Io(_) => PeerCheck::IoFailure,
    }
}

fn outcome_of(outcome: FillOutcome) -> BrowserFillOutcome {
    match outcome {
        FillOutcome::Filled => BrowserFillOutcome::Filled,
        FillOutcome::NeedsConfirmation => BrowserFillOutcome::NeedsConfirmation,
        FillOutcome::NoMatchingPage => BrowserFillOutcome::NoMatchingPage,
        FillOutcome::Locked => BrowserFillOutcome::Locked,
        FillOutcome::Unavailable => BrowserFillOutcome::Unavailable,
    }
}

fn refusal_code(error: &CoreError) -> ErrorCode {
    match error {
        CoreError::Platform(_) | CoreError::Cancelled => ErrorCode::Declined,
        CoreError::Locked => ErrorCode::Locked,
        CoreError::DeviceRevoked => ErrorCode::Revoked,
        _ => ErrorCode::Refused,
    }
}

struct Keys {
    engine: Arc<Core>,
    handle: Handle,
}

impl ExtensionKeys for Keys {
    fn release(&self, request: &UnlockRequest) -> Result<Release, Denial> {
        let device = hasp_crypto::to_hex(request.device_id.as_bytes());
        let peer = peer_string(request.browser, &request.origin);
        let nonce = hasp_proto::base64url::encode(&request.nonce);
        let released = self
            .handle
            .block_on(self.engine.release_extension_key(&device, &peer, &nonce))
            .map_err(|error| match error {
                CoreError::Platform(_) | CoreError::Cancelled => Denial::Declined,
                CoreError::NotFound(_) => Denial::Revoked,
                CoreError::Locked => Denial::Locked,
                _ => Denial::Unknown,
            })?;
        let k_ext = hasp_crypto::SecretKey::from_slice(released.key.as_bytes())
            .map_err(|_| Denial::Unknown)?;
        Ok(Release {
            k_ext,
            valid_until: released.valid_until,
        })
    }

    fn remember(&self, _: Paired) {}

    fn is_paired(&self, device: hasp_proto::DeviceId, browser: Browser, origin: &str) -> bool {
        let device = hasp_crypto::to_hex(device.as_bytes());
        self.handle.block_on(
            self.engine
                .extension_paired(&device, &peer_string(browser, origin)),
        )
    }
}

struct Connection {
    id: u64,
    pusher: Pusher,
    stream: UnixStream,
}

struct Shared {
    engine: Arc<Core>,
    handle: Handle,
    delegate: Arc<dyn BridgeDelegate>,
    policy: DesktopPolicy,
    keys: Keys,
    connections: Mutex<Vec<Connection>>,
    stopping: AtomicBool,
    next: AtomicU64,
}

/// The app side of the native-messaging bridge (protocol 7.2 C and 7.16): the one
/// implementation of the socket, the code-signature check of the helper, the extension id
/// allowlist, pairing, key release and the Quick Access fill channel. A same-user process that
/// is not the signed helper is closed before a byte is read.
#[derive(uniffi::Object)]
pub struct ExtensionBridge {
    shared: Arc<Shared>,
    directory: PathBuf,
    listening: Mutex<bool>,
}

impl std::fmt::Debug for ExtensionBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtensionBridge(..)")
    }
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `~/Library/Group Containers/<team>.kr.jmo.hasp` for this user.
#[uniffi::export]
pub fn bridge_group_container(team_id: String) -> Result<String, HaspError> {
    let home = std::env::home_dir().ok_or(HaspError::Internal)?;
    Ok(group_container_dir(&home, &team_id)
        .to_string_lossy()
        .into_owned())
}

#[uniffi::export]
impl ExtensionBridge {
    #[uniffi::constructor]
    pub fn new(
        client: Arc<Client>,
        config: BridgeConfig,
        delegate: Arc<dyn BridgeDelegate>,
    ) -> Result<Arc<Self>, HaspError> {
        let signing = if cfg!(debug_assertions) && config.any_team_certificate {
            Signing::AnyTeamCertificate
        } else {
            Signing::DeveloperId
        };
        let host = Requirement::signed_by(&[identity::HOST_IDENTIFIER], &config.team_id, signing)
            .map_err(|_| HaspError::Refused)?;
        let allowlist = if config.chromium_ids.is_empty() && config.gecko_ids.is_empty() {
            ExtensionAllowlist::published()
        } else {
            let chromium: Vec<&str> = config.chromium_ids.iter().map(String::as_str).collect();
            let gecko: Vec<&str> = config.gecko_ids.iter().map(String::as_str).collect();
            ExtensionAllowlist::new(&chromium, &gecko)
        };
        let handle = client.runtime.handle().clone();
        let engine = Arc::clone(&client.engine);
        let shared = Shared {
            keys: Keys {
                engine: Arc::clone(&engine),
                handle: handle.clone(),
            },
            engine,
            handle,
            delegate,
            policy: DesktopPolicy {
                host,
                host_path: PathBuf::from(config.helper_path),
                allowlist,
            },
            connections: Mutex::new(Vec::new()),
            stopping: AtomicBool::new(false),
            next: AtomicU64::new(1),
        };
        Ok(Arc::new(Self {
            shared: Arc::new(shared),
            directory: PathBuf::from(config.directory),
            listening: Mutex::new(false),
        }))
    }

    pub fn start(&self) -> Result<(), HaspError> {
        let mut listening = locked(&self.listening);
        if *listening {
            return Ok(());
        }
        let owner = home_owner_uid().ok_or(HaspError::Internal)?;
        let listener = AppListener::bind(&self.directory, owner).map_err(|error| match error {
            IpcError::InUse => HaspError::Conflict,
            IpcError::Directory(_) | IpcError::PathTooLong(_) => HaspError::Refused,
            IpcError::Io(_) => HaspError::Internal,
        })?;
        self.shared.stopping.store(false, Ordering::SeqCst);
        let shared = Arc::clone(&self.shared);
        std::thread::spawn(move || accept_loop(&shared, &listener));
        *listening = true;
        Ok(())
    }

    pub fn stop(&self) {
        let mut listening = locked(&self.listening);
        if !*listening {
            return;
        }
        *listening = false;
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Ok(path) = hasp_nmh::ipc::socket_path(&self.directory) {
            UnixStream::connect(path).ok();
        }
        for connection in locked(&self.shared.connections).drain(..) {
            connection.stream.shutdown(std::net::Shutdown::Both).ok();
        }
    }

    pub fn push_lock(&self) {
        for connection in locked(&self.shared.connections).iter() {
            connection.pusher.push_lock().ok();
        }
    }

    pub fn has_paired_extension(&self, browser: String) -> bool {
        let Some(browser) = browser_of(&browser) else {
            return false;
        };
        self.pusher_for(browser).is_some()
    }

    pub fn page_host(&self, browser: String) -> Result<Option<String>, HaspError> {
        Ok(self
            .focused_pusher(&browser)?
            .and_then(|(_, state)| state.host))
    }

    pub fn request_fill(
        &self,
        browser: String,
        vault: String,
        item: String,
    ) -> Result<BrowserFillOutcome, HaspError> {
        let Some((pusher, _)) = self.focused_pusher(&browser)? else {
            return Ok(BrowserFillOutcome::NoMatchingPage);
        };
        pusher
            .request_fill(&self.shared.keys, &vault, &item, PUSH_TIMEOUT)
            .map(outcome_of)
            .map_err(push_error)
    }
}

/// Of the replies of every paired connection of one browser, the single one whose window is the
/// one the user is looking at. Two profiles of the same browser answer a `page_query` at once; a
/// reply that is not focused, or a tie, never receives a fill.
fn only_focused<T>(replies: Vec<(T, PageState)>) -> Option<(T, PageState)> {
    let mut focused = replies.into_iter().filter(|(_, state)| state.focused);
    let first = focused.next()?;
    focused.next().is_none().then_some(first)
}

impl ExtensionBridge {
    fn pushers_for(&self, browser: Browser) -> Vec<Pusher> {
        locked(&self.shared.connections)
            .iter()
            .map(|connection| &connection.pusher)
            .filter(|pusher| pusher.browser() == browser && pusher.is_paired(&self.shared.keys))
            .cloned()
            .collect()
    }

    fn pusher_for(&self, browser: Browser) -> Option<Pusher> {
        self.pushers_for(browser).into_iter().next()
    }

    fn focused_pusher(&self, browser: &str) -> Result<Option<(Pusher, PageState)>, HaspError> {
        let browser = browser_of(browser).ok_or(HaspError::NotFound)?;
        let pushers = self.pushers_for(browser);
        if pushers.is_empty() {
            return Err(HaspError::NotFound);
        }
        let keys = &self.shared.keys;
        let replies: Vec<Result<(Pusher, PageState), PushError>> = std::thread::scope(|scope| {
            let asked: Vec<_> = pushers
                .into_iter()
                .map(|pusher| {
                    scope.spawn(move || {
                        pusher
                            .page_host(keys, PUSH_TIMEOUT)
                            .map(|state| (pusher, state))
                    })
                })
                .collect();
            asked
                .into_iter()
                .map(|handle| handle.join().unwrap_or(Err(PushError::Closed)))
                .collect()
        });
        let answered: Vec<(Pusher, PageState)> = replies
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .cloned()
            .collect();
        if answered.is_empty() {
            let error = replies.into_iter().find_map(Result::err);
            return error.map_or(Ok(None), |error| Err(push_error(error)));
        }
        Ok(only_focused(answered))
    }
}

fn push_error(error: PushError) -> HaspError {
    match error {
        PushError::NotPaired => HaspError::Authz,
        PushError::Timeout => HaspError::Pending,
        PushError::Closed => HaspError::Offline,
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &AppListener) {
    while let Ok(stream) = listener.accept() {
        if shared.stopping.load(Ordering::SeqCst) {
            break;
        }
        if locked(&shared.connections).len() >= MAX_CONNECTIONS {
            continue;
        }
        let shared = Arc::clone(shared);
        std::thread::spawn(move || serve(&shared, stream));
    }
}

fn serve(shared: &Arc<Shared>, stream: UnixStream) {
    let Ok(kept) = stream.try_clone() else {
        return;
    };
    let mut session = match admit(&VERIFIER, &shared.policy, stream) {
        Ok(session) => session,
        Err(error) => {
            shared.delegate.peer_refused(check_of(&error));
            return;
        }
    };
    let (browser, origin) = (session.browser(), session.origin().to_owned());
    let Some(pusher) = session.pusher() else {
        return;
    };
    let id = shared.next.fetch_add(1, Ordering::SeqCst);
    locked(&shared.connections).push(Connection {
        id,
        pusher,
        stream: kept,
    });
    shared
        .delegate
        .connected(browser.name().to_owned(), origin.clone());
    loop {
        match session.recv_request() {
            Ok(Some(Request::Replied)) => {}
            Ok(Some(Request::Enrol { id, data })) => {
                let paired = {
                    let channel = session.pairing_channel(id, data);
                    shared.handle.block_on(
                        shared
                            .engine
                            .serve_extension_pairing(&channel, &peer_string(browser, &origin)),
                    )
                };
                match paired {
                    Ok(device) => {
                        if let Some(raw) = hasp_crypto::from_hex(&device)
                            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                        {
                            session.mark_paired(hasp_proto::DeviceId::from_bytes(raw));
                        }
                        shared
                            .delegate
                            .paired(browser.name().to_owned(), origin.clone(), device);
                    }
                    Err(error) => {
                        if session.refuse(id, refusal_code(&error)).is_err() {
                            break;
                        }
                    }
                }
            }
            Ok(Some(Request::Unlock {
                id,
                device_id,
                nonce,
            })) => match session.serve_unlock(&shared.keys, id, device_id, nonce) {
                Ok(Served::Closed) | Err(_) => break,
                Ok(_) => {}
            },
            Ok(None) | Err(_) => break,
        }
    }
    locked(&shared.connections).retain(|connection| connection.id != id);
    shared
        .delegate
        .disconnected(browser.name().to_owned(), origin);
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[derive(Debug)]
    struct NoStore;

    impl crate::PlatformStore for NoStore {
        fn hardware_gated(&self) -> bool {
            false
        }

        fn put(&self, _: String, _: Vec<u8>) -> Result<(), HaspError> {
            Ok(())
        }

        fn get(&self, _: String) -> Result<Vec<u8>, HaspError> {
            Err(HaspError::NotFound)
        }

        fn delete(&self, _: String) -> Result<(), HaspError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct NoBiometric;

    impl crate::PlatformBiometric for NoBiometric {
        fn available(&self) -> bool {
            false
        }

        fn authenticate(&self, _: String) -> Result<(), HaspError> {
            Err(HaspError::Cancelled)
        }
    }

    #[derive(Debug)]
    struct Recorder(Mutex<mpsc::Sender<PeerCheck>>);

    impl BridgeDelegate for Recorder {
        fn peer_refused(&self, check: PeerCheck) {
            locked(&self.0).send(check).ok();
        }

        fn connected(&self, _: String, _: String) {}

        fn paired(&self, _: String, _: String, _: String) {}

        fn disconnected(&self, _: String, _: String) {}
    }

    #[test]
    fn maps_browser_names_and_formats_the_peer_string() {
        assert_eq!(browser_of("firefox"), Some(Browser::Firefox));
        assert_eq!(browser_of("Chrome"), None);
        assert_eq!(peer_string(Browser::Chrome, "abc"), "chrome:abc");
    }

    #[test]
    fn a_connection_from_a_process_that_is_not_the_signed_helper_is_refused_and_reported() {
        let work = std::env::temp_dir().join(format!("hb-{}", std::process::id()));
        std::fs::create_dir_all(&work).unwrap();
        let client = Client::open(
            work.join("store").to_string_lossy().into_owned(),
            "https://hasp.test".to_owned(),
            "macos".to_owned(),
            Arc::new(NoStore),
            Arc::new(NoBiometric),
        )
        .unwrap();
        let (sender, receiver) = mpsc::channel();
        let bridge = ExtensionBridge::new(
            client,
            BridgeConfig {
                directory: work.join("sock").to_string_lossy().into_owned(),
                helper_path: "/Applications/Hasp.app/Contents/Helpers/hasp-nmh".to_owned(),
                team_id: "ABCDE12345".to_owned(),
                chromium_ids: Vec::new(),
                gecko_ids: Vec::new(),
                any_team_certificate: false,
            },
            Arc::new(Recorder(Mutex::new(sender))),
        )
        .unwrap();
        bridge.start().unwrap();
        assert!(matches!(bridge.start(), Ok(())));
        let path = hasp_nmh::ipc::socket_path(&work.join("sock")).unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        let verdict = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(verdict, PeerCheck::NotSignedHost);
        assert!(!bridge.has_paired_extension("chrome".to_owned()));
        assert!(matches!(
            bridge.request_fill("chrome".to_owned(), "a".repeat(32), "b".repeat(32)),
            Err(HaspError::NotFound)
        ));
        std::io::Read::read(&mut stream, &mut [0_u8; 1]).ok();
        bridge.stop();
        let closed = (0..50).any(|_| {
            std::thread::park_timeout(Duration::from_millis(50));
            UnixStream::connect(&path).is_err()
        });
        assert!(closed, "the socket is gone after stop");
        std::fs::remove_dir_all(&work).ok();
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;

    fn reply(profile: &'static str, host: &str, focused: bool) -> (&'static str, PageState) {
        (
            profile,
            PageState {
                host: Some(host.to_owned()),
                focused,
            },
        )
    }

    #[test]
    fn two_profiles_answer_and_only_the_focused_window_receives_the_fill() {
        let picked = only_focused(vec![
            reply("work", "bank.example", false),
            reply("home", "shop.example", true),
        ])
        .unwrap();
        assert_eq!(picked.0, "home");
        assert_eq!(picked.1.host.as_deref(), Some("shop.example"));
    }

    #[test]
    fn no_focused_window_and_two_focused_windows_both_refuse_to_choose() {
        assert!(
            only_focused(vec![
                reply("work", "a.example", false),
                reply("home", "b.example", false)
            ])
            .is_none()
        );
        assert!(
            only_focused(vec![
                reply("work", "a.example", true),
                reply("home", "b.example", true)
            ])
            .is_none()
        );
    }
}
