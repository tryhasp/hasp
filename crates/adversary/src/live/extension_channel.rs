use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use hasp_core::CoreError;
use hasp_core::client::{Channel, ChannelError, Client, ClientState};
use hasp_crypto::SecretKey;
use hasp_nmh::desktop::{
    AdmitError, Denial, DesktopPolicy, ExtensionKeys, Paired, Release, Served, Session,
    UnlockRequest, admit,
};
use hasp_nmh::double::Double;
use hasp_nmh::framing::{MAX_FROM_BROWSER, MAX_TO_BROWSER, read_frame, write_frame};
use hasp_nmh::host::{HostError, HostIo, HostPolicy, run};
use hasp_nmh::identity;
use hasp_nmh::ipc::FramedLink;
use hasp_nmh::message::{DesktopMessage, ErrorCode, ExtensionMessage};
use hasp_nmh::origin::{ExtensionAllowlist, OriginError};
use hasp_nmh::peer::{BROWSERS, CodeTarget, PeerError, Requirement, Signing};
use hasp_proto::DeviceId;
use hasp_proto::base64url;
use hasp_proto::wire::OpId;
use hasp_testsupport::World;

use super::lab::{Phone, SharedStore, cancel, phone, run as drive};
use super::mallory::Mallory;

const TEAM: &str = "ABCDE12345";
const HOST_PATH: &str = "/Applications/Hasp.app/Contents/MacOS/hasp-nmh";
const BROWSER: CodeTarget = CodeTarget::Pid(4242);
const APP: CodeTarget = CodeTarget::AuditToken([1; 32]);
const HOST: CodeTarget = CodeTarget::AuditToken([2; 32]);
const VALID_FOR: u64 = 600;

struct Port {
    stream: Mutex<UnixStream>,
    ids: AtomicU64,
}

impl Port {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
            ids: AtomicU64::new(1),
        }
    }
}

impl Channel for Port {
    fn send(&self, message: Vec<u8>) -> impl Future<Output = Result<(), ChannelError>> + Send {
        let request = ExtensionMessage::EnrolRequest {
            id: self.ids.fetch_add(1, Ordering::Relaxed),
            data: base64url::encode(&message),
        };
        let sent = self
            .stream
            .lock()
            .map_err(|_| ChannelError::Closed)
            .and_then(|mut s| {
                write_frame(&mut *s, &request.encode().unwrap(), MAX_FROM_BROWSER)
                    .map_err(|_| ChannelError::Closed)
            });
        std::future::ready(sent)
    }

    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, ChannelError>> + Send {
        let reply = self
            .stream
            .lock()
            .map_err(|_| ChannelError::Closed)
            .and_then(|mut s| {
                read_frame(&mut *s, MAX_TO_BROWSER)
                    .map_err(|_| ChannelError::Closed)?
                    .ok_or(ChannelError::Closed)
            })
            .and_then(|frame| match DesktopMessage::decode(&frame) {
                Ok(DesktopMessage::EnrolReply { data, .. }) => {
                    base64url::decode(data.expose()).ok_or(ChannelError::Closed)
                }
                _ => Err(ChannelError::Peer),
            });
        std::future::ready(reply)
    }
}

#[derive(Default)]
struct Keys {
    approve: AtomicBool,
    store: Mutex<BTreeMap<[u8; 16], [u8; 32]>>,
    revoked: Mutex<BTreeSet<[u8; 16]>>,
}

impl Keys {
    fn approving() -> Self {
        let keys = Self::default();
        keys.approve.store(true, Ordering::Relaxed);
        keys
    }

    fn revoke(&self, device: &DeviceId) {
        self.store.lock().unwrap().remove(device.as_bytes());
        self.revoked.lock().unwrap().insert(*device.as_bytes());
    }
}

impl ExtensionKeys for Keys {
    fn release(&self, request: &UnlockRequest) -> Result<Release, Denial> {
        let device = request.device_id.as_bytes();
        if self
            .revoked
            .lock()
            .map_err(|_| Denial::Unknown)?
            .contains(device)
        {
            return Err(Denial::Revoked);
        }
        if !self.approve.load(Ordering::Relaxed) {
            return Err(Denial::Declined);
        }
        let store = self.store.lock().map_err(|_| Denial::Unknown)?;
        let key = store.get(device).ok_or(Denial::Unknown)?;
        Ok(Release {
            k_ext: SecretKey::from_bytes(*key),
            valid_until: VALID_FOR,
        })
    }

    fn remember(&self, paired: Paired) {
        self.store
            .lock()
            .unwrap()
            .insert(*paired.device_id.as_bytes(), *paired.k_ext.expose());
    }
}

fn allowlist() -> ExtensionAllowlist {
    ExtensionAllowlist::new(&[identity::CHROMIUM_DEV_ID], &[])
}

fn requirement(id: &str) -> Requirement {
    Requirement::signed_by(&[id], TEAM, Signing::DeveloperId).unwrap()
}

fn chrome_args(id: &str) -> Vec<String> {
    vec!["hasp-nmh".to_owned(), format!("chrome-extension://{id}/")]
}

struct Rig {
    desktop: Phone,
    extension: Client<Mallory, SharedStore>,
    mallory: Mallory,
    port: UnixStream,
    app_side: UnixStream,
    host: JoinHandle<Result<(), HostError>>,
}

struct Scene<'a> {
    extension_id: &'a str,
    browser_signed: bool,
}

fn rig(world: &mut World, scene: &Scene<'_>) -> Rig {
    let mallory = Mallory::new(&world.server);
    let desktop = drive(phone(world, &mallory, "alice@example.com", true));
    let (extension, _) = world.client_on(mallory.clone(), SharedStore::default(), false);
    let (browser_host, port) = UnixStream::pair().unwrap();
    let (app_host, app_side) = UnixStream::pair().unwrap();
    let verifier = Double::new(BROWSER, APP);
    if scene.browser_signed {
        verifier.sign(
            &BROWSER,
            BROWSERS[0].requirement().unwrap(),
            "/Applications/Google Chrome.app",
        );
    }
    verifier.sign(
        &APP,
        requirement(identity::APP_IDENTIFIER),
        "/Applications/Hasp.app",
    );
    let args = chrome_args(scene.extension_id);
    let reader = browser_host.try_clone().unwrap();
    let host = thread::spawn(move || {
        let allow = allowlist();
        let policy = HostPolicy {
            allowlist: &allow,
            app: requirement(identity::APP_IDENTIFIER),
        };
        run(
            &verifier,
            &policy,
            &args,
            HostIo {
                connect: move || Ok(app_host),
                browser_in: reader,
                browser_out: browser_host,
            },
        )
    });
    Rig {
        desktop,
        extension,
        mallory,
        port,
        app_side,
        host,
    }
}

fn process_exits(rig: &Rig) {
    rig.app_side.shutdown(std::net::Shutdown::Both).unwrap();
    rig.port.shutdown(std::net::Shutdown::Both).unwrap();
}

fn desktop_policy() -> DesktopPolicy {
    DesktopPolicy {
        host: requirement(identity::HOST_IDENTIFIER),
        host_path: PathBuf::from(HOST_PATH),
        allowlist: allowlist(),
    }
}

fn host_double(path: &str) -> Double {
    let double = Double::new(CodeTarget::Pid(1), HOST);
    double.sign(&HOST, requirement(identity::HOST_IDENTIFIER), path);
    double
}

fn nothing_was_approved(mallory: &Mallory, desktop: &mut Phone) {
    assert!(mallory.seen_op(OpId::EnrolApprove).is_empty());
    let devices = drive(desktop.client.devices(&cancel())).unwrap();
    assert_eq!(devices.len(), 1);
}

fn pair_over_the_port(
    extension: &mut Client<Mallory, SharedStore>,
    port: &UnixStream,
) -> Result<SecretKey, CoreError> {
    let port = Port::new(
        port.try_clone()
            .map_err(|_| CoreError::Refused("channel"))?,
    );
    drive(extension.pair_with_desktop(&port, "chrome", &cancel()))
}

fn unlock_message(id: u64, device: &DeviceId) -> ExtensionMessage {
    ExtensionMessage::Unlock {
        id,
        device_id: base64url::encode(device.as_bytes()),
        nonce: base64url::encode(&[9; 16]),
    }
}

fn ask(port: &mut UnixStream, message: &ExtensionMessage) -> DesktopMessage {
    write_frame(port, &message.encode().unwrap(), MAX_FROM_BROWSER).unwrap();
    let frame = read_frame(port, MAX_TO_BROWSER).unwrap().unwrap();
    DesktopMessage::decode(&frame).unwrap()
}

fn serve_once(session: &mut Session<FramedLink>, desktop: &mut Phone, keys: &Keys) -> Served {
    drive(session.serve_one(&mut desktop.client, keys, &cancel())).unwrap()
}

#[test]
fn e33_an_unknown_extension_id_never_reaches_the_app_and_mints_no_session() {
    let mut world = World::new();
    let mut rig = rig(
        &mut world,
        &Scene {
            extension_id: &"a".repeat(32),
            browser_signed: true,
        },
    );
    let admitted = admit(
        &host_double(HOST_PATH),
        &desktop_policy(),
        rig.app_side.try_clone().unwrap(),
    );
    assert!(
        matches!(admitted, Err(AdmitError::Hello(_))),
        "{admitted:?}"
    );
    let paired = pair_over_the_port(&mut rig.extension, &rig.port);
    assert!(paired.is_err());
    assert!(matches!(
        rig.host.join().unwrap(),
        Err(HostError::Origin(OriginError::Unknown))
    ));
    nothing_was_approved(&rig.mallory, &mut rig.desktop);
}

#[test]
fn e33_a_spoofed_browser_parent_is_refused_and_mints_no_session() {
    let mut world = World::new();
    let mut rig = rig(
        &mut world,
        &Scene {
            extension_id: identity::CHROMIUM_DEV_ID,
            browser_signed: false,
        },
    );
    assert!(pair_over_the_port(&mut rig.extension, &rig.port).is_err());
    let host = rig.host.join().unwrap();
    assert!(
        matches!(host, Err(HostError::Parent(PeerError::Mismatch))),
        "{host:?}"
    );
    nothing_was_approved(&rig.mallory, &mut rig.desktop);
}

#[test]
fn e33_a_same_user_binary_posing_as_the_host_is_refused_by_the_app() {
    let mut world = World::new();
    let mut rig = rig(
        &mut world,
        &Scene {
            extension_id: identity::CHROMIUM_DEV_ID,
            browser_signed: true,
        },
    );
    let admitted = admit(
        &host_double("/tmp/evil/hasp-nmh"),
        &desktop_policy(),
        rig.app_side.try_clone().unwrap(),
    );
    assert!(
        matches!(admitted, Err(AdmitError::NotOurHost)),
        "{admitted:?}"
    );
    process_exits(&rig);
    assert!(pair_over_the_port(&mut rig.extension, &rig.port).is_err());
    nothing_was_approved(&rig.mallory, &mut rig.desktop);
}

#[cfg(target_os = "macos")]
#[test]
fn e33_the_operating_system_check_refuses_an_unsigned_binary_as_the_host() {
    let mut world = World::new();
    let mut rig = rig(
        &mut world,
        &Scene {
            extension_id: identity::CHROMIUM_DEV_ID,
            browser_signed: true,
        },
    );
    let admitted = admit(
        &hasp_nmh::macos::SystemVerifier,
        &desktop_policy(),
        rig.app_side.try_clone().unwrap(),
    );
    assert!(
        matches!(
            admitted,
            Err(AdmitError::Peer(PeerError::Mismatch | PeerError::Check(_)))
        ),
        "{admitted:?}"
    );
    process_exits(&rig);
    assert!(pair_over_the_port(&mut rig.extension, &rig.port).is_err());
    nothing_was_approved(&rig.mallory, &mut rig.desktop);
}

#[test]
fn e33_path_c_then_unlock_then_a_replayed_unlock_after_revoke_releases_nothing() {
    let mut world = World::new();
    let mut rig = rig(
        &mut world,
        &Scene {
            extension_id: identity::CHROMIUM_DEV_ID,
            browser_signed: true,
        },
    );
    let keys = Keys::approving();
    let mut session = admit(
        &host_double(HOST_PATH),
        &desktop_policy(),
        rig.app_side.try_clone().unwrap(),
    )
    .unwrap();

    let (served, k_ext) = thread::scope(|scope| {
        let served = scope.spawn(|| serve_once(&mut session, &mut rig.desktop, &keys));
        let k_ext = pair_over_the_port(&mut rig.extension, &rig.port).unwrap();
        (served.join().unwrap(), k_ext)
    });
    let Served::Paired(device) = served else {
        panic!("{served:?}");
    };
    let listed = drive(rig.desktop.client.devices(&cancel())).unwrap();
    let entry = listed.iter().find(|d| !d.current).unwrap();
    assert_eq!(entry.device_id, device);
    assert_eq!(entry.platform, "extension");

    rig.extension.lock();
    keys.approve.store(false, Ordering::Relaxed);
    let declined = thread::scope(|scope| {
        let served = scope.spawn(|| serve_once(&mut session, &mut rig.desktop, &keys));
        let reply = ask(&mut rig.port, &unlock_message(10, &device));
        assert_eq!(served.join().unwrap(), Served::Refused(ErrorCode::Declined));
        reply
    });
    assert_eq!(
        declined,
        DesktopMessage::Error {
            id: Some(10),
            code: ErrorCode::Declined
        }
    );
    assert!(!rig.extension.is_unlocked());

    keys.approve.store(true, Ordering::Relaxed);
    let released = thread::scope(|scope| {
        let served = scope.spawn(|| serve_once(&mut session, &mut rig.desktop, &keys));
        let reply = ask(&mut rig.port, &unlock_message(11, &device));
        assert_eq!(served.join().unwrap(), Served::Unlocked);
        reply
    });
    let DesktopMessage::UnlockReply {
        id,
        k_ext: released,
        valid_until,
    } = released
    else {
        panic!("{released:?}");
    };
    assert_eq!((id, valid_until), (11, VALID_FOR));
    assert_eq!(
        base64url::decode(released.expose()).unwrap(),
        k_ext.expose()
    );
    drive(rig.extension.unlock_extension(&k_ext, &cancel())).unwrap();
    assert!(rig.extension.is_unlocked());
    rig.extension.lock();

    let victim = listed.iter().find(|d| !d.current).unwrap();
    drive(
        rig.desktop
            .client
            .revoke_device(&victim.session_id, &victim.device_id, &cancel()),
    )
    .unwrap();
    keys.revoke(&device);
    let replayed = thread::scope(|scope| {
        let served = scope.spawn(|| serve_once(&mut session, &mut rig.desktop, &keys));
        let reply = ask(&mut rig.port, &unlock_message(12, &device));
        assert_eq!(served.join().unwrap(), Served::Refused(ErrorCode::Revoked));
        reply
    });
    assert_eq!(
        replayed,
        DesktopMessage::Error {
            id: Some(12),
            code: ErrorCode::Revoked
        }
    );
    let error = drive(rig.extension.unlock_extension(&k_ext, &cancel())).unwrap_err();
    assert!(matches!(error, CoreError::DeviceRevoked), "{error:?}");
    assert_eq!(rig.extension.state().unwrap(), ClientState::Empty);
}

#[test]
fn e33_an_unlock_without_a_fresh_nonce_is_not_even_decoded() {
    let device = base64url::encode(&[7; 16]);
    let without = format!(r#"{{"type":"unlock","id":3,"device_id":"{device}"}}"#);
    assert!(ExtensionMessage::decode(without.as_bytes()).is_err());
    let short = format!(r#"{{"type":"unlock","id":3,"device_id":"{device}","nonce":"AAAA"}}"#);
    assert!(ExtensionMessage::decode(short.as_bytes()).is_err());
}

#[test]
fn e33_a_foreign_process_cannot_show_the_extensions_window_code() {
    let device = DeviceId::from_bytes([7; 16]);
    let extension_nonce = [0x11; 16];
    let attacker_nonce = [0x22; 16];
    let shown_by_extension = hasp_core::client::unlock_code(&device, &extension_nonce);
    let shown_by_desktop_for_attacker = hasp_core::client::unlock_code(&device, &attacker_nonce);
    assert_ne!(
        shown_by_extension, shown_by_desktop_for_attacker,
        "the Touch ID prompt of an attacker's unlock does not match what the user sees in the extension"
    );
    assert_eq!(
        shown_by_extension,
        hasp_core::client::unlock_code(&device, &extension_nonce),
        "the same device and nonce always give the same code"
    );
}
