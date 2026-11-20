use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::desktop::{AdmitError, DesktopPolicy, Link, admit};
use crate::double::Double;
use crate::framing::{MAX_FROM_BROWSER, read_frame, write_frame};
use crate::host::{HostError, HostIo, HostPolicy, run};
use crate::identity;
use crate::message::{Browser, DesktopMessage, ErrorCode, ExtensionMessage, SecretText};
use crate::origin::{ExtensionAllowlist, OriginError};
use crate::peer::{BROWSERS, CodeTarget, PeerError, Requirement, Signing};

const CHROME_ID: &str = "gchilemfcapcihefglfdhgihpcjcdogp";
const TEAM: &str = "ABCDE12345";
const HOST_PATH: &str = "/Applications/Hasp.app/Contents/MacOS/hasp-nmh";
const PARENT: CodeTarget = CodeTarget::Pid(100);

fn double(peer: CodeTarget) -> Double {
    Double::new(PARENT, peer)
}

fn app_requirement() -> Requirement {
    Requirement::signed_by(&[identity::APP_IDENTIFIER], TEAM, Signing::DeveloperId).unwrap()
}

fn host_requirement() -> Requirement {
    Requirement::signed_by(&[identity::HOST_IDENTIFIER], TEAM, Signing::DeveloperId).unwrap()
}

fn allowlist() -> ExtensionAllowlist {
    ExtensionAllowlist::new(&[CHROME_ID], &["hasp-dev@hasp.app"])
}

fn chrome_args(id: &str) -> Vec<String> {
    vec!["hasp-nmh".to_owned(), format!("chrome-extension://{id}/")]
}

fn trusted_double(app: &CodeTarget) -> Double {
    let double = double(app.clone());
    double.sign(
        &PARENT,
        BROWSERS[0].requirement().unwrap(),
        "/Applications/Google Chrome.app",
    );
    double.sign(app, app_requirement(), "/Applications/Hasp.app");
    double
}

struct Wire {
    ext: UnixStream,
    host: Option<thread::JoinHandle<Result<(), HostError>>>,
    app: UnixStream,
}

fn start_host(double: Double, args: Vec<String>) -> Wire {
    let (browser_host, ext) = UnixStream::pair().unwrap();
    let (app_host, app) = UnixStream::pair().unwrap();
    let reader = browser_host.try_clone().unwrap();
    let host = thread::spawn(move || {
        let allow = allowlist();
        let policy = HostPolicy {
            allowlist: &allow,
            app: app_requirement(),
        };
        run(
            &double,
            &policy,
            &args,
            HostIo {
                connect: move || Ok(app_host),
                browser_in: reader,
                browser_out: browser_host,
            },
        )
    });
    Wire {
        ext,
        host: Some(host),
        app,
    }
}

fn policy() -> DesktopPolicy {
    DesktopPolicy {
        host: host_requirement(),
        host_path: PathBuf::from(HOST_PATH),
        allowlist: allowlist(),
    }
}

fn send(stream: &mut UnixStream, message: &ExtensionMessage) {
    write_frame(stream, &message.encode().unwrap(), MAX_FROM_BROWSER).unwrap();
}

fn unlock(id: u64) -> ExtensionMessage {
    ExtensionMessage::Unlock {
        id,
        device_id: hasp_proto::base64url::encode(&[3; 16]),
        nonce: hasp_proto::base64url::encode(&[4; 16]),
    }
}

fn read_desktop(stream: &mut UnixStream) -> Option<DesktopMessage> {
    read_frame(stream, 1 << 20)
        .unwrap()
        .map(|f| DesktopMessage::decode(&f).unwrap())
}

#[test]
fn spoofed_origin_an_unknown_extension_id_is_refused_before_the_app_is_contacted() {
    let (mut browser_out, _peer) = UnixStream::pair().unwrap();
    let contacted = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&contacted);
    let allow = allowlist();
    let policy = HostPolicy {
        allowlist: &allow,
        app: app_requirement(),
    };
    let double = trusted_double(&CodeTarget::AuditToken([1; 32]));
    let result = run(
        &double,
        &policy,
        &chrome_args(&"a".repeat(32)),
        HostIo {
            connect: move || {
                *flag.lock().unwrap() = true;
                Err(std::io::Error::other("unreachable"))
            },
            browser_in: std::io::empty(),
            browser_out: browser_out.try_clone().unwrap(),
        },
    );
    assert!(matches!(
        result,
        Err(HostError::Origin(OriginError::Unknown))
    ));
    assert!(!*contacted.lock().unwrap());
    browser_out.set_nonblocking(true).unwrap();
    let mut byte = [0_u8; 1];
    assert!(browser_out.read(&mut byte).is_err());
}

#[test]
fn spoofed_origin_a_chromium_id_arriving_through_firefox_is_refused() {
    let double = double(CodeTarget::AuditToken([1; 32]));
    double.sign(
        &PARENT,
        BROWSERS[3].requirement().unwrap(),
        "/Applications/Firefox.app",
    );
    let wire = start_host(double, chrome_args(CHROME_ID));
    let result = wire.host.unwrap().join().unwrap();
    assert!(matches!(
        result,
        Err(HostError::Origin(OriginError::WrongBrowser))
    ));
}

#[test]
fn a_parent_that_is_not_a_signed_browser_is_refused() {
    let double = double(CodeTarget::AuditToken([1; 32]));
    let wire = start_host(double, chrome_args(CHROME_ID));
    let result = wire.host.unwrap().join().unwrap();
    assert!(matches!(
        result,
        Err(HostError::Parent(PeerError::Mismatch))
    ));
}

#[test]
fn a_parent_signed_with_a_browsers_name_but_another_team_is_refused() {
    let double = double(CodeTarget::AuditToken([1; 32]));
    let forged =
        Requirement::signed_by(&["com.google.Chrome"], TEAM, Signing::DeveloperId).unwrap();
    double.sign(&PARENT, forged, "/tmp/Chrome");
    let wire = start_host(double, chrome_args(CHROME_ID));
    assert!(matches!(
        wire.host.unwrap().join().unwrap(),
        Err(HostError::Parent(PeerError::Mismatch))
    ));
}

#[test]
fn a_socket_that_is_not_the_signed_app_gets_nothing_and_the_browser_is_told_unavailable() {
    let double = double(CodeTarget::AuditToken([9; 32]));
    double.sign(
        &PARENT,
        BROWSERS[0].requirement().unwrap(),
        "/Applications/Google Chrome.app",
    );
    let mut wire = start_host(double, chrome_args(CHROME_ID));
    let told = read_desktop(&mut wire.ext).unwrap();
    assert_eq!(
        told,
        DesktopMessage::Error {
            id: None,
            code: ErrorCode::Unavailable
        }
    );
    assert!(matches!(
        wire.host.take().unwrap().join().unwrap(),
        Err(HostError::App(PeerError::Mismatch))
    ));
    wire.app.set_nonblocking(true).unwrap();
    let mut byte = [0_u8; 1];
    let read = wire.app.read(&mut byte);
    assert!(matches!(read, Ok(0)) || read.is_err());
}

#[test]
fn an_unreachable_app_is_reported_as_unavailable() {
    let double = double(CodeTarget::AuditToken([1; 32]));
    double.sign(
        &PARENT,
        BROWSERS[0].requirement().unwrap(),
        "/Applications/Google Chrome.app",
    );
    let (browser_host, mut ext) = UnixStream::pair().unwrap();
    let reader = browser_host.try_clone().unwrap();
    let allow = allowlist();
    let policy = HostPolicy {
        allowlist: &allow,
        app: app_requirement(),
    };
    let result = run(
        &double,
        &policy,
        &chrome_args(CHROME_ID),
        HostIo {
            connect: || Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            browser_in: reader,
            browser_out: browser_host,
        },
    );
    assert!(matches!(result, Err(HostError::Unavailable)));
    assert_eq!(
        read_desktop(&mut ext),
        Some(DesktopMessage::Error {
            id: None,
            code: ErrorCode::Unavailable
        })
    );
}

#[test]
fn relays_unlock_to_the_app_and_the_reply_back_and_nothing_else() {
    let app_token = CodeTarget::AuditToken([1; 32]);
    let mut wire = start_host(trusted_double(&app_token), chrome_args(CHROME_ID));
    let desk = double(CodeTarget::AuditToken([7; 32]));
    desk.sign(
        &CodeTarget::AuditToken([7; 32]),
        host_requirement(),
        HOST_PATH,
    );
    let mut session = admit(&desk, &policy(), wire.app.try_clone().unwrap()).unwrap();
    assert_eq!(session.browser(), Browser::Chrome);
    assert_eq!(session.origin(), CHROME_ID);

    send(&mut wire.ext, &unlock(5));
    let mut link = crate::ipc::FramedLink::new(wire.app.try_clone().unwrap());
    let received = link.recv().unwrap().unwrap();
    assert_eq!(received, unlock(5));
    let reply = DesktopMessage::UnlockReply {
        id: 5,
        k_ext: SecretText::new(hasp_proto::base64url::encode(&[8; 32])),
        valid_until: 600,
    };
    link.send(&reply).unwrap();
    assert_eq!(read_desktop(&mut wire.ext), Some(reply));
    session.push_lock().unwrap();
    assert_eq!(read_desktop(&mut wire.ext), Some(DesktopMessage::Lock));

    write_frame(
        &mut wire.ext,
        br#"{"type":"get_secret","id":6}"#,
        MAX_FROM_BROWSER,
    )
    .unwrap();
    assert_eq!(
        read_desktop(&mut wire.ext),
        Some(DesktopMessage::Error {
            id: None,
            code: ErrorCode::Malformed
        })
    );
    wire.app.set_nonblocking(true).unwrap();
    let mut buf = [0_u8; 1];
    let outcome = wire.app.read(&mut buf);
    assert!(matches!(outcome, Ok(0)) || outcome.is_err());
}

#[test]
fn an_oversized_frame_from_the_browser_ends_the_host_and_reaches_nobody() {
    let mut wire = start_host(
        trusted_double(&CodeTarget::AuditToken([1; 32])),
        chrome_args(CHROME_ID),
    );
    let desk = double(CodeTarget::AuditToken([7; 32]));
    desk.sign(
        &CodeTarget::AuditToken([7; 32]),
        host_requirement(),
        HOST_PATH,
    );
    admit(&desk, &policy(), wire.app.try_clone().unwrap()).unwrap();
    let length = u32::try_from(MAX_FROM_BROWSER + 1).unwrap();
    wire.ext.write_all(&length.to_ne_bytes()).unwrap();
    wire.ext.write_all(&[b'x'; 64]).unwrap();
    assert!(wire.host.take().unwrap().join().unwrap().is_ok());
    let mut link = crate::ipc::FramedLink::new(wire.app.try_clone().unwrap());
    assert!(link.recv().unwrap().is_none());
}

#[test]
fn spoofed_host_a_foreign_binary_is_refused_by_the_app_even_with_a_valid_team() {
    let (_client, server) = UnixStream::pair().unwrap();
    let foreign = double(CodeTarget::AuditToken([7; 32]));
    foreign.sign(
        &CodeTarget::AuditToken([7; 32]),
        host_requirement(),
        "/tmp/evil/hasp-nmh",
    );
    assert!(matches!(
        admit(&foreign, &policy(), server),
        Err(AdmitError::NotOurHost)
    ));
}

#[test]
fn spoofed_host_an_unsigned_peer_is_refused_before_anything_is_read() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let hello = crate::message::Hello::new(Browser::Chrome, CHROME_ID)
        .encode()
        .unwrap();
    write_frame(&mut client, &hello, 4096).unwrap();
    let unsigned = double(CodeTarget::AuditToken([7; 32]));
    assert!(matches!(
        admit(&unsigned, &policy(), server),
        Err(AdmitError::Peer(PeerError::Mismatch))
    ));
}

#[test]
fn the_app_refuses_an_origin_the_host_attests_that_is_not_allowed() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let hello = crate::message::Hello::new(Browser::Chrome, &"b".repeat(32))
        .encode()
        .unwrap();
    write_frame(&mut client, &hello, 4096).unwrap();
    let host = double(CodeTarget::AuditToken([7; 32]));
    host.sign(
        &CodeTarget::AuditToken([7; 32]),
        host_requirement(),
        HOST_PATH,
    );
    assert!(matches!(
        admit(&host, &policy(), server),
        Err(AdmitError::Origin(OriginError::Unknown))
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn spoofed_host_the_real_check_refuses_this_unsigned_test_binary_as_the_host() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let hello = crate::message::Hello::new(Browser::Chrome, CHROME_ID)
        .encode()
        .unwrap();
    write_frame(&mut client, &hello, 4096).unwrap();
    let result = admit(&crate::macos::SystemVerifier, &policy(), server);
    assert!(
        matches!(
            result,
            Err(AdmitError::Peer(PeerError::Mismatch | PeerError::Check(_)))
        ),
        "{result:?}"
    );
}

struct Roster {
    paired: std::sync::atomic::AtomicBool,
}

impl crate::desktop::ExtensionKeys for Roster {
    fn release(
        &self,
        _: &crate::desktop::UnlockRequest,
    ) -> Result<crate::desktop::Release, crate::desktop::Denial> {
        Err(crate::desktop::Denial::Unknown)
    }

    fn remember(&self, _: crate::desktop::Paired) {}

    fn is_paired(&self, device: hasp_proto::DeviceId, browser: Browser, origin: &str) -> bool {
        self.paired.load(std::sync::atomic::Ordering::SeqCst)
            && device == hasp_proto::DeviceId::from_bytes([3; 16])
            && browser == Browser::Chrome
            && origin == CHROME_ID
    }
}

fn admitted_wire() -> (Wire, crate::desktop::Session<crate::ipc::FramedLink>) {
    let app_token = CodeTarget::AuditToken([1; 32]);
    let wire = start_host(trusted_double(&app_token), chrome_args(CHROME_ID));
    let desk = double(CodeTarget::AuditToken([7; 32]));
    desk.sign(
        &CodeTarget::AuditToken([7; 32]),
        host_requirement(),
        HOST_PATH,
    );
    let session = admit(&desk, &policy(), wire.app.try_clone().unwrap()).unwrap();
    (wire, session)
}

fn unlock_session(wire: &mut Wire, session: &mut crate::desktop::Session<crate::ipc::FramedLink>) {
    send(&mut wire.ext, &unlock(5));
    let Some(crate::desktop::Request::Unlock { id, device_id, .. }) =
        session.recv_request().unwrap()
    else {
        panic!("expected an unlock request");
    };
    let release = crate::desktop::Release {
        k_ext: hasp_crypto::SecretKey::from_bytes([8; 32]),
        valid_until: 600,
    };
    session.answer_unlock(id, device_id, Ok(release)).unwrap();
    assert!(matches!(
        read_desktop(&mut wire.ext),
        Some(DesktopMessage::UnlockReply { id: 5, .. })
    ));
}

#[test]
fn a_fill_request_goes_only_to_the_paired_extension_connection_and_its_reply_comes_back() {
    let (mut wire, mut session) = admitted_wire();
    let pusher = session.pusher().unwrap();
    let keys = Arc::new(Roster {
        paired: std::sync::atomic::AtomicBool::new(true),
    });
    let vault = "00112233445566778899aabbccddeeff";
    let item = "ffeeddccbbaa99887766554433221100";
    let wait = std::time::Duration::from_secs(5);

    assert_eq!(
        pusher.request_fill(&*keys, vault, item, wait),
        Err(crate::desktop::PushError::NotPaired),
        "a connection that never paired or unlocked is not pushed to"
    );
    assert_eq!(
        pusher.page_host(&*keys, wait),
        Err(crate::desktop::PushError::NotPaired)
    );
    unlock_session(&mut wire, &mut session);

    let reader = thread::spawn(move || while let Ok(Some(_)) = session.recv_request() {});
    let ask = {
        let (pusher, keys) = (pusher.clone(), Arc::clone(&keys));
        thread::spawn(move || pusher.request_fill(&*keys, vault, item, wait))
    };
    let Some(DesktopMessage::FillRequest {
        id,
        vault: got_vault,
        item: got_item,
    }) = read_desktop(&mut wire.ext)
    else {
        panic!("expected a fill request");
    };
    assert_eq!((got_vault.as_str(), got_item.as_str()), (vault, item));
    send(
        &mut wire.ext,
        &ExtensionMessage::FillReply {
            id,
            outcome: crate::message::FillOutcome::NeedsConfirmation,
        },
    );
    assert_eq!(
        ask.join().unwrap(),
        Ok(crate::message::FillOutcome::NeedsConfirmation)
    );

    let page = {
        let (pusher, keys) = (pusher.clone(), Arc::clone(&keys));
        thread::spawn(move || pusher.page_host(&*keys, wait))
    };
    let Some(DesktopMessage::PageQuery { id }) = read_desktop(&mut wire.ext) else {
        panic!("expected a page query");
    };
    send(
        &mut wire.ext,
        &ExtensionMessage::PageReply {
            id,
            host: Some("accounts.example.com".to_owned()),
            focused: true,
        },
    );
    assert_eq!(
        page.join().unwrap(),
        Ok(crate::desktop::PageState {
            host: Some("accounts.example.com".to_owned()),
            focused: true
        })
    );

    keys.paired
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        pusher.request_fill(&*keys, vault, item, wait),
        Err(crate::desktop::PushError::NotPaired),
        "an unpaired extension is refused on a connection that is still open"
    );
    drop(wire);
    reader.join().unwrap();
}

#[test]
fn an_unsolicited_reply_ends_the_link_and_an_unanswered_request_times_out() {
    let (mut wire, mut session) = admitted_wire();
    unlock_session(&mut wire, &mut session);
    let pusher = session.pusher().unwrap();
    let keys = Roster {
        paired: std::sync::atomic::AtomicBool::new(true),
    };
    assert_eq!(
        pusher.request_fill(
            &keys,
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
            std::time::Duration::from_millis(100)
        ),
        Err(crate::desktop::PushError::Timeout)
    );
    assert!(matches!(
        read_desktop(&mut wire.ext),
        Some(DesktopMessage::FillRequest { .. })
    ));
    send(
        &mut wire.ext,
        &ExtensionMessage::FillReply {
            id: 1,
            outcome: crate::message::FillOutcome::Filled,
        },
    );
    assert!(matches!(
        session.recv_request(),
        Err(crate::desktop::LinkError::Malformed)
    ));
}
