use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use crate::framing::{
    FrameError, MAX_FROM_BROWSER, MAX_HELLO, MAX_TO_BROWSER, read_frame, write_frame,
};
use crate::message::{DesktopMessage, ErrorCode, ExtensionMessage, Hello};
use crate::origin::{ExtensionAllowlist, ExtensionOrigin, OriginError};
use crate::peer::{CodeVerifier, PeerError, Requirement, identify_browser};

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("caller origin: {0}")]
    Origin(#[from] OriginError),
    #[error("the parent process is not an allowed browser: {0}")]
    Parent(PeerError),
    #[error("the parent process changed during startup")]
    ParentChanged,
    #[error("the desktop app is not reachable")]
    Unavailable,
    #[error("the socket peer is not the Hasp app: {0}")]
    App(PeerError),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
}

#[derive(Debug)]
pub struct HostIo<R, W, C> {
    pub connect: C,
    pub browser_in: R,
    pub browser_out: W,
}

#[derive(Debug)]
pub struct HostPolicy<'a> {
    pub allowlist: &'a ExtensionAllowlist,
    pub app: Requirement,
}

/// Runs the native-messaging host. Verification order, each step before anything is read from
/// the browser or sent to the app: the extension id in `args` against the allowlist, the parent
/// process as an allowed browser (and the id matching that browser's family), then the app
/// socket peer against the app's signing identity. Only the closed message set is relayed, and
/// each frame is re-encoded from its parsed form so nothing else rides along.
pub fn run<V, R, W, C>(
    verifier: &V,
    policy: &HostPolicy<'_>,
    args: &[String],
    io: HostIo<R, W, C>,
) -> Result<(), HostError>
where
    V: CodeVerifier,
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    C: FnOnce() -> io::Result<UnixStream>,
{
    let HostIo {
        connect,
        browser_in,
        browser_out,
    } = io;
    let origin = ExtensionOrigin::from_args(args)?;
    let parent = verifier.parent().map_err(HostError::Parent)?;
    let browser = identify_browser(verifier, &parent).map_err(HostError::Parent)?;
    policy.allowlist.admit(&origin, browser)?;

    let out = Arc::new(Mutex::new(browser_out));
    let Ok(mut stream) = connect() else {
        return Err(unavailable(&out));
    };
    let app_check = verifier
        .peer_of(&stream)
        .and_then(|target| verifier.verify(&target, &policy.app))
        .map(|_| ());
    if let Err(error) = app_check {
        unavailable(&out);
        return Err(HostError::App(error));
    }
    if verifier.parent().map_err(HostError::Parent)? != parent {
        return Err(HostError::ParentChanged);
    }

    let hello = Hello::new(browser, origin.id())
        .encode()
        .map_err(|_| HostError::Unavailable)?;
    if write_frame(&mut stream, &hello, MAX_HELLO).is_err() {
        return Err(unavailable(&out));
    }

    let to_app = stream.try_clone().map_err(|_| HostError::Unavailable)?;
    let errors = Arc::clone(&out);
    std::thread::spawn(move || relay_to_app(browser_in, to_app, &errors));
    relay_to_browser(stream, &out)
}

fn unavailable<W: Write>(out: &Arc<Mutex<W>>) -> HostError {
    reply_error(out, None, ErrorCode::Unavailable);
    HostError::Unavailable
}

fn reply_error<W: Write>(out: &Arc<Mutex<W>>, id: Option<u64>, code: ErrorCode) {
    let Ok(frame) = (DesktopMessage::Error { id, code }).encode() else {
        return;
    };
    if let Ok(mut writer) = out.lock() {
        write_frame(&mut *writer, &frame, MAX_TO_BROWSER).ok();
    }
}

fn relay_to_app<R: Read, W: Write>(mut browser: R, mut app: UnixStream, out: &Arc<Mutex<W>>) {
    while let Ok(Some(frame)) = read_frame(&mut browser, MAX_FROM_BROWSER) {
        let Ok(message) = ExtensionMessage::decode(&frame) else {
            reply_error(out, None, ErrorCode::Malformed);
            break;
        };
        let Ok(forward) = message.encode() else {
            break;
        };
        if write_frame(&mut app, &forward, MAX_FROM_BROWSER).is_err() {
            reply_error(out, Some(message.id()), ErrorCode::Unavailable);
            break;
        }
    }
    app.shutdown(Shutdown::Both).ok();
}

fn relay_to_browser<W: Write>(mut app: UnixStream, out: &Arc<Mutex<W>>) -> Result<(), HostError> {
    loop {
        let Some(frame) = read_frame(&mut app, MAX_TO_BROWSER)? else {
            return Ok(());
        };
        let Ok(message) = DesktopMessage::decode(&frame) else {
            reply_error(out, None, ErrorCode::Malformed);
            return Ok(());
        };
        let Ok(forward) = message.encode() else {
            return Ok(());
        };
        let Ok(mut writer) = out.lock() else {
            return Ok(());
        };
        write_frame(&mut *writer, &forward, MAX_TO_BROWSER)?;
    }
}
