use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::desktop::{Link, LinkError, LinkWriter};
use crate::framing::{FrameError, MAX_FROM_BROWSER, MAX_TO_BROWSER, read_frame, write_frame};
use crate::identity;
use crate::message::{DesktopMessage, ExtensionMessage};

const SUN_PATH_MAX: usize = 103;
pub const ADMIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("socket path of {0} bytes does not fit sun_path")]
    PathTooLong(usize),
    #[error("{} is not a private directory owned by this user", .0.display())]
    Directory(PathBuf),
    #[error("another app instance already listens on the socket")]
    InUse,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

pub fn group_container_dir(home: &Path, team_id: &str) -> PathBuf {
    home.join("Library")
        .join("Group Containers")
        .join(format!("{team_id}.{}", identity::APP_GROUP_SUFFIX))
}

pub fn socket_path(dir: &Path) -> Result<PathBuf, IpcError> {
    let path = dir.join(identity::SOCKET_NAME);
    let len = path.as_os_str().len();
    if len > SUN_PATH_MAX {
        return Err(IpcError::PathTooLong(len));
    }
    Ok(path)
}

#[derive(Debug)]
pub struct AppListener {
    listener: UnixListener,
    path: PathBuf,
}

impl AppListener {
    /// Binds the app's socket inside `dir`, which must be owned by this user and closed to
    /// group and others, then restricts the socket itself to its owner. A socket left by a dead
    /// process is replaced; a live one is not.
    pub fn bind(dir: &Path, owner_uid: u32) -> Result<Self, IpcError> {
        ensure_private_dir(dir, owner_uid)?;
        let path = socket_path(dir)?;
        if path.exists() {
            match UnixStream::connect(&path) {
                Ok(_) => return Err(IpcError::InUse),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(&path)?,
                Err(e) => return Err(e.into()),
            }
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }

    pub fn accept(&self) -> io::Result<UnixStream> {
        self.listener.accept().map(|(stream, _)| stream)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AppListener {
    fn drop(&mut self) {
        fs::remove_file(&self.path).ok();
    }
}

/// The uid that owns this user's home directory, the owner every private directory and socket
/// must have.
pub fn home_owner_uid() -> Option<u32> {
    let home = std::env::home_dir()?;
    fs::metadata(home).ok().map(|meta| meta.uid())
}

pub fn connect(dir: &Path, owner_uid: u32) -> Result<UnixStream, IpcError> {
    check_dir(dir, owner_uid)?;
    Ok(UnixStream::connect(socket_path(dir)?)?)
}

fn ensure_private_dir(dir: &Path, owner_uid: u32) -> Result<(), IpcError> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    check_dir(dir, owner_uid)
}

fn check_dir(dir: &Path, owner_uid: u32) -> Result<(), IpcError> {
    let meta = fs::symlink_metadata(dir)?;
    let private = meta.is_dir() && meta.uid() == owner_uid && meta.mode().trailing_zeros() >= 6;
    if private {
        Ok(())
    } else {
        Err(IpcError::Directory(dir.to_path_buf()))
    }
}

#[derive(Debug)]
pub struct FramedLink {
    stream: UnixStream,
}

impl FramedLink {
    pub fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        self.stream.try_clone().map(Self::new)
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }

    pub fn stream(&mut self) -> &mut UnixStream {
        &mut self.stream
    }
}

impl Link for FramedLink {
    fn recv(&mut self) -> Result<Option<ExtensionMessage>, LinkError> {
        match read_frame(&mut self.stream, MAX_FROM_BROWSER) {
            Ok(Some(frame)) => ExtensionMessage::decode(&frame)
                .map(Some)
                .map_err(|_| LinkError::Malformed),
            Ok(None) => Ok(None),
            Err(FrameError::Io(e)) => Err(LinkError::Io(e)),
            Err(_) => Err(LinkError::Malformed),
        }
    }

    fn send(&mut self, message: &DesktopMessage) -> Result<(), LinkError> {
        let frame = message.encode().map_err(|_| LinkError::Malformed)?;
        write_frame(&mut self.stream, &frame, MAX_TO_BROWSER).map_err(|e| match e {
            FrameError::Io(e) => LinkError::Io(e),
            _ => LinkError::Malformed,
        })
    }

    fn writer(&self) -> Option<Box<dyn LinkWriter>> {
        self.try_clone()
            .ok()
            .map(|link| Box::new(link) as Box<dyn LinkWriter>)
    }
}

impl LinkWriter for FramedLink {
    fn send(&mut self, message: &DesktopMessage) -> Result<(), LinkError> {
        Link::send(self, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        let probe = std::env::temp_dir().join(format!(
            "hasp-nmh-uid-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&probe, b"").unwrap();
        let uid = fs::metadata(&probe).unwrap().uid();
        fs::remove_file(&probe).ok();
        uid
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hasp-nmh-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        dir
    }

    #[test]
    fn group_container_follows_the_apple_layout() {
        let dir = group_container_dir(Path::new("/Users/a"), "ABCDE12345");
        assert_eq!(
            dir,
            PathBuf::from("/Users/a/Library/Group Containers/ABCDE12345.kr.jmo.hasp")
        );
    }

    #[test]
    fn refuses_a_directory_others_can_write() {
        let dir = scratch("open");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let me = fs::metadata(&dir).unwrap().uid();
        assert!(matches!(
            AppListener::bind(&dir, me),
            Err(IpcError::Directory(_))
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_directory_others_can_read() {
        let dir = scratch("readable");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let me = fs::metadata(&dir).unwrap().uid();
        assert!(matches!(
            AppListener::bind(&dir, me),
            Err(IpcError::Directory(_))
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_directory_of_another_owner() {
        let dir = scratch("owner");
        fs::create_dir_all(&dir).unwrap();
        let me = fs::metadata(&dir).unwrap().uid();
        assert!(matches!(
            connect(&dir, me.wrapping_add(1)),
            Err(IpcError::Directory(_))
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binds_privately_refuses_a_second_listener_and_replaces_a_stale_socket() {
        let dir = scratch("bind");
        let me = uid();
        let first = AppListener::bind(&dir, me).unwrap();
        let mode = fs::metadata(first.path()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(matches!(AppListener::bind(&dir, me), Err(IpcError::InUse)));
        let client = connect(&dir, me).unwrap();
        let served = first.accept().unwrap();
        drop((client, served));
        let path = first.path().to_path_buf();
        drop(first);
        assert!(!path.exists());
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists());
        AppListener::bind(&dir, me).unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_path_that_does_not_fit_sun_path() {
        let long = PathBuf::from(format!("/{}", "a".repeat(120)));
        assert!(matches!(socket_path(&long), Err(IpcError::PathTooLong(_))));
    }
}
