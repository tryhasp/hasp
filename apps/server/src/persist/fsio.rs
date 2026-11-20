use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use hasp_crypto::sha256;

#[cfg(unix)]
fn private_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn private_options(_: &mut OpenOptions) {}

pub(crate) fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn create_dir_durable(path: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path;
    while !cursor.exists() {
        missing.push(cursor);
        match cursor.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => cursor = parent,
            Some(_) | None => break,
        }
    }
    for dir in missing.into_iter().rev() {
        match make_private_dir(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn make_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
pub(crate) fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub(crate) fn restrict(_: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn restrict_database(db: &Path) -> std::io::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = db.as_os_str().to_os_string();
        name.push(suffix);
        let path = std::path::PathBuf::from(name);
        if path.exists() {
            restrict(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn remove_dir_durable(path: &Path) -> std::io::Result<()> {
    fs::remove_dir_all(path)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent)?;
    }
    Ok(())
}

/// A crash leaves the old file or the whole new one.
pub(crate) fn write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    create_dir_durable(dir)?;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = dir.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    private_options(&mut options);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    sync_dir(dir)
}

pub(crate) fn copy_durable(from: &Path, to: &Path) -> std::io::Result<[u8; 32]> {
    let bytes = fs::read(from)?;
    write_durable(to, &bytes)?;
    Ok(sha256(&[&bytes]))
}
