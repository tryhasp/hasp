use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::CliError;

pub(crate) fn private_dir(path: &Path) -> Result<(), CliError> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if fs::symlink_metadata(path).is_ok_and(|meta| !meta.file_type().is_file()) {
        return Err(CliError::usage(format!(
            "{} is a link or not a regular file; refusing to write through it",
            path.display()
        )));
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    write_private(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{private_dir, write_private};

    #[test]
    fn write_private_refuses_a_symlink_and_leaves_its_target_alone() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(write_private(&link, b"secret").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn write_private_creates_a_0600_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("out");
        write_private(&file, b"secret").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn private_dir_creates_0700_and_leaves_an_existing_dir_alone() {
        let root = tempfile::tempdir().unwrap();
        let fresh = root.path().join("fresh");
        private_dir(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let shared = root.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&shared).unwrap();
        assert_eq!(
            std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
