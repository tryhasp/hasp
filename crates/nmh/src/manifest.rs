use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::identity;
use crate::message::{Browser, Family};
use crate::origin::ExtensionAllowlist;

pub const HOST_BROWSERS: [Browser; 4] = [
    Browser::Chrome,
    Browser::Edge,
    Browser::Brave,
    Browser::Firefox,
];

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("the host path must be absolute")]
    RelativeHost,
    #[error("no extension id is published for this browser family")]
    NoExtensionIds,
    #[error("Safari has no native-messaging host")]
    NoHost,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub enum Outcome {
    Written(PathBuf),
    NotInstalled,
    Failed(InstallError),
}

pub fn support_dir(browser: Browser, home: &Path) -> Option<PathBuf> {
    let base = home.join("Library").join("Application Support");
    match browser {
        Browser::Chrome => Some(base.join("Google").join("Chrome")),
        Browser::Edge => Some(base.join("Microsoft Edge")),
        Browser::Brave => Some(base.join("BraveSoftware").join("Brave-Browser")),
        Browser::Firefox => Some(base.join("Mozilla")),
        Browser::Safari => None,
    }
}

pub fn manifest_path(browser: Browser, home: &Path) -> Option<PathBuf> {
    support_dir(browser, home).map(|dir| {
        dir.join("NativeMessagingHosts")
            .join(format!("{}.json", identity::HOST_NAME))
    })
}

pub fn manifest_json(
    browser: Browser,
    host_path: &Path,
    allowlist: &ExtensionAllowlist,
) -> Result<String, InstallError> {
    if !host_path.is_absolute() {
        return Err(InstallError::RelativeHost);
    }
    let path = host_path.to_string_lossy();
    let manifest = match browser.family() {
        Family::Chromium => {
            let origins: Vec<String> = allowlist
                .chromium_ids()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect();
            if origins.is_empty() {
                return Err(InstallError::NoExtensionIds);
            }
            json!({
                "name": identity::HOST_NAME,
                "description": identity::HOST_DESCRIPTION,
                "path": path,
                "type": "stdio",
                "allowed_origins": origins,
            })
        }
        Family::Gecko => {
            let ids: Vec<&str> = allowlist.gecko_ids().collect();
            if ids.is_empty() {
                return Err(InstallError::NoExtensionIds);
            }
            json!({
                "name": identity::HOST_NAME,
                "description": identity::HOST_DESCRIPTION,
                "path": path,
                "type": "stdio",
                "allowed_extensions": ids,
            })
        }
        Family::WebKit => return Err(InstallError::NoHost),
    };
    serde_json::to_string_pretty(&manifest).map_err(|_| InstallError::NoHost)
}

/// Writes the host manifest for every installed browser. Each browser is independent: a
/// failure for one is reported and never stops the others. A browser whose profile directory
/// does not exist is skipped instead of creating directories for software that is not there.
pub fn install_all(
    home: &Path,
    host_path: &Path,
    allowlist: &ExtensionAllowlist,
) -> Vec<(Browser, Outcome)> {
    HOST_BROWSERS
        .iter()
        .map(|browser| (*browser, install(*browser, home, host_path, allowlist)))
        .collect()
}

pub fn install(
    browser: Browser,
    home: &Path,
    host_path: &Path,
    allowlist: &ExtensionAllowlist,
) -> Outcome {
    match write(browser, home, host_path, allowlist) {
        Ok(Some(path)) => Outcome::Written(path),
        Ok(None) => Outcome::NotInstalled,
        Err(error) => Outcome::Failed(error),
    }
}

fn write(
    browser: Browser,
    home: &Path,
    host_path: &Path,
    allowlist: &ExtensionAllowlist,
) -> Result<Option<PathBuf>, InstallError> {
    let (Some(support), Some(target)) = (support_dir(browser, home), manifest_path(browser, home))
    else {
        return Err(InstallError::NoHost);
    };
    let body = manifest_json(browser, host_path, allowlist)?;
    if !support.is_dir() {
        return Ok(None);
    }
    let dir = target.parent().ok_or(InstallError::NoHost)?;
    fs::create_dir_all(dir)?;
    let staging = dir.join(format!(".{}.tmp", identity::HOST_NAME));
    fs::write(&staging, body)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o644))?;
    fs::rename(&staging, &target)?;
    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "gchilemfcapcihefglfdhgihpcjcdogp";

    fn allow() -> ExtensionAllowlist {
        ExtensionAllowlist::new(&[ID], &["hasp-dev@hasp.app"])
    }

    fn home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hasp-manifest-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn chromium_manifest_lists_exactly_the_allowed_origins() {
        let text = manifest_json(Browser::Chrome, Path::new("/App/hasp-nmh"), &allow()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["name"], "kr.jmo.hasp.nmh");
        assert_eq!(value["type"], "stdio");
        assert_eq!(value["path"], "/App/hasp-nmh");
        assert_eq!(
            value["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{ID}/")])
        );
        assert!(value.get("allowed_extensions").is_none());
    }

    #[test]
    fn firefox_manifest_uses_allowed_extensions() {
        let text = manifest_json(Browser::Firefox, Path::new("/App/hasp-nmh"), &allow()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value["allowed_extensions"],
            serde_json::json!(["hasp-dev@hasp.app"])
        );
        assert!(value.get("allowed_origins").is_none());
    }

    #[test]
    fn refuses_a_relative_host_path_and_an_empty_id_list() {
        assert!(matches!(
            manifest_json(Browser::Chrome, Path::new("hasp-nmh"), &allow()),
            Err(InstallError::RelativeHost)
        ));
        let empty = ExtensionAllowlist::new(&[], &[]);
        assert!(matches!(
            manifest_json(Browser::Edge, Path::new("/a"), &empty),
            Err(InstallError::NoExtensionIds)
        ));
    }

    #[test]
    fn installs_where_each_browser_reads_its_manifest() {
        let home = home("paths");
        for (browser, dir) in [
            (Browser::Chrome, "Library/Application Support/Google/Chrome"),
            (Browser::Edge, "Library/Application Support/Microsoft Edge"),
            (
                Browser::Brave,
                "Library/Application Support/BraveSoftware/Brave-Browser",
            ),
            (Browser::Firefox, "Library/Application Support/Mozilla"),
        ] {
            fs::create_dir_all(home.join(dir)).unwrap();
            let path = manifest_path(browser, &home).unwrap();
            assert_eq!(
                path,
                home.join(dir)
                    .join("NativeMessagingHosts/kr.jmo.hasp.nmh.json")
            );
        }
        let outcomes = install_all(&home, Path::new("/App/hasp-nmh"), &allow());
        assert_eq!(outcomes.len(), 4);
        for (browser, outcome) in &outcomes {
            let Outcome::Written(path) = outcome else {
                panic!("{browser:?}: {outcome:?}");
            };
            assert!(path.is_file());
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn skips_browsers_that_are_not_installed() {
        let home = home("skip");
        fs::create_dir_all(home.join("Library/Application Support/Google/Chrome")).unwrap();
        let outcomes = install_all(&home, Path::new("/App/hasp-nmh"), &allow());
        assert!(matches!(outcomes[0].1, Outcome::Written(_)));
        assert!(
            outcomes[1..]
                .iter()
                .all(|(_, o)| matches!(o, Outcome::NotInstalled))
        );
        assert!(!home.join("Library/Application Support/Mozilla").exists());
        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn one_browser_failing_does_not_stop_the_others() {
        let home = home("fail");
        let chrome = home.join("Library/Application Support/Google/Chrome");
        fs::create_dir_all(&chrome).unwrap();
        fs::write(chrome.join("NativeMessagingHosts"), b"a file in the way").unwrap();
        fs::create_dir_all(home.join("Library/Application Support/Mozilla")).unwrap();
        let outcomes = install_all(&home, Path::new("/App/hasp-nmh"), &allow());
        assert!(matches!(outcomes[0].1, Outcome::Failed(_)));
        assert!(matches!(outcomes[3].1, Outcome::Written(_)));
        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_dev_extension_id_is_derived_from_the_fixed_public_key() {
        let url_safe = identity::CHROMIUM_DEV_PUBLIC_KEY
            .replace('+', "-")
            .replace('/', "_");
        let der = hasp_proto::base64url::decode(&url_safe).unwrap();
        let digest = hasp_crypto::sha256(&[&der]);
        let id: String = digest[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .map(|n| char::from(b'a' + n))
            .collect();
        assert_eq!(id, identity::CHROMIUM_DEV_ID);
    }
}
