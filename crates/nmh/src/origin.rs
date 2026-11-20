use std::collections::BTreeSet;
use std::path::Path;

use crate::identity;
use crate::message::{Browser, Family};

const CHROMIUM_SCHEME: &str = "chrome-extension://";
const CHROMIUM_ID_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExtensionOrigin {
    Chromium(String),
    Gecko(String),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    #[error("the caller arguments are not those a browser passes")]
    Arguments,
    #[error("extension id not on the allowlist")]
    Unknown,
    #[error("the extension id belongs to another browser family")]
    WrongBrowser,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionAllowlist {
    chromium: BTreeSet<String>,
    gecko: BTreeSet<String>,
}

impl ExtensionAllowlist {
    pub fn new(chromium: &[&str], gecko: &[&str]) -> Self {
        Self {
            chromium: chromium.iter().map(|id| (*id).to_owned()).collect(),
            gecko: gecko.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    pub fn published() -> Self {
        let mut chromium = identity::CHROMIUM_STORE_IDS.to_vec();
        let mut gecko = identity::FIREFOX_STORE_IDS.to_vec();
        if cfg!(feature = "dev-extension") {
            chromium.push(identity::CHROMIUM_DEV_ID);
            gecko.push(identity::FIREFOX_DEV_ID);
        }
        Self::new(&chromium, &gecko)
    }

    pub fn chromium_ids(&self) -> impl Iterator<Item = &str> {
        self.chromium.iter().map(String::as_str)
    }

    pub fn gecko_ids(&self) -> impl Iterator<Item = &str> {
        self.gecko.iter().map(String::as_str)
    }

    pub fn permits(&self, origin: &ExtensionOrigin) -> bool {
        match origin {
            ExtensionOrigin::Chromium(id) => self.chromium.contains(id),
            ExtensionOrigin::Gecko(id) => self.gecko.contains(id),
        }
    }

    pub fn admit(&self, origin: &ExtensionOrigin, browser: Browser) -> Result<(), OriginError> {
        let expected = match origin {
            ExtensionOrigin::Chromium(_) => Family::Chromium,
            ExtensionOrigin::Gecko(_) => Family::Gecko,
        };
        if browser.family() != expected {
            return Err(OriginError::WrongBrowser);
        }
        if !self.permits(origin) {
            return Err(OriginError::Unknown);
        }
        Ok(())
    }
}

impl ExtensionOrigin {
    pub fn id(&self) -> &str {
        match self {
            Self::Chromium(id) | Self::Gecko(id) => id,
        }
    }

    /// Chromium passes `chrome-extension://<id>/` and, on Windows only, `--parent-window=N`.
    /// Firefox passes the manifest path and then the add-on id. Anything else is refused.
    pub fn from_args(args: &[String]) -> Result<Self, OriginError> {
        let mut rest = args.iter().skip(1).map(String::as_str);
        let first = rest.next().ok_or(OriginError::Arguments)?;
        if let Some(tail) = first.strip_prefix(CHROMIUM_SCHEME) {
            if rest.next().is_some() {
                return Err(OriginError::Arguments);
            }
            let id = tail.strip_suffix('/').ok_or(OriginError::Arguments)?;
            let valid =
                id.len() == CHROMIUM_ID_LEN && id.bytes().all(|b| (b'a'..=b'p').contains(&b));
            if !valid {
                return Err(OriginError::Arguments);
            }
            return Ok(Self::Chromium(id.to_owned()));
        }
        let manifest = Path::new(first);
        let named = manifest.is_absolute()
            && manifest.file_name().and_then(|n| n.to_str())
                == Some(&format!("{}.json", identity::HOST_NAME));
        let id = rest.next().ok_or(OriginError::Arguments)?;
        if !named || rest.next().is_some() || id.is_empty() || id.len() > 128 {
            return Err(OriginError::Arguments);
        }
        Ok(Self::Gecko(id.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    const ID: &str = "gchilemfcapcihefglfdhgihpcjcdogp";

    #[test]
    fn parses_the_chromium_origin_argument() {
        let origin =
            ExtensionOrigin::from_args(&args(&["host", &format!("chrome-extension://{ID}/")]))
                .unwrap();
        assert_eq!(origin, ExtensionOrigin::Chromium(ID.to_owned()));
    }

    #[test]
    fn refuses_malformed_chromium_arguments() {
        for bad in [
            vec!["host"],
            vec!["host", "chrome-extension://short/"],
            vec!["host", &format!("chrome-extension://{ID}")],
            vec!["host", &format!("chrome-extension://{ID}/x")],
            vec![
                "host",
                &format!("chrome-extension://{}/", ID.to_uppercase()),
            ],
            vec!["host", &format!("chrome-extension://{ID}/"), "extra"],
            vec!["host", &format!("chrome-extension://{}/", "q".repeat(32))],
        ] {
            assert_eq!(
                ExtensionOrigin::from_args(&args(&bad)),
                Err(OriginError::Arguments),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parses_the_firefox_arguments() {
        let origin = ExtensionOrigin::from_args(&args(&[
            "host",
            "/Users/x/Library/Application Support/Mozilla/NativeMessagingHosts/kr.jmo.hasp.nmh.json",
            "hasp-dev@hasp.app",
        ]))
        .unwrap();
        assert_eq!(
            origin,
            ExtensionOrigin::Gecko("hasp-dev@hasp.app".to_owned())
        );
        assert!(ExtensionOrigin::from_args(&args(&["host", "relative.json", "a@b"])).is_err());
        assert!(ExtensionOrigin::from_args(&args(&["host", "/tmp/evil.json", "a@b"])).is_err());
    }

    #[test]
    fn allowlist_refuses_unknown_ids_and_mixed_families() {
        let allow = ExtensionAllowlist::new(&[ID], &["hasp-dev@hasp.app"]);
        let known = ExtensionOrigin::Chromium(ID.to_owned());
        assert_eq!(allow.admit(&known, Browser::Chrome), Ok(()));
        assert_eq!(allow.admit(&known, Browser::Brave), Ok(()));
        assert_eq!(
            allow.admit(&known, Browser::Firefox),
            Err(OriginError::WrongBrowser)
        );
        let stranger = ExtensionOrigin::Chromium("a".repeat(32));
        assert_eq!(
            allow.admit(&stranger, Browser::Chrome),
            Err(OriginError::Unknown)
        );
        let gecko = ExtensionOrigin::Gecko("hasp-dev@hasp.app".to_owned());
        assert_eq!(allow.admit(&gecko, Browser::Firefox), Ok(()));
        assert_eq!(
            allow.admit(&gecko, Browser::Chrome),
            Err(OriginError::WrongBrowser)
        );
    }

    #[test]
    fn the_default_allowlist_holds_the_dev_id_only_with_the_dev_feature() {
        let allow = ExtensionAllowlist::published();
        let dev = ExtensionOrigin::Chromium(identity::CHROMIUM_DEV_ID.to_owned());
        assert_eq!(allow.permits(&dev), cfg!(feature = "dev-extension"));
    }
}
