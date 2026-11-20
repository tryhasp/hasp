use std::fmt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::message::Browser;

const DEVELOPER_ID_CA: &str = "certificate 1[field.1.2.840.113635.100.6.2.6]";
const DEVELOPER_ID_APPLICATION: &str = "certificate leaf[field.1.2.840.113635.100.6.1.13]";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeTarget {
    Pid(i32),
    AuditToken([u8; 32]),
    Path(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signing {
    DeveloperId,
    AnyTeamCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCode {
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PeerError {
    #[error("the peer cannot be identified")]
    Unidentified,
    #[error("the peer runs as another user")]
    OtherUser,
    #[error("the peer code does not satisfy the requirement")]
    Mismatch,
    #[error("the code signature check failed with status {0}")]
    Check(i32),
    #[error("not a valid requirement")]
    Requirement,
    #[error("code signature checks are not available on this platform")]
    Unsupported,
}

pub trait CodeVerifier {
    /// The process on the other end of a connected socket, as an audit token that survives pid
    /// reuse. Refuses a peer that runs as another user.
    fn peer_of(&self, stream: &UnixStream) -> Result<CodeTarget, PeerError>;

    fn parent(&self) -> Result<CodeTarget, PeerError>;

    fn verify(
        &self,
        target: &CodeTarget,
        requirement: &Requirement,
    ) -> Result<VerifiedCode, PeerError>;
}

#[derive(Clone, Copy, Debug)]
pub struct BrowserRule {
    pub browser: Browser,
    pub bundle_ids: &'static [&'static str],
    pub team_id: &'static str,
}

pub const BROWSERS: [BrowserRule; 4] = [
    BrowserRule {
        browser: Browser::Chrome,
        bundle_ids: &[
            "com.google.Chrome",
            "com.google.Chrome.beta",
            "com.google.Chrome.dev",
            "com.google.Chrome.canary",
        ],
        team_id: "EQHXZ8M8AV",
    },
    BrowserRule {
        browser: Browser::Edge,
        bundle_ids: &[
            "com.microsoft.edgemac",
            "com.microsoft.edgemac.Beta",
            "com.microsoft.edgemac.Dev",
            "com.microsoft.edgemac.Canary",
        ],
        team_id: "UBF8T346G9",
    },
    BrowserRule {
        browser: Browser::Brave,
        bundle_ids: &[
            "com.brave.Browser",
            "com.brave.Browser.beta",
            "com.brave.Browser.dev",
            "com.brave.Browser.nightly",
        ],
        team_id: "KL8N8XSYF4",
    },
    BrowserRule {
        browser: Browser::Firefox,
        bundle_ids: &[
            "org.mozilla.firefox",
            "org.mozilla.firefoxdeveloperedition",
            "org.mozilla.nightly",
        ],
        team_id: "43AQ936H96",
    },
];

impl Requirement {
    pub fn signed_by(
        identifiers: &[&str],
        team_id: &str,
        signing: Signing,
    ) -> Result<Self, PeerError> {
        let team_ok = team_id.len() == 10 && team_id.bytes().all(|b| b.is_ascii_alphanumeric());
        let ids_ok = !identifiers.is_empty()
            && identifiers.iter().all(|id| {
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            });
        if !team_ok || !ids_ok {
            return Err(PeerError::Requirement);
        }
        let named = identifiers
            .iter()
            .map(|id| format!("identifier \"{id}\""))
            .collect::<Vec<_>>()
            .join(" or ");
        let chain = match signing {
            Signing::DeveloperId => {
                format!("{DEVELOPER_ID_CA} and {DEVELOPER_ID_APPLICATION} and ")
            }
            Signing::AnyTeamCertificate => String::new(),
        };
        Ok(Self(format!(
            "({named}) and anchor apple generic and {chain}certificate leaf[subject.OU] = \"{team_id}\""
        )))
    }

    pub fn apple_system() -> Self {
        Self("anchor apple".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl BrowserRule {
    pub fn requirement(&self) -> Result<Requirement, PeerError> {
        Requirement::signed_by(self.bundle_ids, self.team_id, Signing::DeveloperId)
    }
}

/// Matches the process against each browser's signing identity and returns which browser it is.
pub fn identify_browser<V: CodeVerifier>(
    verifier: &V,
    target: &CodeTarget,
) -> Result<Browser, PeerError> {
    let mut last = PeerError::Mismatch;
    for rule in &BROWSERS {
        match verifier.verify(target, &rule.requirement()?) {
            Ok(_) => return Ok(rule.browser),
            Err(PeerError::Mismatch) => {}
            Err(other) => last = other,
        }
    }
    Err(last)
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_developer_id_requirement_chrome_ships() {
        let rule = &BROWSERS[0];
        let text = rule.requirement().unwrap();
        assert!(text.as_str().contains("identifier \"com.google.Chrome\""));
        assert!(text.as_str().contains("anchor apple generic"));
        assert!(
            text.as_str()
                .ends_with("certificate leaf[subject.OU] = \"EQHXZ8M8AV\"")
        );
    }

    #[test]
    fn refuses_a_requirement_with_injected_syntax() {
        assert_eq!(
            Requirement::signed_by(
                &["a\" or anchor apple or identifier \"b"],
                "EQHXZ8M8AV",
                Signing::DeveloperId
            ),
            Err(PeerError::Requirement)
        );
        assert_eq!(
            Requirement::signed_by(&["a.b"], "EQ\" or \"", Signing::DeveloperId),
            Err(PeerError::Requirement)
        );
        assert_eq!(
            Requirement::signed_by(&[], "EQHXZ8M8AV", Signing::DeveloperId),
            Err(PeerError::Requirement)
        );
    }
}
