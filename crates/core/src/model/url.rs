use url::Url;

use crate::model::ModelError;
use crate::model::id::Id;

const MAX_URL_BYTES: usize = 2048;
const MAX_HOST_BYTES: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Domain,
    Host,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    Website,
    SignIn,
    Api,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlEntry {
    id: Id,
    url: String,
    mode: MatchMode,
    confirmed_hosts: Vec<String>,
    kind: UrlKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSummary {
    pub host: String,
    pub port: Option<u16>,
    pub mode: MatchMode,
}

impl UrlEntry {
    pub fn new(id: Id, url: &str, mode: MatchMode, kind: UrlKind) -> Result<Self, ModelError> {
        let url = url.trim();
        if url.is_empty() || url.len() > MAX_URL_BYTES {
            return Err(ModelError::Url);
        }
        Url::parse(url).map_err(|_| ModelError::Url)?;
        Ok(Self {
            id,
            url: url.to_owned(),
            mode,
            confirmed_hosts: Vec::new(),
            kind,
        })
    }

    pub fn confirm_host(&mut self, host: &str) -> Result<(), ModelError> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.len() > MAX_HOST_BYTES || host.contains(['/', ':', ' ', '@']) {
            return Err(ModelError::Url);
        }
        if !self.confirmed_hosts.contains(&host) {
            self.confirmed_hosts.push(host);
        }
        Ok(())
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: MatchMode) {
        self.mode = mode;
    }

    pub fn confirmed_hosts(&self) -> &[String] {
        &self.confirmed_hosts
    }

    pub fn kind(&self) -> UrlKind {
        self.kind
    }

    pub fn summary(&self) -> Option<UrlSummary> {
        let parsed = Url::parse(&self.url).ok()?;
        Some(UrlSummary {
            host: parsed.host_str()?.to_ascii_lowercase(),
            port: parsed.port(),
            mode: self.mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str) -> Result<UrlEntry, ModelError> {
        UrlEntry::new(
            Id::from_bytes([1; 16]),
            url,
            MatchMode::Domain,
            UrlKind::Website,
        )
    }

    #[test]
    fn accepts_valid_urls_and_summarises_host_and_port() {
        let summary = entry("https://Example.com:8443/login")
            .unwrap()
            .summary()
            .unwrap();
        assert_eq!(summary.host, "example.com");
        assert_eq!(summary.port, Some(8443));
        assert_eq!(summary.mode, MatchMode::Domain);
    }

    #[test]
    fn rejects_unparseable_and_oversized_urls() {
        assert!(entry("").is_err());
        assert!(entry("not a url").is_err());
        assert!(entry(&format!("https://a.com/{}", "x".repeat(2048))).is_err());
    }

    #[test]
    fn confirmed_hosts_are_normalised_and_deduplicated() {
        let mut url = entry("https://example.com").unwrap();
        url.confirm_host("Login.Example.COM.").unwrap();
        url.confirm_host("login.example.com").unwrap();
        assert_eq!(url.confirmed_hosts(), ["login.example.com"]);
        assert!(url.confirm_host("a/b").is_err());
        assert!(url.confirm_host("").is_err());
    }
}
