use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::matcher::MatchError;

const MAX_URL_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostName {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: Scheme,
    host: HostName,
    port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    InsecureOrigin,
    UnsupportedScheme,
}

impl Origin {
    pub fn parse(text: &str) -> Result<Self, MatchError> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_URL_LEN {
            return Err(MatchError::Url);
        }
        if !text.contains("://") && has_opaque_scheme(text) {
            return Err(MatchError::Scheme);
        }
        let url = if text.contains("://") {
            Url::parse(text)
        } else {
            Url::parse(&format!("https://{text}"))
        }
        .map_err(|_| MatchError::Url)?;
        let scheme = match url.scheme() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(MatchError::Scheme),
        };
        let host = match url.host().ok_or(MatchError::Host)? {
            Host::Domain(name) => {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                if name.is_empty() {
                    return Err(MatchError::Host);
                }
                HostName::Domain(name)
            }
            Host::Ipv4(addr) => HostName::Ipv4(addr),
            Host::Ipv6(addr) => HostName::Ipv6(addr),
        };
        Ok(Self {
            scheme,
            host,
            port: url.port(),
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &HostName {
        &self.host
    }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            HostName::Domain(name) => Some(name),
            HostName::Ipv4(_) | HostName::Ipv6(_) => None,
        }
    }

    pub fn explicit_port(&self) -> Option<u16> {
        self.port
    }

    pub fn host_string(&self) -> String {
        match &self.host {
            HostName::Domain(name) => name.clone(),
            HostName::Ipv4(addr) => addr.to_string(),
            HostName::Ipv6(addr) => format!("[{addr}]"),
        }
    }

    pub fn is_loopback(&self) -> bool {
        match &self.host {
            HostName::Domain(name) => name == "localhost" || name.ends_with(".localhost"),
            HostName::Ipv4(addr) => addr.is_loopback(),
            HostName::Ipv6(addr) => addr.is_loopback(),
        }
    }

    pub fn check_fillable(&self) -> Result<(), Refusal> {
        match self.scheme {
            Scheme::Https => Ok(()),
            Scheme::Http if self.is_loopback() => Ok(()),
            Scheme::Http => Err(Refusal::InsecureOrigin),
        }
    }

    pub fn same_host_and_port(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port
    }
}

fn has_opaque_scheme(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let scheme_like = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    scheme_like && !rest.starts_with(|c: char| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(text: &str) -> String {
        Origin::parse(text).unwrap().host_string()
    }

    #[test]
    fn normalises_hosts() {
        assert_eq!(host("HTTPS://WWW.Example.COM/Login"), "www.example.com");
        assert_eq!(host("https://example.com./"), "example.com");
        assert_eq!(host("example.com/path"), "example.com");
        assert_eq!(host("https://bücher.de"), "xn--bcher-kva.de");
        assert_eq!(host("https://네이버.한국"), "xn--950bt9s8xi.xn--3e0b707e");
        assert_eq!(host("https://[::1]:8443/x"), "[::1]");
        assert_eq!(host("https://0x7f.1/"), "127.0.0.1");
    }

    #[test]
    fn strips_default_ports_only() {
        assert_eq!(
            Origin::parse("https://a.com:443").unwrap().explicit_port(),
            None
        );
        assert_eq!(
            Origin::parse("http://a.com:80").unwrap().explicit_port(),
            None
        );
        assert_eq!(
            Origin::parse("https://a.com:8443").unwrap().explicit_port(),
            Some(8443)
        );
        assert_eq!(
            Origin::parse("http://a.com:443").unwrap().explicit_port(),
            Some(443)
        );
    }

    #[test]
    fn rejects_unsupported_input() {
        assert!(matches!(
            Origin::parse("ftp://a.com"),
            Err(MatchError::Scheme)
        ));
        assert!(matches!(
            Origin::parse("file:///etc/passwd"),
            Err(MatchError::Scheme)
        ));
        assert!(matches!(
            Origin::parse("javascript:alert(1)"),
            Err(MatchError::Scheme)
        ));
        assert!(matches!(
            Origin::parse("mailto:a@b.com"),
            Err(MatchError::Scheme)
        ));
        assert!(Origin::parse("localhost:3000/x").is_ok());
        assert!(Origin::parse("").is_err());
        assert!(Origin::parse("https://").is_err());
    }

    #[test]
    fn http_is_fillable_only_on_loopback() {
        assert_eq!(
            Origin::parse("http://example.com")
                .unwrap()
                .check_fillable(),
            Err(Refusal::InsecureOrigin)
        );
        assert!(
            Origin::parse("http://localhost:3000")
                .unwrap()
                .check_fillable()
                .is_ok()
        );
        assert!(
            Origin::parse("http://127.0.0.1")
                .unwrap()
                .check_fillable()
                .is_ok()
        );
        assert!(
            Origin::parse("http://[::1]")
                .unwrap()
                .check_fillable()
                .is_ok()
        );
        assert!(
            Origin::parse("http://app.localhost")
                .unwrap()
                .check_fillable()
                .is_ok()
        );
        assert!(
            Origin::parse("https://example.com")
                .unwrap()
                .check_fillable()
                .is_ok()
        );
    }
}
