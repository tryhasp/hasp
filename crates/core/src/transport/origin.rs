use std::net::IpAddr;

use url::{Host, Url};

/// The origin the user typed. The client never follows a server-supplied URL, so every request is
/// built from this value and a fixed path.
#[derive(Debug, thiserror::Error)]
#[error("the origin is not a valid server address: {0}")]
pub struct OriginError(pub &'static str);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    url: Url,
}

impl Origin {
    /// Accepts `https://host[:port]`. Plain `http://` is accepted only for a loopback IP literal
    /// (`127.0.0.0/8` or `::1`), never for a name, because a resolver decides what a name means.
    pub fn parse(text: &str) -> Result<Self, OriginError> {
        let url = Url::parse(text.trim()).map_err(|_| OriginError("not a URL"))?;
        let loopback = match url.host() {
            Some(Host::Domain(_)) => false,
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            None => return Err(OriginError("no host")),
        };
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            "http" => return Err(OriginError("plain http is allowed only for loopback")),
            _ => return Err(OriginError("the scheme must be https")),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OriginError("credentials in the URL"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(OriginError("query or fragment"));
        }
        if url.path() != "/" {
            return Err(OriginError("a path"));
        }
        Ok(Self { url })
    }

    pub fn is_secure(&self) -> bool {
        self.url.scheme() == "https"
    }

    pub fn http(&self, path: &str) -> Result<Url, OriginError> {
        self.url.join(path).map_err(|_| OriginError("not joinable"))
    }

    pub fn websocket(&self, path: &str) -> Result<Url, OriginError> {
        let mut url = self.http(path)?;
        let scheme = if self.is_secure() { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|()| OriginError("no websocket scheme"))?;
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::Origin;

    #[test]
    fn accepts_https_and_a_port() {
        assert!(Origin::parse("https://vault.example.com").is_ok());
        assert!(Origin::parse("https://vault.example.com:8443/").is_ok());
    }

    #[test]
    fn accepts_plain_http_only_on_loopback() {
        assert!(Origin::parse("http://127.0.0.1:8080").is_ok());
        assert!(Origin::parse("http://127.0.0.2:8080").is_ok());
        assert!(Origin::parse("http://localhost:8080").is_err());
        assert!(Origin::parse("http://LOCALHOST").is_err());
        assert!(Origin::parse("http://localhost.").is_err());
        assert!(Origin::parse("http://[::ffff:127.0.0.1]:8080").is_err());
        assert!(Origin::parse("https://localhost:8443").is_ok());
        assert!(Origin::parse("http://[::1]:8080").is_ok());
        assert!(Origin::parse("http://vault.example.com").is_err());
        assert!(Origin::parse("http://192.168.1.5").is_err());
    }

    #[test]
    fn rejects_credentials_paths_queries_and_other_schemes() {
        for text in [
            "https://user:pw@vault.example.com",
            "https://vault.example.com/v1",
            "https://vault.example.com/?a=b",
            "https://vault.example.com/#frag",
            "ftp://vault.example.com",
            "vault.example.com",
        ] {
            assert!(Origin::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn maps_to_websocket_schemes() {
        let secure = Origin::parse("https://vault.example.com").unwrap();
        assert_eq!(
            secure.websocket("/v1/ws").unwrap().as_str(),
            "wss://vault.example.com/v1/ws"
        );
        let local = Origin::parse("http://127.0.0.1:9").unwrap();
        assert_eq!(
            local.websocket("/v1/ws").unwrap().as_str(),
            "ws://127.0.0.1:9/v1/ws"
        );
    }
}
