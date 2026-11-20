use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not a CIDR block or address")]
pub struct CidrError;

impl Cidr {
    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = address.parse().map_err(|_| CidrError)?;
        let width: u8 = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().map_err(|_| CidrError)?,
            None => width,
        };
        if prefix > width {
            return Err(CidrError);
        }
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                prefix_of(u128::from(u32::from(network)), self.prefix, 32)
                    == prefix_of(u128::from(u32::from(ip)), self.prefix, 32)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_of(u128::from(network), self.prefix, 128)
                    == prefix_of(u128::from(ip), self.prefix, 128)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

fn prefix_of(value: u128, prefix: u8, width: u8) -> u128 {
    let host = u32::from(width.saturating_sub(prefix));
    value.checked_shr(host).unwrap_or(0)
}

pub(crate) fn client_ip(peer: IpAddr, forwarded: Option<&str>, trusted: &[Cidr]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: IpAddr| trusted.iter().any(|cidr| cidr.contains(ip));
    if !is_trusted(peer) {
        return peer;
    }
    let Some(forwarded) = forwarded else {
        return peer;
    };
    let mut leftmost = peer;
    for entry in forwarded.rsplit(',') {
        let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            return peer;
        };
        let ip = ip.to_canonical();
        if !is_trusted(ip) {
            return ip;
        }
        leftmost = ip;
    }
    leftmost
}

pub(crate) fn header_client_ip(peer: IpAddr, values: &[&str], trusted: &[Cidr]) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted.iter().any(|cidr| cidr.contains(peer)) {
        return peer;
    }
    match values {
        [value] => value
            .trim()
            .parse::<IpAddr>()
            .map_or(peer, |ip| ip.to_canonical()),
        _ => peer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn proxies() -> Vec<Cidr> {
        vec![
            Cidr::parse("172.16.0.0/12").unwrap(),
            Cidr::parse("::1").unwrap(),
        ]
    }

    #[test]
    fn parses_blocks_and_single_addresses() {
        assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(ip("10.9.9.9")));
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(ip("11.0.0.1")));
        assert!(Cidr::parse("10.0.0.7").unwrap().contains(ip("10.0.0.7")));
        assert!(!Cidr::parse("10.0.0.7").unwrap().contains(ip("10.0.0.8")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fd12::1")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
    }

    #[test]
    fn mapped_v6_matches_v4_blocks() {
        assert!(
            Cidr::parse("172.16.0.0/12")
                .unwrap()
                .contains(ip("::ffff:172.17.0.2"))
        );
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_header() {
        assert_eq!(
            client_ip(ip("203.0.113.9"), Some("1.2.3.4"), &proxies()),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn trusted_peer_takes_rightmost_untrusted_entry() {
        let chain = "6.6.6.6, 198.51.100.4, 172.17.0.5";
        assert_eq!(
            client_ip(ip("172.17.0.2"), Some(chain), &proxies()),
            ip("198.51.100.4")
        );
    }

    #[test]
    fn spoofed_leading_entries_do_not_count() {
        assert_eq!(
            client_ip(ip("172.17.0.2"), Some("1.1.1.1, 2.2.2.2"), &proxies()),
            ip("2.2.2.2")
        );
    }

    #[test]
    fn malformed_header_falls_back_to_the_peer() {
        assert_eq!(
            client_ip(ip("172.17.0.2"), Some("garbage"), &proxies()),
            ip("172.17.0.2")
        );
        assert_eq!(
            client_ip(ip("172.17.0.2"), None, &proxies()),
            ip("172.17.0.2")
        );
    }

    #[test]
    fn single_header_from_a_trusted_peer_is_the_client() {
        assert_eq!(
            header_client_ip(ip("172.17.0.2"), &["203.0.113.9"], &proxies()),
            ip("203.0.113.9")
        );
        assert_eq!(
            header_client_ip(ip("172.17.0.2"), &["2001:db8::7"], &proxies()),
            ip("2001:db8::7")
        );
    }

    #[test]
    fn header_from_an_untrusted_peer_is_ignored() {
        assert_eq!(
            header_client_ip(ip("203.0.113.9"), &["1.2.3.4"], &proxies()),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn malformed_or_repeated_header_falls_back_to_the_peer() {
        let peer = ip("172.17.0.2");
        for values in [
            &["garbage"][..],
            &["1.2.3.4, 5.6.7.8"][..],
            &["1.2.3.4:80"][..],
            &[""][..],
            &["1.2.3.4", "5.6.7.8"][..],
            &[][..],
        ] {
            assert_eq!(
                header_client_ip(peer, values, &proxies()),
                peer,
                "{values:?}"
            );
        }
    }

    #[test]
    fn all_trusted_chain_yields_the_leftmost() {
        assert_eq!(
            client_ip(ip("172.17.0.2"), Some("172.20.0.1, 172.18.0.9"), &proxies()),
            ip("172.20.0.1")
        );
    }
}
