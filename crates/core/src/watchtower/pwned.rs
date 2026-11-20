use std::collections::BTreeMap;
use std::future::Future;

use hasp_crypto::to_hex;

use crate::model::item::Time;
use crate::watchtower::WatchtowerError;

pub const RANGE_URL_BASE: &str = "https://api.pwnedpasswords.com/range/";
pub const PADDING_HEADER: (&str, &str) = ("Add-Padding", "true");
pub const PREFIX_LEN: usize = 5;
pub const SUFFIX_LEN: usize = 35;
pub const CACHE_TTL_S: u64 = 24 * 60 * 60;
const MAX_CACHED_PREFIXES: usize = 256;
const SHA1_HEX_LEN: usize = 40;

/// The only thing about a password that ever leaves the device: five uppercase hex characters of
/// its SHA-1. The type cannot hold more, so a `RangeClient` cannot be handed more.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Prefix(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Suffix(String);

/// Fetches `RANGE_URL_BASE` + prefix with the `PADDING_HEADER` set and returns the response body
/// unchanged. Core never opens a connection; the binary or app injects this.
pub trait RangeClient {
    fn range(
        &self,
        prefix: &Prefix,
    ) -> impl Future<Output = Result<String, WatchtowerError>> + Send;
}

#[derive(Debug, Default)]
pub(crate) struct RangeCache {
    entries: BTreeMap<Prefix, CachedRange>,
}

#[derive(Debug)]
struct CachedRange {
    fetched_at: Time,
    counts: BTreeMap<String, u64>,
}

impl Prefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn url(&self) -> String {
        format!("{RANGE_URL_BASE}{}", self.0)
    }
}

impl Suffix {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn split_digest(digest: &[u8; hasp_crypto::SHA1_LEN]) -> Option<(Prefix, Suffix)> {
    let hex = zeroize::Zeroizing::new(to_hex(digest).to_ascii_uppercase());
    if hex.len() != SHA1_HEX_LEN {
        return None;
    }
    let (prefix, suffix) = hex.split_at_checked(PREFIX_LEN)?;
    Some((Prefix(prefix.to_owned()), Suffix(suffix.to_owned())))
}

/// Parses `SUFFIX:COUNT` lines. Padding entries carry count 0 and are dropped.
pub fn parse_range(body: &str) -> Result<BTreeMap<String, u64>, WatchtowerError> {
    let mut counts = BTreeMap::new();
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (suffix, count) = line.split_once(':').ok_or(WatchtowerError::Response)?;
        let valid_suffix =
            suffix.len() == SUFFIX_LEN && suffix.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid_suffix {
            return Err(WatchtowerError::Response);
        }
        let count: u64 = count
            .trim()
            .parse()
            .map_err(|_| WatchtowerError::Response)?;
        if count > 0 {
            counts.insert(suffix.to_ascii_uppercase(), count);
        }
    }
    Ok(counts)
}

impl RangeCache {
    pub(crate) fn lookup(&self, prefix: &Prefix, suffix: &Suffix, now: Time) -> Option<u64> {
        let cached = self.entries.get(prefix)?;
        if now.saturating_sub(cached.fetched_at) >= CACHE_TTL_S {
            return None;
        }
        Some(cached.counts.get(suffix.as_str()).copied().unwrap_or(0))
    }

    pub(crate) fn store(&mut self, prefix: Prefix, counts: BTreeMap<String, u64>, now: Time) {
        self.entries
            .retain(|_, cached| now.saturating_sub(cached.fetched_at) < CACHE_TTL_S);
        while self.entries.len() >= MAX_CACHED_PREFIXES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, cached)| cached.fetched_at)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => self.entries.remove(&key),
                None => break,
            };
        }
        self.entries.insert(
            prefix,
            CachedRange {
                fetched_at: now,
                counts,
            },
        );
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX_A: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn splits_the_known_hibp_example_hash() {
        let digest = hasp_crypto::sha1_of_secret(b"password");
        let (prefix, suffix) = split_digest(&digest).unwrap();
        assert_eq!(prefix.as_str(), "5BAA6");
        assert_eq!(suffix.as_str(), SUFFIX_A);
        assert_eq!(prefix.url(), "https://api.pwnedpasswords.com/range/5BAA6");
    }

    #[test]
    fn parses_counts_and_drops_padding_entries() {
        let body = format!(
            "{SUFFIX_A}:10434004\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n\
             00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
        );
        let counts = parse_range(&body).unwrap();
        assert_eq!(counts.len(), 2);
        assert_eq!(counts.get(SUFFIX_A), Some(&10_434_004));
        assert_eq!(counts.get("00D4F6E8FA6EECAD2A3AA415EEC418D38EC"), Some(&2));
        assert!(!counts.contains_key("0018A45C4D1DEF81644B54AB7F969B88D65"));
    }

    #[test]
    fn accepts_lowercase_hex_blank_lines_and_an_empty_body() {
        let counts = parse_range(&format!("\n{}:3\n\n", SUFFIX_A.to_ascii_lowercase())).unwrap();
        assert_eq!(counts.get(SUFFIX_A), Some(&3));
        assert!(parse_range("").unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_lines() {
        for body in [
            "garbage",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:x",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8",
            "SHORT:1",
            "ZZ4C9B93F3F0682250B6CF8331B7EE68FD8:1",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:-1",
        ] {
            assert!(
                matches!(parse_range(body), Err(WatchtowerError::Response)),
                "{body}"
            );
        }
    }

    #[test]
    fn cache_expires_by_ttl_and_is_bounded() {
        let digest = hasp_crypto::sha1_of_secret(b"password");
        let (prefix, suffix) = split_digest(&digest).unwrap();
        let mut cache = RangeCache::default();
        cache.store(
            prefix.clone(),
            BTreeMap::from([(suffix.as_str().to_owned(), 7)]),
            100,
        );
        assert_eq!(
            cache.lookup(&prefix, &suffix, 100 + CACHE_TTL_S - 1),
            Some(7)
        );
        assert_eq!(cache.lookup(&prefix, &suffix, 100 + CACHE_TTL_S), None);
        cache.clear();
        for n in 0..(MAX_CACHED_PREFIXES + 20) {
            let digest = hasp_crypto::sha1_of_secret(n.to_string().as_bytes());
            let (prefix, _) = split_digest(&digest).unwrap();
            cache.store(prefix, BTreeMap::new(), u64::try_from(n).unwrap());
        }
        assert!(cache.len() <= MAX_CACHED_PREFIXES);
    }
}
