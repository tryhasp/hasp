mod checks;
pub mod estimate;
pub mod pwned;
pub mod report;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use hasp_crypto::{SHA1_LEN, SHA256_LEN, SecretKey, hmac_sha256, sha1_of_secret};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::model::field::{FieldValue, Purpose, Section};
use crate::model::id::Id;
use crate::model::item::{Item, Time};
use crate::model::template::{Templates, WatchtowerCheck};
use crate::watchtower::estimate::{WeakReason, estimate_bits, weak_reasons};
use crate::watchtower::pwned::{
    Prefix, RangeCache, RangeClient, Suffix, parse_range, split_digest,
};
use crate::watchtower::report::{Counts, Detail, Finding, ItemReport, Report, Severity};

pub const DEFAULT_ALERT_WINDOW_DAYS: u32 = 60;
const EXPIRING_SOON_DAYS: i64 = 30;
const SEVERE_BITS: f64 = 20.0;

#[derive(Debug, thiserror::Error)]
pub enum WatchtowerError {
    #[error("the breach check is not enabled")]
    PwnedDisabled,
    #[error("the breach service could not be reached")]
    Network,
    #[error("the breach service sent an unreadable response")]
    Response,
    #[error("crypto: {0}")]
    Crypto(#[from] hasp_crypto::CryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwnedMode {
    Off,
    OptedIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PwnedRun {
    pub requests: usize,
    pub resolved: usize,
}

/// Holds derived checks for decrypted items, never a password. A password leaves `upsert`
/// as a per-instance keyed hash (reuse), a SHA-1 wiped on drop (breach lookup) and a bit
/// estimate. One instance lives while the vault is unlocked.
pub struct Watchtower {
    tag_key: SecretKey,
    entries: BTreeMap<Id, Entry>,
    groups: BTreeMap<[u8; SHA256_LEN], BTreeSet<Id>>,
    pwned_mode: PwnedMode,
    cache: RangeCache,
}

struct Entry {
    passwords: Vec<Password>,
    checks: BTreeSet<WatchtowerCheck>,
    insecure_url: bool,
    expiries: Vec<Time>,
    window_days: u32,
}

struct Password {
    tag: [u8; SHA256_LEN],
    sha1: Zeroizing<[u8; SHA1_LEN]>,
    bits: f64,
    reasons: Vec<WeakReason>,
    verdict: Option<Verdict>,
}

#[derive(Clone, Copy)]
struct Verdict {
    count: u64,
    at: Time,
}

struct Lookup {
    item: Id,
    slot: usize,
    suffix: Suffix,
}

impl std::fmt::Debug for Watchtower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watchtower")
            .field("items", &self.entries.len())
            .field("pwned_mode", &self.pwned_mode)
            .finish_non_exhaustive()
    }
}

impl Watchtower {
    pub fn new() -> Result<Self, WatchtowerError> {
        Ok(Self {
            tag_key: SecretKey::random()?,
            entries: BTreeMap::new(),
            groups: BTreeMap::new(),
            pwned_mode: PwnedMode::Off,
            cache: RangeCache::default(),
        })
    }

    pub fn pwned_mode(&self) -> PwnedMode {
        self.pwned_mode
    }

    pub fn set_pwned_mode(&mut self, mode: PwnedMode) {
        if mode == PwnedMode::Off {
            self.cache.clear();
            for entry in self.entries.values_mut() {
                for password in &mut entry.passwords {
                    password.verdict = None;
                }
            }
        }
        self.pwned_mode = mode;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Recomputes one item. Only active items are checked; any other state removes the item.
    /// The caller passes an id that is unique across vaults.
    pub fn upsert(&mut self, key: Id, item: &Item, templates: &Templates) {
        let previous = self.detach(key);
        if !item.overview().state.is_active() {
            return;
        }
        let template = templates
            .get(&item.overview().kind)
            .unwrap_or_else(|| templates.custom());
        let capabilities = &template.capabilities;
        let checks: BTreeSet<WatchtowerCheck> = capabilities.watchtower.iter().copied().collect();
        let wants_passwords = [
            WatchtowerCheck::Vulnerable,
            WatchtowerCheck::Reused,
            WatchtowerCheck::Weak,
        ]
        .iter()
        .any(|check| checks.contains(check));
        let passwords = if wants_passwords {
            self.passwords_of(item, previous.as_ref())
        } else {
            Vec::new()
        };
        if checks.contains(&WatchtowerCheck::Reused) {
            for password in &passwords {
                self.groups.entry(password.tag).or_default().insert(key);
            }
        }
        let insecure_url = checks.contains(&WatchtowerCheck::InsecureUrl)
            && checks::only_insecure_urls(&item.details().urls);
        let expiries = if checks.contains(&WatchtowerCheck::Expiring) {
            checks::expiry_dates(item)
        } else {
            Vec::new()
        };
        self.entries.insert(
            key,
            Entry {
                passwords,
                checks,
                insecure_url,
                expiries,
                window_days: capabilities
                    .expiry_window_days
                    .unwrap_or(DEFAULT_ALERT_WINDOW_DAYS),
            },
        );
    }

    pub fn remove(&mut self, key: Id) {
        self.detach(key);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.groups.clear();
        self.cache.clear();
    }

    /// Looks every unchecked or stale password up in the range API, one request per distinct
    /// prefix. Only the 5-character prefix reaches the client; the suffix compare is local.
    pub async fn check_pwned<C: RangeClient>(
        &mut self,
        client: &C,
        now: Time,
    ) -> Result<PwnedRun, WatchtowerError> {
        if self.pwned_mode == PwnedMode::Off {
            return Err(WatchtowerError::PwnedDisabled);
        }
        let mut run = PwnedRun {
            requests: 0,
            resolved: 0,
        };
        for (prefix, lookups) in self.pending_lookups(now) {
            let known = self.cache_counts(&prefix, &lookups, now);
            let counts = if let Some(counts) = known {
                counts
            } else {
                let body = client.range(&prefix).await?;
                run.requests += 1;
                let parsed = parse_range(&body)?;
                self.cache.store(prefix.clone(), parsed, now);
                self.cache_counts(&prefix, &lookups, now)
                    .unwrap_or_default()
            };
            for (lookup, count) in lookups.iter().zip(counts) {
                if let Some(password) = self
                    .entries
                    .get_mut(&lookup.item)
                    .and_then(|entry| entry.passwords.get_mut(lookup.slot))
                {
                    password.verdict = Some(Verdict { count, at: now });
                    run.resolved += 1;
                }
            }
        }
        Ok(run)
    }

    pub fn report(&self, now: Time) -> Report {
        let mut counts = Counts::default();
        let mut items = Vec::new();
        for (&item, entry) in &self.entries {
            let findings = self.findings(entry, item, now);
            if findings.is_empty() {
                continue;
            }
            for finding in &findings {
                counts.add(finding.category());
            }
            items.push(ItemReport { item, findings });
        }
        items.sort_by(|a, b| b.severity().cmp(&a.severity()).then(a.item.cmp(&b.item)));
        Report { items, counts }
    }

    pub fn item_report(&self, key: Id, now: Time) -> Option<ItemReport> {
        let entry = self.entries.get(&key)?;
        let findings = self.findings(entry, key, now);
        (!findings.is_empty()).then_some(ItemReport {
            item: key,
            findings,
        })
    }

    fn detach(&mut self, key: Id) -> Option<Entry> {
        let entry = self.entries.remove(&key)?;
        for password in &entry.passwords {
            if let Some(group) = self.groups.get_mut(&password.tag) {
                group.remove(&key);
                if group.is_empty() {
                    self.groups.remove(&password.tag);
                }
            }
        }
        Some(entry)
    }

    fn passwords_of(&self, item: &Item, previous: Option<&Entry>) -> Vec<Password> {
        let mut out: Vec<Password> = Vec::new();
        let fields = item
            .details()
            .sections
            .iter()
            .flat_map(Section::fields)
            .filter(|field| field.purpose() == Some(Purpose::Password));
        for field in fields {
            let FieldValue::Concealed(secret) = field.value() else {
                continue;
            };
            let text = secret.expose_secret();
            if text.is_empty() {
                continue;
            }
            let tag = hmac_sha256(&self.tag_key, text.as_bytes());
            if out.iter().any(|known| known.tag == tag) {
                continue;
            }
            let bits = estimate_bits(text);
            let verdict = previous
                .and_then(|entry| entry.passwords.iter().find(|known| known.tag == tag))
                .and_then(|known| known.verdict);
            out.push(Password {
                tag,
                sha1: sha1_of_secret(text.as_bytes()),
                bits,
                reasons: weak_reasons(text, bits),
                verdict,
            });
        }
        out
    }

    fn pending_lookups(&self, now: Time) -> BTreeMap<Prefix, Vec<Lookup>> {
        let mut pending: BTreeMap<Prefix, Vec<Lookup>> = BTreeMap::new();
        for (&item, entry) in &self.entries {
            if !entry.checks.contains(&WatchtowerCheck::Vulnerable) {
                continue;
            }
            for (slot, password) in entry.passwords.iter().enumerate() {
                let fresh = password
                    .verdict
                    .is_some_and(|v| now.saturating_sub(v.at) < pwned::CACHE_TTL_S);
                if fresh {
                    continue;
                }
                if let Some((prefix, suffix)) = split_digest(&password.sha1) {
                    pending
                        .entry(prefix)
                        .or_default()
                        .push(Lookup { item, slot, suffix });
                }
            }
        }
        pending
    }

    fn cache_counts(&self, prefix: &Prefix, lookups: &[Lookup], now: Time) -> Option<Vec<u64>> {
        lookups
            .iter()
            .map(|lookup| self.cache.lookup(prefix, &lookup.suffix, now))
            .collect()
    }

    fn findings(&self, entry: &Entry, key: Id, now: Time) -> Vec<Finding> {
        let mut findings = Vec::new();
        let count = entry
            .passwords
            .iter()
            .filter_map(|p| p.verdict)
            .map(|v| v.count)
            .max()
            .filter(|count| *count > 0);
        if let Some(count) = count {
            findings.push(Finding {
                severity: Severity::High,
                detail: Detail::Pwned { count },
            });
        }
        if let Some(items) = self.reuse_size(entry, key) {
            findings.push(Finding {
                severity: Severity::Medium,
                detail: Detail::Reused { items },
            });
        }
        if let Some(finding) = weak_finding(entry) {
            findings.push(finding);
        }
        if entry.insecure_url {
            findings.push(Finding {
                severity: Severity::Medium,
                detail: Detail::InsecureUrl,
            });
        }
        if let Some(finding) = expiring_finding(entry, now) {
            findings.push(finding);
        }
        findings
    }

    fn reuse_size(&self, entry: &Entry, key: Id) -> Option<usize> {
        if !entry.checks.contains(&WatchtowerCheck::Reused) {
            return None;
        }
        entry
            .passwords
            .iter()
            .filter_map(|password| self.groups.get(&password.tag))
            .filter(|group| group.len() > 1 && group.contains(&key))
            .map(BTreeSet::len)
            .max()
    }
}

fn weak_finding(entry: &Entry) -> Option<Finding> {
    if !entry.checks.contains(&WatchtowerCheck::Weak) {
        return None;
    }
    let weakest = entry
        .passwords
        .iter()
        .filter(|password| !password.reasons.is_empty())
        .min_by(|a, b| a.bits.total_cmp(&b.bits))?;
    let severity = if weakest.bits < SEVERE_BITS {
        Severity::High
    } else {
        Severity::Medium
    };
    Some(Finding {
        severity,
        detail: Detail::Weak {
            bits: rounded(weakest.bits),
            reasons: weakest.reasons.clone(),
        },
    })
}

fn expiring_finding(entry: &Entry, now: Time) -> Option<Finding> {
    let window = i64::from(entry.window_days);
    let days_left = entry
        .expiries
        .iter()
        .map(|&expiry| checks::days_until(expiry, now))
        .filter(|days| *days <= window)
        .min()?;
    let severity = if days_left < 0 {
        Severity::High
    } else if days_left <= EXPIRING_SOON_DAYS {
        Severity::Medium
    } else {
        Severity::Low
    };
    Some(Finding {
        severity,
        detail: Detail::Expiring { days_left },
    })
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to the u32 range first"
)]
fn rounded(bits: f64) -> u32 {
    bits.round().clamp(0.0, f64::from(u32::MAX)) as u32
}
