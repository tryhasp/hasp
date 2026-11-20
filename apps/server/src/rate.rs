use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RateClass {
    Login,
    Register,
    Recovery,
    General,
    Socket,
}

#[derive(Clone, Copy, Debug)]
pub struct RateKey<'a> {
    pub peer: Option<IpAddr>,
    pub subject: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimited {
    pub retry_after: u64,
}

pub trait RateLimiter: Send + Sync {
    fn admit(&self, class: RateClass, key: &RateKey<'_>, now: u64) -> Result<(), RateLimited>;
    fn record_failure(&self, class: RateClass, key: &RateKey<'_>, now: u64);
    fn record_success(&self, class: RateClass, key: &RateKey<'_>, now: u64);
    fn prune(&self, _now: u64) {}
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Unlimited;

impl RateLimiter for Unlimited {
    fn admit(&self, _: RateClass, _: &RateKey<'_>, _: u64) -> Result<(), RateLimited> {
        Ok(())
    }

    fn record_failure(&self, _: RateClass, _: &RateKey<'_>, _: u64) {}

    fn record_success(&self, _: RateClass, _: &RateKey<'_>, _: u64) {}
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub login_per_peer: u32,
    pub login_failures: u32,
    pub register_per_peer: u32,
    pub recovery_per_subject: u32,
    pub recovery_per_peer: u32,
    pub general_per_subject: u32,
    pub socket_per_peer: u32,
    pub backoff_cap: u64,
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            login_per_peer: 10,
            login_failures: 5,
            register_per_peer: 5,
            recovery_per_subject: 3,
            recovery_per_peer: 10,
            general_per_subject: 1200,
            socket_per_peer: 10,
            backoff_cap: 15 * 60,
            max_entries: 100_000,
        }
    }
}

const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const FAILURE_WINDOW: u64 = 15 * 60;
const ACCOUNT_BUDGET_FACTOR: u32 = 4;

#[derive(Clone, Copy, Debug)]
struct Window {
    start: u64,
    span: u64,
    count: u32,
}

type WindowKey = (RateClass, bool, Vec<u8>);
type FailureKey = (Vec<u8>, Option<Vec<u8>>);

#[derive(Debug, Default)]
struct Counters {
    windows: BTreeMap<WindowKey, Window>,
    failures: BTreeMap<FailureKey, (u64, u32)>,
    cap: usize,
    backoff_cap: u64,
}

#[derive(Debug)]
pub struct WindowLimiter {
    limits: Limits,
    counters: Mutex<Counters>,
}

pub(crate) fn peer_bucket(peer: IpAddr) -> Vec<u8> {
    match peer.to_canonical() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().iter().take(8).copied().collect(),
    }
}

impl WindowLimiter {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            counters: Mutex::new(Counters {
                cap: limits.max_entries,
                backoff_cap: limits.backoff_cap,
                ..Counters::default()
            }),
        }
    }

    fn peer_bytes(key: &RateKey<'_>) -> Option<Vec<u8>> {
        key.peer.map(peer_bucket)
    }

    fn counters(&self) -> Result<MutexGuard<'_, Counters>, RateLimited> {
        self.counters.lock().map_err(|poisoned| {
            let mut counters = poisoned.into_inner();
            *counters = Counters {
                cap: self.limits.max_entries,
                backoff_cap: self.limits.backoff_cap,
                ..Counters::default()
            };
            drop(counters);
            self.counters.clear_poison();
            RateLimited { retry_after: 1 }
        })
    }

    #[cfg(test)]
    fn sizes(&self) -> (usize, usize) {
        self.counters
            .lock()
            .map(|c| (c.windows.len(), c.failures.len()))
            .unwrap_or_default()
    }
}

impl Counters {
    fn hit(
        &mut self,
        key: WindowKey,
        (limit, span): (u32, u64),
        now: u64,
    ) -> Result<(), RateLimited> {
        let key = if self.windows.len() >= self.cap && !self.windows.contains_key(&key) {
            (key.0, key.1, Vec::new())
        } else {
            key
        };
        let window = self.windows.entry(key).or_insert(Window {
            start: now,
            span,
            count: 0,
        });
        if now.saturating_sub(window.start) >= span {
            *window = Window {
                start: now,
                span,
                count: 0,
            };
        }
        if window.count >= limit {
            return Err(RateLimited {
                retry_after: span.saturating_sub(now.saturating_sub(window.start)).max(1),
            });
        }
        window.count = window.count.saturating_add(1);
        Ok(())
    }

    fn backoff(&self, key: &FailureKey, threshold: u32, now: u64) -> Result<(), RateLimited> {
        let Some(&(last, count)) = self.failures.get(key) else {
            return Ok(());
        };
        if count < threshold {
            return Ok(());
        }
        let wait = 1_u64
            .checked_shl(count.saturating_sub(threshold).min(20))
            .unwrap_or(self.backoff_cap)
            .min(self.backoff_cap);
        let until = last.saturating_add(wait);
        if now < until {
            return Err(RateLimited {
                retry_after: until.saturating_sub(now),
            });
        }
        Ok(())
    }

    fn fail(&mut self, key: FailureKey, now: u64) {
        if self.failures.len() >= self.cap && !self.failures.contains_key(&key) {
            return;
        }
        let entry = self.failures.entry(key).or_insert((now, 0));
        if now.saturating_sub(entry.0) > FAILURE_WINDOW.saturating_add(self.backoff_cap) {
            *entry = (now, 0);
        }
        *entry = (now, entry.1.saturating_add(1));
    }
}

impl RateLimiter for WindowLimiter {
    fn admit(&self, class: RateClass, key: &RateKey<'_>, now: u64) -> Result<(), RateLimited> {
        let mut counters = self.counters()?;
        let limits = self.limits;
        let peer = Self::peer_bytes(key);
        let subject = key.subject.map(<[u8]>::to_vec);
        match class {
            RateClass::Login => {
                if let Some(peer) = &peer {
                    counters.hit(
                        (class, true, peer.clone()),
                        (limits.login_per_peer, MINUTE),
                        now,
                    )?;
                }
                let Some(subject) = subject else {
                    return Ok(());
                };
                match peer {
                    Some(peer) => {
                        counters.backoff(
                            &(subject.clone(), Some(peer)),
                            limits.login_failures,
                            now,
                        )?;
                        let budget = limits.login_failures.saturating_mul(ACCOUNT_BUDGET_FACTOR);
                        counters.backoff(&(subject, None), budget, now)
                    }
                    None => counters.backoff(&(subject, None), limits.login_failures, now),
                }
            }
            RateClass::Register => match peer {
                Some(peer) => {
                    counters.hit((class, true, peer), (limits.register_per_peer, HOUR), now)
                }
                None => Ok(()),
            },
            RateClass::Recovery => {
                let mut budget = limits.recovery_per_subject;
                if let Some(peer) = &peer {
                    counters.hit(
                        (class, true, peer.clone()),
                        (limits.recovery_per_peer, HOUR),
                        now,
                    )?;
                    if let Some(subject) = &subject {
                        let pair = [subject.as_slice(), peer.as_slice()].concat();
                        counters.hit((class, true, pair), (budget, HOUR), now)?;
                    }
                    budget = budget.saturating_mul(ACCOUNT_BUDGET_FACTOR);
                }
                match subject {
                    Some(subject) => counters.hit((class, false, subject), (budget, HOUR), now),
                    None => Ok(()),
                }
            }
            RateClass::Socket => match peer {
                Some(peer) => {
                    counters.hit((class, true, peer), (limits.socket_per_peer, MINUTE), now)
                }
                None => Ok(()),
            },
            RateClass::General => match subject {
                Some(subject) => counters.hit(
                    (class, false, subject),
                    (limits.general_per_subject, MINUTE),
                    now,
                ),
                None => Ok(()),
            },
        }
    }

    fn record_failure(&self, class: RateClass, key: &RateKey<'_>, now: u64) {
        if class != RateClass::Login {
            return;
        }
        let (Some(subject), Ok(mut counters)) = (key.subject, self.counters()) else {
            return;
        };
        let peer = Self::peer_bytes(key);
        if peer.is_some() {
            counters.fail((subject.to_vec(), peer), now);
        }
        counters.fail((subject.to_vec(), None), now);
    }

    fn record_success(&self, class: RateClass, key: &RateKey<'_>, _now: u64) {
        if class != RateClass::Login {
            return;
        }
        let (Some(subject), Ok(mut counters)) = (key.subject, self.counters()) else {
            return;
        };
        counters
            .failures
            .remove(&(subject.to_vec(), Self::peer_bytes(key)));
        counters.failures.remove(&(subject.to_vec(), None));
    }

    fn prune(&self, now: u64) {
        let Ok(mut counters) = self.counters() else {
            return;
        };
        counters
            .windows
            .retain(|_, window| now.saturating_sub(window.start) < window.span);
        let keep = FAILURE_WINDOW.saturating_add(self.limits.backoff_cap);
        counters
            .failures
            .retain(|_, (last, _)| now.saturating_sub(*last) <= keep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(subject: &[u8]) -> RateKey<'_> {
        RateKey {
            peer: Some(IpAddr::from([10, 0, 0, 1])),
            subject: Some(subject),
        }
    }

    #[test]
    fn login_per_peer_window_blocks_then_resets() {
        let limiter = WindowLimiter::new(Limits::default());
        for _ in 0..10 {
            limiter.admit(RateClass::Login, &key(b"a"), 100).unwrap();
        }
        let blocked = limiter
            .admit(RateClass::Login, &key(b"a"), 101)
            .unwrap_err();
        assert!(blocked.retry_after > 0);
        limiter.admit(RateClass::Login, &key(b"a"), 161).unwrap();
    }

    #[test]
    fn failures_back_off_exponentially_and_success_clears_them() {
        let limiter = WindowLimiter::new(Limits {
            login_per_peer: 1000,
            ..Limits::default()
        });
        for _ in 0..5 {
            limiter.record_failure(RateClass::Login, &key(b"a"), 100);
        }
        assert!(limiter.admit(RateClass::Login, &key(b"a"), 100).is_err());
        assert!(limiter.admit(RateClass::Login, &key(b"b"), 100).is_ok());
        assert!(limiter.admit(RateClass::Login, &key(b"a"), 102).is_ok());
        limiter.record_failure(RateClass::Login, &key(b"a"), 102);
        assert!(limiter.admit(RateClass::Login, &key(b"a"), 103).is_err());
        limiter.record_success(RateClass::Login, &key(b"a"), 200);
        assert!(limiter.admit(RateClass::Login, &key(b"a"), 200).is_ok());
    }

    #[test]
    fn one_peer_cannot_lock_an_account_out_for_everyone() {
        let limiter = WindowLimiter::new(Limits {
            login_per_peer: 1000,
            ..Limits::default()
        });
        let attacker = key(b"a");
        let owner = RateKey {
            peer: Some(IpAddr::from([10, 0, 0, 2])),
            subject: Some(b"a"),
        };
        for _ in 0..8 {
            limiter.record_failure(RateClass::Login, &attacker, 100);
        }
        assert!(limiter.admit(RateClass::Login, &attacker, 100).is_err());
        assert!(limiter.admit(RateClass::Login, &owner, 100).is_ok());
    }

    #[test]
    fn many_peers_failing_still_trip_the_account_budget() {
        let limiter = WindowLimiter::new(Limits {
            login_per_peer: 1000,
            ..Limits::default()
        });
        for last in 0..20_u8 {
            let from = RateKey {
                peer: Some(IpAddr::from([10, 0, 1, last])),
                subject: Some(b"a"),
            };
            limiter.record_failure(RateClass::Login, &from, 100);
        }
        let owner = RateKey {
            peer: Some(IpAddr::from([10, 0, 0, 2])),
            subject: Some(b"a"),
        };
        assert!(limiter.admit(RateClass::Login, &owner, 100).is_err());
    }

    #[test]
    fn recovery_attempts_from_one_peer_leave_the_owner_budget() {
        let limiter = WindowLimiter::new(Limits {
            recovery_per_peer: 1000,
            ..Limits::default()
        });
        for _ in 0..3 {
            limiter.admit(RateClass::Recovery, &key(b"a"), 0).unwrap();
        }
        assert!(limiter.admit(RateClass::Recovery, &key(b"a"), 1).is_err());
        let owner = RateKey {
            peer: Some(IpAddr::from([10, 0, 0, 2])),
            subject: Some(b"a"),
        };
        assert!(limiter.admit(RateClass::Recovery, &owner, 1).is_ok());
    }

    #[test]
    fn backoff_is_capped() {
        let limiter = WindowLimiter::new(Limits {
            login_per_peer: 1000,
            ..Limits::default()
        });
        for _ in 0..40 {
            limiter.record_failure(RateClass::Login, &key(b"a"), 100);
        }
        let blocked = limiter
            .admit(RateClass::Login, &key(b"a"), 100)
            .unwrap_err();
        assert_eq!(blocked.retry_after, 900);
    }

    #[test]
    fn recovery_is_limited_per_account() {
        let limiter = WindowLimiter::new(Limits::default());
        for _ in 0..3 {
            limiter
                .admit(RateClass::Recovery, &key(b"acct"), 0)
                .unwrap();
        }
        assert!(
            limiter
                .admit(RateClass::Recovery, &key(b"acct"), 1)
                .is_err()
        );
        assert!(
            limiter
                .admit(RateClass::Recovery, &key(b"other"), 1)
                .is_ok()
        );
    }

    #[test]
    fn unlimited_never_refuses() {
        for _ in 0..1000 {
            Unlimited.admit(RateClass::Login, &key(b"a"), 0).unwrap();
        }
    }

    #[test]
    fn prune_drops_expired_windows_and_failures() {
        let limiter = WindowLimiter::new(Limits::default());
        limiter.admit(RateClass::General, &key(b"s"), 0).unwrap();
        limiter.record_failure(RateClass::Login, &key(b"a"), 0);
        assert_eq!(limiter.sizes(), (1, 2));
        limiter.prune(30);
        assert_eq!(limiter.sizes(), (1, 2));
        limiter.prune(100_000);
        assert_eq!(limiter.sizes(), (0, 0));
    }

    #[test]
    fn state_stays_bounded_under_attacker_chosen_keys() {
        let limiter = WindowLimiter::new(Limits {
            max_entries: 50,
            ..Limits::default()
        });
        for i in 0_u32..500 {
            let subject = i.to_be_bytes();
            limiter
                .admit(RateClass::General, &key(&subject), 0)
                .unwrap();
            limiter.record_failure(RateClass::Login, &key(&subject), 0);
        }
        let (windows, failures) = limiter.sizes();
        assert!(windows <= 51);
        assert!(failures <= 50);
    }

    #[test]
    fn full_table_shares_one_bucket_for_new_keys_only() {
        let limiter = WindowLimiter::new(Limits {
            max_entries: 7,
            recovery_per_subject: 1,
            recovery_per_peer: 1000,
            ..Limits::default()
        });
        limiter.admit(RateClass::Recovery, &key(b"a"), 0).unwrap();
        limiter.admit(RateClass::Recovery, &key(b"b"), 0).unwrap();
        limiter.admit(RateClass::Recovery, &key(b"c"), 0).unwrap();
        limiter.admit(RateClass::Recovery, &key(b"d"), 0).unwrap();
        assert!(limiter.admit(RateClass::Recovery, &key(b"e"), 0).is_err());
    }

    #[test]
    fn ipv6_peers_share_a_bucket_per_64() {
        let limiter = WindowLimiter::new(Limits::default());
        let at = |last: u16| RateKey {
            peer: Some(IpAddr::from([0x2001, 0xdb8, 1, 2, 0, 0, 0, last])),
            subject: None,
        };
        for i in 0..5 {
            limiter.admit(RateClass::Register, &at(i), 0).unwrap();
        }
        assert!(limiter.admit(RateClass::Register, &at(99), 0).is_err());
        let other = RateKey {
            peer: Some(IpAddr::from([0x2001, 0xdb8, 1, 3, 0, 0, 0, 1])),
            subject: None,
        };
        limiter.admit(RateClass::Register, &other, 0).unwrap();
    }

    #[test]
    fn poisoned_limiter_fails_closed_once_then_recovers() {
        let limiter = std::sync::Arc::new(WindowLimiter::new(Limits::default()));
        let held = std::sync::Arc::clone(&limiter);
        let _panicked = std::thread::spawn(move || {
            let _guard = held.counters.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(limiter.admit(RateClass::General, &key(b"a"), 0).is_err());
        assert!(limiter.admit(RateClass::General, &key(b"a"), 0).is_ok());
    }
}
