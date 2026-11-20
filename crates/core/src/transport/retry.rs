use std::time::Duration;

/// Exponential backoff with equal jitter: the wait before retry `n` is uniform in
/// `[cap / 2, cap]` where `cap = min(max_delay, base_delay * 2^(n-1))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    pub const fn standard() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(4),
        }
    }

    pub const fn never() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    pub fn delay(&self, retry: u32, entropy: u64) -> Duration {
        let shift = retry.saturating_sub(1).min(20);
        let cap = self
            .base_delay
            .saturating_mul(1_u32 << shift)
            .min(self.max_delay);
        let floor = cap / 2;
        let span = cap.saturating_sub(floor);
        let nanos = span.as_nanos().saturating_mul(u128::from(entropy)) / u128::from(u64::MAX);
        floor.saturating_add(Duration::from_nanos(
            u64::try_from(nanos).unwrap_or(u64::MAX),
        ))
    }
}

pub fn entropy() -> u64 {
    hasp_crypto::random_array::<8>().map_or(u64::MAX / 2, u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use hasp_proto::wire::OpId;

    use super::RetryPolicy;
    use crate::transport::http::is_idempotent;
    use std::time::Duration;

    const POLICY: RetryPolicy = RetryPolicy {
        max_attempts: 5,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(500),
    };

    #[test]
    fn the_wait_doubles_until_the_cap() {
        assert_eq!(POLICY.delay(1, u64::MAX), Duration::from_millis(100));
        assert_eq!(POLICY.delay(2, u64::MAX), Duration::from_millis(200));
        assert_eq!(POLICY.delay(3, u64::MAX), Duration::from_millis(400));
        assert_eq!(POLICY.delay(4, u64::MAX), Duration::from_millis(500));
        assert_eq!(POLICY.delay(40, u64::MAX), Duration::from_millis(500));
    }

    #[test]
    fn jitter_spans_the_upper_half_of_the_cap() {
        assert_eq!(POLICY.delay(2, 0), Duration::from_millis(100));
        assert_eq!(POLICY.delay(2, u64::MAX), Duration::from_millis(200));
        let middle = POLICY.delay(2, u64::MAX / 2);
        assert!(middle > Duration::from_millis(100) && middle < Duration::from_millis(200));
    }

    #[test]
    fn never_waits_zero_and_allows_one_attempt() {
        assert_eq!(RetryPolicy::never().max_attempts, 1);
        assert_eq!(RetryPolicy::never().delay(1, 7), Duration::ZERO);
    }

    #[test]
    fn reads_and_protocol_idempotent_writes_retry() {
        for op in [
            OpId::Pull,
            OpId::Commit,
            OpId::RepairPublish,
            OpId::AttachmentPut,
            OpId::Health,
        ] {
            assert!(is_idempotent(op), "{op:?}");
        }
    }

    #[test]
    fn credential_and_one_shot_writes_never_retry() {
        for op in [
            OpId::RegisterFinish,
            OpId::LoginFinish,
            OpId::SessionRevoke,
            OpId::InviteAccept,
            OpId::AccountDelete,
            OpId::AdminTokenCreate,
        ] {
            assert!(!is_idempotent(op), "{op:?}");
        }
    }
}
