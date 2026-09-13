//! Fleet-aligned retry windows for best-effort two-peer NAT recovery.

use std::time::Duration;

use crate::ids::HiveId;

/// Returns the next shared hive retry boundary after `now`.
pub(super) fn aligned_retry_delay(hive: HiveId, now: Duration, interval: Duration) -> Duration {
    let interval_millis = interval.as_millis().max(1);
    let offset = u128::from(hive_offset_seed(hive)) % interval_millis;
    let phase = now.as_millis() % interval_millis;
    let delay = if phase < offset {
        offset - phase
    } else {
        interval_millis - (phase - offset)
    };
    Duration::from_millis(u64::try_from(delay).unwrap_or(u64::MAX).max(1))
}

/// Returns the stable wall-clock retry round shared by members using `interval`.
pub(super) fn retry_epoch(now: Duration, interval: Duration) -> usize {
    let interval_millis = interval.as_millis().max(1);
    usize::try_from(now.as_millis() / interval_millis).unwrap_or(usize::MAX)
}

pub(super) fn next_service_wait(
    outbound_in_flight: bool,
    next_dial: tokio::time::Instant,
    next_refresh: tokio::time::Instant,
    next_interface_refresh: Option<tokio::time::Instant>,
) -> Duration {
    let now = tokio::time::Instant::now();
    let until_dial = if outbound_in_flight {
        Duration::MAX
    } else {
        next_dial.saturating_duration_since(now)
    };
    let until_interface_refresh =
        next_interface_refresh.map_or(Duration::MAX, |next| next.saturating_duration_since(now));
    until_dial
        .min(next_refresh.saturating_duration_since(now))
        .min(until_interface_refresh)
        .min(Duration::from_secs(1))
}

fn hive_offset_seed(hive: HiveId) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&hive.as_bytes()[..8]);
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{aligned_retry_delay, next_service_wait, retry_epoch};
    use crate::ids::HiveId;

    #[test]
    fn every_member_of_a_hive_uses_the_same_future_boundary() {
        let hive = HiveId::from_bytes([9; 32]);
        let interval = Duration::from_secs(15);
        let now = Duration::from_millis(1_234_567);
        let first = aligned_retry_delay(hive, now, interval);
        let second = aligned_retry_delay(hive, now, interval);
        assert_eq!(first, second);
        assert!(first > Duration::ZERO && first <= interval);
        assert_eq!(retry_epoch(now, interval), retry_epoch(now, interval));
    }

    #[test]
    fn different_hives_spread_their_retry_boundaries() {
        let now = Duration::from_secs(1_000);
        let interval = Duration::from_secs(15);
        let first = aligned_retry_delay(HiveId::from_bytes([1; 32]), now, interval);
        let second = aligned_retry_delay(HiveId::from_bytes([2; 32]), now, interval);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn an_idle_service_waits_for_the_outbound_retry_even_in_anchor_callers() {
        let now = tokio::time::Instant::now();
        let dial = now + Duration::from_millis(10);
        let refresh = now + Duration::from_secs(10);
        let wait = next_service_wait(false, dial, refresh, None);
        assert!(wait <= Duration::from_millis(10));
        assert!(wait < Duration::from_secs(1));
    }
}
