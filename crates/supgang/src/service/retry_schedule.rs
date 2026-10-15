//! Fleet-aligned retry windows for best-effort two-peer NAT recovery.

use std::time::Duration;

use crate::ids::HiveId;

pub(super) fn should_attempt_peer(
    active: &std::collections::BTreeMap<crate::ids::NodeId, super::active::ActiveConnection>,
    peer: crate::ids::NodeId,
) -> bool {
    // A receiver behind a stateful firewall may need its own outbound packet
    // before any peer packet can enter. Identity ordering selects the retained
    // connection, never which device is allowed to participate in recovery.
    !active.contains_key(&peer)
}

/// Whether a live connection to `peer` runs over a path that is not directly
/// attached here, so a directly attached path to the same peer would be
/// better: back on the home LAN, a connection through the gateway's public
/// forward keeps working by hairpin, and nothing else would replace it.
pub(super) fn wants_on_link_path(
    active: &std::collections::BTreeMap<crate::ids::NodeId, super::active::ActiveConnection>,
    peer: crate::ids::NodeId,
    networks: &[crate::network::InterfaceNetwork],
) -> bool {
    active.get(&peer).is_some_and(|connection| {
        let remote = connection.remote_address().ip().to_canonical();
        !networks.iter().any(|network| network.contains(remote))
    })
}

/// Keeps the preferred path and the other address family in every mixed batch.
/// Rotates the remaining hints within the same fixed packet-attempt budget.
pub(super) fn candidate_batch(addresses: &[std::net::SocketAddr], cycle: usize) -> Vec<std::net::SocketAddr> {
    let limit = crate::network::MAX_DIAL_CANDIDATES_PER_ROUND;
    let Some(first) = addresses.first().copied() else {
        return Vec::new();
    };
    let other_family = addresses
        .iter()
        .position(|address| address.is_ipv4() != first.is_ipv4());
    let mut batch = vec![first];
    if let Some(address) = other_family.and_then(|index| addresses.get(index)) {
        batch.push(*address);
    }
    let tail = addresses
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 0 && Some(*index) != other_family)
        .map(|(_, address)| *address)
        .collect::<Vec<_>>();
    let slots = limit.saturating_sub(batch.len());
    let remaining = tail.len();
    if remaining <= slots {
        batch.extend(tail);
    } else {
        let offset = (cycle % remaining) * slots % remaining;
        batch.extend((0..slots).filter_map(|index| tail.get((offset + index) % remaining).copied()));
    }
    batch
}

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

    use super::{aligned_retry_delay, candidate_batch, next_service_wait, retry_epoch};
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

    #[test]
    fn every_candidate_gets_a_bounded_attempt_including_the_tail() {
        for count in 0_u16..=128 {
            let addresses = (1..=count)
                .map(|port| std::net::SocketAddr::from(([127, 0, 0, 1], port)))
                .collect::<Vec<_>>();
            let mut seen = std::collections::BTreeSet::new();
            for cycle in 0..usize::from(count).max(1) {
                let batch = candidate_batch(&addresses, cycle);
                assert!(batch.len() <= crate::network::MAX_DIAL_CANDIDATES_PER_ROUND);
                assert_eq!(batch.first(), addresses.first());
                assert_eq!(
                    batch.iter().collect::<std::collections::BTreeSet<_>>().len(),
                    batch.len()
                );
                seen.extend(batch);
            }
            assert_eq!(seen, addresses.into_iter().collect());
        }
    }

    #[test]
    fn both_address_families_participate_in_every_mixed_retry() -> Result<(), Box<dyn std::error::Error>> {
        for reverse in [false, true] {
            let mut addresses = (1..=7)
                .map(|port| std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)))
                .collect::<Vec<_>>();
            addresses.push("127.0.0.1:100".parse()?);
            if reverse {
                addresses.reverse();
            }
            let mut seen = std::collections::BTreeSet::new();
            for cycle in 0..32 {
                let batch = candidate_batch(&addresses, cycle);
                assert!(batch.len() <= crate::network::MAX_DIAL_CANDIDATES_PER_ROUND);
                assert_eq!(
                    batch.iter().collect::<std::collections::BTreeSet<_>>().len(),
                    batch.len()
                );
                assert_eq!(batch.first(), addresses.first());
                assert!(batch.iter().any(std::net::SocketAddr::is_ipv4));
                assert!(batch.iter().any(std::net::SocketAddr::is_ipv6));
                assert_ne!(
                    batch.first().map(std::net::SocketAddr::is_ipv4),
                    batch.get(1).map(std::net::SocketAddr::is_ipv4)
                );
                seen.extend(batch);
            }
            assert_eq!(seen, addresses.into_iter().collect());
        }
        Ok(())
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
