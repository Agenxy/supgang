use super::compact_addresses;
use crate::cli_peer::ResolvedCandidate;

fn candidate(scope: &str, address: &str, preferred: bool) -> ResolvedCandidate {
    ResolvedCandidate {
        scope: scope.to_owned(),
        kind: if scope == "local" { "local" } else { "direct" }.to_owned(),
        transport: "quic-v1".to_owned(),
        address: address.to_owned(),
        provenance: "device-signed".to_owned(),
        reporter: None,
        report_expires_at: None,
        route_compatible: preferred,
        preferred,
    }
}

fn public_candidate(kind: &str, address: &str) -> ResolvedCandidate {
    ResolvedCandidate {
        scope: "public".to_owned(),
        kind: kind.to_owned(),
        transport: "quic-v1".to_owned(),
        address: address.to_owned(),
        provenance: "device-signed".to_owned(),
        reporter: None,
        report_expires_at: None,
        route_compatible: true,
        preferred: false,
    }
}

#[test]
fn compact_view_keeps_one_preferred_and_one_ipv4_public_alternative() {
    let addresses = [
        candidate("local", "192.168.1.20:44330", true),
        candidate("local", "192.168.64.1:44330", false),
        candidate("public", "[2606:4700:4700::1111]:44330", false),
        candidate("public", "8.8.8.8:44330", false),
    ];
    let selected = compact_addresses(&addresses);
    assert_eq!(selected.len(), 2);
    assert_eq!(
        selected.first().map(|candidate| candidate.address.as_str()),
        Some("192.168.1.20:44330")
    );
    assert_eq!(
        selected.get(1).map(|candidate| candidate.address.as_str()),
        Some("8.8.8.8:44330")
    );
}

#[test]
fn compact_view_does_not_recommend_historical_addresses() {
    let addresses = [candidate("local", "192.168.1.20:44330", false)];
    assert!(compact_addresses(&addresses).is_empty());
}

#[test]
fn compact_view_shows_mapping_instead_of_incidental_direct_interface() {
    let addresses = [
        candidate("local", "192.168.1.20:44330", true),
        public_candidate("direct", "8.8.8.8:44330"),
        public_candidate("mapped", "9.9.9.9:44330"),
    ];
    let selected = compact_addresses(&addresses);
    assert_eq!(selected.len(), 2);
    assert_eq!(selected.get(1).map(|candidate| candidate.kind.as_str()), Some("mapped"));
}
