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

#[test]
fn a_live_connection_address_remains_visible_after_address_reports_expire() -> Result<(), Box<dyn std::error::Error>> {
    let mut peer: crate::cli_peer::PeerRow = serde_json::from_value(serde_json::json!({
        "name":"Test Peer", "name_source":"device-signed", "fingerprint":"12345678", "node_id":"test",
        "connected":true, "status":"fresh", "generation":0, "sequence":1, "expires_at":1000,
        "candidate_count":0, "addresses":[],
        "connection":{"remote_address":"192.0.2.1:44330", "received_datagrams":3, "sent_datagrams":4}
    }))?;
    for all in [false, true] {
        let mut output = Vec::new();
        super::render_computer(&peer, false, all, &mut output, &mut 0)?;
        let output = String::from_utf8(output)?;
        assert!(output.contains("192.0.2.1:44330 (current connection)"));
        assert!(!output.contains("no current address"));
    }
    peer.connected = Some(false);
    let mut output = Vec::new();
    super::render_computer(&peer, false, false, &mut output, &mut 0)?;
    assert!(!std::str::from_utf8(&output)?.contains("current connection"));
    peer.connected = Some(true);
    peer.addresses.push(candidate("local", "192.168.1.2:44330", true));
    output.clear();
    super::render_computer(&peer, false, false, &mut output, &mut 0)?;
    let text = String::from_utf8(output)?;
    assert!(text.contains("192.0.2.1:44330 (current connection)"));
    assert!(!text.contains("192.168.1.2"));
    for connected in [None, Some(false), Some(true)] {
        peer.connected = connected;
        for status in ["revoked", "equivocation", "expired"] {
            peer.status = status.to_owned();
            assert!(!matches!(
                super::peer_status_label(&peer),
                "connected" | "not connected" | "connection unknown"
            ));
        }
    }
    Ok(())
}
