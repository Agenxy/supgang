//! Two-node simulated-network and authenticated-session tests for gang release awareness.

use std::{net::Ipv4Addr, time::Duration};

use super::sim_harness::{Error, Fleet, eventually, wait_connected};
use crate::{
    cli,
    control::{self, ControlReply, ControlRequest},
    ids::NodeId,
    release::{self, MAX_RELEASE_FRAME_BYTES, ReleaseIdentity, UpdateNotice},
    rendezvous::{self, MAX_RENDEZVOUS_FRAME_BYTES, RendezvousError},
    service::{PeerEvent, rendezvous as service_rendezvous},
    simnet::{Network, SiteSpec, V4Access},
};

const PAIRING: Duration = Duration::from_secs(30);
const NOTICE_WAIT: Duration = Duration::from_secs(10);

fn two_node_fleet(first_release: ReleaseIdentity, second_release: ReleaseIdentity) -> Result<Fleet, Error> {
    let network = Network::new(42);
    let lan = network.add_site(SiteSpec {
        v4: Some(V4Access::Public {
            first: Ipv4Addr::new(198, 51, 100, 10),
        }),
        v6: None,
    })?;
    let first = network.add_host(Some(lan))?;
    let second = network.add_host(Some(lan))?;
    let mut fleet = Fleet::pair(network, &[first, second])?;
    fleet.set_release_identity(0, first_release)?;
    fleet.set_release_identity(1, second_release)?;
    fleet.start_all()?;
    wait_connected(&fleet, 0, 1, PAIRING)?;
    wait_connected(&fleet, 1, 0, PAIRING)?;
    Ok(fleet)
}

fn wait_for_notice(path: &std::path::Path) -> Result<UpdateNotice, Error> {
    eventually(NOTICE_WAIT, || {
        let Some(ControlReply::Status { value }) = control::request(path, ControlRequest::Status)? else {
            return Ok(None);
        };
        Ok(value.update_notice)
    })?
    .ok_or_else(|| "expected update_notice was not observed in time".into())
}

fn run_cli_json(state: &std::path::Path, args: &[&str]) -> Result<serde_json::Value, Error> {
    let state_text = state.to_str().ok_or("non-UTF8 test state path")?;
    let mut full = vec!["supgang", "--state-dir", state_text, "--json"];
    full.extend_from_slice(args);
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = cli::run(full, &mut output, &mut error);
    if code != std::process::ExitCode::SUCCESS {
        return Err(format!("CLI failed: {}", String::from_utf8_lossy(&error)).into());
    }
    Ok(serde_json::from_slice(&output)?)
}

#[test]
fn older_node_notices_newer_peer_across_cli_doctor_status_fleet_and_mcp() -> Result<(), Error> {
    let older_id = ReleaseIdentity::new("0.2.0-alpha.21", Some("a".repeat(40)))?;
    let newer_id = ReleaseIdentity::new("0.2.0-alpha.22", Some("b".repeat(40)))?;
    let fleet = two_node_fleet(older_id, newer_id)?;
    let older = fleet.computer(0)?;
    let newer = fleet.computer(1)?;

    // Older node automatically notices the strictly higher SemVer peer.
    let notice = wait_for_notice(&older.path)?;
    assert_eq!(notice.kind, "update-available");
    assert_eq!(notice.local_version, "0.2.0-alpha.21");
    assert_eq!(notice.peer_version, "0.2.0-alpha.22");
    assert_eq!(notice.peers.len(), 1);
    assert_eq!(
        notice.peers.first().map(|peer| peer.node_id.as_str()),
        Some(newer.node.to_string().as_str())
    );
    // Update notices never include network addresses.
    let notice_json = serde_json::to_string(&notice)?;
    assert!(!notice_json.contains("198.51.100."));
    assert!(!notice_json.contains(":44330"));

    // Newer node does NOT report an update notice for the older peer.
    let Some(ControlReply::Status { value: newer_status }) = control::request(&newer.path, ControlRequest::Status)?
    else {
        return Err("newer node status missing".into());
    };
    assert!(newer_status.update_notice.is_none());

    assert_cli_and_mcp_update_notice(&older.path)?;
    Ok(())
}

fn assert_cli_and_mcp_update_notice(state_dir: &std::path::Path) -> Result<(), Error> {
    // Verify CLI JSON surfaces: doctor, status, peers.
    let doctor = run_cli_json(state_dir, &["doctor"])?;
    assert_eq!(
        doctor.pointer("/update_notice/kind"),
        Some(&serde_json::json!("update-available"))
    );
    assert_eq!(
        doctor.pointer("/update_notice/peer_version"),
        Some(&serde_json::json!("0.2.0-alpha.22"))
    );
    assert!(doctor.get("commit").and_then(serde_json::Value::as_str).is_some());

    let status = run_cli_json(state_dir, &["status"])?;
    assert_eq!(
        status.pointer("/update_notice/kind"),
        Some(&serde_json::json!("update-available"))
    );
    assert_eq!(status.get("running_commit"), Some(&serde_json::json!("a".repeat(40))));

    let peers = run_cli_json(state_dir, &["peers"])?;
    assert_eq!(
        peers.pointer("/update_notice/kind"),
        Some(&serde_json::json!("update-available"))
    );
    assert_eq!(
        peers.pointer("/peers/0/release/version"),
        Some(&serde_json::json!("0.2.0-alpha.22"))
    );
    assert_eq!(
        peers.pointer("/peers/0/release/commit"),
        Some(&serde_json::json!("b".repeat(40)))
    );

    // Verify human output names the newer release without leaking addresses in the notice line.
    let state_text = state_dir.to_str().ok_or("non-UTF8 test state path")?;
    let mut human = Vec::new();
    let mut human_err = Vec::new();
    assert_eq!(
        cli::run(
            ["supgang", "--state-dir", state_text, "status"],
            &mut human,
            &mut human_err
        ),
        std::process::ExitCode::SUCCESS
    );
    let human = String::from_utf8(human)?;
    assert!(human.contains("Update notice:"));
    assert!(human.contains("0.2.0-alpha.22"));

    // Verify MCP status and fleet tools expose update_notice cleanly.
    let mcp_status = crate::mcp::data_status_for_test(state_dir)?;
    assert_eq!(
        mcp_status.pointer("/update_notice/kind"),
        Some(&serde_json::json!("update-available"))
    );
    assert_eq!(
        mcp_status.pointer("/update_notice/peer_version"),
        Some(&serde_json::json!("0.2.0-alpha.22"))
    );
    let mcp_fleet = crate::mcp::data_fleet_for_test(state_dir)?;
    assert_eq!(
        mcp_fleet.pointer("/update_notice/kind"),
        Some(&serde_json::json!("update-available"))
    );
    assert_eq!(
        mcp_fleet.pointer("/peers/0/release/version"),
        Some(&serde_json::json!("0.2.0-alpha.22"))
    );
    Ok(())
}

#[test]
fn equal_version_with_different_commits_reports_build_differs() -> Result<(), Error> {
    let build_a = ReleaseIdentity::new("0.2.0-alpha.21", Some("a".repeat(40)))?;
    let build_b = ReleaseIdentity::new("0.2.0-alpha.21", Some("b".repeat(40)))?;
    let fleet = two_node_fleet(build_a, build_b)?;
    let node_a = fleet.computer(0)?;

    let notice = wait_for_notice(&node_a.path)?;
    assert_eq!(notice.kind, "build-differs");
    assert_eq!(notice.local_version, "0.2.0-alpha.21");
    assert_eq!(notice.peer_version, "0.2.0-alpha.21");
    assert!(notice.summary.contains("build differs"));

    let doctor = run_cli_json(&node_a.path, &["doctor"])?;
    assert_eq!(
        doctor.pointer("/update_notice/kind"),
        Some(&serde_json::json!("build-differs"))
    );
    let check_status = doctor
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check.get("id") == Some(&serde_json::json!("release-awareness")))
        })
        .and_then(|check| check.get("status"))
        .and_then(serde_json::Value::as_str);
    assert_eq!(check_status, Some("ok"));
    Ok(())
}

#[test]
fn malformed_and_oversized_release_reports_are_ignored_without_dropping_session() -> Result<(), Error> {
    crate::transport::build_runtime()?.block_on(async {
        let server_identity = crate::transport::TransportIdentity::generate()?;
        let server = quinn::Endpoint::server(
            server_identity.server_config()?,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )?;
        let client_identity = crate::transport::TransportIdentity::generate()?;
        let client = quinn::Endpoint::server(
            client_identity.server_config()?,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )?;
        let accepting = server.clone();
        let accepted = tokio::spawn(async move {
            let incoming = accepting.accept().await.ok_or("server closed")?;
            incoming.await.map_err(|error| error.to_string())
        });
        let client_connection = tokio::time::timeout(
            Duration::from_secs(5),
            client.connect_with(
                crate::transport::pinned_client_config(server_identity.key_id())?,
                server.local_addr()?,
                "supgang.invalid",
            )?,
        )
        .await??;
        let server_connection = accepted.await??;

        let peer = NodeId::from_bytes([7; 32]);
        let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(8);
        let listener = tokio::spawn(service_rendezvous::listener(
            server_connection.clone(),
            peer,
            event_sender,
        ));

        // 1. Oversized datagram above MAX_RENDEZVOUS_FRAME_BYTES.
        client_connection.send_datagram(vec![0xab; MAX_RENDEZVOUS_FRAME_BYTES + 32].into())?;
        // 2. Oversized release datagram above MAX_RELEASE_FRAME_BYTES.
        client_connection.send_datagram(vec![0xcd; MAX_RELEASE_FRAME_BYTES + 16].into())?;
        // 3. Malformed CBOR release frame (invalid semver, bad commit).
        let mut bad_cbor = Vec::new();
        {
            let mut enc = minicbor::Encoder::new(&mut bad_cbor);
            enc.array(4)?.u8(1)?.u8(3)?.str("not-semver")?.str("bad")?;
        }
        client_connection.send_datagram(bad_cbor.into())?;
        // 4. Future version frame.
        let mut future_cbor = Vec::new();
        {
            let mut enc = minicbor::Encoder::new(&mut future_cbor);
            enc.array(4)?.u8(99)?.u8(3)?.str("0.9.0")?.null()?;
        }
        client_connection.send_datagram(future_cbor.into())?;

        // Give the listener time to process and ignore all invalid frames.
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(server_connection.close_reason().is_none());
        assert!(client_connection.close_reason().is_none());
        assert!(event_receiver.try_recv().is_err());

        // A valid release-identity datagram on the SAME session still arrives cleanly.
        let valid = ReleaseIdentity::new("0.2.0-alpha.25", Some("f".repeat(40)))?;
        release::send(&client_connection, &valid)?;
        let event = tokio::time::timeout(Duration::from_secs(2), event_receiver.recv())
            .await?
            .ok_or("release identity event missing")?;
        assert!(matches!(
            event,
            PeerEvent::ReleaseIdentity { peer: from_peer, ref identity, .. }
                if from_peer == peer && *identity == valid
        ));
        drop(event);

        // Old-peer compatibility: rendezvous::decode rejects release frames cleanly
        // so older peers ignore them without dropping the session.
        let frame = release::encode_frame(&valid)?;
        assert_eq!(rendezvous::decode(&frame), Err(RendezvousError::InvalidMessage));

        server.close(0_u8.into(), b"test complete");
        client.close(0_u8.into(), b"test complete");
        listener.abort();
        Ok::<(), Error>(())
    })
}
