use std::{
    fs,
    os::unix::{fs::symlink, net::UnixListener as BlockingUnixListener},
};

use super::{
    ControlError, ControlListener, ControlReply, ControlRequest, ErrorCode, PEER_AT_CAPACITY, decode_request,
    encode_request, request, request_within,
};
use crate::ids::NodeId;
use std::os::unix::fs::PermissionsExt;

#[test]
fn request_encoding_is_canonical_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    for request in [
        ControlRequest::Restart,
        ControlRequest::Status,
        ControlRequest::Peers,
        ControlRequest::Exposures,
        ControlRequest::Resolve(NodeId::from_bytes([7_u8; 32])),
        ControlRequest::Revoke(NodeId::from_bytes([8_u8; 32])),
        ControlRequest::Update {
            target: NodeId::from_bytes([9_u8; 32]),
            digest: [10_u8; 32],
        },
        ControlRequest::TunnelLimits {
            per_peer: 40,
            total: 64,
            idle_seconds: 86_400,
        },
    ] {
        let encoded = encode_request(request.clone());
        assert_eq!(decode_request(&encoded)?, request);
    }
    assert!(matches!(decode_request(b""), Err(ControlError::InvalidRequest)));
    let mut truncated = encode_request(ControlRequest::TunnelLimits {
        per_peer: 1,
        total: 1,
        idle_seconds: 60,
    });
    truncated.pop();
    assert!(matches!(decode_request(&truncated), Err(ControlError::InvalidRequest)));
    let mut trailing = encode_request(ControlRequest::Status);
    trailing.push(0);
    assert!(matches!(decode_request(&trailing), Err(ControlError::InvalidRequest)));
    Ok(())
}

#[test]
fn member_sign_control_request_rejects_trailing_or_changed_length() -> Result<(), Box<dyn std::error::Error>> {
    let request = crate::agent_sign_protocol::SignRequest {
        nonce: [1; 32],
        purpose: "build".to_owned(),
        context: "build.stage".to_owned(),
        digest: [2; 32],
        expires_at: 100,
    };
    let encoded = request.encode()?;
    let mut padded = [0_u8; crate::agent_sign_protocol::MAX_REQUEST_BYTES];
    padded
        .get_mut(..encoded.len())
        .ok_or("invalid length")?
        .copy_from_slice(&encoded);
    let bytes = encode_request(ControlRequest::AgentSign {
        target: NodeId::from_bytes([3; 32]),
        request: Box::new(padded),
        length: u16::try_from(encoded.len())?,
    });
    assert!(matches!(decode_request(&bytes)?, ControlRequest::AgentSign { .. }));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(decode_request(&trailing), Err(ControlError::InvalidRequest)));
    let mut changed_length = bytes;
    let length = changed_length.get_mut(41..43).ok_or("missing length")?;
    length.copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(
        decode_request(&changed_length),
        Err(ControlError::InvalidRequest)
    ));
    Ok(())
}

#[test]
fn member_keygen_control_request_rejects_trailing_or_changed_length() -> Result<(), Box<dyn std::error::Error>> {
    let request = crate::agent_keygen_protocol::KeygenRequest {
        ssh: false,
        nonce: [1; 32],
        purpose: "build".to_owned(),
        note: "stage".to_owned(),
        policy: crate::vault::AgentPolicy::new(vec!["build.stage".to_owned()], None)?,
        expires_at: 100,
    };
    let encoded = request.encode()?;
    let mut padded = Box::new([0_u8; crate::agent_keygen_protocol::MAX_REQUEST_BYTES]);
    padded
        .get_mut(..encoded.len())
        .ok_or("keygen request too large")?
        .copy_from_slice(&encoded);
    let bytes = encode_request(ControlRequest::AgentKeygen {
        target: NodeId::from_bytes([3; 32]),
        request: padded,
        length: u16::try_from(encoded.len())?,
    });
    assert!(matches!(decode_request(&bytes)?, ControlRequest::AgentKeygen { .. }));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(decode_request(&trailing), Err(ControlError::InvalidRequest)));
    let mut changed = bytes;
    changed
        .get_mut(41..43)
        .ok_or("missing request length")?
        .copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(decode_request(&changed), Err(ControlError::InvalidRequest)));
    Ok(())
}

#[test]
fn listener_rejects_symlink_and_cleans_only_its_socket() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = crate::storage::test_tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
    let socket = state_directory.join(super::CONTROL_SOCKET_FILE_NAME);
    let target = temporary.path().join("target");
    fs::write(&target, b"protected")?;
    symlink(&target, &socket)?;
    assert!(matches!(
        ControlListener::bind(&state_directory),
        Err(ControlError::UnsafeSocketPath)
    ));
    fs::remove_file(&socket)?;
    let runtime = crate::transport::build_runtime()?;
    let _runtime_guard = runtime.enter();
    let listener = ControlListener::bind(&state_directory)?;
    assert!(socket.exists());
    drop(listener);
    assert!(!socket.exists());
    assert_eq!(fs::read(target)?, b"protected");
    Ok(())
}

#[test]
fn client_treats_a_safe_stale_socket_as_service_stopped() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = crate::storage::test_tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
    let socket = state_directory.join(super::CONTROL_SOCKET_FILE_NAME);
    let listener = BlockingUnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    drop(listener);

    assert!(request(&state_directory, ControlRequest::Status)?.is_none());
    assert!(socket.exists());
    Ok(())
}

#[test]
fn tunnel_setup_gives_up_at_its_callers_deadline() -> Result<(), Box<dyn std::error::Error>> {
    // `connect` retries setup while a peer reconnects; a retry that starts
    // just before its deadline must not then wait a full setup timeout.
    let temporary = crate::storage::test_tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
    let socket = state_directory.join(super::CONTROL_SOCKET_FILE_NAME);
    let _silent = BlockingUnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;

    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_millis(300);
    let result = super::connect_service_by(
        &state_directory,
        crate::ids::NodeId::from_bytes([7; 32]),
        [0; 16],
        deadline,
    );
    let elapsed = started.elapsed();
    let Err(message) = result else {
        return Err("a silent service admitted a tunnel".into());
    };
    assert!(message.contains("did not answer within 1 s"), "{message}");
    assert!(elapsed < std::time::Duration::from_secs(1), "waited {elapsed:?}");
    let passed = super::connect_service_by(
        &state_directory,
        crate::ids::NodeId::from_bytes([7; 32]),
        [0; 16],
        std::time::Instant::now(),
    );
    assert!(passed.is_err());
    Ok(())
}

#[test]
fn a_reply_that_trickles_in_cannot_stretch_the_setup_deadline() -> Result<(), Box<dyn std::error::Error>> {
    // A per-read timeout would restart with every byte; the deadline must not.
    use std::io::{Read, Write};
    let temporary = crate::storage::test_tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
    let socket = state_directory.join(super::CONTROL_SOCKET_FILE_NAME);
    let listener = BlockingUnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let service = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 64];
        let _read = stream.read(&mut request)?;
        // A frame header announcing 64 bytes, then one byte every 100 ms.
        stream.write_all(&64_u32.to_be_bytes())?;
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if stream.write_all(b" ").is_err() {
                break;
            }
        }
        Ok(())
    });

    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_millis(500);
    let result = super::connect_service_by(
        &state_directory,
        crate::ids::NodeId::from_bytes([7; 32]),
        [0; 16],
        deadline,
    );
    let elapsed = started.elapsed();
    assert!(result.is_err(), "a trickled, incomplete reply admitted a tunnel");
    assert!(elapsed < std::time::Duration::from_millis(900), "waited {elapsed:?}");
    drop(result);
    service.join().map_err(|_| "service thread panicked")??;
    Ok(())
}

#[test]
fn a_service_that_accepts_but_never_answers_is_reported_as_unresponsive() -> Result<(), Box<dyn std::error::Error>> {
    // A heavily loaded computer can leave the service unscheduled after the
    // kernel has accepted the connection. The owner must be told that, within
    // the bound, rather than see a generic socket failure.
    let temporary = crate::storage::test_tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
    let socket = state_directory.join(super::CONTROL_SOCKET_FILE_NAME);
    let _silent = BlockingUnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;

    let started = std::time::Instant::now();
    let result = request_within(
        &state_directory,
        ControlRequest::Status,
        std::time::Duration::from_secs(1),
    );
    let elapsed = started.elapsed();
    let Err(error) = result else {
        return Err("a silent service produced a reply".into());
    };
    assert!(
        matches!(error, ControlError::Unresponsive { seconds: 1 }),
        "unexpected error: {error:?}"
    );
    assert!(error.to_string().contains("did not answer within 1 s"), "{error}");
    assert!(elapsed < std::time::Duration::from_secs(3), "waited {elapsed:?}");
    Ok(())
}

/// Local clients branch on `code`, never on `message`, so the field must be
/// stable on the wire, absent when unclassified, and readable both by older
/// clients (which ignore it) and by this client facing a newer service.
#[test]
fn error_code_is_stable_optional_and_forward_compatible() -> Result<(), Box<dyn std::error::Error>> {
    let coded = serde_json::to_value(ControlReply::coded(ErrorCode::PeerAtCapacity, PEER_AT_CAPACITY))?;
    assert_eq!(
        coded,
        serde_json::json!({"response": "error", "code": "peer_at_capacity", "message": PEER_AT_CAPACITY})
    );
    let plain = serde_json::to_value(ControlReply::error("x".to_owned()))?;
    assert_eq!(plain, serde_json::json!({"response": "error", "message": "x"}));

    let older: ControlReply = serde_json::from_str(r#"{"response":"error","message":"x"}"#)?;
    assert!(matches!(older, ControlReply::Error { code: None, ref message } if message == "x"));
    let newer: ControlReply = serde_json::from_str(r#"{"response":"error","code":"from_the_future","message":"x"}"#)?;
    assert!(matches!(
        newer,
        ControlReply::Error {
            code: Some(ErrorCode::Unknown),
            ..
        }
    ));

    for (code, wire) in [
        (ErrorCode::PeerAtCapacity, "peer_at_capacity"),
        (ErrorCode::PeerFull, "peer_full"),
        (ErrorCode::RuntimeFull, "runtime_full"),
        (ErrorCode::SessionFailed, "session_failed"),
        (ErrorCode::NotConnected, "not_connected"),
        (ErrorCode::AuthorizationLapsed, "authorization_lapsed"),
        (ErrorCode::Revoked, "revoked"),
        (ErrorCode::Refused, "refused"),
        (ErrorCode::UpstreamUnavailable, "upstream_unavailable"),
        (ErrorCode::InvalidName, "invalid_name"),
    ] {
        assert_eq!(serde_json::to_value(code)?, serde_json::json!(wire));
    }
    Ok(())
}
