use std::{
    fs,
    os::unix::{fs::symlink, net::UnixListener as BlockingUnixListener},
};

use super::{ControlError, ControlListener, ControlRequest, decode_request, encode_request, request, request_within};
use crate::ids::NodeId;
use std::os::unix::fs::PermissionsExt;

#[test]
fn request_encoding_is_canonical_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    for request in [
        ControlRequest::Restart,
        ControlRequest::Status,
        ControlRequest::Peers,
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
        let encoded = encode_request(request);
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
fn listener_rejects_symlink_and_cleans_only_its_socket() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
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
    let temporary = tempfile::tempdir()?;
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
fn a_service_that_accepts_but_never_answers_is_reported_as_unresponsive() -> Result<(), Box<dyn std::error::Error>> {
    // A heavily loaded computer can leave the service unscheduled after the
    // kernel has accepted the connection. The owner must be told that, within
    // the bound, rather than see a generic socket failure.
    let temporary = tempfile::tempdir()?;
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
