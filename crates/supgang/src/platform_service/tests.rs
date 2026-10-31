use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    thread,
    time::Duration,
};

use super::wait_for_control;

#[test]
fn definition_replacement_is_atomic_mode_0600_and_leaves_no_temporary_file() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("service");
    super::write_atomic(&path, b"old definition")?;
    let mut old = fs::File::open(&path)?;
    super::write_atomic(&path, b"new definition")?;
    assert_ne!(old.metadata()?.ino(), fs::metadata(&path)?.ino());
    let mut old_bytes = Vec::new();
    old.read_to_end(&mut old_bytes)?;
    assert_eq!(old_bytes, b"old definition");
    assert_eq!(fs::read(&path)?, b"new definition");
    assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    assert!(super::write_atomic(&path, &vec![0; 32 * 1024 + 1]).is_err());
    assert_eq!(fs::read(&path)?, b"new definition");
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn bootout_waits_for_manager_removal_even_after_the_socket_is_gone() -> Result<(), Box<dyn std::error::Error>> {
    let mut states = [true, true, false].into_iter();
    super::wait_until_gone(
        || states.next().ok_or(super::ServiceError::Manager),
        Duration::from_secs(1),
    )?;
    assert!(states.next().is_none());
    Ok(())
}

#[test]
fn bootout_that_never_disappears_fails_within_its_bound() {
    assert!(matches!(
        super::wait_until_gone(|| Ok(true), Duration::ZERO),
        Err(super::ServiceError::DidNotStop)
    ));
    assert!(matches!(
        super::wait_until_gone(|| Err(super::ServiceError::Manager), Duration::ZERO),
        Err(super::ServiceError::Manager)
    ));
}

#[test]
fn stop_wait_retries_a_socket_closing_during_handoff() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state_directory = temporary.path().join("state");
    fs::create_dir(&state_directory)?;
    fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))?;
    let socket = state_directory.join(crate::control::CONTROL_SOCKET_FILE_NAME);
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let closer = thread::spawn(move || {
        let _connection = listener.accept();
    });

    wait_for_control(&state_directory, false, Duration::from_secs(1))?;
    closer.join().map_err(|_| "socket closer panicked")?;
    Ok(())
}
