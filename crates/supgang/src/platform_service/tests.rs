use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    thread,
    time::Duration,
};

use super::wait_for_control;

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
