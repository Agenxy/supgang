use super::{UpdateError, UpdateLock, run_owned};
use std::time::Duration;

#[tokio::test]
async fn cancelled_caller_cannot_release_live_work_or_its_input() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    drop(crate::state::initialize(&state)?);
    let incoming = crate::update::incoming_bundle(&state)?;
    let input_path = incoming.path.clone();
    let lock = UpdateLock::acquire(&state)?;
    let (started, start) = tokio::sync::oneshot::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let caller = tokio::spawn(run_owned(lock, Some(incoming), move || {
        let _sent = started.send(());
        wait.recv_timeout(Duration::from_secs(5))
            .map_err(|_| UpdateError::InvalidBundle)?;
        Err(UpdateError::Tuf)
    }));
    tokio::time::timeout(Duration::from_secs(5), start).await??;
    caller.abort();
    assert!(caller.await.is_err_and(|error| error.is_cancelled()));
    assert!(matches!(UpdateLock::acquire(&state), Err(UpdateError::Busy)));
    assert!(input_path.exists());
    resume.send(())?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while matches!(UpdateLock::acquire(&state), Err(UpdateError::Busy)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let _available = UpdateLock::acquire(&state)?;
    assert!(!input_path.exists());
    Ok(())
}
