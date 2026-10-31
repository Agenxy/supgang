//! The stdio server must not outlive a disconnected client.

use std::{
    io::Write,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use supgang_core as _;

fn spawn_mcp() -> Result<Child, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_supgang"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

fn assert_exits_within(mut child: Child, bound: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + bound;
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(status.success(), "MCP exited with {status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(format!("MCP did not exit within {bound:?}").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn mcp_exits_when_client_closes_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = spawn_mcp()?;
    drop(child.stdin.take());
    assert_exits_within(child, Duration::from_secs(5))
}

#[test]
fn mcp_exits_when_client_closes_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = spawn_mcp()?;
    drop(child.stdout.take());
    child
        .stdin
        .as_mut()
        .ok_or("missing MCP stdin")?
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":3}\n")?;
    assert_exits_within(child, Duration::from_secs(5))
}
