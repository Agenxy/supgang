//! `supgang/custody/v1`, one ASCII line in each direction, then EOF.
//! Blobs, compressed keys and raw signatures are lowercase hex, never argv.
//! One child at a time, no queue, nonblocking pipes, bounded output and deadline.

use super::custody::UnavailableReason;
use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) const PROTOCOL: &str = "supgang/custody/v1";
pub(super) const NAME: &str = "supgang-secure-enclave";
const MAX_WIRE_BYTES: usize = 16_384;
static IN_FLIGHT: Mutex<()> = Mutex::new(());

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        // Even an invalid response must not leave a helper or zombie behind.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn invoke(operation: &str, timeout: Duration) -> Result<Zeroizing<String>, UnavailableReason> {
    let executable = std::env::current_exe().map_err(|_| UnavailableReason::HelperMissing)?;
    let directory = executable.parent().ok_or(UnavailableReason::HelperMissing)?;
    let _guard = IN_FLIGHT.try_lock().map_err(|_| UnavailableReason::HelperBusy)?;
    exchange(&directory.join(NAME), operation, timeout)
}

fn exchange(path: &Path, operation: &str, timeout: Duration) -> Result<Zeroizing<String>, UnavailableReason> {
    exchange_command(&mut Command::new(path), operation, timeout)
}

fn exchange_command(
    command: &mut Command,
    operation: &str,
    timeout: Duration,
) -> Result<Zeroizing<String>, UnavailableReason> {
    let request = Zeroizing::new(format!("{PROTOCOL} {operation}\n"));
    if request.len() > MAX_WIRE_BYTES {
        return Err(UnavailableReason::HelperProtocol);
    }
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                UnavailableReason::HelperMissing
            } else {
                UnavailableReason::HelperRefused(e.raw_os_error().unwrap_or(-1))
            }
        })?;
    let mut child = Running(child);
    let mut input = child.0.stdin.take().ok_or(UnavailableReason::HelperProtocol)?;
    let mut output = child.0.stdout.take().ok_or(UnavailableReason::HelperProtocol)?;
    nonblocking(&input)?;
    nonblocking(&output)?;
    let started = Instant::now();
    let mut sent = 0;
    // Nonblocking writes put even a helper that never reads under the deadline.
    while sent < request.len() {
        deadline(started, timeout)?;
        match input.write(
            request
                .as_bytes()
                .get(sent..)
                .ok_or(UnavailableReason::HelperProtocol)?,
        ) {
            Ok(0) => return Err(UnavailableReason::HelperProtocol),
            Ok(count) => sent += count,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return Err(UnavailableReason::HelperProtocol),
        }
    }
    drop(input);
    let mut bytes = Zeroizing::new(Vec::new());
    let mut eof = false;
    loop {
        deadline(started, timeout)?;
        let mut buffer = zeroize::Zeroizing::new([0_u8; 1024]);
        match output.read(buffer.as_mut()) {
            Ok(0) => eof = true,
            Ok(count) => {
                if bytes.len() + count > MAX_WIRE_BYTES {
                    return Err(UnavailableReason::HelperProtocol);
                }
                bytes.extend_from_slice(buffer.get(..count).ok_or(UnavailableReason::HelperProtocol)?);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(UnavailableReason::HelperProtocol),
        }
        if let Some(status) = child.0.try_wait().map_err(|_| UnavailableReason::HelperProtocol)? {
            if !status.success() {
                return Err(UnavailableReason::HelperRefused(status.code().unwrap_or(-1)));
            }
            if eof {
                return parse_response(&bytes);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), UnavailableReason> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| UnavailableReason::HelperProtocol)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| UnavailableReason::HelperProtocol)
}

fn deadline(started: Instant, timeout: Duration) -> Result<(), UnavailableReason> {
    if started.elapsed() >= timeout {
        Err(UnavailableReason::HelperTimedOut)
    } else {
        Ok(())
    }
}

pub(super) fn parse_response(bytes: &[u8]) -> Result<Zeroizing<String>, UnavailableReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnavailableReason::HelperProtocol)?;
    let line = text.strip_suffix('\n').ok_or(UnavailableReason::HelperProtocol)?;
    if line.bytes().any(|b| !(32..=126).contains(&b)) {
        return Err(UnavailableReason::HelperProtocol);
    }
    let body = line
        .strip_prefix(PROTOCOL)
        .and_then(|s| s.strip_prefix(' '))
        .ok_or(UnavailableReason::HelperProtocol)?;
    if let Some(value) = body.strip_prefix("ok ") {
        return Ok(Zeroizing::new(value.to_owned()));
    }
    let reason = match body {
        "error no-hardware" => UnavailableReason::NoHardware,
        "error owner-declined-presence" => UnavailableReason::OwnerDeclinedPresence,
        "error protocol" => UnavailableReason::HelperProtocol,
        _ => body
            .strip_prefix("error refused ")
            .and_then(|s| s.parse().ok())
            .map_or(UnavailableReason::HelperProtocol, UnavailableReason::HelperRefused),
    };
    Err(reason)
}

#[cfg(test)]
mod tests;
