//! Read the local routing table without sending a packet.

use std::io::Read;

const MAX_TABLE_BYTES: u64 = 1024 * 1024;

#[cfg(target_os = "macos")]
fn table(family: &str) -> Result<String, String> {
    use std::{
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };
    let mut child = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", family])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "could not read local routing table")?;
    let stdout = child.stdout.take().ok_or("missing routing table output")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout.take(MAX_TABLE_BYTES + 1).read_to_end(&mut bytes);
        let _ = sender.send((read, bytes));
    });
    let query_result = receiver.recv_timeout(Duration::from_secs(3));
    if query_result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| "could not finish routing table query")?;
    reader.join().map_err(|_| "routing table reader failed")?;
    let (read, bytes) = query_result.map_err(|_| "routing table query timed out")?;
    read.map_err(|_| "could not read routing table output")?;
    if !status.success() || bytes.len() as u64 > MAX_TABLE_BYTES {
        return Err("routing table query failed or exceeded its limit".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "routing table is not UTF-8".to_owned())
}

#[cfg(target_os = "macos")]
fn table_has_default(table: &str) -> bool {
    table.lines().any(|line| {
        matches!(
            line.split_ascii_whitespace().next(),
            Some("default" | "0.0.0.0/0" | "::/0")
        )
    })
}

#[cfg(target_os = "macos")]
pub fn has_default_route() -> Result<bool, String> {
    for family in ["inet", "inet6"] {
        let table = table(family)?;
        if table_has_default(&table) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::table_has_default;

    #[test]
    fn default_route_recognizes_both_families_and_ignores_host_routes() {
        assert!(table_has_default("Destination Gateway Flags\ndefault 192.0.2.1 UGSc\n"));
        assert!(table_has_default("Destination Gateway Flags\n::/0 fe80::1 UGc\n"));
        assert!(!table_has_default("Destination Gateway Flags\n192.0.2.1 link#1 UH\n"));
    }
}

#[cfg(target_os = "linux")]
fn table(path: &str) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|_| "could not open local routing table")?;
    let mut bytes = Vec::new();
    file.take(MAX_TABLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read local routing table")?;
    if bytes.len() as u64 > MAX_TABLE_BYTES {
        return Err("local routing table exceeded its limit".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "routing table is not UTF-8".to_owned())
}

#[cfg(target_os = "linux")]
fn ipv4_has_default(table: &str) -> bool {
    table.lines().skip(1).any(|line| {
        let mut fields = line.split_ascii_whitespace();
        let _interface = fields.next();
        fields.next() == Some("00000000")
    })
}

#[cfg(target_os = "linux")]
fn ipv6_has_default(table: &str) -> bool {
    table.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("00000000000000000000000000000000") && fields.next() == Some("00000000")
    })
}

#[cfg(target_os = "linux")]
pub fn has_default_route() -> Result<bool, String> {
    let ipv4 = table("/proc/net/route")?;
    if ipv4_has_default(&ipv4) {
        return Ok(true);
    }
    let ipv6 = table("/proc/net/ipv6_route")?;
    Ok(ipv6_has_default(&ipv6))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ipv4_has_default, ipv6_has_default};

    #[test]
    fn proc_route_rows_distinguish_default_from_host_routes() {
        assert!(ipv4_has_default("Iface Destination Gateway\neth0 00000000 010200C0\n"));
        assert!(!ipv4_has_default("Iface Destination Gateway\neth0 010200C0 00000000\n"));
        assert!(ipv6_has_default(
            "00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000\n"
        ));
        assert!(!ipv6_has_default(
            "20010DB8000000000000000000000001 00000080 00000000000000000000000000000000 00000000\n"
        ));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn has_default_route() -> Result<bool, String> {
    Err("offline routing-table guard is unavailable on this platform".to_owned())
}
