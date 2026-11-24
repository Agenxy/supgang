//! Test-only stdin/stdout bridge for two-way SLIP-39 cross-checking against
//! `shamir-mnemonic 0.3.0`. Never compiled into the `supgang` binary.

#![forbid(unsafe_code)]

use std::{
    fmt::Write as _,
    io::{self, Read, Write},
};

const MAX_STDIN_BYTES: u64 = 16 * 1024;

fn decode_hex(text: &str) -> Result<Vec<u8>, &'static str> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("odd hex length");
    }
    let mut out = Vec::with_capacity(pairs.len());
    for &[hi, lo] in pairs {
        let high = hex_nibble(hi)?;
        let low = hex_nibble(lo)?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        if let Some(&hi) = DIGITS.get(usize::from(byte >> 4)) {
            out.push(char::from(hi));
        }
        if let Some(&lo) = DIGITS.get(usize::from(byte & 0x0F)) {
            out.push(char::from(lo));
        }
    }
    out
}

fn parse_groups(spec: &str) -> Result<Vec<(u8, u8)>, &'static str> {
    let mut groups = Vec::new();
    for part in spec.split(',') {
        let (threshold, count) = part.split_once(':').ok_or("bad group spec")?;
        let t: u8 = threshold.parse().map_err(|_| "bad threshold")?;
        let n: u8 = count.parse().map_err(|_| "bad count")?;
        groups.push((t, n));
    }
    Ok(groups)
}

fn handle(input: &str) -> Result<String, String> {
    let mut lines = input.lines();
    let header = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = header.split_whitespace().collect();
    match parts.first().copied() {
        Some("split_2_of_3") => {
            let master_hex = parts.get(1).ok_or("missing master hex")?;
            let master = decode_hex(master_hex)?;
            let shares = supgang_core::slip39::split_2_of_3(&master).map_err(|err| err.to_string())?;
            let mut out = String::from("OK\n");
            for share in shares {
                out.push_str(share.as_str());
                out.push('\n');
            }
            Ok(out)
        }
        Some("split") => {
            let extendable = *parts.get(1).ok_or("missing extendable")? == "1";
            let exponent: u8 = parts
                .get(2)
                .ok_or("missing exponent")?
                .parse()
                .map_err(|_| "bad exponent")?;
            let group_threshold: u8 = parts
                .get(3)
                .ok_or("missing group_threshold")?
                .parse()
                .map_err(|_| "bad group_threshold")?;
            let groups = parse_groups(parts.get(4).ok_or("missing groups")?)?;
            let passphrase = decode_hex(parts.get(5).ok_or("missing passphrase hex")?)?;
            let master = decode_hex(parts.get(6).ok_or("missing master hex")?)?;
            let generated = supgang_core::slip39::generate_mnemonics(
                group_threshold,
                &groups,
                &master,
                &passphrase,
                extendable,
                exponent,
            )
            .map_err(|err| err.to_string())?;
            let mut out = String::from("OK\n");
            for (group_idx, group) in generated.into_iter().enumerate() {
                for share in group {
                    let _ = writeln!(out, "{group_idx}|{}", share.as_str());
                }
            }
            Ok(out)
        }
        Some("combine") => {
            let passphrase = if let Some(hex_pass) = parts.get(1) {
                decode_hex(hex_pass)?
            } else {
                Vec::new()
            };
            let mnemonics: Vec<&str> = lines.filter(|line| !line.trim().is_empty()).collect();
            let secret =
                supgang_core::slip39::combine_mnemonics(&mnemonics, &passphrase).map_err(|err| err.to_string())?;
            Ok(format!("OK\n{}\n", encode_hex(secret.as_slice())))
        }
        _ => Err("unknown operation".to_owned()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = Vec::new();
    io::stdin().take(MAX_STDIN_BYTES + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_STDIN_BYTES {
        return Err("stdin exceeded bound".into());
    }
    let text = String::from_utf8(raw)?;
    let mut stdout = io::stdout().lock();
    match handle(&text) {
        Ok(body) => stdout.write_all(body.as_bytes())?,
        Err(reason) => writeln!(stdout, "ERR {reason}")?,
    }
    Ok(())
}
