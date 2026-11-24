//! Read-only derivation of an NC0 LMS public key from a hidden-TTY master hex.

use std::{io::Write, process::ExitCode, time::Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    cli::render_error,
    cli_lms_escrow::{hidden_passphrase, prepare_owner_terminal},
    vault::{self, MASTER_LEN, RootRole},
};

const MASTER_HEX_LEN: usize = MASTER_LEN * 2;

#[derive(Serialize)]
struct PublicOutput<'a> {
    schema: &'static str,
    status: &'static str,
    role: &'static str,
    name: &'static str,
    public_key: String,
    lms_identifier: String,
    root_t1: String,
    fingerprint: &'a str,
}

fn decode_master_hex(raw: &[u8]) -> Result<Zeroizing<[u8; MASTER_LEN]>, String> {
    let trimmed = raw.trim_ascii();
    if trimmed.len() != MASTER_HEX_LEN {
        return Err("master secret must be exactly 64 hexadecimal characters (32 bytes)".to_owned());
    }
    let mut master = Zeroizing::new([0_u8; MASTER_LEN]);
    hex::decode_to_slice(trimmed, master.as_mut())
        .map_err(|_| "master secret must be exactly 64 hexadecimal characters (32 bytes)".to_owned())?;
    Ok(master)
}

fn render_public(
    role: RootRole,
    identity: &vault::LmsPublic,
    json: bool,
    output: &mut dyn Write,
) -> Result<(), String> {
    let public_key = hex::encode(identity.public_key);
    let lms_identifier = hex::encode(identity.public_key.get(8..24).ok_or("short LMS public key")?);
    let root_t1 = hex::encode(identity.public_key.get(24..56).ok_or("short LMS public key")?);
    if json {
        let response = PublicOutput {
            schema: "supgang.nc0-lms-derive-public/v1",
            status: "ok",
            role: role.as_str(),
            name: role.root_name(),
            public_key,
            lms_identifier,
            root_t1,
            fingerprint: &identity.fingerprint,
        };
        serde_json::to_writer(&mut *output, &response).map_err(|_| "could not write JSON result")?;
        writeln!(output).map_err(|_| "could not finish JSON result")?;
    } else {
        writeln!(
            output,
            "Role: {}\nName: {}\nPublic key: {public_key}\nLMS I: {lms_identifier}\nRoot T[1]: {root_t1}\nFingerprint: {}",
            role.as_str(),
            role.root_name(),
            identity.fingerprint
        )
        .map_err(|_| "could not write public receipt")?;
    }
    Ok(())
}

fn derive(role_arg: &str, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> Result<(), String> {
    prepare_owner_terminal()?;
    let role = RootRole::parse(role_arg).map_err(|problem| problem.to_string())?;
    let raw = hidden_passphrase("Master secret hex (hidden): ", error)?;
    let master = decode_master_hex(raw.as_slice())?;
    drop(raw);
    writeln!(
        error,
        "Deriving NC0 LMS public key for {} (role {}); computing 1,048,576 leaves.",
        role.root_name(),
        role.as_str()
    )
    .map_err(|_| "could not show LMS progress")?;
    let started = Instant::now();
    let identity = vault::derive_lms_public(master.as_ref(), role, |done, total| {
        if done % 65_536 == 0 || done == total {
            let _ = writeln!(error, "LMS tree: {done}/{total}");
        }
    })
    .map_err(|problem| problem.to_string())?;
    drop(master);
    writeln!(
        error,
        "LMS public derivation took {:.1}s.",
        started.elapsed().as_secs_f64()
    )
    .map_err(|_| "could not show LMS timing")?;
    render_public(role, &identity, json, output)
}

pub fn run(role: &str, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match derive(role, json, output, error) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => render_error(json, &problem, output, error),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_master_hex, render_public};
    use crate::vault::{LmsPublic, RootRole};

    #[test]
    fn master_hex_decoder_enforces_exact_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let valid = b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let decoded = decode_master_hex(valid)?;
        assert_eq!(decoded.first(), Some(&0x00));
        assert_eq!(decoded.last(), Some(&0x1f));

        let padded = b"  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f  ";
        assert_eq!(decode_master_hex(padded)?.as_ref(), decoded.as_ref());

        let upper = b"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        assert_eq!(decode_master_hex(upper)?.as_ref(), decoded.as_ref());

        for bad in [
            b"".as_slice(),
            b"000102",
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00",
            b"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            b"zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ] {
            let err = decode_master_hex(bad).err().ok_or("expected invalid hex error")?;
            assert!(err.contains("64 hexadecimal characters"));
        }
        Ok(())
    }

    #[test]
    fn render_public_emits_expected_json_and_text() -> Result<(), Box<dyn std::error::Error>> {
        let mut pub56 = [0_u8; 56];
        pub56
            .get_mut(..8)
            .ok_or("short")?
            .copy_from_slice(&[0, 0, 0, 8, 0, 0, 0, 1]);
        pub56.get_mut(8..24).ok_or("short")?.fill(0xaa);
        pub56.get_mut(24..56).ok_or("short")?.fill(0xbb);
        let identity = LmsPublic {
            public_key: pub56,
            fingerprint: "11".repeat(32),
        };
        let mut json_out = Vec::new();
        render_public(RootRole::Primary, &identity, true, &mut json_out)?;
        let value: serde_json::Value = serde_json::from_slice(&json_out)?;
        assert_eq!(
            value.get("schema").and_then(serde_json::Value::as_str),
            Some("supgang.nc0-lms-derive-public/v1")
        );
        assert_eq!(value.get("role").and_then(serde_json::Value::as_str), Some("primary"));
        assert_eq!(
            value.get("name").and_then(serde_json::Value::as_str),
            Some("nc0-product-primary")
        );
        assert_eq!(
            value.get("lms_identifier").and_then(serde_json::Value::as_str),
            Some("aa".repeat(16).as_str())
        );
        assert_eq!(
            value.get("root_t1").and_then(serde_json::Value::as_str),
            Some("bb".repeat(32).as_str())
        );
        assert_eq!(
            value.get("fingerprint").and_then(serde_json::Value::as_str),
            Some("11".repeat(32).as_str())
        );

        let mut text_out = Vec::new();
        render_public(RootRole::Recovery, &identity, false, &mut text_out)?;
        let text = String::from_utf8(text_out)?;
        assert!(text.contains("Role: recovery"));
        assert!(text.contains("Name: nc0-product-recovery"));
        assert!(text.contains(&format!("Root T[1]: {}", "bb".repeat(32))));
        Ok(())
    }
}
