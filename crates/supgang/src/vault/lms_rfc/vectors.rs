//! Independent, public TEST signatures supplied by Agenxy procurement.

use std::{collections::HashSet, fs, path::Path};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{PUBLIC_LEN, SIGNATURE_LEN, verify_fixed};

const MANIFEST_SHA256: &str = "fba4405192284d62c8ef9fffd6753551b4b64ae7658a7bba10291d3fa8faa50f";
const PRIMARY_SHA256: &str = "ed7c8940fd4032e096021e21cfc2ec86365e7db67a6c6e509a3907d0d96442d4";
const RECOVERY_SHA256: &str = "5edbd2d510e5523dce92f9a5b19791817f7ab0bac53f7363d4f3b92ffd29f322";

#[derive(Deserialize)]
struct Manifest {
    label: String,
    #[serde(rename = "LMS_type")]
    lms_type: u32,
    #[serde(rename = "LMOTS_type")]
    lmots_type: u32,
    public_key_bytes: usize,
    message_bytes: usize,
    signature_bytes: usize,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "case")]
    name: String,
    public_key: String,
    message: String,
    message_sha256: String,
    signature: String,
    signature_sha256: String,
    expected_accept: bool,
}

fn fixture(directory: &Path, name: &str, size: usize, digest: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    assert_eq!(Path::new(name).file_name().and_then(|part| part.to_str()), Some(name));
    let bytes = fs::read(directory.join(name))?;
    assert_eq!(bytes.len(), size, "{name}: wrong size");
    assert_eq!(hex::encode(Sha256::digest(&bytes)), digest, "{name}: wrong SHA-256");
    Ok(bytes)
}

#[test]
fn procurement_public_test_vectors_match_fixed_roots() -> Result<(), Box<dyn std::error::Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors/lms-nc0-test");
    let manifest_bytes = fs::read(directory.join("TEST-LMS-vectors.json"))?;
    assert_eq!(hex::encode(Sha256::digest(&manifest_bytes)), MANIFEST_SHA256);
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    assert_eq!(manifest.label, "PUBLIC TEST ONLY - NEVER PRODUCT OR TAPEOUT");
    assert_eq!((manifest.lms_type, manifest.lmots_type), (8, 1));
    assert_eq!(
        (
            manifest.public_key_bytes,
            manifest.message_bytes,
            manifest.signature_bytes
        ),
        (56, 32, 9_164)
    );
    assert_eq!(manifest.cases.len(), 10);

    let mut names = HashSet::new();
    let mut accepted = 0;
    let mut rejected = 0;
    for case in manifest.cases {
        assert!(names.insert(case.name.clone()), "duplicate case: {}", case.name);
        let key_digest = match case.public_key.as_str() {
            "TEST-primary-public.bin" => PRIMARY_SHA256,
            "TEST-recovery-public.bin" => RECOVERY_SHA256,
            other => return Err(std::io::Error::other(format!("unexpected public key fixture: {other}")).into()),
        };
        let public: [u8; PUBLIC_LEN] = fixture(&directory, &case.public_key, PUBLIC_LEN, key_digest)?
            .try_into()
            .map_err(|_| "public key has wrong length")?;
        let message: [u8; 32] = fixture(&directory, &case.message, 32, &case.message_sha256)?
            .try_into()
            .map_err(|_| "message has wrong length")?;
        let signature = fixture(&directory, &case.signature, SIGNATURE_LEN, &case.signature_sha256)?;
        // verify_fixed compares the computed candidate root with public[24..56].
        assert_eq!(
            verify_fixed(&public, &message, &signature),
            case.expected_accept,
            "{}: LMS verification differs from independent TEST expectation",
            case.name
        );
        if case.expected_accept {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!((accepted, rejected), (8, 2));
    Ok(())
}
