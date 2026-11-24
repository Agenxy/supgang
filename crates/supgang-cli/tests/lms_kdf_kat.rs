//! NC0 product-root KDF known answers for the full H20/W1 public key (Labs spec rev 2).
//!
//! Each case derives a complete 2^20-leaf tree. Cargo runs test binaries one at a time,
//! so keeping these here stops them starving the simulated-network timing tests in the
//! library's own test binary.

use std::fmt::Write as _;

use supgang_core::vault::{RootRole, derive_lms_public};

/// The TEST master `000102..1f`. Never a real root.
fn test_master() -> [u8; 32] {
    core::array::from_fn(|index| u8::try_from(index).unwrap_or(0))
}

fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}")?;
    }
    Ok(text)
}

fn check(role: RootRole, pub56: &str, fingerprint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let public = derive_lms_public(&test_master(), role, |_, _| {})?;
    assert_eq!(hex(&public.public_key)?, pub56);
    assert_eq!(public.fingerprint, fingerprint);
    Ok(())
}

#[test]
fn primary_root_public_key_matches_the_known_answer() -> Result<(), Box<dyn std::error::Error>> {
    // u32(8) || u32(1) || I = OKM[32..48] || T[1]
    check(
        RootRole::Primary,
        "0000000800000001e9042da9345063a411cffea9be4b6e0bb8547249f0f57763fbe1db67565b1d65c387ba95e5b902f1ae32e74dd453d57e",
        "e150742e94bff4a7ae2c6b41e8367c19162127e166a76cc3e4985984cd202932",
    )
}

#[test]
fn recovery_root_public_key_matches_the_known_answer() -> Result<(), Box<dyn std::error::Error>> {
    check(
        RootRole::Recovery,
        "000000080000000157f644285f666d1cca75c9726a84d5d4a67c41713d9e1ca9f2ff8b21ee788d96bda1f03234d72141af3e92ddedb9b465",
        "dda58b9612c73e99e50f64285587817f8ee2e445000534782188029d2859d3ab",
    )
}
