use sha2::{Digest, Sha256};

use super::{Slip39Error, combine_mnemonics, generate_mnemonics, split_2_of_3, wordlist};

const VECTORS_JSON: &str = include_str!("../../tests/fixtures/slip39-vectors.json");
const VECTORS_SHA256: &str = "13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4";

#[test]
fn official_slip39_vectors_pass_byte_for_byte() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(hex::encode(Sha256::digest(VECTORS_JSON.as_bytes())), VECTORS_SHA256);
    let vectors: Vec<(String, Vec<String>, String, String)> = serde_json::from_str(VECTORS_JSON)?;
    assert_eq!(vectors.len(), 45);

    let mut valid_count = 0_usize;
    let mut invalid_count = 0_usize;

    for (description, mnemonics, expected_hex, _xprv) in vectors {
        let refs: Vec<&str> = mnemonics.iter().map(String::as_str).collect();
        let result = combine_mnemonics(&refs, b"TREZOR");
        if expected_hex.is_empty() {
            assert!(result.is_err(), "invalid vector unexpectedly succeeded: {description}");
            invalid_count += 1;
        } else {
            let recovered = result.map_err(|err| format!("valid vector failed ({description}): {err}"))?;
            assert_eq!(
                hex::encode(recovered.as_slice()),
                expected_hex,
                "secret mismatch on vector: {description}"
            );
            valid_count += 1;
        }
    }

    assert_eq!(valid_count, 15);
    assert_eq!(invalid_count, 30);
    Ok(())
}

#[test]
fn split_2_of_3_round_trips_every_pair_and_rejects_faults() -> Result<(), Box<dyn std::error::Error>> {
    let master: [u8; 32] = core::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
    let shares = split_2_of_3(&master)?;
    for share in &shares {
        assert_eq!(share.split_whitespace().count(), 33);
    }

    // Every pair (A+B, A+C, B+C) reconstructs the exact 32-byte master.
    let pairs = [(0_usize, 1_usize), (0, 2), (1, 2)];
    for (left, right) in pairs {
        let left_share = shares.get(left).ok_or("missing share")?;
        let right_share = shares.get(right).ok_or("missing share")?;
        let recovered = combine_mnemonics(&[left_share.as_str(), right_share.as_str()], b"")?;
        assert_eq!(recovered.as_slice(), master.as_slice());
    }

    // Single share, duplicate share, and all 3 shares (exceeds threshold) are refused.
    let s0 = shares.first().ok_or("missing share 0")?;
    let s1 = shares.get(1).ok_or("missing share 1")?;
    let s2 = shares.get(2).ok_or("missing share 2")?;
    assert_eq!(
        combine_mnemonics(&[s0.as_str()], b""),
        Err(Slip39Error::InvalidShareCount)
    );
    assert_eq!(
        combine_mnemonics(&[s0.as_str(), s0.as_str()], b""),
        Err(Slip39Error::DuplicateShareIndex)
    );
    assert_eq!(
        combine_mnemonics(&[s0.as_str(), s1.as_str(), s2.as_str()], b""),
        Err(Slip39Error::InvalidShareCount)
    );

    // Non-empty passphrase yields a different secret (SLIP-39 plausible deniability).
    let wrong_pass = combine_mnemonics(&[s0.as_str(), s1.as_str()], b"wrong")?;
    assert_ne!(wrong_pass.as_slice(), master.as_slice());

    // Tampered word fails RS1024 checksum.
    let mut words: Vec<&str> = s0.split_whitespace().collect();
    let last = words.last_mut().ok_or("empty mnemonic")?;
    *last = if *last == "academic" { "acid" } else { "academic" };
    let tampered = words.join(" ");
    assert_eq!(
        combine_mnemonics(&[tampered.as_str(), s1.as_str()], b""),
        Err(Slip39Error::InvalidChecksum)
    );

    // Non-32-byte master refused by split_2_of_3.
    assert_eq!(split_2_of_3(&[0_u8; 16]), Err(Slip39Error::InvalidSecretLength));
    assert_eq!(split_2_of_3(&[0_u8; 31]), Err(Slip39Error::InvalidSecretLength));
    assert_eq!(split_2_of_3(&[0_u8; 33]), Err(Slip39Error::InvalidSecretLength));

    // 1-of-N with N > 1 refused.
    assert_eq!(
        generate_mnemonics(1, &[(1, 2)], &master, b"", true, 0),
        Err(Slip39Error::InvalidParameters)
    );
    Ok(())
}

#[test]
fn wordlist_contains_1024_unique_sorted_words() -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..u16::try_from(wordlist::WORD_COUNT)? {
        let word = wordlist::word_at(index)?;
        assert_eq!(wordlist::index_of(word)?, index);
        assert_eq!(wordlist::index_of(&word.to_ascii_uppercase())?, index);
    }
    assert_eq!(wordlist::word_at(1_024), Err(Slip39Error::InvalidWordIndex));
    assert_eq!(wordlist::index_of("notaword"), Err(Slip39Error::InvalidWord));
    Ok(())
}
