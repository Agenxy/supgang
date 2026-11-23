//! Bounded age v1 scrypt files for the offline LMS escrow ceremony.
//!
//! This intentionally supports exactly one scrypt stanza and one final payload
//! chunk. The wire format is standard age v1, while the accepted input is small.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use hmac::{Hmac, Mac};
use scrypt::{Params, scrypt};
use sha2::Sha256;
use zeroize::Zeroizing;

const PREFIX: &[u8] = b"age-encryption.org/v1\n-> scrypt ";
const SCRYPT_SALT_PREFIX: &[u8] = b"age-encryption.org/v1/scrypt";
const WRITE_LOG_N: u8 = 20;
const MIN_READ_LOG_N: u8 = 18;
const MAX_READ_LOG_N: u8 = 22;
const MAX_PLAINTEXT: usize = 12_000;
pub const MAX_FILE: usize = MAX_PLAINTEXT + 512;

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, &'static str> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| "could not obtain operating-system randomness")?;
    Ok(bytes)
}

fn derive(passphrase: &[u8], salt: &[u8; 16], log_n: u8) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut full_salt = [0_u8; SCRYPT_SALT_PREFIX.len() + 16];
    let (prefix, random) = full_salt.split_at_mut(SCRYPT_SALT_PREFIX.len());
    prefix.copy_from_slice(SCRYPT_SALT_PREFIX);
    random.copy_from_slice(salt);
    let params = Params::new(log_n, 8, 1).map_err(|_| "invalid scrypt parameters")?;
    let mut key = Zeroizing::new([0_u8; 32]);
    scrypt(passphrase, &full_salt, &params, key.as_mut()).map_err(|_| "scrypt failed")?;
    Ok(key)
}

fn hkdf(file_key: &[u8; 16], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(salt), file_key)
        .expand(info, key.as_mut())
        .map_err(|_| "age key derivation failed")?;
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> Result<ChaCha20Poly1305, &'static str> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| "age cipher key failed")
}

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn decode_exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], &'static str> {
    let decoded = STANDARD_NO_PAD.decode(bytes).map_err(|_| "invalid age base64")?;
    if decoded.len() != N || b64(&decoded).as_bytes() != bytes {
        return Err("noncanonical age base64");
    }
    decoded.try_into().map_err(|_| "invalid age field length")
}

fn mac(file_key: &[u8; 16], header: &[u8]) -> Result<[u8; 32], &'static str> {
    let key = hkdf(file_key, &[], b"header")?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_ref()).map_err(|_| "age MAC key failed")?;
    hmac.update(header);
    Ok(hmac.finalize().into_bytes().into())
}

fn verify_mac(file_key: &[u8; 16], header: &[u8], expected: &[u8; 32]) -> Result<(), &'static str> {
    let key = hkdf(file_key, &[], b"header")?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_ref()).map_err(|_| "age MAC key failed")?;
    hmac.update(header);
    hmac.verify_slice(expected)
        .map_err(|_| "age header authentication failed")
}

pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err("escrow record exceeds age payload limit");
    }
    let salt = random::<16>()?;
    let file_key = random::<16>()?;
    let nonce = random::<16>()?;
    let wrap_key = derive(passphrase, &salt, WRITE_LOG_N)?;
    let wrapped = cipher(&wrap_key)?
        .encrypt(&[0_u8; 12].into(), &file_key[..])
        .map_err(|_| "could not wrap age file key")?;
    let mut header = Vec::with_capacity(160);
    header.extend_from_slice(PREFIX);
    header.extend_from_slice(b64(salt.as_ref()).as_bytes());
    header.extend_from_slice(format!(" {WRITE_LOG_N}\n").as_bytes());
    header.extend_from_slice(b64(&wrapped).as_bytes());
    header.extend_from_slice(b"\n---");
    let tag = mac(&file_key, &header)?;
    header.extend_from_slice(b" ");
    header.extend_from_slice(b64(&tag).as_bytes());
    header.extend_from_slice(b"\n");
    let payload_key = hkdf(&file_key, &nonce[..], b"payload")?;
    let mut chunk_nonce = [0_u8; 12];
    chunk_nonce[11] = 1;
    let ciphertext = cipher(&payload_key)?
        .encrypt(&chunk_nonce.into(), plaintext)
        .map_err(|_| "could not encrypt age payload")?;
    let mut output = Zeroizing::new(Vec::with_capacity(header.len() + 16 + ciphertext.len()));
    output.extend_from_slice(&header);
    output.extend_from_slice(nonce.as_ref());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(input: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    decrypt_with_range(input, passphrase, MIN_READ_LOG_N, MAX_READ_LOG_N)
}

fn decrypt_with_range(
    input: &[u8],
    passphrase: &[u8],
    min_log_n: u8,
    max_log_n: u8,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if input.len() > MAX_FILE || !input.starts_with(PREFIX) {
        return Err("invalid age v1 escrow file");
    }
    let body = input.get(PREFIX.len()..).ok_or("truncated age header")?;
    let salt_end = body.iter().position(|byte| *byte == b' ').ok_or("truncated age salt")?;
    let salt = decode_exact::<16>(body.get(..salt_end).ok_or("truncated age salt")?)?;
    let rest = body.get(salt_end..).ok_or("truncated age work factor")?;
    let factor_end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("truncated age work factor")?;
    let factor = rest.get(1..factor_end).ok_or("invalid age scrypt work factor")?;
    if factor.is_empty() || factor.first() == Some(&b'0') || !factor.iter().all(u8::is_ascii_digit) {
        return Err("invalid age scrypt work factor");
    }
    let log_n: u8 = std::str::from_utf8(factor)
        .map_err(|_| "invalid age scrypt work factor")?
        .parse()
        .map_err(|_| "invalid age scrypt work factor")?;
    if !(min_log_n..=max_log_n).contains(&log_n) {
        return Err("unsupported age scrypt work factor");
    }
    let rest = rest.get(factor_end + 1..).ok_or("truncated age stanza")?;
    let wrap_end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("truncated age stanza")?;
    let wrapped = decode_exact::<32>(rest.get(..wrap_end).ok_or("truncated age stanza")?)?;
    let rest = rest.get(wrap_end + 1..).ok_or("truncated age MAC")?;
    if !rest.starts_with(b"--- ") {
        return Err("invalid age header terminator");
    }
    let mac_end = rest.iter().position(|byte| *byte == b'\n').ok_or("truncated age MAC")?;
    let expected_mac = decode_exact::<32>(rest.get(4..mac_end).ok_or("truncated age MAC")?)?;
    let payload_offset = input.len() - rest.len() + mac_end + 1;
    let payload = input.get(payload_offset..).ok_or("truncated age payload")?;
    if payload.len() < 16 + 16 || payload.len() > 16 + MAX_PLAINTEXT + 16 {
        return Err("invalid age payload length");
    }
    let wrap_key = derive(passphrase, &salt, log_n)?;
    let file_key = Zeroizing::new(
        cipher(&wrap_key)?
            .decrypt(&[0_u8; 12].into(), &wrapped[..])
            .map_err(|_| "age passphrase or file authentication failed")?,
    );
    let file_key: Zeroizing<[u8; 16]> =
        Zeroizing::new(file_key.as_slice().try_into().map_err(|_| "invalid age file key")?);
    let header_to_mac = input.get(..payload_offset - 45).ok_or("truncated age header")?;
    verify_mac(&file_key, header_to_mac, &expected_mac)?;
    let nonce: [u8; 16] = payload
        .get(..16)
        .ok_or("truncated age nonce")?
        .try_into()
        .map_err(|_| "truncated age nonce")?;
    let payload_key = hkdf(&file_key, &nonce, b"payload")?;
    let mut chunk_nonce = [0_u8; 12];
    chunk_nonce[11] = 1;
    let plaintext = cipher(&payload_key)?
        .decrypt(&chunk_nonce.into(), payload.get(16..).ok_or("truncated age payload")?)
        .map_err(|_| "age payload authentication failed")?;
    if plaintext.is_empty() {
        return Err("empty escrow record");
    }
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::{decrypt, decrypt_with_range, encrypt};
    use sha2::{Digest, Sha256};

    fn cctv_ciphertext(vector: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let source = hex::decode(vector.trim())?;
        let split = source
            .windows(2)
            .position(|bytes| bytes == b"\n\n")
            .ok_or("CCTV metadata separator missing")?;
        Ok(source.get(split + 2..).ok_or("CCTV ciphertext missing")?.to_vec())
    }

    #[test]
    fn cctv_scrypt_vectors_cover_success_and_rejection_cases() -> Result<(), Box<dyn std::error::Error>> {
        let valid = cctv_ciphertext(include_str!("../tests/fixtures/cctv-scrypt.hex"))?;
        assert!(
            decrypt(&valid, b"password").is_err(),
            "product policy must refuse log2 N=10"
        );
        let plaintext = decrypt_with_range(&valid, b"password", 10, 22)?;
        assert_eq!(
            hex::encode(Sha256::digest(plaintext.as_slice())),
            "013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab"
        );
        let cases = [
            (
                "wrong passphrase",
                include_str!("../tests/fixtures/cctv-scrypt_no_match.hex"),
                b"wrong".as_slice(),
            ),
            (
                "work factor 23",
                include_str!("../tests/fixtures/cctv-scrypt_work_factor_23.hex"),
                b"password".as_slice(),
            ),
            (
                "changed work factor",
                include_str!("../tests/fixtures/cctv-scrypt_work_factor_wrong.hex"),
                b"password".as_slice(),
            ),
            (
                "noncanonical salt",
                include_str!("../tests/fixtures/cctv-scrypt_not_canonical_salt.hex"),
                b"password".as_slice(),
            ),
            (
                "extra argument",
                include_str!("../tests/fixtures/cctv-scrypt_extra_argument.hex"),
                b"password".as_slice(),
            ),
            (
                "duplicate scrypt stanza",
                include_str!("../tests/fixtures/cctv-scrypt_double.hex"),
                b"password".as_slice(),
            ),
            (
                "mixed stanza",
                include_str!("../tests/fixtures/cctv-scrypt_and_x25519.hex"),
                b"password".as_slice(),
            ),
            (
                "bad wrap tag",
                include_str!("../tests/fixtures/cctv-scrypt_bad_tag.hex"),
                b"password".as_slice(),
            ),
            (
                "noncanonical work factor",
                include_str!("../tests/fixtures/cctv-scrypt_work_factor_leading_zero_decimal.hex"),
                b"password".as_slice(),
            ),
        ];
        for (name, vector, passphrase) in cases {
            let input = cctv_ciphertext(vector)?;
            assert!(decrypt_with_range(&input, passphrase, 10, 22).is_err(), "{name}");
        }
        let mut bad_mac = valid.clone();
        let mac = bad_mac
            .windows(4)
            .position(|window| window == b"--- ")
            .ok_or("CCTV MAC missing")?;
        let first = bad_mac.get_mut(mac + 4).ok_or("CCTV MAC empty")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        assert_eq!(
            decrypt_with_range(&bad_mac, b"password", 10, 22).err(),
            Some("age header authentication failed"),
            "bad header MAC"
        );
        let mut below_floor = valid;
        let factor = below_floor
            .windows(3)
            .position(|window| window == b" 10")
            .ok_or("CCTV factor missing")?;
        below_floor
            .get_mut(factor + 1..factor + 3)
            .ok_or("CCTV factor truncated")?
            .copy_from_slice(b"17");
        assert!(
            decrypt(&below_floor, b"password").is_err(),
            "work factor 17 must be refused"
        );
        Ok(())
    }

    #[test]
    fn decrypts_reference_age_v1_scrypt_fixture() -> Result<(), Box<dyn std::error::Error>> {
        // Produced by age v1.2.1 with `age -p`; the plaintext and passphrase
        // are test-only values and contain no product root material.
        let encrypted = hex::decode(include_str!("../tests/fixtures/age-reference-scrypt-v1.hex").trim())?;
        let plaintext = decrypt(&encrypted, b"test-only-age-reference-passphrase-2026")?;
        assert_eq!(plaintext.as_slice(), b"supgang reference age scrypt fixture v1\n");
        Ok(())
    }

    #[test]
    fn standard_age_v1_scrypt_round_trip_and_must_fails() -> Result<(), Box<dyn std::error::Error>> {
        let passphrase = b"test-only-long-passphrase-2026";
        let plaintext = b"test-only-supgang-lms-escrow-record";
        let encrypted = encrypt(plaintext, passphrase)?;
        assert!(encrypted.windows(4).any(|window| window == b" 20\n"));
        assert_eq!(decrypt(&encrypted, passphrase)?.as_slice(), plaintext);
        let passphrase = b"test-only-age-reference-passphrase-2026";
        let encrypted = hex::decode(include_str!("../tests/fixtures/age-reference-scrypt-v1.hex").trim())?;
        assert!(decrypt(&encrypted, b"wrong-passphrase-test-only").is_err());
        let mut changed = encrypted.clone();
        let salt_byte = changed.get_mut(super::PREFIX.len()).ok_or("missing age salt")?;
        *salt_byte = if *salt_byte == b'A' { b'B' } else { b'A' };
        assert!(decrypt(&changed, passphrase).is_err());
        let mut changed = encrypted.clone();
        let header_mac = changed
            .windows(4)
            .position(|window| window == b"--- ")
            .ok_or("missing header MAC")?;
        *changed.get_mut(header_mac + 4).ok_or("missing MAC byte")? ^= 1;
        assert!(decrypt(&changed, passphrase).is_err());
        let mut changed = encrypted.clone();
        let last = changed.last_mut().ok_or("empty age file")?;
        *last ^= 1;
        assert!(decrypt(&changed, passphrase).is_err());
        assert!(
            decrypt(
                encrypted.get(..encrypted.len() - 1).ok_or("empty age file")?,
                passphrase
            )
            .is_err()
        );
        Ok(())
    }
}
