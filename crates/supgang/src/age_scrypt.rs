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
const LOG_N: u8 = 18;
const MAX_PLAINTEXT: usize = 12_000;
pub const MAX_FILE: usize = MAX_PLAINTEXT + 512;

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, &'static str> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| "could not obtain operating-system randomness")?;
    Ok(bytes)
}

fn derive(passphrase: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut full_salt = [0_u8; SCRYPT_SALT_PREFIX.len() + 16];
    let (prefix, random) = full_salt.split_at_mut(SCRYPT_SALT_PREFIX.len());
    prefix.copy_from_slice(SCRYPT_SALT_PREFIX);
    random.copy_from_slice(salt);
    let params = Params::new(LOG_N, 8, 1).map_err(|_| "invalid scrypt parameters")?;
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
    let wrap_key = derive(passphrase, &salt)?;
    let wrapped = cipher(&wrap_key)?
        .encrypt(&[0_u8; 12].into(), &file_key[..])
        .map_err(|_| "could not wrap age file key")?;
    let mut header = Vec::with_capacity(160);
    header.extend_from_slice(PREFIX);
    header.extend_from_slice(b64(salt.as_ref()).as_bytes());
    header.extend_from_slice(b" 18\n");
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
    if input.len() > MAX_FILE || !input.starts_with(PREFIX) {
        return Err("invalid age v1 escrow file");
    }
    let body = input.get(PREFIX.len()..).ok_or("truncated age header")?;
    let salt_end = body.iter().position(|byte| *byte == b' ').ok_or("truncated age salt")?;
    let salt = decode_exact::<16>(body.get(..salt_end).ok_or("truncated age salt")?)?;
    let rest = body.get(salt_end..).ok_or("truncated age work factor")?;
    if !rest.starts_with(b" 18\n") {
        return Err("unsupported age scrypt work factor");
    }
    let rest = rest.get(4..).ok_or("truncated age stanza")?;
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
    let wrap_key = derive(passphrase, &salt)?;
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
    use super::{decrypt, encrypt};

    #[test]
    fn standard_age_v1_scrypt_round_trip_and_must_fails() -> Result<(), Box<dyn std::error::Error>> {
        let passphrase = b"test-only-long-passphrase-2026";
        let plaintext = b"test-only-supgang-lms-escrow-record";
        let encrypted = encrypt(plaintext, passphrase)?;
        assert_eq!(decrypt(&encrypted, passphrase)?.as_slice(), plaintext);
        assert!(decrypt(&encrypted, b"wrong-passphrase-test-only").is_err());
        let mut changed = encrypted.to_vec();
        let salt_byte = changed.get_mut(super::PREFIX.len()).ok_or("missing age salt")?;
        *salt_byte = if *salt_byte == b'A' { b'B' } else { b'A' };
        assert!(decrypt(&changed, passphrase).is_err());
        let mut changed = encrypted.to_vec();
        let header_mac = changed
            .windows(4)
            .position(|window| window == b"--- ")
            .ok_or("missing header MAC")?;
        *changed.get_mut(header_mac + 4).ok_or("missing MAC byte")? ^= 1;
        assert!(decrypt(&changed, passphrase).is_err());
        let mut changed = encrypted.to_vec();
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
