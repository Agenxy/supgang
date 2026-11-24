//! SLIP-39 4-round Feistel cipher using PBKDF2-HMAC-SHA256.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    CUSTOMIZATION_ORIG, MAX_ITERATION_EXPONENT, MAX_PASSPHRASE_BYTES, MAX_SECRET_BYTES, MIN_SECRET_BYTES, Slip39Error,
};

const BASE_ITERATION_COUNT: u32 = 10_000;
const ROUND_COUNT: u8 = 4;
const SHA256_LEN: usize = 32;

pub(super) fn validate_passphrase(passphrase: &[u8]) -> Result<(), Slip39Error> {
    if passphrase.len() > MAX_PASSPHRASE_BYTES || !passphrase.iter().all(|&byte| (32..=126).contains(&byte)) {
        return Err(Slip39Error::InvalidPassphrase);
    }
    Ok(())
}

/// RFC 2898 PBKDF2-HMAC-SHA256 using only `hmac` and `sha2`.
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<(), Slip39Error> {
    if iterations == 0 || output.is_empty() || output.len() > MAX_SECRET_BYTES / 2 {
        return Err(Slip39Error::Internal);
    }
    let base_mac = Hmac::<Sha256>::new_from_slice(password).map_err(|_| Slip39Error::Internal)?;
    let mut block_index = 1_u32;
    for chunk in output.chunks_mut(SHA256_LEN) {
        let mut mac = base_mac.clone();
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = Zeroizing::new([0_u8; SHA256_LEN]);
        u.copy_from_slice(&mac.finalize().into_bytes());
        let mut acc = Zeroizing::new(*u);
        for _ in 1..iterations {
            let mut next = base_mac.clone();
            next.update(u.as_ref());
            u.copy_from_slice(&next.finalize().into_bytes());
            for (slot, byte) in acc.iter_mut().zip(u.iter()) {
                *slot ^= *byte;
            }
        }
        let slice = acc.get(..chunk.len()).ok_or(Slip39Error::Internal)?;
        chunk.copy_from_slice(slice);
        block_index = block_index.checked_add(1).ok_or(Slip39Error::Internal)?;
    }
    Ok(())
}

fn round_function(
    round: u8,
    passphrase: &[u8],
    iteration_exponent: u8,
    salt: &[u8],
    right: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    let mut password = Zeroizing::new(Vec::with_capacity(1 + passphrase.len()));
    password.push(round);
    password.extend_from_slice(passphrase);

    let mut full_salt = Zeroizing::new(Vec::with_capacity(salt.len() + right.len()));
    full_salt.extend_from_slice(salt);
    full_salt.extend_from_slice(right);

    let iterations = (BASE_ITERATION_COUNT << iteration_exponent) / u32::from(ROUND_COUNT);
    let mut out = Zeroizing::new(vec![0_u8; right.len()]);
    pbkdf2_hmac_sha256(&password, &full_salt, iterations, out.as_mut_slice())?;
    Ok(out)
}

fn build_salt(identifier: u16, extendable: bool) -> Zeroizing<Vec<u8>> {
    if extendable {
        Zeroizing::new(Vec::new())
    } else {
        let mut salt = Zeroizing::new(Vec::with_capacity(CUSTOMIZATION_ORIG.len() + 2));
        salt.extend_from_slice(CUSTOMIZATION_ORIG);
        salt.extend_from_slice(&identifier.to_be_bytes());
        salt
    }
}

fn feistel(
    input: &[u8],
    passphrase: &[u8],
    iteration_exponent: u8,
    identifier: u16,
    extendable: bool,
    rounds: [u8; 4],
) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    validate_passphrase(passphrase)?;
    if iteration_exponent > MAX_ITERATION_EXPONENT {
        return Err(Slip39Error::UnsupportedIterationExponent);
    }
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&input.len()) || !input.len().is_multiple_of(2) {
        return Err(Slip39Error::InvalidSecretLength);
    }
    let half = input.len() / 2;
    let mut left = Zeroizing::new(input.get(..half).ok_or(Slip39Error::Internal)?.to_vec());
    let mut right = Zeroizing::new(input.get(half..).ok_or(Slip39Error::Internal)?.to_vec());
    let salt = build_salt(identifier, extendable);
    for round in rounds {
        let mask = round_function(round, passphrase, iteration_exponent, &salt, &right)?;
        for (l, m) in left.iter_mut().zip(mask.iter()) {
            *l ^= *m;
        }
        std::mem::swap(&mut left, &mut right);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(input.len()));
    output.extend_from_slice(&right);
    output.extend_from_slice(&left);
    Ok(output)
}

pub(super) fn encrypt(
    master_secret: &[u8],
    passphrase: &[u8],
    iteration_exponent: u8,
    identifier: u16,
    extendable: bool,
) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    feistel(
        master_secret,
        passphrase,
        iteration_exponent,
        identifier,
        extendable,
        [0, 1, 2, 3],
    )
}

pub(super) fn decrypt(
    encrypted_master_secret: &[u8],
    passphrase: &[u8],
    iteration_exponent: u8,
    identifier: u16,
    extendable: bool,
) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    feistel(
        encrypted_master_secret,
        passphrase,
        iteration_exponent,
        identifier,
        extendable,
        [3, 2, 1, 0],
    )
}
