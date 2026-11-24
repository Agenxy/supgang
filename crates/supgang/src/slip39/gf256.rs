//! GF(256) Shamir secret sharing with SLIP-39 digest share authentication.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{MAX_SECRET_BYTES, MAX_SHARE_COUNT, MIN_SECRET_BYTES, Slip39Error};

pub(super) const SECRET_INDEX: u8 = 255;
pub(super) const DIGEST_INDEX: u8 = 254;
pub(super) const DIGEST_LEN: usize = 4;

const fn build_tables() -> ([u8; 255], [u8; 256]) {
    let mut exp = [0_u8; 255];
    let mut log = [0_u8; 256];
    let mut poly: u16 = 1;
    let mut i = 0;
    while i < 255 {
        #[expect(clippy::cast_possible_truncation, reason = "poly is reduced modulo 0x11B to 8 bits")]
        let byte = poly as u8;
        #[expect(clippy::indexing_slicing, reason = "i < 255 and byte <= 255 in compile-time table")]
        {
            exp[i] = byte;
            #[expect(clippy::cast_possible_truncation, reason = "i < 255 fits in u8")]
            {
                log[byte as usize] = i as u8;
            }
        }
        poly = (poly << 1) ^ poly;
        if (poly & 0x100) != 0 {
            poly ^= 0x11B;
        }
        i += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 255], [u8; 256]) = build_tables();
const EXP_TABLE: [u8; 255] = TABLES.0;
const LOG_TABLE: [u8; 256] = TABLES.1;

/// One GF(256) evaluation point `(x, f(x))` with zeroized share bytes.
pub(super) struct RawShare {
    pub(super) x: u8,
    pub(super) data: Zeroizing<Vec<u8>>,
}

fn gf_log(value: u8) -> Result<i32, Slip39Error> {
    if value == 0 {
        return Err(Slip39Error::DuplicateShareIndex);
    }
    LOG_TABLE
        .get(usize::from(value))
        .copied()
        .map(i32::from)
        .ok_or(Slip39Error::Internal)
}

fn gf_exp(exponent: i32) -> Result<u8, Slip39Error> {
    let reduced = usize::try_from(exponent.rem_euclid(255)).map_err(|_| Slip39Error::Internal)?;
    EXP_TABLE.get(reduced).copied().ok_or(Slip39Error::Internal)
}

pub(super) fn interpolate(shares: &[RawShare], target_x: u8) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    if shares.is_empty() || shares.len() > usize::from(MAX_SHARE_COUNT) + 2 {
        return Err(Slip39Error::InvalidShareCount);
    }
    let expected_len = shares.first().ok_or(Slip39Error::InvalidShareCount)?.data.len();
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&expected_len) || !expected_len.is_multiple_of(2) {
        return Err(Slip39Error::InvalidSecretLength);
    }
    let mut seen = [false; 256];
    for share in shares {
        if share.data.len() != expected_len {
            return Err(Slip39Error::InconsistentShareLength);
        }
        let slot = seen.get_mut(usize::from(share.x)).ok_or(Slip39Error::Internal)?;
        if *slot {
            return Err(Slip39Error::DuplicateShareIndex);
        }
        *slot = true;
    }
    for share in shares {
        if share.x == target_x {
            return Ok(Zeroizing::new(share.data.to_vec()));
        }
    }

    let mut log_prod = 0_i32;
    for share in shares {
        log_prod += gf_log(share.x ^ target_x)?;
    }

    let mut result = Zeroizing::new(vec![0_u8; expected_len]);
    for share in shares {
        let mut denom_log = gf_log(share.x ^ target_x)?;
        for other in shares {
            if other.x != share.x {
                denom_log += gf_log(share.x ^ other.x)?;
            }
        }
        let log_basis = (log_prod - denom_log).rem_euclid(255);
        for (acc, &byte) in result.iter_mut().zip(share.data.iter()) {
            if byte != 0 {
                let term = gf_exp(gf_log(byte)? + log_basis)?;
                *acc ^= term;
            }
        }
    }
    Ok(result)
}

fn create_digest(random_part: &[u8], shared_secret: &[u8]) -> Result<[u8; DIGEST_LEN], Slip39Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(random_part).map_err(|_| Slip39Error::Internal)?;
    mac.update(shared_secret);
    let full = mac.finalize().into_bytes();
    full.get(..DIGEST_LEN)
        .ok_or(Slip39Error::Internal)?
        .try_into()
        .map_err(|_| Slip39Error::Internal)
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right.iter()).fold(0_u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

pub(super) fn split_secret_raw(
    threshold: u8,
    share_count: u8,
    shared_secret: &[u8],
) -> Result<Vec<RawShare>, Slip39Error> {
    if threshold == 0 || threshold > share_count || share_count > MAX_SHARE_COUNT {
        return Err(Slip39Error::InvalidParameters);
    }
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&shared_secret.len()) || !shared_secret.len().is_multiple_of(2) {
        return Err(Slip39Error::InvalidSecretLength);
    }
    if threshold == 1 {
        return Ok((0..share_count)
            .map(|index| RawShare {
                x: index,
                data: Zeroizing::new(shared_secret.to_vec()),
            })
            .collect());
    }

    let random_share_count = threshold - 2;
    let mut shares = Vec::with_capacity(usize::from(share_count));
    for index in 0..random_share_count {
        let mut random = Zeroizing::new(vec![0_u8; shared_secret.len()]);
        getrandom::fill(random.as_mut_slice()).map_err(|_| Slip39Error::RandomnessUnavailable)?;
        shares.push(RawShare { x: index, data: random });
    }

    let random_part_len = shared_secret.len() - DIGEST_LEN;
    let mut random_part = Zeroizing::new(vec![0_u8; random_part_len]);
    getrandom::fill(random_part.as_mut_slice()).map_err(|_| Slip39Error::RandomnessUnavailable)?;
    let digest = create_digest(&random_part, shared_secret)?;

    let mut digest_share_bytes = Zeroizing::new(Vec::with_capacity(shared_secret.len()));
    digest_share_bytes.extend_from_slice(&digest);
    digest_share_bytes.extend_from_slice(&random_part);

    let mut base_shares = Vec::with_capacity(usize::from(threshold));
    for share in &shares {
        base_shares.push(RawShare {
            x: share.x,
            data: Zeroizing::new(share.data.to_vec()),
        });
    }
    base_shares.push(RawShare {
        x: DIGEST_INDEX,
        data: digest_share_bytes,
    });
    base_shares.push(RawShare {
        x: SECRET_INDEX,
        data: Zeroizing::new(shared_secret.to_vec()),
    });

    for index in random_share_count..share_count {
        let data = interpolate(&base_shares, index)?;
        shares.push(RawShare { x: index, data });
    }
    Ok(shares)
}

pub(super) fn recover_secret_raw(threshold: u8, shares: &[RawShare]) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    if threshold == 0 || shares.len() != usize::from(threshold) {
        return Err(Slip39Error::InvalidShareCount);
    }
    if threshold == 1 {
        let first = shares.first().ok_or(Slip39Error::InvalidShareCount)?;
        return Ok(Zeroizing::new(first.data.to_vec()));
    }
    let shared_secret = interpolate(shares, SECRET_INDEX)?;
    let digest_share = interpolate(shares, DIGEST_INDEX)?;
    let digest = digest_share.get(..DIGEST_LEN).ok_or(Slip39Error::InvalidDigest)?;
    let random_part = digest_share.get(DIGEST_LEN..).ok_or(Slip39Error::InvalidDigest)?;
    let expected = create_digest(random_part, &shared_secret)?;
    if !ct_eq(digest, &expected) {
        return Err(Slip39Error::InvalidDigest);
    }
    Ok(shared_secret)
}
