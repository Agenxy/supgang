//! Pure-Rust SLIP-39 Shamir secret sharing for NC0 product-root escrow.
//!
//! Implements RS1024 checksums, the 4-round Feistel cipher over
//! PBKDF2-HMAC-SHA256, GF(256) Shamir splitting/interpolation with digest-share
//! authentication, and the SHA-256-pinned 1024-word SLIP-39 wordlist.

use std::collections::BTreeMap;

use thiserror::Error;
use zeroize::Zeroizing;

mod cipher;
mod gf256;
mod rs1024;
mod wordlist;

#[cfg(test)]
mod tests;

/// Minimum allowed secret length in bytes (128 bits).
pub const MIN_SECRET_BYTES: usize = 16;
/// Maximum bounded secret length in bytes (512 bits).
pub const MAX_SECRET_BYTES: usize = 64;
/// Maximum shares per group and maximum groups per split.
pub const MAX_SHARE_COUNT: u8 = 16;
/// Required NC0 master secret length in bytes (256 bits).
pub const NC0_MASTER_BYTES: usize = 32;
/// Standard iteration exponent used when generating NC0 ceremony shares.
pub const DEFAULT_ITERATION_EXPONENT: u8 = 1;
/// Maximum bounded iteration exponent accepted by the Feistel KDF.
pub const MAX_ITERATION_EXPONENT: u8 = 8;

const RADIX_BITS: usize = 10;
const ID_EXP_WORDS: usize = 2;
const PARAM_WORDS: usize = 2;
const METADATA_WORDS: usize = ID_EXP_WORDS + PARAM_WORDS + rs1024::CHECKSUM_WORDS;
const MIN_MNEMONIC_WORDS: usize = METADATA_WORDS + 13;
const MAX_MNEMONIC_WORDS: usize = METADATA_WORDS + 52;
const MAX_MNEMONIC_INPUT_BYTES: usize = 1_024;
const MAX_INPUT_SHARES: usize = 64;
const MAX_PASSPHRASE_BYTES: usize = 256;
const CUSTOMIZATION_ORIG: &[u8] = b"shamir";
const CUSTOMIZATION_EXTENDABLE: &[u8] = b"shamir_extendable";

/// Bounded SLIP-39 refusal. Messages never include secret bytes or words.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum Slip39Error {
    /// Embedded wordlist failed structural validation.
    #[error("embedded SLIP-39 wordlist is corrupt")]
    CorruptWordlist,
    /// Word index outside `0..1024`.
    #[error("SLIP-39 word index out of range")]
    InvalidWordIndex,
    /// Word is not in the 1024-word SLIP-39 wordlist.
    #[error("unknown SLIP-39 mnemonic word")]
    InvalidWord,
    /// Mnemonic has too few, too many, or non-aligned words.
    #[error("invalid SLIP-39 mnemonic length")]
    InvalidLength,
    /// Nonzero leading padding bits in the share value.
    #[error("invalid SLIP-39 mnemonic padding")]
    InvalidPadding,
    /// RS1024 checksum failed.
    #[error("invalid SLIP-39 mnemonic checksum")]
    InvalidChecksum,
    /// Invalid threshold, group count, or share count parameter.
    #[error("invalid SLIP-39 sharing parameters")]
    InvalidParameters,
    /// Secret length is below 16 bytes, above 64 bytes, or odd.
    #[error("invalid SLIP-39 secret length")]
    InvalidSecretLength,
    /// Passphrase contains non-printable-ASCII bytes or exceeds 256 bytes.
    #[error("SLIP-39 passphrase must be printable ASCII up to 256 bytes")]
    InvalidPassphrase,
    /// Iteration exponent exceeds the bounded limit.
    #[error("SLIP-39 iteration exponent exceeds bounded limit")]
    UnsupportedIterationExponent,
    /// Share set is empty, over-bounded, or does not match threshold count.
    #[error("invalid number of SLIP-39 shares or groups")]
    InvalidShareCount,
    /// Shares in the set disagree on identifier, flags, exponent, or thresholds.
    #[error("SLIP-39 shares have mismatching metadata parameters")]
    MismatchedParameters,
    /// Two shares in the same group have the same member index.
    #[error("duplicate SLIP-39 share index")]
    DuplicateShareIndex,
    /// Shares in a group do not all have the same byte length.
    #[error("inconsistent SLIP-39 share lengths")]
    InconsistentShareLength,
    /// Reconstructed digest share does not authenticate the recovered secret.
    #[error("SLIP-39 share digest authentication failed")]
    InvalidDigest,
    /// Operating-system CSPRNG failed.
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
    /// Internal invariant failure.
    #[error("internal SLIP-39 error")]
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommonParams {
    identifier: u16,
    extendable: bool,
    iteration_exponent: u8,
    group_threshold: u8,
    group_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GroupParams {
    common: CommonParams,
    group_index: u8,
    member_threshold: u8,
}

/// One parsed SLIP-39 share with zeroized value bytes.
struct Share {
    identifier: u16,
    extendable: bool,
    iteration_exponent: u8,
    group_index: u8,
    group_threshold: u8,
    group_count: u8,
    member_index: u8,
    member_threshold: u8,
    value: Zeroizing<Vec<u8>>,
}

impl Share {
    const fn common_params(&self) -> CommonParams {
        CommonParams {
            identifier: self.identifier,
            extendable: self.extendable,
            iteration_exponent: self.iteration_exponent,
            group_threshold: self.group_threshold,
            group_count: self.group_count,
        }
    }

    const fn group_params(&self) -> GroupParams {
        GroupParams {
            common: self.common_params(),
            group_index: self.group_index,
            member_threshold: self.member_threshold,
        }
    }

    fn to_mnemonic(&self) -> Result<Zeroizing<String>, Slip39Error> {
        let mut indices = Zeroizing::new(Vec::with_capacity(MAX_MNEMONIC_WORDS));
        let id_exp: u32 = (u32::from(self.identifier) << 5)
            | (u32::from(u8::from(self.extendable)) << 4)
            | u32::from(self.iteration_exponent);
        indices.push(u16::try_from((id_exp >> 10) & 0x3FF).map_err(|_| Slip39Error::Internal)?);
        indices.push(u16::try_from(id_exp & 0x3FF).map_err(|_| Slip39Error::Internal)?);

        let params: u32 = (u32::from(self.group_index) << 16)
            | (u32::from(self.group_threshold - 1) << 12)
            | (u32::from(self.group_count - 1) << 8)
            | (u32::from(self.member_index) << 4)
            | u32::from(self.member_threshold - 1);
        indices.push(u16::try_from((params >> 10) & 0x3FF).map_err(|_| Slip39Error::Internal)?);
        indices.push(u16::try_from(params & 0x3FF).map_err(|_| Slip39Error::Internal)?);

        encode_value_words(&self.value, &mut indices)?;
        let checksum = rs1024::create_checksum(&indices, customization(self.extendable));
        indices.extend_from_slice(&checksum);

        let mut mnemonic = Zeroizing::new(String::with_capacity(indices.len() * 9));
        for (position, &index) in indices.iter().enumerate() {
            if position != 0 {
                mnemonic.push(' ');
            }
            mnemonic.push_str(wordlist::word_at(index)?);
        }
        Ok(mnemonic)
    }

    fn from_mnemonic(mnemonic: &str) -> Result<Self, Slip39Error> {
        if mnemonic.len() > MAX_MNEMONIC_INPUT_BYTES {
            return Err(Slip39Error::InvalidLength);
        }
        let mut indices = Zeroizing::new(Vec::with_capacity(MAX_MNEMONIC_WORDS));
        for token in mnemonic.split_whitespace() {
            if indices.len() >= MAX_MNEMONIC_WORDS {
                return Err(Slip39Error::InvalidLength);
            }
            indices.push(wordlist::index_of(token)?);
        }
        if indices.len() < MIN_MNEMONIC_WORDS {
            return Err(Slip39Error::InvalidLength);
        }
        let value_word_count = indices.len() - METADATA_WORDS;
        let padding_bits = (RADIX_BITS * value_word_count) % 16;
        if padding_bits > 8 {
            return Err(Slip39Error::InvalidLength);
        }

        let w0 = *indices.first().ok_or(Slip39Error::InvalidLength)?;
        let w1 = *indices.get(1).ok_or(Slip39Error::InvalidLength)?;
        let id_exp = (u32::from(w0) << 10) | u32::from(w1);
        let identifier = u16::try_from(id_exp >> 5).map_err(|_| Slip39Error::Internal)?;
        let extendable = ((id_exp >> 4) & 1) != 0;
        let iteration_exponent = u8::try_from(id_exp & 0x0F).map_err(|_| Slip39Error::Internal)?;

        if !rs1024::verify_checksum(&indices, customization(extendable)) {
            return Err(Slip39Error::InvalidChecksum);
        }

        let w2 = *indices.get(2).ok_or(Slip39Error::InvalidLength)?;
        let w3 = *indices.get(3).ok_or(Slip39Error::InvalidLength)?;
        let params = (u32::from(w2) << 10) | u32::from(w3);
        let group_index = u8::try_from((params >> 16) & 0x0F).map_err(|_| Slip39Error::Internal)?;
        let group_threshold = u8::try_from(((params >> 12) & 0x0F) + 1).map_err(|_| Slip39Error::Internal)?;
        let group_count = u8::try_from(((params >> 8) & 0x0F) + 1).map_err(|_| Slip39Error::Internal)?;
        let member_index = u8::try_from((params >> 4) & 0x0F).map_err(|_| Slip39Error::Internal)?;
        let member_threshold = u8::try_from((params & 0x0F) + 1).map_err(|_| Slip39Error::Internal)?;

        if group_count < group_threshold || group_index >= group_count {
            return Err(Slip39Error::InvalidParameters);
        }

        let value_words = indices
            .get(ID_EXP_WORDS + PARAM_WORDS..indices.len() - rs1024::CHECKSUM_WORDS)
            .ok_or(Slip39Error::InvalidLength)?;
        let value = decode_value_words(value_words, padding_bits)?;
        Ok(Self {
            identifier,
            extendable,
            iteration_exponent,
            group_index,
            group_threshold,
            group_count,
            member_index,
            member_threshold,
            value,
        })
    }
}

const fn customization(extendable: bool) -> &'static [u8] {
    if extendable {
        CUSTOMIZATION_EXTENDABLE
    } else {
        CUSTOMIZATION_ORIG
    }
}

fn encode_value_words(value: &[u8], out: &mut Vec<u16>) -> Result<(), Slip39Error> {
    let total_value_bits = value.len() * 8;
    let word_count = total_value_bits.div_ceil(RADIX_BITS);
    let total_stream_bits = word_count * RADIX_BITS;
    let pad_bits = total_stream_bits - total_value_bits;
    for word_idx in 0..word_count {
        let mut word = 0_u16;
        for bit_in_word in 0..RADIX_BITS {
            let stream_bit = word_idx * RADIX_BITS + bit_in_word;
            let bit = if stream_bit < pad_bits {
                0_u16
            } else {
                let value_bit = stream_bit - pad_bits;
                let byte = *value.get(value_bit / 8).ok_or(Slip39Error::Internal)?;
                u16::from((byte >> (7 - (value_bit % 8))) & 1)
            };
            word = (word << 1) | bit;
        }
        out.push(word);
    }
    Ok(())
}

fn decode_value_words(words: &[u16], padding_bits: usize) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    let first = *words.first().ok_or(Slip39Error::InvalidLength)?;
    if padding_bits > 0 && (first >> (RADIX_BITS - padding_bits)) != 0 {
        return Err(Slip39Error::InvalidPadding);
    }
    let total_stream_bits = words.len() * RADIX_BITS;
    let value_bits = total_stream_bits - padding_bits;
    if !value_bits.is_multiple_of(8) {
        return Err(Slip39Error::InvalidLength);
    }
    let byte_len = value_bits / 8;
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&byte_len) || !byte_len.is_multiple_of(2) {
        return Err(Slip39Error::InvalidSecretLength);
    }
    let mut out = Zeroizing::new(vec![0_u8; byte_len]);
    for byte_idx in 0..byte_len {
        let mut byte = 0_u8;
        for bit_in_byte in 0..8 {
            let stream_bit = padding_bits + byte_idx * 8 + bit_in_byte;
            let word = *words.get(stream_bit / RADIX_BITS).ok_or(Slip39Error::Internal)?;
            let shift = RADIX_BITS - 1 - (stream_bit % RADIX_BITS);
            let bit = u8::try_from((word >> shift) & 1).map_err(|_| Slip39Error::Internal)?;
            byte = (byte << 1) | bit;
        }
        *out.get_mut(byte_idx).ok_or(Slip39Error::Internal)? = byte;
    }
    Ok(out)
}

fn random_identifier() -> Result<u16, Slip39Error> {
    let mut bytes = [0_u8; 2];
    getrandom::fill(&mut bytes).map_err(|_| Slip39Error::RandomnessUnavailable)?;
    Ok(u16::from_be_bytes(bytes) & 0x7FFF)
}

/// Split a 32-byte NC0 master secret into three 2-of-3 single-group SLIP-39
/// shares with an empty SLIP-39 passphrase and standard iteration exponent.
///
/// # Errors
/// Refuses any secret length other than 32 bytes or OS CSPRNG failure.
pub fn split_2_of_3(master_secret: &[u8]) -> Result<[Zeroizing<String>; 3], Slip39Error> {
    if master_secret.len() != NC0_MASTER_BYTES {
        return Err(Slip39Error::InvalidSecretLength);
    }
    let mut groups = generate_mnemonics(1, &[(2, 3)], master_secret, b"", true, DEFAULT_ITERATION_EXPONENT)?;
    let group = groups.pop().ok_or(Slip39Error::Internal)?;
    let mut iter = group.into_iter();
    let first = iter.next().ok_or(Slip39Error::Internal)?;
    let second = iter.next().ok_or(Slip39Error::Internal)?;
    let third = iter.next().ok_or(Slip39Error::Internal)?;
    if iter.next().is_some() {
        return Err(Slip39Error::Internal);
    }
    Ok([first, second, third])
}

/// Split `master_secret` into SLIP-39 mnemonic groups under explicit parameters.
///
/// # Errors
/// Refuses invalid secret lengths, passphrases, group/member thresholds,
/// 1-of-N groups with `N > 1`, unsupported exponents, or CSPRNG failures.
pub fn generate_mnemonics(
    group_threshold: u8,
    groups: &[(u8, u8)],
    master_secret: &[u8],
    passphrase: &[u8],
    extendable: bool,
    iteration_exponent: u8,
) -> Result<Vec<Vec<Zeroizing<String>>>, Slip39Error> {
    cipher::validate_passphrase(passphrase)?;
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&master_secret.len()) || !master_secret.len().is_multiple_of(2) {
        return Err(Slip39Error::InvalidSecretLength);
    }
    let group_count = u8::try_from(groups.len()).map_err(|_| Slip39Error::InvalidParameters)?;
    if group_threshold == 0 || group_count == 0 || group_threshold > group_count || group_count > MAX_SHARE_COUNT {
        return Err(Slip39Error::InvalidParameters);
    }
    for &(member_threshold, member_count) in groups {
        if member_threshold == 0
            || member_threshold > member_count
            || member_count > MAX_SHARE_COUNT
            || (member_threshold == 1 && member_count > 1)
        {
            return Err(Slip39Error::InvalidParameters);
        }
    }

    let identifier = random_identifier()?;
    let ems = cipher::encrypt(master_secret, passphrase, iteration_exponent, identifier, extendable)?;
    let group_shares = gf256::split_secret_raw(group_threshold, group_count, &ems)?;

    let mut result = Vec::with_capacity(groups.len());
    for (&(member_threshold, member_count), group_share) in groups.iter().zip(group_shares.iter()) {
        let member_shares = gf256::split_secret_raw(member_threshold, member_count, &group_share.data)?;
        let mut mnemonics = Vec::with_capacity(usize::from(member_count));
        for member in member_shares {
            let share = Share {
                identifier,
                extendable,
                iteration_exponent,
                group_index: group_share.x,
                group_threshold,
                group_count,
                member_index: member.x,
                member_threshold,
                value: member.data,
            };
            mnemonics.push(share.to_mnemonic()?);
        }
        result.push(mnemonics);
    }
    Ok(result)
}

/// Combine SLIP-39 mnemonic shares and decrypt the recovered master secret.
///
/// # Errors
/// Refuses empty/oversized inputs, bad words, checksums, padding, mismatched
/// parameters, duplicate indices, insufficient or excess shares/groups,
/// invalid digests, or bad passphrases.
pub fn combine_mnemonics(mnemonics: &[&str], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, Slip39Error> {
    cipher::validate_passphrase(passphrase)?;
    if mnemonics.is_empty() || mnemonics.len() > MAX_INPUT_SHARES {
        return Err(Slip39Error::InvalidShareCount);
    }

    let mut common: Option<CommonParams> = None;
    let mut groups: BTreeMap<u8, (GroupParams, Vec<gf256::RawShare>)> = BTreeMap::new();

    for mnemonic in mnemonics {
        let share = Share::from_mnemonic(mnemonic)?;
        let share_common = share.common_params();
        if let Some(expected) = common {
            if expected != share_common {
                return Err(Slip39Error::MismatchedParameters);
            }
        } else {
            common = Some(share_common);
        }
        let share_group = share.group_params();
        let entry = groups
            .entry(share.group_index)
            .or_insert_with(|| (share_group, Vec::new()));
        if entry.0 != share_group {
            return Err(Slip39Error::MismatchedParameters);
        }
        if entry.1.iter().any(|existing| existing.x == share.member_index) {
            return Err(Slip39Error::DuplicateShareIndex);
        }
        entry.1.push(gf256::RawShare {
            x: share.member_index,
            data: share.value,
        });
    }

    let params = common.ok_or(Slip39Error::InvalidShareCount)?;
    if groups.len() != usize::from(params.group_threshold) {
        return Err(Slip39Error::InvalidShareCount);
    }

    let mut recovered_groups = Vec::with_capacity(groups.len());
    for (group_index, (group_params, raw_shares)) in groups {
        if raw_shares.len() != usize::from(group_params.member_threshold) {
            return Err(Slip39Error::InvalidShareCount);
        }
        let group_secret = gf256::recover_secret_raw(group_params.member_threshold, &raw_shares)?;
        recovered_groups.push(gf256::RawShare {
            x: group_index,
            data: group_secret,
        });
    }

    let ems = gf256::recover_secret_raw(params.group_threshold, &recovered_groups)?;
    cipher::decrypt(
        &ems,
        passphrase,
        params.iteration_exponent,
        params.identifier,
        params.extendable,
    )
}
