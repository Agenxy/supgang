//! Isolated ADR 0004 state-machine prototype using disposable test keys.
//!
//! Every share here is `file` custody in memory. There is no sealed custody,
//! provider, network, CLI, CA, or connection to the live service. The simulated
//! DKG channel is neither encrypted nor an implementation of owner pairing.
//! Session files retain locks and public commitments, never nonce secrets.
//! Whole-directory rollback and hostile same-user memory access are outside
//! this test-key model; do not use these interfaces for real authority.

use frost_ed25519::rand_core::SeedableRng as _;
use minicbor::Decoder;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroize as _;

pub mod control_auth;
pub mod founding;
pub mod owner_action;
pub mod regroup;
pub mod release_statement;
pub mod session;
pub mod status;
pub mod status_renewal;
pub mod step;

#[cfg(test)]
mod tests;

/// SHA-256 content identity, independent of signature bytes.
pub type Digest = [u8; 32];
/// Maximum participants in either signing group.
pub const MAX_PARTICIPANTS: usize = 16;
/// Maximum encoded step, including opaque operation payload.
pub const MAX_STEP_BYTES: usize = 16 * 1024;
/// Maximum retained chain entries, pending entries, or session records.
pub const MAX_RECORDS: usize = 256;

/// Failure without secret-bearing diagnostic data.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid parameters, encoding or state transition.
    #[error("invalid threshold parameters, encoding or transition")]
    Invalid,
    /// A finite resource or counter is exhausted.
    #[error("threshold prototype bound exceeded")]
    Bound,
    /// FROST 3.0.0 cannot perform DKG with a threshold of one.
    #[error("FROST 3.0.0 DKG requires a threshold of at least two")]
    ThresholdOne,
    /// The owner did not explicitly accept single-device-loss failure.
    #[error("group cannot survive one loss; explicit acceptance required")]
    SingleLoss,
    /// No affirmative presence callback result.
    #[error("participant presence was not confirmed")]
    Presence,
    /// A predecessor or session is already reserved.
    #[error("predecessor or signing session is locked")]
    Locked,
    /// Authority belongs to another hive, roster or generation.
    #[error("threshold authority does not match the current group")]
    Authority,
    /// A message, commitment set, or cryptographic proof did not match.
    #[error("threshold signature or signing package failed verification")]
    Proof,
    /// A fork was observed and ordinary administration is halted.
    #[error("threshold chain halted on authenticated equivocation")]
    Halted,
    /// Durable state could not be safely advanced.
    #[error("threshold session store conflict or poisoned handle")]
    Store,
    /// OS entropy unavailable.
    #[error("secure randomness unavailable")]
    Random,
    /// FROST protocol failure; underlying details are not printed.
    #[error("FROST protocol refused the operation")]
    Frost(#[from] frost_ed25519::Error),
    /// Device proof failure.
    #[error("device proof failed")]
    Device(#[from] crate::device_key::DeviceKeyError),
    /// Canonical encoder failure.
    #[error("threshold encoding failed")]
    Encode(#[from] minicbor::encode::Error<core::convert::Infallible>),
    /// Strict decoder failure.
    #[error("threshold decoding failed")]
    Decode(#[from] minicbor::decode::Error),
    /// Protected-file validation failure.
    #[error("threshold protected storage failed")]
    Storage(#[from] crate::storage::StorageError),
    /// Exclusive ownership unavailable.
    #[error("threshold store is already owned or cannot be locked")]
    Lock(#[from] crate::state_lock::StateLockError),
    /// Atomic-file operation failed.
    #[error("threshold storage I/O failed")]
    Io(#[from] std::io::Error),
}

fn hash(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

fn rng() -> Result<rand_chacha::ChaCha20Rng, Error> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::Random)?;
    let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(rng)
}

fn length(value: usize) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::Bound)
}

fn array(d: &mut Decoder<'_>, size: u64) -> Result<(), Error> {
    if d.array()? != Some(size) {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], Error> {
    d.bytes()?.try_into().map_err(|_| Error::Invalid)
}

fn count(d: &mut Decoder<'_>, maximum: usize) -> Result<usize, Error> {
    let count = usize::try_from(d.array()?.ok_or(Error::Invalid)?).map_err(|_| Error::Bound)?;
    if count > maximum {
        return Err(Error::Bound);
    }
    Ok(count)
}

fn canonical(input: &[u8], encoded: &[u8]) -> Result<(), Error> {
    if input != encoded {
        return Err(Error::Invalid);
    }
    Ok(())
}
