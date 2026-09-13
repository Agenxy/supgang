use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, decode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    identity::{RootIdentity, verify_domain},
    ids::{HiveId, NodeId},
};

use super::{UPDATE_DIGEST_BYTES, UpdateError, artifact_like_read, lifecycle, updates_directory};

const AUTHORIZATION_VERSION: u16 = 2;
const SIGNATURE_BYTES: usize = 64;
const NONCE_BYTES: usize = 32;
const AUTHORIZATION_DOMAIN: &[u8] = b"supgang/peer-update-authorization/v1\0";
const MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 10 * 60;
pub(super) const MAX_AUTHORIZATION_BYTES: usize = 256;
const NONCE_LEDGER_FILE: &str = "authorization-nonces.json";
const NONCE_LEDGER_SCHEMA: &str = "supgang.update-authorization-nonces/v1";
const MAX_NONCE_RECORDS: usize = 256;
const MAX_NONCE_LEDGER_BYTES: u64 = 128 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateAuthorization {
    pub(crate) hive_id: HiveId,
    pub(crate) issuer: NodeId,
    pub(crate) target: NodeId,
    pub(crate) bundle_digest: [u8; UPDATE_DIGEST_BYTES],
    pub(crate) bundle_length: u64,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    nonce: [u8; NONCE_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthorizationError {
    #[error("peer update authorization is invalid")]
    Invalid,
    #[error("peer update authorization could not obtain secure randomness")]
    Random,
}

impl UpdateAuthorization {
    pub(crate) fn sign(
        root: &RootIdentity,
        issuer: NodeId,
        target: NodeId,
        bundle_digest: [u8; UPDATE_DIGEST_BYTES],
        bundle_length: u64,
        now: u64,
    ) -> Result<Self, AuthorizationError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| AuthorizationError::Random)?;
        let mut value = Self {
            hive_id: root.hive_id(),
            issuer,
            target,
            bundle_digest,
            bundle_length,
            issued_at: now,
            expires_at: now.saturating_add(5 * 60),
            nonce,
            signature: [0_u8; SIGNATURE_BYTES],
        };
        value.signature = root.sign_domain(AUTHORIZATION_DOMAIN, &value.payload()?);
        Ok(value)
    }

    pub(crate) fn verify(
        &self,
        root: &VerifyingKey,
        expected_hive: HiveId,
        authenticated_issuer: NodeId,
        local_target: NodeId,
        now: u64,
    ) -> Result<(), AuthorizationError> {
        if self.hive_id != expected_hive
            || self.issuer != authenticated_issuer
            || self.target != local_target
            || self.expires_at < now
            || self.issued_at > now
            || self.expires_at < self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_AUTHORIZATION_LIFETIME_SECONDS
            || !(1..=super::MAX_UPDATE_BUNDLE_BYTES).contains(&self.bundle_length)
            || !verify_domain(root, AUTHORIZATION_DOMAIN, &self.payload()?, &self.signature)
        {
            return Err(AuthorizationError::Invalid);
        }
        Ok(())
    }

    fn payload(&self) -> Result<Vec<u8>, AuthorizationError> {
        let mut bytes = Vec::with_capacity(192);
        let mut encoder = Encoder::new(&mut bytes);
        encoder.array(9).map_err(map_encode)?;
        encoder.u16(AUTHORIZATION_VERSION).map_err(map_encode)?;
        encoder.bytes(self.hive_id.as_bytes()).map_err(map_encode)?;
        encoder.bytes(self.issuer.as_bytes()).map_err(map_encode)?;
        encoder.bytes(self.target.as_bytes()).map_err(map_encode)?;
        encoder.bytes(&self.bundle_digest).map_err(map_encode)?;
        encoder.u64(self.bundle_length).map_err(map_encode)?;
        encoder.u64(self.issued_at).map_err(map_encode)?;
        encoder.u64(self.expires_at).map_err(map_encode)?;
        encoder.bytes(&self.nonce).map_err(map_encode)?;
        Ok(bytes)
    }
}

pub fn encode_authorization(value: &UpdateAuthorization) -> Result<Vec<u8>, AuthorizationError> {
    let payload = value.payload()?;
    let mut bytes = Vec::with_capacity(MAX_AUTHORIZATION_BYTES);
    let mut encoder = Encoder::new(&mut bytes);
    encoder.array(2).map_err(map_encode)?;
    encoder.bytes(&payload).map_err(map_encode)?;
    encoder.bytes(&value.signature).map_err(map_encode)?;
    if bytes.is_empty() || bytes.len() > MAX_AUTHORIZATION_BYTES {
        return Err(AuthorizationError::Invalid);
    }
    Ok(bytes)
}

pub fn decode_authorization(bytes: &[u8]) -> Result<UpdateAuthorization, AuthorizationError> {
    if bytes.is_empty() || bytes.len() > MAX_AUTHORIZATION_BYTES {
        return Err(AuthorizationError::Invalid);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(map_decode)? != Some(2) {
        return Err(AuthorizationError::Invalid);
    }
    let payload = decoder.bytes().map_err(map_decode)?;
    let signature = read_fixed(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(AuthorizationError::Invalid);
    }
    let mut payload_decoder = Decoder::new(payload);
    if payload_decoder.array().map_err(map_decode)? != Some(9)
        || payload_decoder.u16().map_err(map_decode)? != AUTHORIZATION_VERSION
    {
        return Err(AuthorizationError::Invalid);
    }
    let value = UpdateAuthorization {
        hive_id: HiveId::from_bytes(read_fixed(&mut payload_decoder)?),
        issuer: NodeId::from_bytes(read_fixed(&mut payload_decoder)?),
        target: NodeId::from_bytes(read_fixed(&mut payload_decoder)?),
        bundle_digest: read_fixed(&mut payload_decoder)?,
        bundle_length: payload_decoder.u64().map_err(map_decode)?,
        issued_at: payload_decoder.u64().map_err(map_decode)?,
        expires_at: payload_decoder.u64().map_err(map_decode)?,
        nonce: read_fixed(&mut payload_decoder)?,
        signature,
    };
    if payload_decoder.position() != payload.len() || encode_authorization(&value)?.as_slice() != bytes {
        return Err(AuthorizationError::Invalid);
    }
    Ok(value)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NonceLedger {
    schema: String,
    records: Vec<NonceRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct NonceRecord {
    issuer: String,
    target: String,
    nonce: String,
    digest: String,
    bundle_length: u64,
    expires_at: u64,
}

pub fn reserve_authorization(
    state_directory: &std::path::Path,
    authorization: &UpdateAuthorization,
    now: u64,
    _lock: &super::UpdateLock,
) -> Result<(), UpdateError> {
    let updates = updates_directory(state_directory, true)?;
    let path = updates.join(NONCE_LEDGER_FILE);
    let mut ledger = match path.symlink_metadata() {
        Ok(_) => {
            let bytes = artifact_like_read(&path, MAX_NONCE_LEDGER_BYTES, 0o600)?;
            let parsed: NonceLedger = serde_json::from_slice(&bytes).map_err(|_| UpdateError::InvalidBundle)?;
            if serde_json::to_vec(&parsed).map_err(|_| UpdateError::InvalidBundle)? != bytes
                || parsed.schema != NONCE_LEDGER_SCHEMA
                || parsed.records.len() > MAX_NONCE_RECORDS
                || parsed.records.iter().any(|record| !record.valid())
            {
                return Err(UpdateError::InvalidBundle);
            }
            parsed
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => NonceLedger {
            schema: NONCE_LEDGER_SCHEMA.to_owned(),
            records: Vec::new(),
        },
        Err(error) => return Err(error.into()),
    };
    ledger.records.retain(|record| record.expires_at >= now);
    let candidate = NonceRecord::from_authorization(authorization);
    if ledger.records.iter().any(|record| {
        record.issuer == candidate.issuer && record.target == candidate.target && record.nonce == candidate.nonce
    }) {
        return Err(UpdateError::ReplayedAuthorization);
    }
    if ledger.records.len() >= MAX_NONCE_RECORDS {
        return Err(UpdateError::Capacity);
    }
    ledger.records.push(candidate);
    ledger.records.sort_unstable();
    let bytes = serde_json::to_vec(&ledger).map_err(|_| UpdateError::InvalidBundle)?;
    if bytes.len() > usize::try_from(MAX_NONCE_LEDGER_BYTES).map_err(|_| UpdateError::Capacity)? {
        return Err(UpdateError::Capacity);
    }
    lifecycle::write_atomic_bounded(
        &updates,
        NONCE_LEDGER_FILE,
        &bytes,
        0o600,
        usize::try_from(MAX_NONCE_LEDGER_BYTES).map_err(|_| UpdateError::Capacity)?,
    )
}

impl NonceRecord {
    fn from_authorization(value: &UpdateAuthorization) -> Self {
        Self {
            issuer: value.issuer.to_string(),
            target: value.target.to_string(),
            nonce: hex::encode(value.nonce),
            digest: hex::encode(value.bundle_digest),
            bundle_length: value.bundle_length,
            expires_at: value.expires_at,
        }
    }

    fn valid(&self) -> bool {
        self.issuer.parse::<NodeId>().is_ok()
            && self.target.parse::<NodeId>().is_ok()
            && hex::decode(&self.nonce).is_ok_and(|bytes| bytes.len() == NONCE_BYTES)
            && hex::decode(&self.digest).is_ok_and(|bytes| bytes.len() == UPDATE_DIGEST_BYTES)
            && (1..=super::MAX_UPDATE_BUNDLE_BYTES).contains(&self.bundle_length)
    }
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], AuthorizationError> {
    decoder
        .bytes()
        .map_err(map_decode)?
        .try_into()
        .map_err(|_| AuthorizationError::Invalid)
}

fn map_encode<E>(_: minicbor::encode::Error<E>) -> AuthorizationError {
    AuthorizationError::Invalid
}

fn map_decode(_: decode::Error) -> AuthorizationError {
    AuthorizationError::Invalid
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationError, MAX_NONCE_RECORDS, UpdateAuthorization, decode_authorization, encode_authorization,
    };
    use crate::{identity::RootIdentity, ids::NodeId};

    #[test]
    fn authorization_binds_root_issuer_target_digest_and_time() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let issuer = NodeId::from_bytes([1; 32]);
        let target = NodeId::from_bytes([2; 32]);
        let value = UpdateAuthorization::sign(&root, issuer, target, [3; 32], 1_024, 100)?;
        let decoded = decode_authorization(&encode_authorization(&value)?)?;
        decoded.verify(&root.verifying_key(), root.hive_id(), issuer, target, 101)?;
        assert_eq!(
            decoded.verify(
                &root.verifying_key(),
                root.hive_id(),
                NodeId::from_bytes([9; 32]),
                target,
                101
            ),
            Err(AuthorizationError::Invalid)
        );
        assert_eq!(
            decoded.verify(&root.verifying_key(), root.hive_id(), issuer, target, 1_000),
            Err(AuthorizationError::Invalid)
        );
        let mut wrong_length = decoded;
        wrong_length.bundle_length = 2_048;
        assert_eq!(
            wrong_length.verify(&root.verifying_key(), root.hive_id(), issuer, target, 101),
            Err(AuthorizationError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn authorization_nonce_is_consumed_durably_before_bundle_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let root = RootIdentity::generate()?;
        let authorization = UpdateAuthorization::sign(
            &root,
            NodeId::from_bytes([1; 32]),
            NodeId::from_bytes([2; 32]),
            [3; 32],
            1_024,
            100,
        )?;
        {
            let lock = crate::update::UpdateLock::acquire(&state)?;
            super::reserve_authorization(&state, &authorization, 100, &lock)?;
        }
        let lock = crate::update::UpdateLock::acquire(&state)?;
        assert!(matches!(
            super::reserve_authorization(&state, &authorization, 101, &lock),
            Err(crate::update::UpdateError::ReplayedAuthorization)
        ));
        Ok(())
    }

    #[test]
    fn authorization_nonce_ledger_is_bounded_and_prunes_expired_records() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        drop(crate::state::initialize(&state)?);
        let root = RootIdentity::generate()?;
        let issuer = NodeId::from_bytes([1; 32]);
        let target = NodeId::from_bytes([2; 32]);
        let lock = crate::update::UpdateLock::acquire(&state)?;
        for index in 0..MAX_NONCE_RECORDS {
            let digest_byte = u8::try_from(index)?;
            let authorization = UpdateAuthorization::sign(&root, issuer, target, [digest_byte; 32], 1_024, 100)?;
            super::reserve_authorization(&state, &authorization, 100, &lock)?;
        }
        let full = UpdateAuthorization::sign(&root, issuer, target, [0xff; 32], 1_024, 100)?;
        assert!(matches!(
            super::reserve_authorization(&state, &full, 100, &lock),
            Err(crate::update::UpdateError::Capacity)
        ));
        super::reserve_authorization(&state, &full, 401, &lock)?;
        Ok(())
    }
}
