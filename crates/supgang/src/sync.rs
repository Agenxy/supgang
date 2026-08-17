//! Small, bounded contact anti-entropy over an authenticated peer connection.

use minicbor::{Decoder, Encoder, decode};
use quinn::{Connection, RecvStream, SendStream};
use thiserror::Error;

use crate::{
    contact::{MAX_CONTACT_BYTES, PeerContact, decode_contact, encode_contact},
    revocation::{
        MAX_SIGNED_REVOCATION_BYTES, SignedRevocationList, decode_signed_revocations, encode_signed_revocations,
    },
};

/// Maximum contacts sent by one side in one reconciliation round.
pub const MAX_SYNC_CONTACTS: usize = 8;
/// Maximum encoded reconciliation frame size.
pub const MAX_SYNC_FRAME_BYTES: usize = 64 * 1024;
/// Maximum root-signed revocation notice frame accepted on a one-way stream.
pub const MAX_REVOCATION_NOTICE_FRAME_BYTES: usize = 10 * 1024;

const SYNC_VERSION: u16 = 2;
const SYNC_OFFER: u8 = 1;
const SYNC_REPLY: u8 = 2;
const REVOCATION_NOTICE_VERSION: u16 = 1;

/// A contact reconciliation framing or canonical-encoding failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SyncError {
    /// QUIC stream creation, I/O, or finish failed.
    #[error("peer contact synchronization transport failed")]
    Transport,
    /// A frame or contact count exceeded its fixed protocol budget.
    #[error("peer contact synchronization exceeded its fixed size limit")]
    Oversized,
    /// A message had a wrong version, type, count, or trailing bytes.
    #[error("peer contact synchronization message has an invalid shape")]
    InvalidShape,
    /// A nested contact was malformed or non-canonical.
    #[error("peer contact synchronization contained an invalid contact")]
    InvalidContact,
    /// Deterministic encoding failed.
    #[error("peer contact synchronization encoding failed")]
    Encoding,
    /// A nested root-signed revocation snapshot was malformed.
    #[error("peer contact synchronization contained invalid revocation state")]
    InvalidRevocation,
}

/// One bounded anti-entropy page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPage {
    /// Rotating contact subset.
    pub contacts: Vec<PeerContact>,
    /// Latest root-signed revocation snapshot.
    pub revocations: SignedRevocationList,
}

/// Exchanges one contact page from the outbound side.
///
/// Both sides must have completed mutual session authentication first.
/// Returned contacts remain untrusted until the caller verifies and imports
/// each one against its local hive root.
///
/// # Errors
///
/// Rejects oversized, malformed, non-canonical, or failed stream exchange.
pub async fn exchange_outbound(connection: &Connection, page: &SyncPage) -> Result<SyncPage, SyncError> {
    let offer = encode_bundle(SYNC_OFFER, page)?;
    let (mut send, mut receive) = connection.open_bi().await.map_err(|_| SyncError::Transport)?;
    write_frame(&mut send, &offer, MAX_SYNC_FRAME_BYTES).await?;
    let reply = decode_bundle(&read_frame(&mut receive, MAX_SYNC_FRAME_BYTES).await?, SYNC_REPLY)?;
    send.finish().map_err(|_| SyncError::Transport)?;
    Ok(reply)
}

/// Receives one contact page and sends the inbound side's page in return.
///
/// Both sides must have completed mutual session authentication first.
/// Returned contacts remain untrusted until local verification and import.
///
/// # Errors
///
/// Rejects oversized, malformed, non-canonical, or failed stream exchange.
pub async fn exchange_inbound(connection: &Connection, page: &SyncPage) -> Result<SyncPage, SyncError> {
    let (mut send, mut receive) = connection.accept_bi().await.map_err(|_| SyncError::Transport)?;
    let offered = decode_bundle(&read_frame(&mut receive, MAX_SYNC_FRAME_BYTES).await?, SYNC_OFFER)?;
    write_frame(&mut send, &encode_bundle(SYNC_REPLY, page)?, MAX_SYNC_FRAME_BYTES).await?;
    send.finish().map_err(|_| SyncError::Transport)?;
    Ok(offered)
}

/// Pushes the latest root-signed revocation snapshot over an authenticated
/// connection without waiting for the next contact-gossip turn.
///
/// Completion means the peer acknowledged every stream byte, not that it
/// accepted the root signature.
///
/// # Errors
///
/// Rejects malformed snapshots, size overflow, and failed QUIC delivery.
pub async fn send_revocation_notice(
    connection: &Connection,
    revocations: &SignedRevocationList,
) -> Result<(), SyncError> {
    let payload = encode_revocation_notice(revocations)?;
    let mut send = connection.open_uni().await.map_err(|_| SyncError::Transport)?;
    write_frame(&mut send, &payload, MAX_REVOCATION_NOTICE_FRAME_BYTES).await?;
    send.finish().map_err(|_| SyncError::Transport)?;
    match send.stopped().await.map_err(|_| SyncError::Transport)? {
        None => Ok(()),
        Some(_) => Err(SyncError::Transport),
    }
}

/// Receives one bounded root-signed revocation notice from an already
/// authenticated connection. Signature verification remains the caller's job.
///
/// # Errors
///
/// Rejects malformed, non-canonical, oversized, or failed QUIC input.
pub async fn receive_revocation_notice(connection: &Connection) -> Result<SignedRevocationList, SyncError> {
    let mut receive = connection.accept_uni().await.map_err(|_| SyncError::Transport)?;
    decode_revocation_notice(&read_frame(&mut receive, MAX_REVOCATION_NOTICE_FRAME_BYTES).await?)
}

fn encode_bundle(message_type: u8, page: &SyncPage) -> Result<Vec<u8>, SyncError> {
    if page.contacts.len() > MAX_SYNC_CONTACTS {
        return Err(SyncError::Oversized);
    }
    let encoded_contacts = page
        .contacts
        .iter()
        .map(encode_contact)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SyncError::InvalidContact)?;
    let revocations = encode_signed_revocations(&page.revocations).map_err(|_| SyncError::InvalidRevocation)?;
    let mut output = Vec::with_capacity(1_024);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(4).map_err(|_| SyncError::Encoding)?;
    encoder.u16(SYNC_VERSION).map_err(|_| SyncError::Encoding)?;
    encoder.u8(message_type).map_err(|_| SyncError::Encoding)?;
    encoder
        .array(u64::try_from(encoded_contacts.len()).map_err(|_| SyncError::Oversized)?)
        .map_err(|_| SyncError::Encoding)?;
    for contact in encoded_contacts {
        encoder.bytes(&contact).map_err(|_| SyncError::Encoding)?;
    }
    encoder.bytes(&revocations).map_err(|_| SyncError::Encoding)?;
    if output.is_empty() || output.len() > MAX_SYNC_FRAME_BYTES {
        return Err(SyncError::Oversized);
    }
    Ok(output)
}

fn decode_bundle(input: &[u8], expected_type: u8) -> Result<SyncPage, SyncError> {
    if input.is_empty() || input.len() > MAX_SYNC_FRAME_BYTES {
        return Err(SyncError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    if decoder.array().map_err(map_decode)? != Some(4)
        || decoder.u16().map_err(map_decode)? != SYNC_VERSION
        || decoder.u8().map_err(map_decode)? != expected_type
    {
        return Err(SyncError::InvalidShape);
    }
    let count = decoder.array().map_err(map_decode)?.ok_or(SyncError::InvalidShape)?;
    let count = usize::try_from(count).map_err(|_| SyncError::Oversized)?;
    if count > MAX_SYNC_CONTACTS {
        return Err(SyncError::Oversized);
    }
    let mut contacts = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = decoder.bytes().map_err(map_decode)?;
        if bytes.len() > MAX_CONTACT_BYTES {
            return Err(SyncError::Oversized);
        }
        contacts.push(decode_contact(bytes).map_err(|_| SyncError::InvalidContact)?);
    }
    let revocation_bytes = decoder.bytes().map_err(map_decode)?;
    if revocation_bytes.len() > MAX_SIGNED_REVOCATION_BYTES || decoder.position() != input.len() {
        return Err(SyncError::InvalidShape);
    }
    let page = SyncPage {
        contacts,
        revocations: decode_signed_revocations(revocation_bytes).map_err(|_| SyncError::InvalidRevocation)?,
    };
    if encode_bundle(expected_type, &page)
        .map_err(|_| SyncError::InvalidShape)?
        .as_slice()
        != input
    {
        return Err(SyncError::InvalidShape);
    }
    Ok(page)
}

fn encode_revocation_notice(revocations: &SignedRevocationList) -> Result<Vec<u8>, SyncError> {
    let signed = encode_signed_revocations(revocations).map_err(|_| SyncError::InvalidRevocation)?;
    let mut output = Vec::with_capacity(signed.len().saturating_add(8));
    let mut encoder = Encoder::new(&mut output);
    encoder.array(2).map_err(|_| SyncError::Encoding)?;
    encoder
        .u16(REVOCATION_NOTICE_VERSION)
        .map_err(|_| SyncError::Encoding)?;
    encoder.bytes(&signed).map_err(|_| SyncError::Encoding)?;
    if output.is_empty() || output.len() > MAX_REVOCATION_NOTICE_FRAME_BYTES {
        return Err(SyncError::Oversized);
    }
    Ok(output)
}

fn decode_revocation_notice(input: &[u8]) -> Result<SignedRevocationList, SyncError> {
    if input.is_empty() || input.len() > MAX_REVOCATION_NOTICE_FRAME_BYTES {
        return Err(SyncError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    if decoder.array().map_err(map_decode)? != Some(2)
        || decoder.u16().map_err(map_decode)? != REVOCATION_NOTICE_VERSION
    {
        return Err(SyncError::InvalidShape);
    }
    let signed = decoder.bytes().map_err(map_decode)?;
    if signed.len() > MAX_SIGNED_REVOCATION_BYTES || decoder.position() != input.len() {
        return Err(SyncError::InvalidShape);
    }
    let revocations = decode_signed_revocations(signed).map_err(|_| SyncError::InvalidRevocation)?;
    if encode_revocation_notice(&revocations)?.as_slice() != input {
        return Err(SyncError::InvalidShape);
    }
    Ok(revocations)
}

fn map_decode(_: decode::Error) -> SyncError {
    SyncError::InvalidShape
}

async fn write_frame(send: &mut SendStream, payload: &[u8], maximum: usize) -> Result<(), SyncError> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(SyncError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| SyncError::Oversized)?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|_| SyncError::Transport)?;
    send.write_all(payload).await.map_err(|_| SyncError::Transport)
}

async fn read_frame(receive: &mut RecvStream, maximum: usize) -> Result<Vec<u8>, SyncError> {
    let mut length = [0_u8; 4];
    receive
        .read_exact(&mut length)
        .await
        .map_err(|_| SyncError::Transport)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| SyncError::Oversized)?;
    if !(1..=maximum).contains(&length) {
        return Err(SyncError::Oversized);
    }
    let mut payload = vec![0_u8; length];
    receive
        .read_exact(&mut payload)
        .await
        .map_err(|_| SyncError::Transport)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{
        SYNC_OFFER, SyncError, SyncPage, decode_bundle, decode_revocation_notice, encode_bundle,
        encode_revocation_notice,
    };
    use crate::{identity::RootIdentity, revocation::SignedRevocationList};

    #[test]
    fn empty_bundle_is_canonical_and_bounds_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let page = SyncPage {
            contacts: Vec::new(),
            revocations: SignedRevocationList::empty(&root, 10)?,
        };
        let encoded = encode_bundle(SYNC_OFFER, &page)?;
        assert!(decode_bundle(&encoded, SYNC_OFFER)?.contacts.is_empty());
        let mut malformed = encoded;
        malformed.push(0);
        assert_eq!(decode_bundle(&malformed, SYNC_OFFER), Err(SyncError::InvalidShape));
        Ok(())
    }

    #[test]
    fn revocation_notice_is_canonical_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let root = RootIdentity::generate()?;
        let revocations = SignedRevocationList::empty(&root, 10)?;
        let encoded = encode_revocation_notice(&revocations)?;
        assert_eq!(decode_revocation_notice(&encoded)?, revocations);
        let mut malformed = encoded;
        malformed.push(0);
        assert_eq!(decode_revocation_notice(&malformed), Err(SyncError::InvalidShape));
        Ok(())
    }
}
