//! Mutual device authentication bound to a confirmed QUIC TLS session.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder, encode};
use quinn::{Connection, RecvStream, SendStream};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    contact::{ContactError, MAX_CONTACT_BYTES, PeerContact, decode_contact, encode_contact},
    identity::{DeviceIdentity, verify_domain},
    revocation::SignedRevocationList,
};

/// Maximum application authentication frame accepted on a peer connection.
pub const MAX_SESSION_FRAME_BYTES: usize = 16 * 1024;

const PROTOCOL_VERSION: u16 = 1;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const CLIENT_PROOF: u8 = 3;
const SERVER_ACK: u8 = 4;
const NONCE_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const EXPORTER_BYTES: usize = 32;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Supgang-Session-v1";
const EXPORTER_CONTEXT: &[u8] = b"supgang/1";
const SERVER_PROOF_DOMAIN: &[u8] = b"supgang/session/server-proof/v1\0";
const CLIENT_PROOF_DOMAIN: &[u8] = b"supgang/session/client-proof/v1\0";

/// A peer-session framing, authorization, or proof failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionError {
    /// QUIC stream setup, I/O, finish, or TLS exporter access failed.
    #[error("authenticated peer session transport failed")]
    Transport,
    /// A frame was empty or exceeded the fixed application budget.
    #[error("authenticated peer session frame is outside its size limit")]
    FrameSize,
    /// A message had a wrong version, type, field count, or fixed-byte length.
    #[error("authenticated peer session message has an invalid shape")]
    InvalidMessage,
    /// A message was malformed or could not be encoded.
    #[error("authenticated peer session message encoding failed")]
    Encoding,
    /// Contact authorization, signature, identity binding, or freshness failed.
    #[error("peer contact is not currently authorized")]
    Contact,
    /// The authenticated server is not the expected stable node or transport key.
    #[error("connected server does not match the signed contact used for dialing")]
    UnexpectedServer,
    /// A challenge response did not verify for the claimed device key and TLS channel.
    #[error("peer session proof is invalid")]
    InvalidProof,
    /// The operating system did not provide a fresh challenge.
    #[error("peer session challenge generation failed")]
    Random,
    /// The local or remote stable device identity is root-revoked.
    #[error("peer session device identity is revoked")]
    Revoked,
}

impl From<ContactError> for SessionError {
    fn from(_: ContactError) -> Self {
        Self::Contact
    }
}

/// An authorized peer plus the local source socket that peer observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    /// Fresh root-authorized and device-signed peer contact.
    pub contact: PeerContact,
    /// This computer's source socket as reported inside the bound proof.
    pub observed_local_address: SocketAddr,
}

/// Authenticates an outbound peer and proves the local device in return.
///
/// Certificate pinning must already have used `expected.endpoint` when the
/// QUIC connection was created. The device proofs additionally bind both
/// identities and fresh challenges to the TLS exporter for this exact session.
///
/// # Errors
///
/// Rejects stale or invalid contacts, a different server identity or pin,
/// malformed frames, invalid proofs, replay on another TLS session, and I/O.
pub async fn authenticate_outbound(
    connection: &Connection,
    local_contact: &PeerContact,
    local_identity: &DeviceIdentity,
    expected: &PeerContact,
    root_key: &VerifyingKey,
    revocations: &SignedRevocationList,
    now: u64,
) -> Result<AuthenticatedPeer, SessionError> {
    revocations.verify(root_key).map_err(|_| SessionError::Contact)?;
    local_contact.verify(root_key, now)?;
    expected.verify_historical(root_key)?;
    if local_contact.endpoint.record.node_id != local_identity.node_id()
        || revocations.contains(&local_identity.node_id())
        || revocations.contains(&expected.endpoint.record.node_id)
    {
        return Err(SessionError::Contact);
    }
    let channel_binding = channel_binding(connection)?;
    let mut client_nonce = random_nonce()?;
    let (mut send, mut receive) = connection.open_bi().await.map_err(|_| SessionError::Transport)?;
    write_frame(&mut send, &encode_client_hello(local_contact, &client_nonce)?).await?;

    let server_hello = decode_server_hello(&read_frame(&mut receive).await?)?;
    server_hello.contact.verify(root_key, now)?;
    if server_hello.client_nonce != client_nonce
        || server_hello.contact.endpoint.record.node_id != expected.endpoint.record.node_id
        || server_hello.contact.endpoint.record.transport_key_id != expected.endpoint.record.transport_key_id
        || revocations.contains(&server_hello.contact.endpoint.record.node_id)
    {
        client_nonce.zeroize();
        return Err(SessionError::UnexpectedServer);
    }
    let transcript = transcript(
        local_contact,
        &server_hello.contact,
        &client_nonce,
        &server_hello.server_nonce,
        &channel_binding,
        server_hello.observed_client_address,
    )?;
    let server_key = VerifyingKey::from_bytes(&server_hello.contact.membership.certificate.device_verifying_key)
        .map_err(|_| SessionError::Contact)?;
    if !verify_domain(&server_key, SERVER_PROOF_DOMAIN, &transcript, &server_hello.signature) {
        client_nonce.zeroize();
        return Err(SessionError::InvalidProof);
    }
    let observed_server_address = connection.remote_address();
    let client_transcript = extend_client_transcript(&transcript, observed_server_address)?;
    let proof = local_identity.sign_domain(CLIENT_PROOF_DOMAIN, &client_transcript);
    write_frame(
        &mut send,
        &encode_client_proof(&server_hello.server_nonce, observed_server_address, &proof)?,
    )
    .await?;
    let acknowledged_nonce = decode_server_ack(&read_frame(&mut receive).await?)?;
    if acknowledged_nonce != client_nonce {
        client_nonce.zeroize();
        return Err(SessionError::InvalidProof);
    }
    send.finish().map_err(|_| SessionError::Transport)?;
    client_nonce.zeroize();
    Ok(AuthenticatedPeer {
        contact: server_hello.contact,
        observed_local_address: server_hello.observed_client_address,
    })
}

/// Authenticates an inbound member before returning its claimed contact.
///
/// Callers must not expose synchronization, introduction, relay, or durable
/// state changes on the connection until this function succeeds.
///
/// # Errors
///
/// Rejects stale or invalid contacts, malformed frames, invalid device proofs,
/// cross-session replay, challenge failure, and I/O.
pub async fn authenticate_inbound(
    connection: &Connection,
    local_contact: &PeerContact,
    local_identity: &DeviceIdentity,
    root_key: &VerifyingKey,
    revocations: &SignedRevocationList,
    now: u64,
) -> Result<AuthenticatedPeer, SessionError> {
    revocations.verify(root_key).map_err(|_| SessionError::Contact)?;
    local_contact.verify(root_key, now)?;
    if local_contact.endpoint.record.node_id != local_identity.node_id()
        || revocations.contains(&local_identity.node_id())
    {
        return Err(SessionError::Contact);
    }
    let channel_binding = channel_binding(connection)?;
    let (mut send, mut receive) = connection.accept_bi().await.map_err(|_| SessionError::Transport)?;
    let client_hello = decode_client_hello(&read_frame(&mut receive).await?)?;
    client_hello.contact.verify(root_key, now)?;
    if revocations.contains(&client_hello.contact.endpoint.record.node_id) {
        return Err(SessionError::Revoked);
    }
    let mut server_nonce = random_nonce()?;
    let observed_client_address = connection.remote_address();
    let transcript = transcript(
        &client_hello.contact,
        local_contact,
        &client_hello.client_nonce,
        &server_nonce,
        &channel_binding,
        observed_client_address,
    )?;
    let server_proof = local_identity.sign_domain(SERVER_PROOF_DOMAIN, &transcript);
    write_frame(
        &mut send,
        &encode_server_hello(
            local_contact,
            &client_hello.client_nonce,
            &server_nonce,
            observed_client_address,
            &server_proof,
        )?,
    )
    .await?;

    let client_proof = decode_client_proof(&read_frame(&mut receive).await?)?;
    if client_proof.server_nonce != server_nonce {
        server_nonce.zeroize();
        return Err(SessionError::InvalidProof);
    }
    let client_key = VerifyingKey::from_bytes(&client_hello.contact.membership.certificate.device_verifying_key)
        .map_err(|_| SessionError::Contact)?;
    let client_transcript = extend_client_transcript(&transcript, client_proof.observed_server_address)?;
    if !verify_domain(
        &client_key,
        CLIENT_PROOF_DOMAIN,
        &client_transcript,
        &client_proof.signature,
    ) {
        server_nonce.zeroize();
        return Err(SessionError::InvalidProof);
    }
    write_frame(&mut send, &encode_server_ack(&client_hello.client_nonce)?).await?;
    send.finish().map_err(|_| SessionError::Transport)?;
    server_nonce.zeroize();
    Ok(AuthenticatedPeer {
        contact: client_hello.contact,
        observed_local_address: client_proof.observed_server_address,
    })
}

struct ClientHelloMessage {
    contact: PeerContact,
    client_nonce: [u8; NONCE_BYTES],
}

struct ServerHelloMessage {
    contact: PeerContact,
    client_nonce: [u8; NONCE_BYTES],
    server_nonce: [u8; NONCE_BYTES],
    observed_client_address: SocketAddr,
    signature: [u8; SIGNATURE_BYTES],
}

struct ClientProofMessage {
    server_nonce: [u8; NONCE_BYTES],
    observed_server_address: SocketAddr,
    signature: [u8; SIGNATURE_BYTES],
}

fn encode_client_hello(contact: &PeerContact, client_nonce: &[u8; NONCE_BYTES]) -> Result<Vec<u8>, SessionError> {
    let contact = encode_contact(contact)?;
    encode_message(4, |encoder| {
        encoder.u16(PROTOCOL_VERSION)?;
        encoder.u8(CLIENT_HELLO)?;
        encoder.bytes(&contact)?;
        encoder.bytes(client_nonce)?;
        Ok(())
    })
}

fn decode_client_hello(input: &[u8]) -> Result<ClientHelloMessage, SessionError> {
    let mut decoder = Decoder::new(input);
    require_header(&mut decoder, 4, CLIENT_HELLO)?;
    let contact = decode_bounded_contact(&mut decoder)?;
    let client_nonce = read_fixed(&mut decoder)?;
    finish_decode(&decoder, input)?;
    let message = ClientHelloMessage { contact, client_nonce };
    if encode_client_hello(&message.contact, &message.client_nonce)?.as_slice() != input {
        return Err(SessionError::InvalidMessage);
    }
    Ok(message)
}

fn encode_server_hello(
    contact: &PeerContact,
    client_nonce: &[u8; NONCE_BYTES],
    server_nonce: &[u8; NONCE_BYTES],
    observed_client_address: SocketAddr,
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<Vec<u8>, SessionError> {
    let contact = encode_contact(contact)?;
    encode_message(7, |encoder| {
        encoder.u16(PROTOCOL_VERSION)?;
        encoder.u8(SERVER_HELLO)?;
        encoder.bytes(&contact)?;
        encoder.bytes(client_nonce)?;
        encoder.bytes(server_nonce)?;
        encode_socket_address(encoder, observed_client_address)?;
        encoder.bytes(signature)?;
        Ok(())
    })
}

fn decode_server_hello(input: &[u8]) -> Result<ServerHelloMessage, SessionError> {
    let mut decoder = Decoder::new(input);
    require_header(&mut decoder, 7, SERVER_HELLO)?;
    let contact = decode_bounded_contact(&mut decoder)?;
    let client_nonce = read_fixed(&mut decoder)?;
    let server_nonce = read_fixed(&mut decoder)?;
    let observed_client_address = decode_socket_address(&mut decoder)?;
    let signature = read_fixed(&mut decoder)?;
    finish_decode(&decoder, input)?;
    let message = ServerHelloMessage {
        contact,
        client_nonce,
        server_nonce,
        observed_client_address,
        signature,
    };
    if encode_server_hello(
        &message.contact,
        &message.client_nonce,
        &message.server_nonce,
        message.observed_client_address,
        &message.signature,
    )?
    .as_slice()
        != input
    {
        return Err(SessionError::InvalidMessage);
    }
    Ok(message)
}

fn encode_client_proof(
    server_nonce: &[u8; NONCE_BYTES],
    observed_server_address: SocketAddr,
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<Vec<u8>, SessionError> {
    encode_message(5, |encoder| {
        encoder.u16(PROTOCOL_VERSION)?;
        encoder.u8(CLIENT_PROOF)?;
        encoder.bytes(server_nonce)?;
        encode_socket_address(encoder, observed_server_address)?;
        encoder.bytes(signature)?;
        Ok(())
    })
}

fn decode_client_proof(input: &[u8]) -> Result<ClientProofMessage, SessionError> {
    let mut decoder = Decoder::new(input);
    require_header(&mut decoder, 5, CLIENT_PROOF)?;
    let server_nonce = read_fixed(&mut decoder)?;
    let observed_server_address = decode_socket_address(&mut decoder)?;
    let signature = read_fixed(&mut decoder)?;
    finish_decode(&decoder, input)?;
    let message = ClientProofMessage {
        server_nonce,
        observed_server_address,
        signature,
    };
    if encode_client_proof(
        &message.server_nonce,
        message.observed_server_address,
        &message.signature,
    )?
    .as_slice()
        != input
    {
        return Err(SessionError::InvalidMessage);
    }
    Ok(message)
}

fn encode_server_ack(client_nonce: &[u8; NONCE_BYTES]) -> Result<Vec<u8>, SessionError> {
    encode_message(3, |encoder| {
        encoder.u16(PROTOCOL_VERSION)?;
        encoder.u8(SERVER_ACK)?;
        encoder.bytes(client_nonce)?;
        Ok(())
    })
}

fn decode_server_ack(input: &[u8]) -> Result<[u8; NONCE_BYTES], SessionError> {
    let mut decoder = Decoder::new(input);
    require_header(&mut decoder, 3, SERVER_ACK)?;
    let nonce = read_fixed(&mut decoder)?;
    finish_decode(&decoder, input)?;
    if encode_server_ack(&nonce)?.as_slice() != input {
        return Err(SessionError::InvalidMessage);
    }
    Ok(nonce)
}

fn transcript(
    client: &PeerContact,
    server: &PeerContact,
    client_nonce: &[u8; NONCE_BYTES],
    server_nonce: &[u8; NONCE_BYTES],
    channel_binding: &[u8; EXPORTER_BYTES],
    observed_client_address: SocketAddr,
) -> Result<Vec<u8>, SessionError> {
    let client = encode_contact(client)?;
    let server = encode_contact(server)?;
    encode_message(7, |encoder| {
        encoder.u16(PROTOCOL_VERSION)?;
        encoder.bytes(&client)?;
        encoder.bytes(&server)?;
        encoder.bytes(client_nonce)?;
        encoder.bytes(server_nonce)?;
        encoder.bytes(channel_binding)?;
        encode_socket_address(encoder, observed_client_address)?;
        Ok(())
    })
}

fn extend_client_transcript(base: &[u8], observed_server_address: SocketAddr) -> Result<Vec<u8>, SessionError> {
    encode_message(3, |encoder| {
        encoder.u16(PROTOCOL_VERSION)?;
        encoder.bytes(base)?;
        encode_socket_address(encoder, observed_server_address)?;
        Ok(())
    })
}

fn encode_socket_address(
    encoder: &mut Encoder<&mut Vec<u8>>,
    address: SocketAddr,
) -> Result<(), encode::Error<core::convert::Infallible>> {
    encoder.array(2)?;
    match address.ip() {
        IpAddr::V4(ip) => encoder.bytes(&ip.octets())?,
        IpAddr::V6(ip) => encoder.bytes(&ip.octets())?,
    };
    encoder.u16(address.port())?;
    Ok(())
}

fn decode_socket_address(decoder: &mut Decoder<'_>) -> Result<SocketAddr, SessionError> {
    if decoder.array().map_err(|_| SessionError::Encoding)? != Some(2) {
        return Err(SessionError::InvalidMessage);
    }
    let bytes = decoder.bytes().map_err(|_| SessionError::Encoding)?;
    let ip = match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| SessionError::InvalidMessage)?,
        )),
        16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| SessionError::InvalidMessage)?,
        )),
        _ => return Err(SessionError::InvalidMessage),
    };
    let port = decoder.u16().map_err(|_| SessionError::Encoding)?;
    if ip.is_unspecified() || ip.is_multicast() || port == 0 {
        return Err(SessionError::InvalidMessage);
    }
    Ok(SocketAddr::new(ip, port))
}

fn encode_message(
    fields: u64,
    body: impl FnOnce(&mut Encoder<&mut Vec<u8>>) -> Result<(), encode::Error<core::convert::Infallible>>,
) -> Result<Vec<u8>, SessionError> {
    let mut output = Vec::with_capacity(512);
    let mut encoder = Encoder::new(&mut output);
    encoder.array(fields).map_err(|_| SessionError::Encoding)?;
    body(&mut encoder).map_err(|_| SessionError::Encoding)?;
    if output.is_empty() || output.len() > MAX_SESSION_FRAME_BYTES {
        return Err(SessionError::FrameSize);
    }
    Ok(output)
}

fn require_header(decoder: &mut Decoder<'_>, fields: u64, message_type: u8) -> Result<(), SessionError> {
    if decoder.array().map_err(|_| SessionError::Encoding)? != Some(fields)
        || decoder.u16().map_err(|_| SessionError::Encoding)? != PROTOCOL_VERSION
        || decoder.u8().map_err(|_| SessionError::Encoding)? != message_type
    {
        return Err(SessionError::InvalidMessage);
    }
    Ok(())
}

fn decode_bounded_contact(decoder: &mut Decoder<'_>) -> Result<PeerContact, SessionError> {
    let bytes = decoder.bytes().map_err(|_| SessionError::Encoding)?;
    if bytes.len() > MAX_CONTACT_BYTES {
        return Err(SessionError::FrameSize);
    }
    decode_contact(bytes).map_err(Into::into)
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], SessionError> {
    decoder
        .bytes()
        .map_err(|_| SessionError::Encoding)?
        .try_into()
        .map_err(|_| SessionError::InvalidMessage)
}

fn finish_decode(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), SessionError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(SessionError::InvalidMessage)
    }
}

fn channel_binding(connection: &Connection) -> Result<[u8; EXPORTER_BYTES], SessionError> {
    let mut output = [0_u8; EXPORTER_BYTES];
    connection
        .export_keying_material(&mut output, EXPORTER_LABEL, EXPORTER_CONTEXT)
        .map_err(|_| SessionError::Transport)?;
    Ok(output)
}

fn random_nonce() -> Result<[u8; NONCE_BYTES], SessionError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| SessionError::Random)?;
    Ok(nonce)
}

async fn write_frame(send: &mut SendStream, payload: &[u8]) -> Result<(), SessionError> {
    if payload.is_empty() || payload.len() > MAX_SESSION_FRAME_BYTES {
        return Err(SessionError::FrameSize);
    }
    let length = u32::try_from(payload.len()).map_err(|_| SessionError::FrameSize)?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|_| SessionError::Transport)?;
    send.write_all(payload).await.map_err(|_| SessionError::Transport)
}

async fn read_frame(receive: &mut RecvStream) -> Result<Vec<u8>, SessionError> {
    let mut length = [0_u8; 4];
    receive
        .read_exact(&mut length)
        .await
        .map_err(|_| SessionError::Transport)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| SessionError::FrameSize)?;
    if !(1..=MAX_SESSION_FRAME_BYTES).contains(&length) {
        return Err(SessionError::FrameSize);
    }
    let mut payload = vec![0_u8; length];
    receive
        .read_exact(&mut payload)
        .await
        .map_err(|_| SessionError::Transport)?;
    Ok(payload)
}

#[cfg(test)]
mod tests;
