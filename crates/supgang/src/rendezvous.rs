//! Small authenticated-session datagrams for peer-assisted NAT traversal.
//!
//! These frames are valid only on a QUIC connection that has already passed
//! Supgang's mutual device authentication. They are deliberately ephemeral:
//! no rendezvous frame changes durable state or becomes an endpoint claim.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use minicbor::{Decoder, Encoder, decode as cbor_decode};
use quinn::Connection;
use thiserror::Error;

use crate::{
    candidate::{CandidateKind, CandidateTransport, EndpointCandidate},
    ids::NodeId,
};

/// Maximum encoded peer-assisted traversal datagram.
pub const MAX_RENDEZVOUS_FRAME_BYTES: usize = 256;
/// Fresh random identifier bytes carried by one short-lived traversal round.
pub const RENDEZVOUS_ID_BYTES: usize = 16;

const RENDEZVOUS_VERSION: u16 = 1;
const REQUEST: u8 = 1;
const OFFER: u8 = 2;

/// A short-lived request or observed-address offer carried by an authenticated peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RendezvousMessage {
    /// Ask this connected member to introduce the sender to `target` if both are active.
    Request {
        /// Random identifier used to suppress accidental duplicate work.
        rendezvous_id: [u8; RENDEZVOUS_ID_BYTES],
        /// Stable authorized member the requester wants to reach.
        target: NodeId,
    },
    /// Try one address observed on an introducer's authenticated connection to `target`.
    Offer {
        /// Identifier copied from the corresponding request.
        rendezvous_id: [u8; RENDEZVOUS_ID_BYTES],
        /// Stable member expected at the offered socket.
        target: NodeId,
        /// Ephemeral socket observed by the authenticated introducer.
        address: SocketAddr,
    },
}

/// Rendezvous framing, validation, or transport failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RendezvousError {
    /// The datagram was empty or exceeded its fixed budget.
    #[error("peer-assisted connection message exceeds its size limit")]
    Oversized,
    /// The datagram was malformed, non-canonical, or used an unsupported version.
    #[error("peer-assisted connection message is invalid")]
    InvalidMessage,
    /// QUIC datagrams are unavailable or the bounded send queue is full.
    #[error("peer-assisted connection message could not be delivered")]
    Transport,
}

/// Sends one bounded message over an already authenticated QUIC connection.
///
/// # Errors
///
/// Returns an error when encoding fails, the peer did not negotiate datagrams,
/// or the fixed outgoing buffer is currently full.
pub fn send(connection: &Connection, message: &RendezvousMessage) -> Result<(), RendezvousError> {
    let frame = encode(message)?;
    connection
        .send_datagram(frame.into())
        .map_err(|_| RendezvousError::Transport)
}

/// Receives one bounded message from an already authenticated QUIC connection.
///
/// # Errors
///
/// Rejects failed transport, malformed input, unsupported versions, unsafe
/// socket addresses, and non-canonical encodings.
pub async fn receive(connection: &Connection) -> Result<RendezvousMessage, RendezvousError> {
    let frame = connection
        .read_datagram()
        .await
        .map_err(|_| RendezvousError::Transport)?;
    decode(&frame)
}

fn encode(message: &RendezvousMessage) -> Result<Vec<u8>, RendezvousError> {
    let mut output = Vec::with_capacity(96);
    let mut encoder = Encoder::new(&mut output);
    match message {
        RendezvousMessage::Request { rendezvous_id, target } => {
            encoder.array(4).map_err(map_encode)?;
            encoder.u16(RENDEZVOUS_VERSION).map_err(map_encode)?;
            encoder.u8(REQUEST).map_err(map_encode)?;
            encoder.bytes(rendezvous_id).map_err(map_encode)?;
            encoder.bytes(target.as_bytes()).map_err(map_encode)?;
        }
        RendezvousMessage::Offer {
            rendezvous_id,
            target,
            address,
        } => {
            validate_address(*address)?;
            encoder.array(6).map_err(map_encode)?;
            encoder.u16(RENDEZVOUS_VERSION).map_err(map_encode)?;
            encoder.u8(OFFER).map_err(map_encode)?;
            encoder.bytes(rendezvous_id).map_err(map_encode)?;
            encoder.bytes(target.as_bytes()).map_err(map_encode)?;
            encode_ip(&mut encoder, address.ip()).map_err(map_encode)?;
            encoder.u16(address.port()).map_err(map_encode)?;
        }
    }
    if output.is_empty() || output.len() > MAX_RENDEZVOUS_FRAME_BYTES {
        return Err(RendezvousError::Oversized);
    }
    Ok(output)
}

fn decode(input: &[u8]) -> Result<RendezvousMessage, RendezvousError> {
    if input.is_empty() || input.len() > MAX_RENDEZVOUS_FRAME_BYTES {
        return Err(RendezvousError::Oversized);
    }
    let mut decoder = Decoder::new(input);
    let fields = decoder
        .array()
        .map_err(map_decode)?
        .ok_or(RendezvousError::InvalidMessage)?;
    if decoder.u16().map_err(map_decode)? != RENDEZVOUS_VERSION {
        return Err(RendezvousError::InvalidMessage);
    }
    let message_type = decoder.u8().map_err(map_decode)?;
    let rendezvous_id = read_fixed(&mut decoder)?;
    let target = NodeId::from_bytes(read_fixed(&mut decoder)?);
    let message = match (message_type, fields) {
        (REQUEST, 4) => RendezvousMessage::Request { rendezvous_id, target },
        (OFFER, 6) => {
            let ip = decode_ip(&mut decoder)?;
            let address = SocketAddr::new(ip, decoder.u16().map_err(map_decode)?);
            validate_address(address)?;
            RendezvousMessage::Offer {
                rendezvous_id,
                target,
                address,
            }
        }
        _ => return Err(RendezvousError::InvalidMessage),
    };
    if decoder.position() != input.len() || encode(&message)?.as_slice() != input {
        return Err(RendezvousError::InvalidMessage);
    }
    Ok(message)
}

fn validate_address(address: SocketAddr) -> Result<(), RendezvousError> {
    if EndpointCandidate::new(CandidateKind::Reflexive, CandidateTransport::QuicV1, address).is_ok() {
        Ok(())
    } else {
        Err(RendezvousError::InvalidMessage)
    }
}

fn encode_ip<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    address: IpAddr,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    match address {
        IpAddr::V4(value) => encoder.bytes(&value.octets()),
        IpAddr::V6(value) => encoder.bytes(&value.octets()),
    }?;
    Ok(())
}

fn decode_ip(decoder: &mut Decoder<'_>) -> Result<IpAddr, RendezvousError> {
    let bytes = decoder.bytes().map_err(map_decode)?;
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes)
            .map(|octets| IpAddr::V4(Ipv4Addr::from(octets)))
            .map_err(|_| RendezvousError::InvalidMessage),
        16 => <[u8; 16]>::try_from(bytes)
            .map(|octets| IpAddr::V6(Ipv6Addr::from(octets)))
            .map_err(|_| RendezvousError::InvalidMessage),
        _ => Err(RendezvousError::InvalidMessage),
    }
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], RendezvousError> {
    decoder
        .bytes()
        .map_err(map_decode)?
        .try_into()
        .map_err(|_| RendezvousError::InvalidMessage)
}

fn map_encode<E>(_: minicbor::encode::Error<E>) -> RendezvousError {
    RendezvousError::InvalidMessage
}

fn map_decode(_: cbor_decode::Error) -> RendezvousError {
    RendezvousError::InvalidMessage
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use proptest::prelude::*;

    use super::{RendezvousError, RendezvousMessage, decode, encode};
    use crate::ids::NodeId;

    #[test]
    fn request_and_offer_are_canonical_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let request = RendezvousMessage::Request {
            rendezvous_id: [7; 16],
            target: NodeId::from_bytes([8; 32]),
        };
        let offer = RendezvousMessage::Offer {
            rendezvous_id: [7; 16],
            target: NodeId::from_bytes([8; 32]),
            address: SocketAddr::from(([8, 8, 8, 10], 44_330)),
        };
        assert_eq!(decode(&encode(&request)?)?, request);
        assert_eq!(decode(&encode(&offer)?)?, offer);
        Ok(())
    }

    #[test]
    fn unsafe_addresses_and_trailing_bytes_fail_closed() {
        let unsafe_offer = RendezvousMessage::Offer {
            rendezvous_id: [1; 16],
            target: NodeId::from_bytes([2; 32]),
            address: SocketAddr::from(([0, 0, 0, 0], 44_330)),
        };
        assert_eq!(encode(&unsafe_offer), Err(RendezvousError::InvalidMessage));

        let private_offer = RendezvousMessage::Offer {
            rendezvous_id: [1; 16],
            target: NodeId::from_bytes([2; 32]),
            address: SocketAddr::from(([192, 168, 1, 50], 44_330)),
        };
        assert_eq!(encode(&private_offer), Err(RendezvousError::InvalidMessage));

        let request = RendezvousMessage::Request {
            rendezvous_id: [3; 16],
            target: NodeId::from_bytes([4; 32]),
        };
        let mut encoded = encode(&request).unwrap_or_else(|_| unreachable!());
        encoded.push(0);
        assert_eq!(decode(&encoded), Err(RendezvousError::InvalidMessage));
    }

    #[test]
    fn bounded_datagrams_cross_the_selected_transport() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let server_identity = crate::transport::TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(server_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let client_identity = crate::transport::TransportIdentity::generate()?;
            let client =
                quinn::Endpoint::server(client_identity.server_config()?, SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let accepting = server.clone();
            let accepted = tokio::spawn(async move {
                let incoming = accepting.accept().await.ok_or("server endpoint closed")?;
                incoming.await.map_err(|error| error.to_string())
            });
            let client_connection = tokio::time::timeout(
                Duration::from_secs(5),
                client.connect_with(
                    crate::transport::pinned_client_config(server_identity.key_id())?,
                    server.local_addr()?,
                    "supgang.invalid",
                )?,
            )
            .await??;
            let server_connection = accepted.await??;
            let request = RendezvousMessage::Request {
                rendezvous_id: [5; 16],
                target: NodeId::from_bytes([6; 32]),
            };
            super::send(&client_connection, &request)?;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), super::receive(&server_connection)).await??,
                request
            );
            let offer = RendezvousMessage::Offer {
                rendezvous_id: [5; 16],
                target: NodeId::from_bytes([6; 32]),
                address: SocketAddr::from(([8, 8, 8, 7], 44_330)),
            };
            super::send(&server_connection, &offer)?;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), super::receive(&client_connection)).await??,
                offer
            );
            server.close(0_u8.into(), b"test complete");
            client.close(0_u8.into(), b"test complete");
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1_000)) {
            let _result = decode(&bytes);
        }
    }
}
