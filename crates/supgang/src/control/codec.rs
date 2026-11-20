//! Fixed-size owner-socket request codec.

use super::{
    ControlError, ControlRequest, NodeId, REQUEST_ADD_MAPPED, REQUEST_AGENT_KEYGEN, REQUEST_AGENT_SIGN,
    REQUEST_CONNECT, REQUEST_EXPOSE, REQUEST_EXPOSURES, REQUEST_MAGIC, REQUEST_PEERS, REQUEST_RESOLVE, REQUEST_RESTART,
    REQUEST_REVOKE, REQUEST_STATUS, REQUEST_TUNNEL_LIMITS, REQUEST_UPDATE,
};

pub(super) fn encode_request(request: ControlRequest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REQUEST_MAGIC.len() + 1 + 32);
    bytes.extend_from_slice(REQUEST_MAGIC);
    match request {
        ControlRequest::AddMapped { address } => {
            bytes.push(REQUEST_ADD_MAPPED);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
        }
        ControlRequest::Connect { target, name } => {
            bytes.push(REQUEST_CONNECT);
            bytes.extend_from_slice(target.as_bytes());
            bytes.extend_from_slice(&name);
        }
        ControlRequest::AgentSign {
            target,
            request,
            length,
        } => {
            bytes.push(REQUEST_AGENT_SIGN);
            bytes.extend_from_slice(target.as_bytes());
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(request.get(..usize::from(length)).unwrap_or(&[]));
        }
        ControlRequest::AgentKeygen {
            target,
            request,
            length,
        } => {
            bytes.push(REQUEST_AGENT_KEYGEN);
            bytes.extend_from_slice(target.as_bytes());
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(request.get(..usize::from(length)).unwrap_or(&[]));
        }
        ControlRequest::Expose { name, port } => {
            bytes.push(REQUEST_EXPOSE);
            bytes.extend_from_slice(&name);
            bytes.extend_from_slice(&port.to_be_bytes());
        }
        ControlRequest::TunnelLimits {
            per_peer,
            total,
            idle_seconds,
        } => {
            bytes.push(REQUEST_TUNNEL_LIMITS);
            bytes.extend_from_slice(&per_peer.to_be_bytes());
            bytes.extend_from_slice(&total.to_be_bytes());
            bytes.extend_from_slice(&idle_seconds.to_be_bytes());
        }
        ControlRequest::Restart => bytes.push(REQUEST_RESTART),
        ControlRequest::Exposures => bytes.push(REQUEST_EXPOSURES),
        ControlRequest::Status => bytes.push(REQUEST_STATUS),
        ControlRequest::Peers => bytes.push(REQUEST_PEERS),
        ControlRequest::Resolve(node_id) => {
            bytes.push(REQUEST_RESOLVE);
            bytes.extend_from_slice(node_id.as_bytes());
        }
        ControlRequest::Revoke(node_id) => {
            bytes.push(REQUEST_REVOKE);
            bytes.extend_from_slice(node_id.as_bytes());
        }
        ControlRequest::Update { target, digest } => {
            bytes.push(REQUEST_UPDATE);
            bytes.extend_from_slice(target.as_bytes());
            bytes.extend_from_slice(&digest);
        }
    }
    bytes
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<ControlRequest, ControlError> {
    if bytes.get(..REQUEST_MAGIC.len()) != Some(REQUEST_MAGIC) {
        return Err(ControlError::InvalidRequest);
    }
    let command = bytes
        .get(REQUEST_MAGIC.len())
        .copied()
        .ok_or(ControlError::InvalidRequest)?;
    match command {
        REQUEST_ADD_MAPPED if bytes.len() == REQUEST_MAGIC.len() + 1 + 6 => {
            let raw: [u8; 4] = bytes
                .get(9..13)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            let port = bytes
                .get(13..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::AddMapped {
                address: std::net::SocketAddrV4::new(raw.into(), u16::from_be_bytes(port)),
            })
        }
        REQUEST_CONNECT if bytes.len() == REQUEST_MAGIC.len() + 1 + 48 => {
            let target = bytes
                .get(9..41)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            let name = bytes
                .get(41..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            crate::tunnel_policy::decoded_name(name).map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Connect {
                target: NodeId::from_bytes(target),
                name,
            })
        }
        REQUEST_AGENT_SIGN if bytes.len() >= REQUEST_MAGIC.len() + 1 + 32 + 2 => {
            let target: [u8; 32] = bytes
                .get(9..41)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            let length = u16::from_be_bytes(
                bytes
                    .get(41..43)
                    .ok_or(ControlError::InvalidRequest)?
                    .try_into()
                    .map_err(|_| ControlError::InvalidRequest)?,
            );
            let payload = bytes.get(43..).ok_or(ControlError::InvalidRequest)?;
            if usize::from(length) != payload.len()
                || payload.is_empty()
                || payload.len() > crate::agent_sign_protocol::MAX_REQUEST_BYTES
                || crate::agent_sign_protocol::SignRequest::decode(payload).is_err()
            {
                return Err(ControlError::InvalidRequest);
            }
            let mut request = [0_u8; crate::agent_sign_protocol::MAX_REQUEST_BYTES];
            request
                .get_mut(..payload.len())
                .ok_or(ControlError::InvalidRequest)?
                .copy_from_slice(payload);
            Ok(ControlRequest::AgentSign {
                target: NodeId::from_bytes(target),
                request: Box::new(request),
                length,
            })
        }
        REQUEST_AGENT_KEYGEN if bytes.len() >= REQUEST_MAGIC.len() + 1 + 32 + 2 => {
            let target: [u8; 32] = bytes
                .get(9..41)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            let length = u16::from_be_bytes(
                bytes
                    .get(41..43)
                    .ok_or(ControlError::InvalidRequest)?
                    .try_into()
                    .map_err(|_| ControlError::InvalidRequest)?,
            );
            let payload = bytes.get(43..).ok_or(ControlError::InvalidRequest)?;
            if usize::from(length) != payload.len()
                || payload.is_empty()
                || payload.len() > crate::agent_keygen_protocol::MAX_REQUEST_BYTES
                || crate::agent_keygen_protocol::KeygenRequest::decode(payload).is_err()
            {
                return Err(ControlError::InvalidRequest);
            }
            let mut request = Box::new([0_u8; crate::agent_keygen_protocol::MAX_REQUEST_BYTES]);
            request
                .get_mut(..payload.len())
                .ok_or(ControlError::InvalidRequest)?
                .copy_from_slice(payload);
            Ok(ControlRequest::AgentKeygen {
                target: NodeId::from_bytes(target),
                request,
                length,
            })
        }
        REQUEST_EXPOSE if bytes.len() == REQUEST_MAGIC.len() + 1 + 18 => {
            let name = bytes
                .get(9..25)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            crate::tunnel_policy::decoded_name(name).map_err(|_| ControlError::InvalidRequest)?;
            let port = bytes
                .get(25..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Expose {
                name,
                port: u16::from_be_bytes(port),
            })
        }
        REQUEST_TUNNEL_LIMITS if bytes.len() == REQUEST_MAGIC.len() + 1 + 8 => {
            let field = |range: std::ops::Range<usize>| bytes.get(range).ok_or(ControlError::InvalidRequest);
            let per_peer = u16::from_be_bytes(field(9..11)?.try_into().map_err(|_| ControlError::InvalidRequest)?);
            let total = u16::from_be_bytes(field(11..13)?.try_into().map_err(|_| ControlError::InvalidRequest)?);
            let idle_seconds = u32::from_be_bytes(field(13..17)?.try_into().map_err(|_| ControlError::InvalidRequest)?);
            Ok(ControlRequest::TunnelLimits {
                per_peer,
                total,
                idle_seconds,
            })
        }
        REQUEST_RESTART if bytes.len() == REQUEST_MAGIC.len() + 1 => Ok(ControlRequest::Restart),
        REQUEST_EXPOSURES if bytes.len() == REQUEST_MAGIC.len() + 1 => Ok(ControlRequest::Exposures),
        REQUEST_STATUS if bytes.len() == REQUEST_MAGIC.len() + 1 => Ok(ControlRequest::Status),
        REQUEST_PEERS if bytes.len() == REQUEST_MAGIC.len() + 1 => Ok(ControlRequest::Peers),
        REQUEST_RESOLVE if bytes.len() == REQUEST_MAGIC.len() + 1 + 32 => {
            let raw = bytes
                .get(REQUEST_MAGIC.len() + 1..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Resolve(NodeId::from_bytes(raw)))
        }
        REQUEST_REVOKE if bytes.len() == REQUEST_MAGIC.len() + 1 + 32 => {
            let raw = bytes
                .get(REQUEST_MAGIC.len() + 1..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Revoke(NodeId::from_bytes(raw)))
        }
        REQUEST_UPDATE if bytes.len() == REQUEST_MAGIC.len() + 1 + 64 => {
            let target = bytes
                .get(REQUEST_MAGIC.len() + 1..REQUEST_MAGIC.len() + 1 + 32)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            let digest = bytes
                .get(REQUEST_MAGIC.len() + 1 + 32..)
                .ok_or(ControlError::InvalidRequest)?
                .try_into()
                .map_err(|_| ControlError::InvalidRequest)?;
            Ok(ControlRequest::Update {
                target: NodeId::from_bytes(target),
                digest,
            })
        }
        _ => Err(ControlError::InvalidRequest),
    }
}
