//! Typed post-authentication bidirectional stream dispatch.

use quinn::{Connection, RecvStream, SendStream};
use thiserror::Error;

const STREAM_VERSION: u16 = 1;
const HEADER_BYTES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    Sync = 1,
    Update = 2,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StreamError {
    #[error("authenticated peer stream transport failed")]
    Transport,
    #[error("authenticated peer stream type is invalid")]
    Invalid,
}

pub async fn open(connection: &Connection, kind: StreamKind) -> Result<(SendStream, RecvStream), StreamError> {
    let (mut send, receive) = connection.open_bi().await.map_err(|_| StreamError::Transport)?;
    send.write_all(&header(kind))
        .await
        .map_err(|_| StreamError::Transport)?;
    Ok((send, receive))
}

pub async fn accept(connection: &Connection) -> Result<(StreamKind, SendStream, RecvStream), StreamError> {
    let (send, mut receive) = connection.accept_bi().await.map_err(|_| StreamError::Transport)?;
    let mut bytes = [0_u8; HEADER_BYTES];
    receive
        .read_exact(&mut bytes)
        .await
        .map_err(|_| StreamError::Transport)?;
    let kind = match bytes {
        [0, 1, 1] => StreamKind::Sync,
        [0, 1, 2] => StreamKind::Update,
        _ => return Err(StreamError::Invalid),
    };
    Ok((kind, send, receive))
}

const fn header(kind: StreamKind) -> [u8; HEADER_BYTES] {
    let version = STREAM_VERSION.to_be_bytes();
    [version[0], version[1], kind as u8]
}

#[cfg(test)]
mod tests {
    use super::{StreamKind, header};

    #[test]
    fn stream_headers_are_fixed_and_unambiguous() {
        assert_eq!(header(StreamKind::Sync), [0, 1, 1]);
        assert_eq!(header(StreamKind::Update), [0, 1, 2]);
    }
}
