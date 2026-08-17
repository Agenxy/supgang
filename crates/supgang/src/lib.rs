//! Supgang's portable identity, protocol, storage, and service implementation.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod candidate;
pub mod cli;
pub(crate) mod cli_control;
pub(crate) mod cli_peer;
pub(crate) mod cli_service;
pub mod contact;
pub(crate) mod control;
pub mod identity;
pub mod ids;
pub mod invitation;
pub mod journal;
pub mod membership;
pub mod merge;
pub mod peer_directory;
pub mod record;
pub mod revocation;
pub mod service;
pub mod session;
pub mod state;
pub mod state_lock;
pub mod storage;
pub mod sync;
pub mod transport;
pub mod transport_storage;
pub mod wire;

/// Current product and wire-protocol version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
