//! Supgang's portable identity, protocol, storage, and service implementation.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod candidate;
pub mod cli;
pub(crate) mod cli_args;
pub(crate) mod cli_background;
pub(crate) mod cli_control;
pub(crate) mod cli_peer;
pub(crate) mod cli_peer_types;
pub(crate) mod cli_profile;
pub(crate) mod cli_service;
pub(crate) mod cli_settings;
pub(crate) mod cli_update;
pub mod contact;
pub(crate) mod control;
pub mod endpoint_config;
pub mod identity;
pub mod ids;
pub mod invitation;
pub mod journal;
pub(crate) mod mcp;
pub mod membership;
pub mod merge;
pub mod network;
pub mod peer_directory;
pub(crate) mod peer_stream;
pub mod peer_tag;
pub(crate) mod platform_service;
pub mod profile;
pub mod reachability;
pub mod record;
pub mod rendezvous;
pub mod revocation;
pub mod router_mapping;
pub mod service;
pub mod session;
pub mod settings;
pub mod state;
pub mod state_lock;
pub mod storage;
pub mod sync;
pub mod transport;
pub mod transport_storage;
pub mod update;
pub(crate) mod update_wire;
pub mod wire;

/// Current product and wire-protocol version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
