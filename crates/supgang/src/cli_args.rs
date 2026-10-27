//! Typed command-line grammar, separate from execution and rendering policy.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{
    endpoint_config::DEFAULT_PORT,
    ids::{HiveId, NodeId},
    peer_tag::PeerTag,
};

/// Supgang's command-line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "supgang",
    version,
    about = "Finds the current address of your own computers",
    disable_help_subcommand = true,
    subcommand_precedence_over_arg = true
)]
pub struct Cli {
    /// Emit a versioned JSON object instead of human text.
    #[arg(long, global = true)]
    pub json: bool,
    /// Override the platform state directory.
    #[arg(long, global = true, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,
    /// Show only this peer by computer name, local tag, fingerprint, or node ID.
    #[arg(value_name = "PEER")]
    pub peer: Option<String>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Owner-managed public UDP endpoint publication.
#[derive(Debug, Subcommand)]
pub enum EndpointCommand {
    /// Sign and gossip a public IPv4 UDP forward without changing the router.
    AddMapped {
        /// Owner-only UTF-8 file containing one public IPv4:UDP-port socket.
        #[arg(long, value_name = "PATH")]
        from_file: PathBuf,
    },
}

/// Stable local and peer command surface.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Carry stdin/stdout bytes to a target-approved loopback service on a live peer.
    Connect {
        /// Unique signed peer name, local tag, fingerprint or node identity.
        peer: String,
        /// Target-owner service name; the caller cannot select an address or port.
        service: String,
    },
    /// Listen on a loopback TCP port here and carry each connection to a peer's named service.
    Forward {
        /// Port or loopback socket to listen on, e.g. 14331 or 127.0.0.1:14331; never a public address.
        listen: String,
        /// Unique signed peer name, local tag, fingerprint or node identity.
        peer: String,
        /// Target-owner service name exposed on that peer.
        service: String,
    },
    /// Expose a named IPv4 loopback TCP port to authenticated hive members.
    Expose {
        /// Restricted service name, 1 through 16 ASCII bytes.
        name: String,
        /// Nonzero TCP port on 127.0.0.1; SSH uses 22.
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
    },
    /// Remove a service exposure and end existing sessions under that policy.
    Unexpose { name: String },
    /// List named loopback exposures and tunnel limits without changing policy.
    Exposures,
    /// Set bounded tunnel admission and idle limits.
    TunnelLimits {
        /// Concurrent streams per peer, 1 through 64; default 4.
        #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=64))]
        per_peer: u16,
        /// Concurrent streams in this runtime, 1 through 128; default 16.
        #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(1..=128))]
        total: u16,
        /// No-byte idle deadline, 60 through 86400 seconds; default two hours.
        #[arg(long, default_value_t = 7_200, value_parser = clap::value_parser!(u64).range(60..=86_400))]
        idle_seconds: u64,
    },
    /// Create a new private hive and this computer's identity.
    Init,
    /// Validate local security, identity, and durable state.
    Doctor {
        /// Check a peer's public endpoint availability and signed record expiry.
        #[arg(long)]
        peer: Option<String>,
    },
    /// Publish an owner-managed public IPv4 UDP endpoint from a private file.
    Endpoint {
        #[command(subcommand)]
        command: EndpointCommand,
    },
    /// Show or change owner-only local settings.
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },
    /// Show this computer's non-secret hive and node identifiers.
    Status,
    /// Show or change this computer's signed human-readable name.
    Name {
        #[command(subcommand)]
        command: Option<NameCommand>,
    },
    /// Create a recipient-bound request on the computer that will join.
    JoinRequest {
        /// New owner-only request file to carry to an existing member.
        #[arg(value_name = "REQUEST_FILE")]
        output: PathBuf,
    },
    /// Root-authorize a signed request and create its response bundle.
    Invite {
        /// Owner-only request file from the joining computer.
        #[arg(value_name = "REQUEST_FILE")]
        request: PathBuf,
        /// New owner-only bundle to carry back to the joining computer.
        #[arg(value_name = "JOIN_BUNDLE")]
        output: PathBuf,
        /// Membership lifetime in days, from 1 through 3650.
        #[arg(long, default_value_t = 365)]
        days: u16,
        /// Exact joining-computer ID confirmed through a separate channel.
        #[arg(long, value_name = "NODE_ID")]
        expect_node: NodeId,
        /// Allow this computer to help two authenticated peers reconnect.
        #[arg(long)]
        introducer: bool,
    },
    /// Install the root-authorized bundle on its intended computer.
    Join {
        /// Owner-only bundle returned by an existing member.
        #[arg(value_name = "JOIN_BUNDLE")]
        bundle: PathBuf,
        /// Exact hive ID confirmed through a separate channel.
        #[arg(long, value_name = "HIVE_ID")]
        expect_hive: HiveId,
    },
    /// Create an owner-only signed contact file for another hive member.
    Publish {
        /// New contact file to create.
        #[arg(value_name = "CONTACT_FILE")]
        output: PathBuf,
        /// Owner-only endpoint configuration file.
        #[arg(long, value_name = "PATH")]
        endpoints: Option<PathBuf>,
        /// Stable UDP port used by automatic interface discovery.
        #[arg(long, default_value_t = DEFAULT_PORT, conflicts_with = "endpoints")]
        port: u16,
        /// Signed contact lifetime from 1 through 168 hours.
        #[arg(long, default_value_t = 24)]
        hours: u16,
    },
    /// Verify and remember an owner-only contact file from a hive member.
    Import {
        /// Contact file to verify and remember.
        #[arg(value_name = "CONTACT_FILE")]
        input: PathBuf,
    },
    /// Permanently deny one authorized device identity using the hive root.
    Revoke {
        /// Stable 64-character device identifier to revoke.
        #[arg(value_name = "NODE_ID")]
        node_id: NodeId,
    },
    /// List computers and their most useful signed addresses.
    Peers {
        /// Show every retained address and its security provenance.
        #[arg(long)]
        all: bool,
    },
    /// Show fresh signed addresses for one computer.
    Resolve {
        /// Computer name, local tag, shown fingerprint, or stable 64-character node ID.
        #[arg(value_name = "PEER")]
        peer: String,
    },
    /// Advertise a service this computer runs, signed into its peer record.
    Advertise {
        /// The service's own name: 1-16 lowercase letters, digits, or hyphens.
        #[arg(value_name = "NAME")]
        name: String,
        /// The port the service listens on at this computer's addresses.
        #[arg(value_name = "PORT")]
        port: u16,
        /// SHA-256 of the service's TLS public key, as 64 hex digits.
        #[arg(long, value_name = "HEX")]
        key_pin: String,
    },
    /// Stop advertising a service.
    Unadvertise {
        /// Name of the advertised service.
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Give a peer a local shell-friendly nickname.
    Tag {
        /// Existing computer name, tag, fingerprint, or stable node ID.
        #[arg(value_name = "PEER")]
        peer: String,
        /// Local nickname, such as `home` or `office-mac`.
        #[arg(value_name = "TAG")]
        tag: PeerTag,
    },
    /// Remove one exact local peer nickname.
    Untag {
        /// Existing local nickname to remove.
        #[arg(value_name = "TAG", value_parser = PeerTag::existing)]
        tag: PeerTag,
    },
    /// Serve read-only fleet tools over bounded MCP standard I/O.
    ///
    /// MCP 2026-07-28 is stateless; 2025-11-25 uses initialize. These entry paths
    /// are not interchangeable.
    Mcp,
    /// Verify, stage, activate, or deliver signed Supgang releases.
    Update {
        #[command(subcommand)]
        command: UpdateCommand,
    },
    /// Keep Supgang running in the background for this user.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Run the peer service in the foreground.
    Run {
        /// Owner-only endpoint configuration file.
        #[arg(long, value_name = "PATH")]
        endpoints: Option<PathBuf>,
        /// Stable UDP port used by automatic interface discovery.
        #[arg(long, default_value_t = DEFAULT_PORT, conflicts_with = "endpoints")]
        port: u16,
        /// Delay between remembered-peer attempts, from 1 through 3600 seconds.
        #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=3_600))]
        retry_seconds: u64,
        /// Signed endpoint lifetime, from 1 through 168 hours.
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(1..=168))]
        record_hours: u64,
        /// Ask the current local gateway for a renewable UDP mapping.
        #[arg(long, conflicts_with = "endpoints")]
        router_mapping: bool,
    },
    /// Run as an always-on, user-owned meeting point for the gang.
    Anchor {
        /// Owner-only endpoint configuration file.
        #[arg(long, value_name = "PATH")]
        endpoints: Option<PathBuf>,
        /// Stable UDP port used by automatic interface discovery.
        #[arg(long, default_value_t = DEFAULT_PORT, conflicts_with = "endpoints")]
        port: u16,
        /// Ask the current local gateway for a renewable UDP mapping.
        #[arg(long, conflicts_with = "endpoints")]
        router_mapping: bool,
    },
    /// Run the stable installed A/B payload supervisor.
    #[command(hide = true)]
    Supervise {
        /// Owner-only endpoint configuration inherited from service installation.
        #[arg(long, value_name = "PATH")]
        endpoints: Option<PathBuf>,
        /// Run the selected payload in anchor mode.
        #[arg(long)]
        anchor: bool,
        /// Preserve the owner's explicit local-gateway mapping choice.
        #[arg(long, conflicts_with = "endpoints")]
        router_mapping: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    /// Pin this computer's initial TUF release authority through a local file.
    Trust {
        /// Owner-only, self-signed TUF root metadata.
        #[arg(value_name = "ROOT.json")]
        root: PathBuf,
    },
    /// Package an already-signed TUF repository for sovereign carriage.
    Bundle {
        /// Directory containing signed TUF metadata.
        #[arg(long, value_name = "DIR")]
        metadata: PathBuf,
        /// Directory containing signed target files.
        #[arg(long, value_name = "DIR")]
        targets: PathBuf,
        /// Exact signed target name for one OS, architecture, and version.
        #[arg(long, value_name = "NAME")]
        target: String,
        /// New owner-only update bundle.
        #[arg(value_name = "BUNDLE")]
        output: PathBuf,
    },
    /// Independently verify and stage a carried signed release.
    Stage {
        /// Owner-only Supgang update bundle.
        #[arg(value_name = "BUNDLE")]
        bundle: PathBuf,
    },
    /// Queue one signed release for delivery across peer reconnects.
    Send {
        /// Computer name, local tag, fingerprint, or stable node ID.
        #[arg(value_name = "PEER")]
        peer: String,
        /// Owner-only Supgang update bundle.
        #[arg(value_name = "BUNDLE")]
        bundle: PathBuf,
    },
    /// Activate the latest staged release through the A/B supervisor.
    Apply,
    /// Show local update trust and activation state.
    Status,
    /// Return to the release that ran before the last refresh or update.
    ///
    /// Owner-local and bounded: it restores only the recorded previous
    /// release, which this computer already ran, then restarts the service.
    Revert,
}

#[derive(Debug, Subcommand)]
pub enum NameCommand {
    /// Change the name this computer signs into future peer records.
    Set {
        /// Portable 1-63 character computer name.
        #[arg(value_name = "NAME")]
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Change bounded runtime preferences.
    Set {
        /// Historically signed addresses retried per peer, from 8 through 64.
        #[arg(long, value_name = "COUNT", value_parser = clap::value_parser!(u8).range(8..=64))]
        address_history: u8,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Install and start the background service.
    Install {
        /// Owner-only endpoint configuration for a manually managed Internet path.
        #[arg(long, value_name = "PATH")]
        endpoints: Option<PathBuf>,
        /// Keep more authenticated peers connected so this machine can introduce them.
        #[arg(long)]
        anchor: bool,
        /// Ask the current local gateway for a renewable UDP mapping.
        #[arg(long, conflicts_with = "endpoints")]
        router_mapping: bool,
    },
    /// Replace the installed program without changing the service's settings.
    Refresh,
    /// Show whether the background service is installed and running.
    Status,
    /// Start an installed background service.
    Start,
    /// Stop the background service without removing it.
    Stop,
    /// Stop and start the background service.
    Restart,
    /// Remove the background service without deleting Supgang data.
    Uninstall,
}
