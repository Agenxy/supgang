//! Stable command-line interface and machine-readable diagnostics.

use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::SystemTime,
};

use clap::{Parser, error::ErrorKind};
use serde::Serialize;

use crate::{
    VERSION, artifact, cli_background, cli_control, cli_peer, cli_profile, cli_service, cli_settings, cli_update,
    control,
    ids::{HiveId, NodeId},
    invitation::{
        JoinBundle, MAX_JOIN_BUNDLE_BYTES, MAX_JOIN_REQUEST_BYTES, decode_join_bundle, decode_join_request,
        encode_join_bundle, encode_join_request,
    },
    mcp,
    membership::MembershipRoles,
    profile, service, state, storage,
};

use crate::cli_args::{Cli, Command};
pub(crate) use crate::cli_args::{ConfigCommand, NameCommand};

mod doctor;

use doctor::reachability_check;

const EXIT_USAGE: u8 = 2;
const EXIT_FAILURE: u8 = 3;

#[derive(Debug, Serialize)]
struct InitOutput {
    schema: &'static str,
    status: &'static str,
    hive_id: String,
    node_id: String,
    name: String,
    key_protection: &'static str,
}

#[derive(Debug, Serialize)]
struct DoctorOutput {
    schema: &'static str,
    status: &'static str,
    version: &'static str,
    strict_mode: bool,
    public_dependencies: u8,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    id: &'static str,
    status: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ErrorOutput<'a> {
    schema: &'static str,
    status: &'static str,
    error: &'a str,
}

#[derive(Debug, Serialize)]
struct JoinOutput {
    schema: &'static str,
    status: &'static str,
    hive_id: Option<String>,
    node_id: String,
}

/// Parses the process arguments and writes output to the process streams.
#[must_use]
pub fn run_from_env() -> ExitCode {
    // Do not hold global stream locks: the MCP subcommand owns stdio for its
    // asynchronous JSON-RPC transport.
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run(std::env::args_os(), &mut stdout, &mut stderr)
}

/// Executes the CLI against caller-provided streams.
///
/// This entry point keeps tests and embedders independent from global output.
#[must_use]
pub fn run<I, T>(arguments: I, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(parse_error) => {
            if matches!(parse_error.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return if write!(output, "{parse_error}").is_ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(EXIT_FAILURE)
                };
            }
            let _write_result = write!(error, "{parse_error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let state_directory = match cli.state_dir.map_or_else(storage::default_state_directory, Ok) {
        Ok(path) => path,
        Err(storage_error) => return render_error(cli.json, &storage_error.to_string(), output, error),
    };

    if let Some(peer) = cli.peer {
        return cli_control::peer(&state_directory, &peer, cli.json, output, error);
    }

    match cli.command {
        None => {
            let code = cli_control::peers(&state_directory, cli.json, false, output, error);
            if code == ExitCode::SUCCESS && !cli.json && writeln!(output, "Help: supgang --help").is_err() {
                return ExitCode::from(EXIT_FAILURE);
            }
            code
        }
        Some(Command::Init) => init(&state_directory, cli.json, output, error),
        Some(Command::Doctor) => doctor(&state_directory, cli.json, output, error),
        Some(Command::Config { command }) => {
            cli_settings::config(&state_directory, command.as_ref(), cli.json, output, error)
        }
        Some(Command::Status) => cli_control::status(&state_directory, cli.json, output, error),
        Some(Command::Name { command }) => cli_profile::name(&state_directory, command, cli.json, output, error),
        Some(Command::Advertise { name, port, key_pin }) => cli_profile::advertise(
            &state_directory,
            cli_profile::Advertise::Add { name, port, key_pin },
            cli.json,
            output,
            error,
        ),
        Some(Command::Unadvertise { name }) => cli_profile::advertise(
            &state_directory,
            cli_profile::Advertise::Remove { name },
            cli.json,
            output,
            error,
        ),
        Some(Command::JoinRequest { output: request_file }) => {
            join_request(&state_directory, &request_file, cli.json, output, error)
        }
        Some(Command::Invite {
            request,
            output: bundle_file,
            days,
            expect_node,
            introducer,
        }) => invite(
            &state_directory,
            InviteOptions {
                request_file: &request,
                bundle_file: &bundle_file,
                days,
                expected_node: expect_node,
                introducer,
            },
            cli.json,
            output,
            error,
        ),
        Some(Command::Join { bundle, expect_hive }) => {
            join(&state_directory, &bundle, expect_hive, cli.json, output, error)
        }
        Some(Command::Publish {
            output: contact_file,
            endpoints,
            port,
            hours,
        }) => match cli_peer::publish(&state_directory, &contact_file, endpoints.as_deref(), port, hours) {
            Ok(result) => render_publish(&result, cli.json, output, error),
            Err(message) => render_error(cli.json, &message, output, error),
        },
        Some(Command::Import { input }) => match cli_peer::import(&state_directory, &input) {
            Ok(result) => render_import(&result, cli.json, output, error),
            Err(message) => render_error(cli.json, &message, output, error),
        },
        Some(Command::Revoke { node_id }) => cli_control::revoke(&state_directory, node_id, cli.json, output, error),
        Some(Command::Peers { all }) => cli_control::peers(&state_directory, cli.json, all, output, error),
        Some(Command::Resolve { peer }) => cli_control::resolve(&state_directory, &peer, cli.json, output, error),
        Some(Command::Tag { peer, tag }) => cli_control::tag(&state_directory, &peer, tag, cli.json, output, error),
        Some(Command::Untag { tag }) => cli_control::untag(&state_directory, tag, cli.json, output, error),
        Some(Command::Mcp) => {
            if cli.json {
                render_error(
                    true,
                    "mcp reserves standard output for JSON-RPC; omit --json",
                    output,
                    error,
                )
            } else {
                match mcp::serve_stdio(state_directory) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(mcp_error) => render_error(false, &mcp_error.to_string(), output, error),
                }
            }
        }
        Some(Command::Update { command }) => cli_update::update(&state_directory, &command, cli.json, output, error),
        Some(Command::Service { command }) => {
            cli_background::service(&state_directory, &command, cli.json, output, error)
        }
        Some(Command::Run {
            endpoints,
            port,
            retry_seconds,
            record_hours,
            router_mapping,
        }) => match cli_service::run(
            &state_directory,
            cli_service::RunOptions {
                endpoints: endpoints.as_deref(),
                port,
                retry_seconds,
                record_hours,
                router_mapping,
                anchor_mode: false,
                json: cli.json,
            },
            output,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => render_error(cli.json, &message, output, error),
        },
        Some(Command::Anchor {
            endpoints,
            port,
            router_mapping,
        }) => match cli_service::run(
            &state_directory,
            cli_service::RunOptions {
                endpoints: endpoints.as_deref(),
                port,
                retry_seconds: service::DEFAULT_RETRY_SECONDS,
                record_hours: service::DEFAULT_RECORD_LIFETIME_SECONDS / (60 * 60),
                router_mapping,
                anchor_mode: true,
                json: cli.json,
            },
            output,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => render_error(cli.json, &message, output, error),
        },
        Some(Command::Supervise {
            endpoints,
            anchor,
            router_mapping,
        }) => match crate::update::run_supervisor(
            &state_directory,
            crate::update::SupervisorOptions {
                endpoints: endpoints.as_deref(),
                anchor,
                router_mapping,
            },
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(supervisor_error) => render_error(cli.json, &supervisor_error.to_string(), output, error),
        },
    }
}

fn render_publish(
    result: &cli_peer::PublishOutput,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if json {
        render_json(result, output, error)
    } else if writeln!(
        output,
        "Signed contact created for {} at sequence {} with {} candidate(s).",
        result.node_id, result.sequence, result.candidate_count
    )
    .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn render_import(
    result: &cli_peer::ImportOutput,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if json {
        render_json(result, output, error)
    } else if writeln!(output, "Peer {}: {}.", result.node_id, result.decision).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn join_request(
    state_directory: &PathBuf,
    request_file: &PathBuf,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let request = match state::create_join_request(state_directory) {
        Ok(request) => request,
        Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
    };
    let bytes = match encode_join_request(&request) {
        Ok(bytes) => bytes,
        Err(invitation_error) => return render_error(json, &invitation_error.to_string(), output, error),
    };
    if let Err(artifact_error) = artifact::write_new(request_file, &bytes, MAX_JOIN_REQUEST_BYTES) {
        return render_error(json, &artifact_error.to_string(), output, error);
    }
    let result = JoinOutput {
        schema: "supgang.join-request/v1",
        status: "ok",
        hive_id: None,
        node_id: crate::ids::NodeId::from_verifying_key(&request.device_verifying_key).to_string(),
    };
    render_join_output(
        &result,
        "Join request created. Carry it to an existing hive member.",
        json,
        output,
        error,
    )
}

#[derive(Clone, Copy)]
struct InviteOptions<'a> {
    request_file: &'a PathBuf,
    bundle_file: &'a PathBuf,
    days: u16,
    expected_node: NodeId,
    introducer: bool,
}

fn invite(
    state_directory: &PathBuf,
    options: InviteOptions<'_>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if !(1..=3_650).contains(&options.days) {
        return render_error(
            json,
            "membership lifetime must be from 1 through 3650 days",
            output,
            error,
        );
    }
    let request_bytes = match artifact::read(options.request_file, MAX_JOIN_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(artifact_error) => return render_error(json, &artifact_error.to_string(), output, error),
    };
    let request = match decode_join_request(&request_bytes) {
        Ok(request) => request,
        Err(invitation_error) => return render_error(json, &invitation_error.to_string(), output, error),
    };
    let now = match unix_time() {
        Ok(now) => now,
        Err(message) => return render_error(json, message, output, error),
    };
    let mut local_state = match state::open(state_directory) {
        Ok(state) => state,
        Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
    };
    let expires_at = now.saturating_add(u64::from(options.days) * 24 * 60 * 60);
    let roles = if options.introducer {
        MembershipRoles::DEVICE | MembershipRoles::INTRODUCER
    } else {
        MembershipRoles::DEVICE
    };
    let membership = match local_state.authorize_join_request(&request, options.expected_node, roles, now, expires_at) {
        Ok(membership) => membership,
        Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
    };
    let Some(root) = local_state.identity().root.as_ref() else {
        return render_error(json, "this computer does not hold the hive root", output, error);
    };
    let bundle = match JoinBundle::new(root, membership, local_state.revocations().clone(), now) {
        Ok(bundle) => bundle,
        Err(invitation_error) => return render_error(json, &invitation_error.to_string(), output, error),
    };
    let bundle_bytes = match encode_join_bundle(&bundle) {
        Ok(bytes) => bytes,
        Err(invitation_error) => return render_error(json, &invitation_error.to_string(), output, error),
    };
    if let Err(artifact_error) = artifact::write_new(options.bundle_file, &bundle_bytes, MAX_JOIN_BUNDLE_BYTES) {
        return render_error(json, &artifact_error.to_string(), output, error);
    }
    let result = JoinOutput {
        schema: "supgang.invite/v1",
        status: "ok",
        hive_id: Some(local_state.identity().hive_id.to_string()),
        node_id: bundle.membership.certificate.node_id.to_string(),
    };
    render_join_output(
        &result,
        "Join bundle created. Carry it back to the computer that made the request.",
        json,
        output,
        error,
    )
}

fn join(
    state_directory: &PathBuf,
    bundle_file: &PathBuf,
    expected_hive: HiveId,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let bundle_bytes = match artifact::read(bundle_file, MAX_JOIN_BUNDLE_BYTES) {
        Ok(bytes) => bytes,
        Err(artifact_error) => return render_error(json, &artifact_error.to_string(), output, error),
    };
    let bundle = match decode_join_bundle(&bundle_bytes) {
        Ok(bundle) => bundle,
        Err(invitation_error) => return render_error(json, &invitation_error.to_string(), output, error),
    };
    let local_state = match state::install_join_bundle(state_directory, &bundle, expected_hive) {
        Ok(state) => state,
        Err(state_error) => return render_error(json, &state_error.to_string(), output, error),
    };
    let result = JoinOutput {
        schema: "supgang.join/v1",
        status: "ok",
        hive_id: Some(local_state.identity().hive_id.to_string()),
        node_id: local_state.identity().device.node_id().to_string(),
    };
    render_join_output(&result, "This computer joined the hive.", json, output, error)
}

fn render_join_output(
    result: &JoinOutput,
    message: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    if json {
        render_json(result, output, error)
    } else if writeln!(output, "{message}\nThis computer: {}", result.node_id).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

fn unix_time() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the UNIX epoch")
}

fn init(state_directory: &PathBuf, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    match state::initialize(state_directory) {
        Ok(state) => {
            let name = match profile::load_or_create(state_directory, state.identity().device.node_id()) {
                Ok(name) => name,
                Err(profile_error) => return render_error(json, &profile_error.to_string(), output, error),
            };
            let result = InitOutput {
                schema: "supgang.init/v2",
                status: "ok",
                hive_id: state.identity().hive_id.to_string(),
                node_id: state.identity().device.node_id().to_string(),
                name: name.to_string(),
                key_protection: "owner-only-file",
            };
            if json {
                render_json(&result, output, error)
            } else if writeln!(
                output,
                "Supgang initialized.\nHive: {}\nThis computer: {} [{}]\nKey protection: owner-only file (0600)",
                result.hive_id,
                result.name,
                &result.node_id[..8]
            )
            .is_ok()
            {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_FAILURE)
            }
        }
        Err(storage_error) => render_error(json, &storage_error.to_string(), output, error),
    }
}

fn doctor(state_directory: &PathBuf, json: bool, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    let mut checks = vec![DoctorCheck {
        id: "public-dependencies",
        status: "ok",
        detail: "strict mode has no hosted discovery, account, telemetry, DNS publisher, or vendor relay".to_owned(),
    }];
    let identity_result = storage::load_identity(state_directory);
    checks.push(match &identity_result {
        Ok(_) => DoctorCheck {
            id: "identity",
            status: "ok",
            detail: "protected identity is owner-only and its checksum is valid".to_owned(),
        },
        Err(storage_error) => DoctorCheck {
            id: "identity",
            status: "error",
            detail: storage_error.to_string(),
        },
    });
    let status_response = control::request(state_directory, control::ControlRequest::Status);
    let live_reachability = match &status_response {
        Ok(Some(control::ControlReply::Status { value })) => Some((
            value.router_mapping.clone(),
            value.internet_reachability.clone(),
            value.active_peers,
        )),
        _ => None,
    };
    let (state_ok, state_check) = match status_response {
        Ok(Some(control::ControlReply::Status { value })) => (
            true,
            DoctorCheck {
                id: "authoritative-state",
                status: "ok",
                detail: format!(
                    "running owner service holds {} verified event(s) for {} authorized member(s)",
                    value.event_count, value.member_count
                ),
            },
        ),
        Ok(Some(control::ControlReply::Error { message })) => (
            false,
            DoctorCheck {
                id: "authoritative-state",
                status: "error",
                detail: message,
            },
        ),
        Ok(Some(_)) => (
            false,
            DoctorCheck {
                id: "authoritative-state",
                status: "error",
                detail: "local service returned an unexpected response".to_owned(),
            },
        ),
        Ok(None) => match state::open(state_directory) {
            Ok(state) if state.revocations().contains(&state.identity().device.node_id()) => (
                false,
                DoctorCheck {
                    id: "authoritative-state",
                    status: "error",
                    detail: "local device identity is root-revoked; service startup is denied".to_owned(),
                },
            ),
            Ok(state) => (
                true,
                DoctorCheck {
                    id: "authoritative-state",
                    status: "ok",
                    detail: format!(
                        "root authorization and {} committed event(s) replayed with consecutive counters",
                        state.event_count()
                    ),
                },
            ),
            Err(state_error) => (
                false,
                DoctorCheck {
                    id: "authoritative-state",
                    status: "error",
                    detail: state_error.to_string(),
                },
            ),
        },
        Err(control_error) => (
            false,
            DoctorCheck {
                id: "authoritative-state",
                status: "error",
                detail: control_error.to_string(),
            },
        ),
    };
    checks.push(state_check);
    checks.push(reachability_check(live_reachability.as_ref()));
    checks.push(DoctorCheck {
        id: "key-provider",
        status: "warning",
        detail: "identity uses an owner-only file; hardware-backed platform storage is not enabled in this build"
            .to_owned(),
    });
    let failed = identity_result.is_err() || !state_ok || checks.iter().any(|check| check.status == "error");
    let result = DoctorOutput {
        schema: "supgang.doctor/v1",
        status: if failed { "error" } else { "warning" },
        version: VERSION,
        strict_mode: true,
        public_dependencies: 0,
        checks,
    };
    let rendered = if json {
        render_json(&result, output, error)
    } else {
        render_doctor_human(&result, output)
    };
    if rendered != ExitCode::SUCCESS {
        rendered
    } else if failed {
        ExitCode::from(EXIT_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}

fn render_doctor_human(result: &DoctorOutput, output: &mut dyn Write) -> ExitCode {
    if writeln!(output, "Supgang doctor: {}", result.status).is_err() {
        return ExitCode::from(EXIT_FAILURE);
    }
    for check in &result.checks {
        if writeln!(output, "[{}] {}: {}", check.status, check.id, check.detail).is_err() {
            return ExitCode::from(EXIT_FAILURE);
        }
    }
    ExitCode::SUCCESS
}

pub(crate) fn render_json<T: Serialize>(value: &T, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    if let Err(render_error) = serde_json::to_writer(&mut *output, value) {
        let _write_result = writeln!(error, "could not render JSON output: {render_error}");
        return ExitCode::from(EXIT_FAILURE);
    }
    if let Err(render_error) = writeln!(output) {
        let _write_result = writeln!(error, "could not finish JSON output: {render_error}");
        return ExitCode::from(EXIT_FAILURE);
    }
    ExitCode::SUCCESS
}

pub(crate) fn render_error(json: bool, message: &str, output: &mut dyn Write, error: &mut dyn Write) -> ExitCode {
    let rendered = if json {
        render_json(
            &ErrorOutput {
                schema: "supgang.error/v1",
                status: "error",
                error: message,
            },
            output,
            error,
        )
    } else if writeln!(error, "error: {message}").is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    };
    if rendered == ExitCode::SUCCESS {
        ExitCode::from(EXIT_FAILURE)
    } else {
        rendered
    }
}

#[cfg(test)]
mod tests;
