//! Local and remote vault key generation command dispatch.

use std::{io::Write, path::Path, process::ExitCode};

use super::{
    AgentPolicy, KeygenKind, KeygenOptions, SecureEnclave, remote_keygen, show_public, show_ssh_public, vault,
};

pub(super) fn with_terminal(
    state_directory: &Path,
    name: &str,
    note: &str,
    options: KeygenOptions,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    if let Some(remote) = options.remote.as_deref() {
        return match options.kind {
            Some(KeygenKind::Signing) if !options.contexts.is_empty() => remote_keygen::create(
                state_directory,
                remote,
                name,
                note,
                options.contexts,
                options.members,
                options.json,
                output,
            ),
            Some(KeygenKind::Ssh) if options.contexts.is_empty() => remote_keygen::create_ssh(
                state_directory,
                remote,
                name,
                note,
                options.members,
                options.json,
                output,
                error,
            ),
            _ => Err(
                "remote key creation requires --signing ed25519 with --context or --ssh ed25519 without --context"
                    .to_owned(),
            ),
        };
    }
    if options.contexts.is_empty() && !options.owner_terminal {
        return Err("vault keygen requires an interactive terminal with the owner present".to_owned());
    }
    match options.kind {
        Some(KeygenKind::Signing) => {
            let identity = if options.contexts.is_empty() {
                if !options.members.is_empty() {
                    return Err("--member requires at least one --context".to_owned());
                }
                vault::keygen(state_directory, &SecureEnclave, name, note)
            } else {
                let mut contexts = options.contexts;
                contexts.sort();
                let members = if options.members.is_empty() {
                    None
                } else {
                    let mut members = options.members;
                    members.sort_unstable();
                    Some(members)
                };
                let policy = AgentPolicy::new(contexts, members).map_err(|error| error.to_string())?;
                vault::keygen_agent(state_directory, &SecureEnclave, name, note, &policy)
            }
            .map_err(|error| error.to_string())?;
            show_public(name, &identity, options.json, output)
        }
        Some(KeygenKind::Ssh) => {
            if !options.contexts.is_empty() || !options.members.is_empty() {
                return Err("SSH keys do not accept agent signing contexts or members".to_owned());
            }
            let identity =
                vault::ssh_keygen(state_directory, &SecureEnclave, name, note).map_err(|error| error.to_string())?;
            show_ssh_public(name, &identity, options.json, output, error)
        }
        None => Err("choose exactly one key kind: --signing ed25519 or --ssh ed25519".to_owned()),
    }
}
