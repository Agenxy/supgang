//! Explicit policy migration for a previously pinned signing key.

use std::{io::Write, path::Path, process::ExitCode};

use super::{SecureEnclave, show_public, vault};
use crate::{ids::NodeId, vault::AgentPolicy};

pub(super) fn run(
    state_directory: &Path,
    name: &str,
    expected_fingerprint: &str,
    mut contexts: Vec<String>,
    mut members: Vec<NodeId>,
    json: bool,
    output: &mut dyn Write,
) -> Result<ExitCode, String> {
    contexts.sort();
    members.sort_unstable();
    let policy =
        AgentPolicy::new(contexts, (!members.is_empty()).then_some(members)).map_err(|error| error.to_string())?;
    let identity = vault::migrate_agent_policy(state_directory, &SecureEnclave, name, expected_fingerprint, &policy)
        .map_err(|error| error.to_string())?;
    show_public(name, &identity, json, output)
}
