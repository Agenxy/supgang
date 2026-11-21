//! Create a sealed agent-purpose key through a current authenticated member.

use std::{io::Write, path::Path, process::ExitCode};

use sha2::Digest as _;

use super::{show_public, show_ssh_public};
use crate::{
    agent_keygen_protocol::{KeygenRequest, MAX_REQUEST_BYTES},
    cli_control,
    control::{self, ControlReply, ControlRequest},
    ids::NodeId,
    vault::{self, AgentPolicy, SigningPublic},
};

#[expect(clippy::too_many_arguments, reason = "one flat command with its output stream")]
pub(super) fn create(
    state_directory: &Path,
    remote: &str,
    name: &str,
    note: &str,
    mut contexts: Vec<String>,
    mut members: Vec<NodeId>,
    json: bool,
    output: &mut dyn Write,
) -> Result<ExitCode, String> {
    vault::validate_name(name).map_err(|error| error.to_string())?;
    contexts.sort();
    members.sort_unstable();
    let policy =
        AgentPolicy::new(contexts, (!members.is_empty()).then_some(members)).map_err(|error| error.to_string())?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| "could not create a key request nonce")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| "clock is invalid")?
        .as_secs();
    let request = KeygenRequest {
        ssh: false,
        nonce,
        purpose: name.to_owned(),
        note: note.to_owned(),
        policy,
        expires_at: now.checked_add(60).ok_or("clock is invalid")?,
    };
    let identity = send_request(state_directory, remote, &request)?;
    show_public(name, &identity, json, output)
}

#[expect(clippy::too_many_arguments, reason = "one flat command with its output streams")]
pub(super) fn create_ssh(
    state_directory: &Path,
    remote: &str,
    name: &str,
    note: &str,
    mut members: Vec<NodeId>,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<ExitCode, String> {
    members.sort_unstable();
    let policy = AgentPolicy::new(vec!["ssh.keygen".to_owned()], (!members.is_empty()).then_some(members))
        .map_err(|error| error.to_string())?;
    vault::validate_name(name).map_err(|error| error.to_string())?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| "could not create a key request nonce")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| "clock is invalid")?
        .as_secs();
    let request = KeygenRequest {
        ssh: true,
        nonce,
        purpose: name.to_owned(),
        note: note.to_owned(),
        policy,
        expires_at: now.checked_add(60).ok_or("clock is invalid")?,
    };
    let identity = send_request(state_directory, remote, &request)?;
    let ssh = vault::ssh_public_from(name, identity.public_key);
    show_ssh_public(name, &ssh, json, output, error)
}

fn send_request(state_directory: &Path, remote: &str, request: &KeygenRequest) -> Result<SigningPublic, String> {
    let target = cli_control::resolve_peer_node(state_directory, remote)?;
    let bytes = request.encode().map_err(|_| "key creation request is invalid")?;
    let mut padded = Box::new([0_u8; MAX_REQUEST_BYTES]);
    padded
        .get_mut(..bytes.len())
        .ok_or("key creation request is invalid")?
        .copy_from_slice(&bytes);
    let reply = control::request_keygen(
        state_directory,
        ControlRequest::AgentKeygen {
            target,
            request: padded,
            length: u16::try_from(bytes.len()).map_err(|_| "key creation request is invalid")?,
        },
    )
    .map_err(|error| error.to_string())?;
    verify_reply(reply, request)
}

fn verify_reply(reply: Option<ControlReply>, request: &KeygenRequest) -> Result<SigningPublic, String> {
    let (nonce, public_key) = match reply {
        Some(ControlReply::AgentKeyCreated { nonce, public_key }) => (nonce, public_key),
        Some(ControlReply::Error { message }) => return Err(message),
        Some(_) => return Err("local service returned an unexpected key creation reply".to_owned()),
        None => return Err("the local Supgang service must be running for remote key creation".to_owned()),
    };
    let nonce: [u8; 32] = hex::decode(nonce)
        .map_err(|_| "invalid key creation reply")?
        .try_into()
        .map_err(|_| "invalid key creation reply")?;
    let public_key: [u8; 32] = hex::decode(public_key)
        .map_err(|_| "invalid key creation reply")?
        .try_into()
        .map_err(|_| "invalid key creation reply")?;
    if nonce != request.nonce {
        return Err("key creation reply failed nonce verification".to_owned());
    }
    Ok(SigningPublic {
        public_key,
        fingerprint: hex::encode(sha2::Sha256::digest(public_key)),
    })
}

#[cfg(test)]
mod tests {
    use super::{show_ssh_public, verify_reply};
    use crate::{
        agent_keygen_protocol::KeygenRequest,
        control::ControlReply,
        vault::{self, AgentPolicy},
    };

    #[test]
    fn reply_is_bound_to_request_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let request = KeygenRequest {
            ssh: false,
            nonce: [7; 32],
            purpose: "build.stage".to_owned(),
            note: String::new(),
            policy: AgentPolicy::new(vec!["build.stage".to_owned()], None)?,
            expires_at: u64::MAX,
        };
        let reply = ControlReply::AgentKeyCreated {
            nonce: hex::encode([8; 32]),
            public_key: hex::encode([9; 32]),
        };
        assert!(verify_reply(Some(reply), &request).is_err());
        Ok(())
    }

    #[test]
    fn remote_ssh_reply_contains_only_public_line_and_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
        let public = vault::ssh_public_from("q42-kvm-admin", [9; 32]);
        assert_eq!(public.remote_creator, None);
        let mut output = Vec::new();
        let mut error = Vec::new();
        show_ssh_public("q42-kvm-admin", &public, false, &mut output, &mut error)?;
        assert_eq!(String::from_utf8(output)?, format!("{}\n", public.line));
        assert_eq!(String::from_utf8(error)?, format!("{}\n", public.fingerprint));
        Ok(())
    }
}
