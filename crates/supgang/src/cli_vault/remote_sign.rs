//! Remote member signing through the private local service.

use std::{io::Write, path::Path, process::ExitCode};

use sha2::Digest as _;

use super::SignatureOutput;
use crate::{
    agent_sign_protocol::{self, SignRequest},
    cli::{render_error, render_json},
    cli_control,
    control::{self, ControlReply, ControlRequest},
    vault,
};

/// Signs through a current authenticated member, checking an independent key pin.
#[expect(clippy::too_many_arguments, reason = "one flat command with its streams")]
pub fn sign_remote(
    state_directory: &Path,
    remote: &str,
    name: &str,
    context: &str,
    sha256: &str,
    key_pin: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let result = (|| {
        vault::validate_name(name).map_err(|problem| problem.to_string())?;
        vault::validate_context(context).map_err(|problem| problem.to_string())?;
        if sha256.len() != 64
            || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || key_pin.len() != 64
            || !key_pin
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(
                "digest and key pin must each be 64 hexadecimal characters; the key pin must be lowercase".to_owned(),
            );
        }
        let digest: [u8; 32] = hex::decode(sha256)
            .map_err(|_| "invalid digest")?
            .try_into()
            .map_err(|_| "invalid digest")?;
        let target = cli_control::resolve_peer_node(state_directory, remote)?;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| "could not create a signing request nonce")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| "clock is invalid")?
            .as_secs();
        let request = SignRequest {
            nonce,
            purpose: name.to_owned(),
            context: context.to_owned(),
            digest,
            expires_at: now.checked_add(60).ok_or("clock is invalid")?,
        };
        let bytes = request.encode().map_err(|_| "signing request is invalid")?;
        let mut padded = [0_u8; agent_sign_protocol::MAX_REQUEST_BYTES];
        padded
            .get_mut(..bytes.len())
            .ok_or("signing request is invalid")?
            .copy_from_slice(&bytes);
        let reply = control::request_sign(
            state_directory,
            ControlRequest::AgentSign {
                target,
                request: Box::new(padded),
                length: u16::try_from(bytes.len()).map_err(|_| "signing request is invalid")?,
            },
        )
        .map_err(|problem| problem.to_string())?;
        let (signature, fingerprint) = verify_reply(reply, &request, key_pin)?;
        if json {
            let mut sink = Vec::new();
            return Ok(render_json(
                &SignatureOutput {
                    schema: "supgang.signature/v1",
                    status: "ok",
                    signature,
                    fingerprint,
                    context: context.to_owned(),
                    message_sha256: hex::encode(digest),
                },
                output,
                &mut sink,
            ));
        }
        writeln!(
            output,
            "Signature: {signature}\nFingerprint: {fingerprint}\nContext: {context}\nSHA-256: {}",
            hex::encode(digest)
        )
        .map_err(|_| "could not write the signature".to_owned())?;
        Ok(ExitCode::SUCCESS)
    })();
    result.unwrap_or_else(|message| render_error(json, &message, output, error))
}

fn verify_reply(reply: Option<ControlReply>, request: &SignRequest, key_pin: &str) -> Result<(String, String), String> {
    let (reply_nonce, public_key, signature) = match reply {
        Some(ControlReply::AgentSigned {
            nonce,
            public_key,
            signature,
        }) => (nonce, public_key, signature),
        Some(ControlReply::Error { message }) => return Err(message),
        Some(_) => return Err("local service returned an unexpected signing reply".to_owned()),
        None => return Err("the local Supgang service must be running for remote signing".to_owned()),
    };
    let reply_nonce: [u8; 32] = hex::decode(reply_nonce)
        .map_err(|_| "invalid signing reply")?
        .try_into()
        .map_err(|_| "invalid signing reply")?;
    let public_key: [u8; 32] = hex::decode(public_key)
        .map_err(|_| "invalid signing reply")?
        .try_into()
        .map_err(|_| "invalid signing reply")?;
    let signature_bytes: [u8; 64] = hex::decode(&signature)
        .map_err(|_| "invalid signing reply")?
        .try_into()
        .map_err(|_| "invalid signing reply")?;
    let fingerprint = hex::encode(sha2::Sha256::digest(public_key));
    if reply_nonce != request.nonce
        || fingerprint != key_pin
        || !vault::verify_signed(&request.context, &request.digest, &public_key, &signature_bytes)
    {
        return Err("member signing reply failed nonce, key pin or signature verification".to_owned());
    }
    Ok((signature, fingerprint))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::Digest as _;

    use super::verify_reply;
    use crate::{agent_sign_protocol::SignRequest, control::ControlReply};

    #[test]
    fn reply_requires_exact_nonce_key_pin_and_signature() {
        let request = SignRequest {
            nonce: [1; 32],
            purpose: "build".to_owned(),
            context: "build.stage".to_owned(),
            digest: [2; 32],
            expires_at: 100,
        };
        let key = SigningKey::from_bytes(&[3; 32]);
        let mut message = b"supgang-sign/v1\0".to_vec();
        message.extend_from_slice(request.context.as_bytes());
        message.push(0);
        message.extend_from_slice(&request.digest);
        let signature = key.sign(&message).to_bytes();
        let pin = hex::encode(sha2::Sha256::digest(key.verifying_key().to_bytes()));
        let reply = || ControlReply::AgentSigned {
            nonce: hex::encode(request.nonce),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(signature),
        };
        assert!(verify_reply(Some(reply()), &request, &pin).is_ok());
        assert!(verify_reply(Some(reply()), &request, &"0".repeat(64)).is_err());
        let changed = SignRequest {
            nonce: [4; 32],
            ..request.clone()
        };
        assert!(verify_reply(Some(reply()), &changed, &pin).is_err());
        let changed = SignRequest {
            digest: [5; 32],
            ..request
        };
        assert!(verify_reply(Some(reply()), &changed, &pin).is_err());
    }
}
