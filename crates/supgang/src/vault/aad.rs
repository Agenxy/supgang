//! Authenticated metadata for sealed vault entries.

use super::{ENTRY_DOMAIN, Kind, PUBLIC_BYTES, SealMetadata};

/// `domain || name || 0 || ephemeral || stored_at (big-endian) || note`: every
/// field of the entry except the ciphertext and nonce, so editing any fails.
/// Signing entries append `\0signing-ed25519\0 || public` to prevent decoding
/// them as exportable secrets. This suffix cannot be forged through `note`
/// because `validate_note`, called on both add and decode, forbids control
/// characters including NUL. Keep that restriction if the note grammar changes.
pub(super) fn associated_data(
    name: &str,
    note: &str,
    stored_at: u64,
    ephemeral: &[u8; PUBLIC_BYTES],
    metadata: &SealMetadata,
    policy: Option<&[u8]>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_DOMAIN.len() + name.len() + 1 + PUBLIC_BYTES + 8 + note.len() + 48);
    aad.extend_from_slice(ENTRY_DOMAIN);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(ephemeral);
    aad.extend_from_slice(&stored_at.to_be_bytes());
    aad.extend_from_slice(note.as_bytes());
    if metadata.kind != Kind::Secret {
        aad.push(0);
        aad.extend_from_slice(metadata.kind.label().as_bytes());
        aad.push(0);
        if let Some(public) = metadata.signing_public {
            aad.extend_from_slice(&public);
        }
        if let Some(public) = metadata.lms_public {
            aad.extend_from_slice(&public);
        }
        if let Some(next_q) = metadata.lms_next_q {
            aad.extend_from_slice(&next_q.to_be_bytes());
        }
    }
    if let Some(policy) = policy {
        aad.push(0);
        aad.extend_from_slice(b"agent-policy/v1\0");
        aad.extend_from_slice(policy);
    }
    if let Some(creator) = metadata.remote_creator {
        aad.extend_from_slice(b"\0remote-creator/v1\0");
        aad.extend_from_slice(creator.as_bytes());
    }
    if let Some(digest) = metadata.presence_digest {
        aad.extend_from_slice(b"\0lms-presence-wrap/v1\0");
        aad.extend_from_slice(&digest);
    }
    aad
}
