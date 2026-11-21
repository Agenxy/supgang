//! Canonical, bounded vault document encoding.

use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use super::policy::AgentPolicy;
use super::{
    Document, Entry, Kind, MAX_SECRET_BYTES, MAX_SECRETS, TAG_BYTES, VERSION, VaultError, compressed_point,
    validate_name, validate_note,
};
use crate::device_key::custody::SealedKey;

/// Canonical CBOR v1-v3 stay readable; v4 adds agent policy and v5 remote creator.
pub(super) fn encode(document: &Document) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if document.entries.iter().any(|entry| {
        (entry.remote_creator.is_some() != (entry.kind == Kind::SshEd25519 && entry.policy.is_some()))
            || (entry.remote_creator.is_some() && document.version < 5)
            || entry.policy.as_deref().is_some_and(|bytes| {
                document.version < 4
                    || !matches!(entry.kind, Kind::SigningEd25519 | Kind::SshEd25519)
                    || AgentPolicy::decode(bytes).is_err()
                    || (entry.kind == Kind::SshEd25519
                        && AgentPolicy::decode(bytes).is_ok_and(|policy| policy.contexts() != ["ssh.keygen"]))
            })
    }) {
        return Err(VaultError::Corrupt);
    }
    let key = Zeroizing::new(document.key.encode()?);
    let mut e = Encoder::new(Vec::new());
    let entries = u64::try_from(document.entries.len()).map_err(|_| VaultError::Corrupt)?;
    let mut result = e
        .array(4)
        .and_then(|e| e.u8(document.version))
        .and_then(|e| e.bytes(&key))
        .and_then(|e| e.bytes(&document.public))
        .and_then(|e| e.array(entries))
        .map(|_| ());
    for entry in &document.entries {
        result = result.and_then(|()| {
            e.array(match document.version {
                1 => 6,
                2 => 8,
                3 => 10,
                4 => 11,
                _ => 12,
            })
            .and_then(|e| e.str(&entry.name))
            .and_then(|e| e.str(&entry.note))
            .and_then(|e| e.u64(entry.stored_at))
            .and_then(|e| e.bytes(&entry.ephemeral))
            .and_then(|e| e.bytes(&entry.nonce))
            .and_then(|e| e.bytes(&entry.ciphertext))
            .and_then(|e| {
                if document.version == 1 {
                    Ok(e)
                } else {
                    e.str(entry.kind.label())
                }
            })
            .and_then(|e| {
                if document.version == 1 {
                    Ok(e)
                } else if let Some(public) = entry.signing_public {
                    e.bytes(&public)
                } else {
                    e.null()
                }
            })
            .and_then(|e| {
                if document.version < 3 {
                    Ok(e)
                } else if let Some(public) = entry.lms_public {
                    e.bytes(&public)
                } else {
                    e.null()
                }
            })
            .and_then(|e| {
                if document.version < 3 {
                    Ok(e)
                } else if let Some(next_q) = entry.lms_next_q {
                    e.u32(next_q)
                } else {
                    e.null()
                }
            })
            .and_then(|e| {
                if document.version < 4 {
                    Ok(e)
                } else if let Some(policy) = &entry.policy {
                    e.bytes(policy)
                } else {
                    e.null()
                }
            })
            .and_then(|e| {
                if document.version < 5 {
                    Ok(e)
                } else if let Some(creator) = entry.remote_creator {
                    e.bytes(creator.as_bytes())
                } else {
                    e.null()
                }
            })
            .map(|_| ())
        });
    }
    result.map_err(|_| VaultError::Corrupt)?;
    Ok(Zeroizing::new(e.into_writer()))
}

pub(super) fn decode(bytes: &[u8]) -> Result<Document, VaultError> {
    let parse = || -> Result<Document, minicbor::decode::Error> {
        let invalid = |reason| minicbor::decode::Error::message(reason);
        let mut d = Decoder::new(bytes);
        if d.array()? != Some(4) {
            return Err(invalid("vault version"));
        }
        let version = d.u8()?;
        if version != 1 && version != 2 && version != 3 && version != 4 && version != VERSION {
            return Err(invalid("vault version"));
        }
        let key = SealedKey::decode(d.bytes()?).map_err(|_| invalid("vault key"))?;
        let public = compressed_point(d.bytes()?).map_err(|_| invalid("vault public key"))?;
        let count = d.array()?.ok_or_else(|| invalid("vault entries"))?;
        if count > MAX_SECRETS as u64 {
            return Err(invalid("vault entries"));
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            if d.array()?
                != Some(match version {
                    1 => 6,
                    2 => 8,
                    3 => 10,
                    4 => 11,
                    _ => 12,
                })
            {
                return Err(invalid("vault entry"));
            }
            let name = d.str()?.to_owned();
            let note = d.str()?.to_owned();
            let stored_at = d.u64()?;
            let ephemeral = compressed_point(d.bytes()?).map_err(|_| invalid("vault entry key"))?;
            let nonce = d.bytes()?.try_into().map_err(|_| invalid("vault entry nonce"))?;
            let ciphertext = d.bytes()?.to_vec();
            let kind = if version == 1 {
                Kind::Secret
            } else {
                match d.str()? {
                    "secret" => Kind::Secret,
                    "signing-ed25519" => Kind::SigningEd25519,
                    "ssh-ed25519" => Kind::SshEd25519,
                    "lms-sha256-h20-w1" if version >= 3 => Kind::LmsSha256H20W1,
                    _ => return Err(invalid("vault entry kind")),
                }
            };
            let signing_public = if version == 1 {
                None
            } else if kind == Kind::Secret || kind == Kind::LmsSha256H20W1 {
                d.null()?;
                None
            } else {
                Some(d.bytes()?.try_into().map_err(|_| invalid("vault signing public key"))?)
            };
            let (lms_public, lms_next_q) = if version < 3 {
                (None, None)
            } else if kind == Kind::LmsSha256H20W1 {
                let public: [u8; super::lms_rfc::PUBLIC_LEN] =
                    d.bytes()?.try_into().map_err(|_| invalid("vault LMS public key"))?;
                if public[..4] != super::lms_rfc::LMS_TYPE.to_be_bytes()
                    || public[4..8] != super::lms_rfc::OTS_TYPE.to_be_bytes()
                {
                    return Err(invalid("vault LMS type"));
                }
                let next_q = d.u32()?;
                if next_q > (1_u32 << super::lms_rfc::HEIGHT) {
                    return Err(invalid("vault LMS next q"));
                }
                (Some(public), Some(next_q))
            } else {
                d.null()?;
                d.null()?;
                (None, None)
            };
            let policy = if version < 4 {
                None
            } else if d.datatype()? == minicbor::data::Type::Null {
                d.null()?;
                None
            } else {
                let bytes = d.bytes()?;
                if !matches!(kind, Kind::SigningEd25519 | Kind::SshEd25519)
                    || AgentPolicy::decode(bytes).is_err()
                    || (kind == Kind::SshEd25519
                        && AgentPolicy::decode(bytes).is_ok_and(|policy| policy.contexts() != ["ssh.keygen"]))
                {
                    return Err(invalid("vault agent policy"));
                }
                Some(bytes.to_vec())
            };
            let remote_creator = if version < 5 {
                None
            } else if d.datatype()? == minicbor::data::Type::Null {
                d.null()?;
                None
            } else {
                let bytes: [u8; 32] = d.bytes()?.try_into().map_err(|_| invalid("vault remote creator"))?;
                Some(crate::ids::NodeId::from_bytes(bytes))
            };
            if remote_creator.is_some() != (kind == Kind::SshEd25519 && policy.is_some()) {
                return Err(invalid("vault remote creator"));
            }
            let entry = Entry {
                kind,
                signing_public,
                lms_public,
                lms_next_q,
                name,
                note,
                stored_at,
                ephemeral,
                nonce,
                ciphertext,
                policy,
                remote_creator,
            };
            let length = entry.ciphertext.len();
            if validate_name(&entry.name).is_err()
                || validate_note(&entry.note).is_err()
                || !(TAG_BYTES + 1..=TAG_BYTES + MAX_SECRET_BYTES).contains(&length)
                || (kind != Kind::Secret && length != TAG_BYTES + if kind == Kind::LmsSha256H20W1 { 48 } else { 32 })
                || entries.last().is_some_and(|last: &Entry| last.name >= entry.name)
            {
                return Err(invalid("vault entry"));
            }
            entries.push(entry);
        }
        Ok(Document {
            version,
            key,
            public,
            entries,
        })
    };
    let document = parse().map_err(|_| VaultError::Corrupt)?;
    if encode(&document)?.as_slice() != bytes {
        return Err(VaultError::Corrupt);
    }
    Ok(document)
}
