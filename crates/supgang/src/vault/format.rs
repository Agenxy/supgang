//! Canonical, bounded vault document encoding.

use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use super::{
    Document, Entry, Kind, MAX_SECRET_BYTES, MAX_SECRETS, TAG_BYTES, VERSION, VaultError, compressed_point,
    validate_name, validate_note,
};
use crate::device_key::custody::SealedKey;

/// Canonical CBOR v1 stays readable; v2 adds kind and signing public key.
pub(super) fn encode(document: &Document) -> Result<Zeroizing<Vec<u8>>, VaultError> {
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
            e.array(if document.version == 1 { 6 } else { 8 })
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
        if version != 1 && version != VERSION {
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
            if d.array()? != Some(if version == 1 { 6 } else { 8 }) {
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
                    _ => return Err(invalid("vault entry kind")),
                }
            };
            let signing_public = if version == 1 {
                None
            } else if kind == Kind::Secret {
                d.null()?;
                None
            } else {
                Some(d.bytes()?.try_into().map_err(|_| invalid("vault signing public key"))?)
            };
            let entry = Entry {
                kind,
                signing_public,
                name,
                note,
                stored_at,
                ephemeral,
                nonce,
                ciphertext,
            };
            let length = entry.ciphertext.len();
            if validate_name(&entry.name).is_err()
                || validate_note(&entry.note).is_err()
                || !(TAG_BYTES + 1..=TAG_BYTES + MAX_SECRET_BYTES).contains(&length)
                || (kind != Kind::Secret && length != TAG_BYTES + 32)
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
