//! Per-root, presence-gated LMS seed wrapping.

use std::io;

use chacha20poly1305::aead::{Aead, Payload};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::super::{
    Enclave, Entry, NONCE_BYTES, PUBLIC_BYTES, TAG_BYTES, VaultError, cipher, compressed_point, lms_rfc,
    random_secret_key,
};
use crate::device_key::custody::SealedKey;

/// The only copy of an LMS seed is sealed to this per-entry, presence-gated
/// agreement key. The ordinary vault ciphertext holds a one-byte state marker.
#[derive(Clone, Eq, PartialEq)]
pub struct PresenceWrap {
    pub key: SealedKey,
    pub public: [u8; PUBLIC_BYTES],
    pub ephemeral: [u8; PUBLIC_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl PresenceWrap {
    pub fn valid(&self) -> bool {
        self.ciphertext.len() == TAG_BYTES + 48
            && self.key.bytes.len() <= 4096
            && !self.key.bytes.is_empty()
            && compressed_point(&self.public).is_ok()
            && compressed_point(&self.ephemeral).is_ok()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"supgang/lms-presence-wrap/v1\0");
        hash.update([match self.key.kind {
            crate::device_key::custody::CustodyKind::SecureEnclave => 1,
            crate::device_key::custody::CustodyKind::Tpm2 => 2,
            crate::device_key::custody::CustodyKind::SecurityKey => 3,
            crate::device_key::custody::CustodyKind::File => 4,
        }]);
        hash.update(u32::try_from(self.key.bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hash.update(&self.key.bytes);
        hash.update(self.public);
        hash.update(self.ephemeral);
        hash.update(self.nonce);
        hash.update(&self.ciphertext);
        hash.finalize().into()
    }
}

fn presence_aad(
    name: &str,
    note: &str,
    stored_at: u64,
    public: &[u8; lms_rfc::PUBLIC_LEN],
    wrap: &PresenceWrap,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128 + name.len() + note.len());
    aad.extend_from_slice(b"supgang/lms-seed-presence/v1\0");
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(note.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&stored_at.to_be_bytes());
    aad.extend_from_slice(public);
    aad.extend_from_slice(&wrap.public);
    aad.extend_from_slice(&wrap.ephemeral);
    aad
}

pub(super) fn seal_presence(
    enclave: &dyn Enclave,
    name: &str,
    note: &str,
    stored_at: u64,
    public_key: &[u8; lms_rfc::PUBLIC_LEN],
    secret: &[u8; 48],
) -> Result<PresenceWrap, VaultError> {
    let (key, public) = enclave.generate_presence()?;
    let recipient = p256::PublicKey::from_sec1_bytes(&public).map_err(|_| VaultError::Corrupt)?;
    let ephemeral_secret = random_secret_key()?;
    let ephemeral = compressed_point(ephemeral_secret.public_key().to_sec1_point(true).as_bytes())?;
    let shared = p256::ecdh::diffie_hellman(ephemeral_secret.to_nonzero_scalar(), recipient.as_affine());
    let mut raw = Zeroizing::new([0_u8; 32]);
    raw.copy_from_slice(shared.raw_secret_bytes());
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let mut wrap = PresenceWrap {
        key,
        public,
        ephemeral,
        nonce,
        ciphertext: Vec::new(),
    };
    wrap.ciphertext = cipher(&raw, &wrap.ephemeral, &wrap.public, name)?
        .encrypt(
            &wrap.nonce.into(),
            Payload {
                msg: secret,
                aad: &presence_aad(name, note, stored_at, public_key, &wrap),
            },
        )
        .map_err(|_| VaultError::Corrupt)?;
    Ok(wrap)
}

pub(super) fn open_presence(
    enclave: &dyn Enclave,
    entry: &Entry,
    wrap: &PresenceWrap,
    public: &[u8; lms_rfc::PUBLIC_LEN],
    reason: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let shared = enclave.agree_presence(&wrap.key, &wrap.ephemeral, reason)?;
    let secret = cipher(&shared, &wrap.ephemeral, &wrap.public, &entry.name)?
        .decrypt(
            &wrap.nonce.into(),
            Payload {
                msg: &wrap.ciphertext,
                aad: &presence_aad(&entry.name, &entry.note, entry.stored_at, public, wrap),
            },
        )
        .map_err(|_| VaultError::Corrupt)?;
    Ok(Zeroizing::new(secret))
}
