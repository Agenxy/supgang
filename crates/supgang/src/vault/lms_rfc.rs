//! RFC 8554 LMS/LM-OTS primitives. Public vault operations select only H20/W1.
//!
//! The private SEED and I use Appendix A; treehash keeps at most H nodes.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::VaultError;

pub(super) const HEIGHT: u8 = 20;
pub(super) const WIDTH: u8 = 1;
pub(super) const LMS_TYPE: u32 = 8;
pub(super) const OTS_TYPE: u32 = 1;
pub(super) const PUBLIC_LEN: usize = 56;
pub(super) const SIGNATURE_LEN: usize = 9_164;

#[derive(Clone, Copy)]
struct Parameters {
    height: u8,
    width: u8,
    p: u16,
    ls: u8,
    max_chain: u8,
    lms_type: u32,
    ots_type: u32,
}

impl Parameters {
    const fn new(height: u8, width: u8) -> Result<Self, VaultError> {
        let (p, ls, ots_type, max_chain) = match width {
            1 => (265, 7, 1, 1),
            2 => (133, 6, 2, 3),
            4 => (67, 4, 3, 15),
            8 => (34, 0, 4, 255),
            _ => return Err(VaultError::Corrupt),
        };
        let lms_type = match height {
            5 => 5,
            10 => 6,
            15 => 7,
            20 => 8,
            _ => return Err(VaultError::Corrupt),
        };
        Ok(Self {
            height,
            width,
            p,
            ls,
            max_chain,
            lms_type,
            ots_type,
        })
    }

    const fn leaf_count(self) -> u32 {
        1_u32 << self.height
    }

    fn signature_len(self) -> usize {
        4 + 4 + 32 + usize::from(self.p) * 32 + 4 + usize::from(self.height) * 32
    }
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn private_element(seed: &[u8; 32], id: &[u8; 16], q: u32, index: u16) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(digest(&[id, &q.to_be_bytes(), &index.to_be_bytes(), &[0xff], seed]))
}

fn chain(id: &[u8; 16], q: u32, index: u16, start: u8, count: u8, value: &mut [u8; 32]) {
    for j in start..start + count {
        *value = digest(&[id, &q.to_be_bytes(), &index.to_be_bytes(), &[j], value]);
    }
}

fn ots_public(seed: &[u8; 32], id: &[u8; 16], q: u32, params: Parameters) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(id);
    hasher.update(q.to_be_bytes());
    hasher.update([0x80, 0x80]);
    for index in 0..params.p {
        let mut value = private_element(seed, id, q, index);
        chain(id, q, index, 0, params.max_chain, &mut value);
        hasher.update(value.as_ref());
    }
    hasher.finalize().into()
}

fn leaf(seed: &[u8; 32], id: &[u8; 16], q: u32, params: Parameters) -> [u8; 32] {
    let r = params.leaf_count() + q;
    let public = ots_public(seed, id, q, params);
    digest(&[id, &r.to_be_bytes(), &[0x82, 0x82], &public])
}

fn parent(id: &[u8; 16], r: u32, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    digest(&[id, &r.to_be_bytes(), &[0x83, 0x83], left, right])
}

/// Streaming treehash; `target` also collects its authentication path.
pub(super) fn tree(
    seed: &[u8; 32],
    id: &[u8; 16],
    height: u8,
    width: u8,
    target: Option<u32>,
    mut progress: impl FnMut(u32, u32),
) -> Result<([u8; 32], Vec<[u8; 32]>), VaultError> {
    let params = Parameters::new(height, width)?;
    let leaves = params.leaf_count();
    if target.is_some_and(|q| q >= leaves) {
        return Err(VaultError::Corrupt);
    }
    let sibling_nodes: Vec<u32> = target
        .map(|q| (0..height).map(|level| ((leaves + q) >> level) ^ 1).collect())
        .unwrap_or_default();
    let mut path: Vec<Option<[u8; 32]>> = vec![None; sibling_nodes.len()];
    let mut stack: Vec<(u32, [u8; 32])> = Vec::with_capacity(usize::from(height) + 1);
    for q in 0..leaves {
        let mut r = leaves + q;
        let mut value = leaf(seed, id, q, params);
        if let Some(level) = sibling_nodes.iter().position(|candidate| *candidate == r) {
            *path.get_mut(level).ok_or(VaultError::Corrupt)? = Some(value);
        }
        let mut j = q;
        while j & 1 == 1 {
            let (left_r, left) = stack.pop().ok_or(VaultError::Corrupt)?;
            r >>= 1;
            if left_r != 2 * r {
                return Err(VaultError::Corrupt);
            }
            value = parent(id, r, &left, &value);
            if let Some(level) = sibling_nodes.iter().position(|candidate| *candidate == r) {
                *path.get_mut(level).ok_or(VaultError::Corrupt)? = Some(value);
            }
            j >>= 1;
        }
        stack.push((r, value));
        if q & 0x0fff == 0x0fff || q + 1 == leaves {
            progress(q + 1, leaves);
        }
    }
    let (r, root) = stack.pop().ok_or(VaultError::Corrupt)?;
    if r != 1 || !stack.is_empty() {
        return Err(VaultError::Corrupt);
    }
    let path = path
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(VaultError::Corrupt)?;
    Ok((root, path))
}

pub(super) const fn public_key(id: &[u8; 16], root: &[u8; 32]) -> [u8; PUBLIC_LEN] {
    let mut bytes = [0_u8; PUBLIC_LEN];
    let (lms_type, rest) = bytes.split_at_mut(4);
    let (ots_type, rest) = rest.split_at_mut(4);
    let (identifier, root_bytes) = rest.split_at_mut(16);
    lms_type.copy_from_slice(&LMS_TYPE.to_be_bytes());
    ots_type.copy_from_slice(&OTS_TYPE.to_be_bytes());
    identifier.copy_from_slice(id);
    root_bytes.copy_from_slice(root);
    bytes
}

fn coefficient(bytes: &[u8], index: usize, params: Parameters) -> Option<u8> {
    let bit = index.checked_mul(usize::from(params.width))?;
    let shift = 8 - usize::from(params.width) - bit % 8;
    Some((*bytes.get(bit / 8)? >> shift) & params.max_chain)
}

fn checksum(hash: &[u8; 32], params: Parameters) -> Option<[u8; 2]> {
    let mut sum = 0_u16;
    for index in 0..256 / usize::from(params.width) {
        sum += u16::from(params.max_chain) - u16::from(coefficient(hash, index, params)?);
    }
    Some((sum << params.ls).to_be_bytes())
}

/// Sign a message with a caller-supplied randomizer and already-built path.
/// The public command supplies OS-random `C` only after q has been reserved.
pub(super) fn sign_with_path(
    seed: &[u8; 32],
    id: &[u8; 16],
    q: u32,
    message: &[u8],
    randomizer: &[u8; 32],
    path: &[[u8; 32]],
) -> Result<Vec<u8>, VaultError> {
    sign_with_path_params(seed, id, q, message, randomizer, path, Parameters::new(HEIGHT, WIDTH)?)
}

fn sign_with_path_params(
    seed: &[u8; 32],
    id: &[u8; 16],
    q: u32,
    message: &[u8],
    randomizer: &[u8; 32],
    path: &[[u8; 32]],
    params: Parameters,
) -> Result<Vec<u8>, VaultError> {
    if q >= params.leaf_count() || path.len() != usize::from(params.height) {
        return Err(VaultError::Corrupt);
    }
    let hash = digest(&[id, &q.to_be_bytes(), &[0x81, 0x81], randomizer, message]);
    let mut coefficients = [0_u8; 34];
    let (hash_bytes, checksum_bytes) = coefficients.split_at_mut(32);
    hash_bytes.copy_from_slice(&hash);
    checksum_bytes.copy_from_slice(&checksum(&hash, params).ok_or(VaultError::Corrupt)?);
    let mut signature = Vec::with_capacity(params.signature_len());
    signature.extend_from_slice(&q.to_be_bytes());
    signature.extend_from_slice(&params.ots_type.to_be_bytes());
    signature.extend_from_slice(randomizer);
    for index in 0..params.p {
        let count = coefficient(&coefficients, usize::from(index), params).ok_or(VaultError::Corrupt)?;
        let mut value = private_element(seed, id, q, index);
        chain(id, q, index, 0, count, &mut value);
        signature.extend_from_slice(value.as_ref());
    }
    signature.extend_from_slice(&params.lms_type.to_be_bytes());
    for node in path {
        signature.extend_from_slice(node);
    }
    Ok(signature)
}

/// Verify the finished signature against the fixed public root before release.
pub(super) fn verify_fixed(public: &[u8; PUBLIC_LEN], message: &[u8; 32], signature: &[u8]) -> bool {
    Parameters::new(HEIGHT, WIDTH).is_ok_and(|params| verify_with_params(public, message, signature, params))
}

fn verify_with_params(public: &[u8; PUBLIC_LEN], message: &[u8], signature: &[u8], params: Parameters) -> bool {
    verify_candidate(public, message, signature, params).unwrap_or(false)
}

fn verify_candidate(public: &[u8; PUBLIC_LEN], message: &[u8], signature: &[u8], params: Parameters) -> Option<bool> {
    if signature.len() != params.signature_len()
        || public.get(..4)? != params.lms_type.to_be_bytes()
        || public.get(4..8)? != params.ots_type.to_be_bytes()
    {
        return Some(false);
    }
    let id: [u8; 16] = public.get(8..24)?.try_into().ok()?;
    let q = u32::from_be_bytes(signature.get(..4)?.try_into().ok()?);
    if q >= params.leaf_count() || signature.get(4..8)? != params.ots_type.to_be_bytes() {
        return Some(false);
    }
    let randomizer = signature.get(8..40)?;
    let hash = digest(&[&id, &q.to_be_bytes(), &[0x81, 0x81], randomizer, message]);
    let mut coefficients = [0_u8; 34];
    let (hash_bytes, checksum_bytes) = coefficients.split_at_mut(32);
    hash_bytes.copy_from_slice(&hash);
    checksum_bytes.copy_from_slice(&checksum(&hash, params)?);
    let y_end = 40 + usize::from(params.p) * 32;
    let mut hasher = Sha256::new();
    hasher.update(id);
    hasher.update(q.to_be_bytes());
    hasher.update([0x80, 0x80]);
    let (y_chunks, y_tail) = signature.get(40..y_end)?.as_chunks::<32>();
    if !y_tail.is_empty() {
        return Some(false);
    }
    for (index, y) in y_chunks.iter().enumerate() {
        let coefficient = coefficient(&coefficients, index, params)?;
        let mut value = *y;
        chain(
            &id,
            q,
            u16::try_from(index).ok()?,
            coefficient,
            params.max_chain - coefficient,
            &mut value,
        );
        hasher.update(value);
    }
    if signature.get(y_end..y_end + 4)? != params.lms_type.to_be_bytes() {
        return Some(false);
    }
    let key: [u8; 32] = hasher.finalize().into();
    let mut r = params.leaf_count() + q;
    let mut node = digest(&[&id, &r.to_be_bytes(), &[0x82, 0x82], &key]);
    let (path, path_tail) = signature.get(y_end + 4..)?.as_chunks::<32>();
    if !path_tail.is_empty() || path.len() != usize::from(params.height) {
        return Some(false);
    }
    for sibling in path {
        let sibling = *sibling;
        let child_is_left = r & 1 == 0;
        r >>= 1;
        node = if child_is_left {
            parent(&id, r, &node, &sibling)
        } else {
            parent(&id, r, &sibling, &node)
        };
    }
    Some(r == 1 && public.get(24..) == Some(node.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8554_appendix_f_case_2_top_level_public_root() -> Result<(), Box<dyn std::error::Error>> {
        let seed_bytes = hex::decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439")?;
        let id_bytes = hex::decode("d08fabd4a2091ff0a8cb4ed834e74534")?;
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| "bad RFC seed")?;
        let id: [u8; 16] = id_bytes.as_slice().try_into().map_err(|_| "bad RFC identifier")?;
        let (root, path) = tree(&seed, &id, 10, 4, Some(3), |_, _| {})?;
        assert_eq!(
            hex::encode(root),
            "32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e"
        );
        assert_eq!(path.len(), 10);
        let randomizer_bytes = hex::decode("3d46bee8660f8f215d3f96408a7a64cf1c4da02b63a55f62c666ef5707a914ce")?;
        let randomizer: [u8; 32] = randomizer_bytes.as_slice().try_into().map_err(|_| "bad RFC C")?;
        // HSS sig[0] authenticates the second-level public key, not the final message.
        let message = hex::decode(concat!(
            "0000000500000004",
            "215f83b7ccb9acbcd08db97b0d04dc2b",
            "a1cd035833e0e90059603f26e07ad2aa",
            "d152338e7a5e5984bcd5f7bb4eba40b7"
        ))?;
        let signature = sign_with_path_params(&seed, &id, 3, &message, &randomizer, &path, Parameters::new(10, 4)?)?;
        assert_eq!(signature.len(), 2_508);
        assert_eq!(
            hex::encode(Sha256::digest(&signature)),
            "7e3c3836d68274c43edaaaac98a51d2109ae7fd05704555636006a38f0b602d4"
        );
        let mut public = public_key(&id, &root);
        public
            .get_mut(..4)
            .ok_or("short public")?
            .copy_from_slice(&6_u32.to_be_bytes());
        public
            .get_mut(4..8)
            .ok_or("short public")?
            .copy_from_slice(&3_u32.to_be_bytes());
        assert!(verify_with_params(
            &public,
            &message,
            &signature,
            Parameters::new(10, 4)?
        ));
        let mut corrupted = signature;
        *corrupted.last_mut().ok_or("empty signature")? ^= 1;
        assert!(!verify_with_params(
            &public,
            &message,
            &corrupted,
            Parameters::new(10, 4)?
        ));
        Ok(())
    }

    #[test]
    fn fixed_public_sizes_and_path_selection() -> Result<(), Box<dyn std::error::Error>> {
        let seed = [7_u8; 32];
        let id = [9_u8; 16];
        let (root, path) = tree(&seed, &id, 5, 1, Some(3), |_, _| {})?;
        assert_eq!(public_key(&id, &root).len(), PUBLIC_LEN);
        assert_eq!(path.len(), 5);
        let signature = sign_with_path_params(&seed, &id, 3, b"test", &[5_u8; 32], &path, Parameters::new(5, 1)?)?;
        assert_eq!(signature.len(), 4 + 4 + 32 + 265 * 32 + 4 + 5 * 32);
        assert_eq!(signature.get(..4), Some(3_u32.to_be_bytes().as_slice()));
        assert_eq!((HEIGHT, WIDTH), (20, 1));
        assert_eq!(SIGNATURE_LEN, 4 + 4 + 32 + 265 * 32 + 4 + 20 * 32);
        Ok(())
    }
}
