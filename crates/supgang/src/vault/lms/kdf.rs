//! Normative NC0 product-root HKDF-SHA256 KDF (Labs spec rev 2).
//!
//! Derives the RFC 8554 SEED (32 bytes) and I (16 bytes) from a 256-bit master
//! secret `M` and a fixed product-root role (`primary` or `recovery`).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{LmsPublic, identity};
use crate::vault::{VaultError, lms_rfc};

/// Required byte length of an NC0 product-root master secret `M`.
pub const MASTER_LEN: usize = 32;
/// HKDF output length: 32-byte RFC 8554 SEED followed by 16-byte I.
pub const OKM_LEN: usize = 48;
/// Restore/import block size for LMS `q`: any restore advances to the next unused `2^16` block.
pub const RESTORE_Q_BLOCK: u32 = 1 << 16;

const MAX_Q: u32 = 1 << lms_rfc::HEIGHT;

const KDF_SALT: &[u8] = b"agenxy-nc0-root-kdf-v1";
const PRIMARY_INFO: &[u8] = b"NC0-Q LMS root v1|role=primary|lms=8|lmots=1|levels=1";
const RECOVERY_INFO: &[u8] = b"NC0-Q LMS root v1|role=recovery|lms=8|lmots=1|levels=1";

/// Fixed NC0 product-root role bound into the HKDF info string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRole {
    /// Primary product root (`nc0-product-primary`).
    Primary,
    /// Recovery product root (`nc0-product-recovery`).
    Recovery,
}

impl RootRole {
    /// Parse a canonical lowercase role string (`primary` or `recovery`).
    ///
    /// # Errors
    /// Returns [`VaultError::InvalidLmsRole`] for any other string.
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "primary" => Ok(Self::Primary),
            "recovery" => Ok(Self::Recovery),
            _ => Err(VaultError::InvalidLmsRole),
        }
    }

    /// Canonical role label used in KDF `info` and CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Recovery => "recovery",
        }
    }

    /// Canonical product-root name for this role.
    #[must_use]
    pub const fn root_name(self) -> &'static str {
        match self {
            Self::Primary => "nc0-product-primary",
            Self::Recovery => "nc0-product-recovery",
        }
    }

    /// Normative HKDF `info` bytes with no NUL and no newline.
    #[must_use]
    pub const fn kdf_info(self) -> &'static [u8] {
        match self {
            Self::Primary => PRIMARY_INFO,
            Self::Recovery => RECOVERY_INFO,
        }
    }
}

/// Zeroizing RFC 8554 `SEED` and `I` derived from a 256-bit master secret.
pub(super) struct DerivedSeed {
    seed: Zeroizing<[u8; 32]>,
    id: Zeroizing<[u8; 16]>,
}

impl DerivedSeed {
    pub(super) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub(super) fn id(&self) -> &[u8; 16] {
        &self.id
    }
}

/// Run HKDF-SHA256 (RFC 5869 extract then expand) to produce the 48-byte OKM.
///
/// # Errors
/// Refuses any master length other than 32 bytes.
pub(super) fn derive_okm(master: &[u8], role: RootRole) -> Result<Zeroizing<[u8; OKM_LEN]>, VaultError> {
    if master.len() != MASTER_LEN {
        return Err(VaultError::InvalidLmsMasterLength);
    }
    let mut okm = Zeroizing::new([0_u8; OKM_LEN]);
    Hkdf::<Sha256>::new(Some(KDF_SALT), master)
        .expand(role.kdf_info(), okm.as_mut())
        .map_err(|_| VaultError::Corrupt)?;
    Ok(okm)
}

/// Derive RFC 8554 `SEED = OKM[0..32]` and `I = OKM[32..48]` directly.
///
/// # Errors
/// Refuses any master length other than 32 bytes.
pub(super) fn derive_seed(master: &[u8], role: RootRole) -> Result<DerivedSeed, VaultError> {
    let okm = derive_okm(master, role)?;
    let (seed_slice, id_slice) = okm.split_at(32);
    let mut seed = Zeroizing::new([0_u8; 32]);
    let mut id = Zeroizing::new([0_u8; 16]);
    seed.copy_from_slice(seed_slice);
    id.copy_from_slice(id_slice);
    Ok(DerivedSeed { seed, id })
}

/// Derive the 56-byte RFC 8554 H20/W1 public key and its SHA-256 fingerprint
/// from a 32-byte master secret and role. Never signs.
///
/// # Errors
/// Refuses any master length other than 32 bytes or treehash failure.
pub fn derive_public(master: &[u8], role: RootRole, progress: impl FnMut(u32, u32)) -> Result<LmsPublic, VaultError> {
    let derived = derive_seed(master, role)?;
    let (root, _) = lms_rfc::tree(
        derived.seed(),
        derived.id(),
        lms_rfc::HEIGHT,
        lms_rfc::WIDTH,
        None,
        progress,
    )?;
    Ok(identity(lms_rfc::public_key(derived.id(), &root)))
}

/// Compute the first unused `2^16`-aligned `q` block strictly above `highest_logged_q`.
///
/// Any import or restore of an escrowed LMS root must never restore a prior `q`;
/// it requires the independent release log's highest logged `q` and advances to
/// the start of the next unused `2^16` block, refusing once `q >= 2^20`.
///
/// # Errors
/// Returns [`VaultError::LmsExhausted`] if no unused `2^16` block remains below `2^20`.
pub const fn next_restore_q(highest_logged_q: u32) -> Result<u32, VaultError> {
    if highest_logged_q >= MAX_Q {
        return Err(VaultError::LmsExhausted);
    }
    let next_block = (highest_logged_q / RESTORE_Q_BLOCK) + 1;
    let next_q = next_block.saturating_mul(RESTORE_Q_BLOCK);
    if next_q >= MAX_Q {
        return Err(VaultError::LmsExhausted);
    }
    Ok(next_q)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master() -> [u8; MASTER_LEN] {
        core::array::from_fn(|index| u8::try_from(index).unwrap_or(0))
    }

    #[test]
    fn kdf_constants_match_normative_lengths() {
        assert_eq!(KDF_SALT.len(), 22);
        assert_eq!(RootRole::Primary.kdf_info().len(), 53);
        assert_eq!(RootRole::Recovery.kdf_info().len(), 54);
        assert!(!RootRole::Primary.kdf_info().contains(&0));
        assert!(!RootRole::Primary.kdf_info().contains(&b'\n'));
        assert!(!RootRole::Recovery.kdf_info().contains(&0));
        assert!(!RootRole::Recovery.kdf_info().contains(&b'\n'));
        assert_eq!(RootRole::Primary.root_name(), "nc0-product-primary");
        assert_eq!(RootRole::Recovery.root_name(), "nc0-product-recovery");
    }

    #[test]
    fn kat_primary_okm_t1_and_pub56_sha256() -> Result<(), Box<dyn std::error::Error>> {
        let master = test_master();

        // Labs spec rev 2 KAT for TEST master 000102..1f (second-family check).
        let primary_okm = derive_okm(&master, RootRole::Primary)?;
        assert_eq!(
            hex::encode(primary_okm.as_ref()),
            "46489c0c98db7f1e9ea6397f9f7be802bb06b28582991073a12fee790ab3ea16e9042da9345063a411cffea9be4b6e0b"
        );
        let primary_public = derive_public(&master, RootRole::Primary, |_, _| {})?;
        assert_eq!(primary_public.public_key.get(..8), Some(&[0, 0, 0, 8, 0, 0, 0, 1][..]));
        assert_eq!(primary_public.public_key.get(8..24), primary_okm.get(32..48));
        assert_eq!(
            hex::encode(primary_public.public_key.get(24..56).ok_or("short pub56")?),
            "b8547249f0f57763fbe1db67565b1d65c387ba95e5b902f1ae32e74dd453d57e"
        );
        assert_eq!(
            primary_public.fingerprint,
            "e150742e94bff4a7ae2c6b41e8367c19162127e166a76cc3e4985984cd202932"
        );
        Ok(())
    }

    #[test]
    fn kat_recovery_okm_t1_and_pub56_sha256() -> Result<(), Box<dyn std::error::Error>> {
        let master = test_master();

        // Labs spec rev 2 KAT for TEST master 000102..1f (second-family check).
        let recovery_okm = derive_okm(&master, RootRole::Recovery)?;
        assert_eq!(
            hex::encode(recovery_okm.as_ref()),
            "748c9808af52a1c99b2397f74c7cf6456f85e2b20f3e82b5e96d7348dc25901657f644285f666d1cca75c9726a84d5d4"
        );
        let recovery_public = derive_public(&master, RootRole::Recovery, |_, _| {})?;
        assert_eq!(recovery_public.public_key.get(..8), Some(&[0, 0, 0, 8, 0, 0, 0, 1][..]));
        assert_eq!(recovery_public.public_key.get(8..24), recovery_okm.get(32..48));
        assert_eq!(
            hex::encode(recovery_public.public_key.get(24..56).ok_or("short pub56")?),
            "a67c41713d9e1ca9f2ff8b21ee788d96bda1f03234d72141af3e92ddedb9b465"
        );
        assert_eq!(
            recovery_public.fingerprint,
            "dda58b9612c73e99e50f64285587817f8ee2e445000534782188029d2859d3ab"
        );
        Ok(())
    }

    #[test]
    fn must_fail_bit_flip_role_change_and_wrong_master_length() -> Result<(), Box<dyn std::error::Error>> {
        let master = test_master();
        let baseline_okm = derive_okm(&master, RootRole::Primary)?;
        let baseline_seed = derive_seed(&master, RootRole::Primary)?;
        let (baseline_h5_root, _) = lms_rfc::tree(baseline_seed.seed(), baseline_seed.id(), 5, 1, None, |_, _| {})?;
        let baseline_h5_pub = lms_rfc::public_key(baseline_seed.id(), &baseline_h5_root);

        // Flipping one bit of M changes the OKM and the derived public key.
        let mut flipped = master;
        *flipped.first_mut().ok_or("empty master")? ^= 0x01;
        let flipped_okm = derive_okm(&flipped, RootRole::Primary)?;
        assert_ne!(flipped_okm.as_ref(), baseline_okm.as_ref());
        let flipped_seed = derive_seed(&flipped, RootRole::Primary)?;
        let (flipped_h5_root, _) = lms_rfc::tree(flipped_seed.seed(), flipped_seed.id(), 5, 1, None, |_, _| {})?;
        assert_ne!(
            lms_rfc::public_key(flipped_seed.id(), &flipped_h5_root),
            baseline_h5_pub
        );

        let mut flipped_last = master;
        *flipped_last.last_mut().ok_or("empty master")? ^= 0x80;
        assert_ne!(
            derive_okm(&flipped_last, RootRole::Primary)?.as_ref(),
            baseline_okm.as_ref()
        );

        // Changing role changes the OKM.
        assert_ne!(derive_okm(&master, RootRole::Recovery)?.as_ref(), baseline_okm.as_ref());

        // Any master length other than 32 is refused.
        for bad_len in [0_usize, 1, 16, 31, 33, 48, 64] {
            let short_or_long = vec![0x42_u8; bad_len];
            assert!(matches!(
                derive_okm(&short_or_long, RootRole::Primary),
                Err(VaultError::InvalidLmsMasterLength)
            ));
            assert!(matches!(
                derive_public(&short_or_long, RootRole::Recovery, |_, _| {}),
                Err(VaultError::InvalidLmsMasterLength)
            ));
        }

        // Invalid roles are refused.
        for bad_role in [
            "",
            "PRIMARY",
            "Recovery",
            "primary\n",
            "primary ",
            "nc0-product-primary",
            "test",
        ] {
            assert!(matches!(RootRole::parse(bad_role), Err(VaultError::InvalidLmsRole)));
        }
        assert_eq!(RootRole::parse("primary")?, RootRole::Primary);
        assert_eq!(RootRole::parse("recovery")?, RootRole::Recovery);
        Ok(())
    }
}
