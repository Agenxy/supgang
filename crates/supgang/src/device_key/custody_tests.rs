use super::{custody::*, *};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn capability_matrix_is_complete_ordered_and_honest_on_each_platform() {
    let matrix = capabilities();
    assert_eq!(
        matrix.iter().map(|c| c.kind).collect::<Vec<_>>(),
        [
            CustodyKind::SecureEnclave,
            CustodyKind::Tpm2,
            CustodyKind::SecurityKey,
            CustodyKind::File
        ]
    );
    assert_eq!(
        matrix
            .iter()
            .find(|c| c.kind == CustodyKind::File)
            .map(|c| c.availability),
        Some(Availability::Ready)
    );
    assert_eq!(
        matrix
            .iter()
            .find(|c| c.kind == CustodyKind::SecurityKey)
            .map(|c| c.availability),
        Some(Availability::NotBuilt)
    );
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        matrix.first().map(|c| c.availability),
        Some(Availability::Unavailable(UnavailableReason::WrongPlatform))
    );
    let tpm = matrix
        .iter()
        .find(|c| c.kind == CustodyKind::Tpm2)
        .map(|c| c.availability);
    assert_eq!(
        tpm,
        Some(if cfg!(target_os = "linux") {
            Availability::NotBuilt
        } else {
            Availability::Unavailable(UnavailableReason::WrongPlatform)
        })
    );
}

#[test]
fn sealed_records_round_trip_and_refuse_noncanonical_truncated_and_foreign_input() -> TestResult {
    for kind in [
        CustodyKind::SecureEnclave,
        CustodyKind::Tpm2,
        CustodyKind::SecurityKey,
        CustodyKind::File,
    ] {
        let record = SealedKey {
            kind,
            bytes: vec![7; 32],
        };
        let encoded = record.encode()?;
        assert_eq!(SealedKey::decode(&encoded)?, record);
        for length in 0..encoded.len() {
            assert!(SealedKey::decode(encoded.get(..length).ok_or("length")?).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(SealedKey::decode(&trailing).is_err());
        let mut noncanonical = vec![0x98, 3];
        noncanonical.extend_from_slice(encoded.get(1..).ok_or("length")?);
        assert!(SealedKey::decode(&noncanonical).is_err());
        if kind != CustodyKind::File {
            assert!(matches!(FileProvider.load(&record), Err(CustodyError::KindMismatch)));
        }
        assert!(!format!("{record:?}").contains("7, 7"));
    }
    for bytes in [vec![], vec![1; 4097]] {
        assert!(
            SealedKey {
                kind: CustodyKind::Tpm2,
                bytes
            }
            .encode()
            .is_err()
        );
    }
    for bytes in [vec![0x83, 2, 0, 0x41, 1], vec![0x83, 1, 4, 0x41, 1]] {
        assert!(SealedKey::decode(&bytes).is_err());
    }
    assert!(
        FileProvider
            .load(&SealedKey {
                kind: CustodyKind::File,
                bytes: vec![7; 31]
            })
            .is_err()
    );
    assert!(matches!(
        FileProvider.generate(PresencePolicy::Required),
        Err(CustodyError::PresenceUnsupported)
    ));
    Ok(())
}

#[test]
fn sealed_file_is_owner_only_nonreplacing_and_restores_the_same_signer() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
    crate::storage::prepare_directory(temp.path())?;
    let signer = FileProvider.generate(PresencePolicy::Unattended)?;
    let sealed = signer.sealed_key()?;
    sealed.write_new(temp.path())?;
    assert!(sealed.write_new(temp.path()).is_err());
    let path = temp.path().join("device-custody.cbor");
    assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    let loaded = FileProvider.load(&SealedKey::read(temp.path())?)?;
    assert_eq!(loaded.public_key(), signer.public_key());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(SealedKey::read(temp.path()).is_err());
    Ok(())
}

#[test]
fn provider_signatures_normalize_high_s_pad_short_integers_and_refuse_malformed_input() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let signed = key.sign_domain(b"supgang/custody-test/v1\0", b"message")?;
    let parsed = Signature::from_slice(&signed.to_bytes())?;
    let (r, s) = parsed.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())?;
    assert!(DeviceSignature::from_bytes(&high.to_bytes()).is_err());
    assert_eq!(signature::from_raw(&high.to_bytes())?, signed);
    assert_eq!(signature::from_der(high.to_der().as_bytes())?, signed);
    assert_eq!(signature::from_raw(&signed.to_bytes())?, signed);
    let short = signature::from_der(&[0x30, 6, 2, 1, 1, 2, 1, 2])?.to_bytes();
    assert_eq!(short.get(31), Some(&1));
    assert_eq!(short.get(63), Some(&2));
    assert!(short.get(..31).ok_or("length")?.iter().all(|b| *b == 0));
    for malformed in [
        vec![],
        vec![0; 64],
        vec![0xff; 64],
        signed.to_bytes().get(..63).ok_or("length")?.to_vec(),
    ] {
        assert!(signature::from_raw(&malformed).is_err());
    }
    for malformed in [
        vec![],
        vec![0x30, 6, 2, 1, 0, 2, 1, 2],
        vec![0x30, 6, 2, 1, 0x80, 2, 1, 2],
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 2],
        vec![0x30, 6, 2, 1, 1, 2, 1],
    ] {
        assert!(signature::from_der(&malformed).is_err());
    }
    Ok(())
}

// A distinct provider and signer: consumers see only their portable trait objects.
struct TestProvider;
struct TestSigner(FileDeviceKey);
impl CustodyProvider for TestProvider {
    fn kind(&self) -> CustodyKind {
        CustodyKind::SecurityKey
    }
    fn availability(&self) -> Availability {
        Availability::Ready
    }
    fn generate(&self, _: PresencePolicy) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        Ok(Box::new(TestSigner(FileDeviceKey::generate()?)))
    }
    fn load(&self, sealed: &SealedKey) -> Result<Box<dyn DeviceSigner>, CustodyError> {
        sealed.require_kind(self.kind())?;
        Ok(Box::new(TestSigner(FileDeviceKey::from_secret_bytes(&sealed.bytes)?)))
    }
}
impl DeviceSigner for TestSigner {
    fn public_key(&self) -> DevicePublicKey {
        self.0.public_key()
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_domain(&self, domain: &'static [u8], message: &[u8]) -> Result<DeviceSignature, DeviceKeyError> {
        self.0.sign_domain(domain, message)
    }
}

#[test]
fn generic_provider_proves_possession_and_threshold_control_on_every_platform() -> TestResult {
    use crate::{
        authority::*,
        ids::HiveId,
        threshold::{
            control_auth::{Challenge, Proof},
            founding,
        },
    };
    let provider: &dyn CustodyProvider = &TestProvider;
    let signer = provider.generate(PresencePolicy::Required)?;
    let peer = provider.generate(PresencePolicy::Required)?;
    let third = provider.generate(PresencePolicy::Required)?;
    let claims = CertifiedKeyClaims {
        hive: HiveId::from_bytes([3; 32]),
        issuer: device_node_id(signer.public_key()),
        epoch: 0,
        id: [1; 16],
        subject: SubjectKey::P256(signer.public_key()),
        custody: SubjectCustody::Hardware,
        purpose: Purpose::Attest,
        audience: Audience::Attest { instance: [9; 16] },
        operations: vec!["sign-enrollment".to_owned()],
        not_before: 100,
        not_after: 200,
        policy: 1,
    };
    let certificate = CertifiedKey::prove_p256(claims, signer.as_ref())?;
    certificate.verify_possession()?;
    let group = founding::run(
        "custody-test",
        founding::Parameters {
            k: 2,
            n: 3,
            accept_single_loss_failure: false,
        },
        8,
        &[signer.public_key(), peer.public_key(), third.public_key()],
        None,
        |_, _| {},
    )?;
    let descriptor = group.descriptor()?;
    let challenge = Challenge {
        hive: HiveId::from_root_verifying_key(&descriptor.public_key),
        descriptor: descriptor.digest()?,
        generation: 8,
        self_node: device_node_id(signer.public_key()),
        peer_node: device_node_id(peer.public_key()),
        challenge: [1; 32],
        channel_binding: [2; 32],
    };
    let proof = Proof::sign(&challenge, signer.as_ref())?;
    proof.verify(&challenge, descriptor)?;
    let mut changed = challenge;
    changed.channel_binding = [3; 32];
    assert!(proof.verify(&changed, descriptor).is_err());
    Ok(())
}
