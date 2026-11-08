//! Core vectors, using isolated file-held identities only.

use super::*;
use crate::device_key::FileDeviceKey;

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
pub(super) const NOW: u64 = 1_000_000;
pub(super) const ID: CertificateId = [1; 16];
pub(super) const INSTANCE: CertificateId = [9; 16];

pub(super) fn hive() -> HiveId {
    HiveId::from_bytes([3; 32])
}

pub(super) fn claims(key: &FileDeviceKey, id: CertificateId) -> CertifiedKeyClaims {
    CertifiedKeyClaims {
        hive: hive(),
        issuer: device_node_id(key.public_key()),
        epoch: 0,
        id,
        subject: SubjectKey::P256(key.public_key()),
        custody: SubjectCustody::File,
        purpose: Purpose::Attest,
        audience: Audience::Attest { instance: INSTANCE },
        operations: vec!["sign-enrollment".to_owned()],
        not_before: NOW,
        not_after: NOW + 1000,
        policy: 1,
    }
}

pub(super) fn certificate(key: &FileDeviceKey, id: CertificateId) -> Result<CertifiedKey, AuthorityError> {
    CertifiedKey::prove_p256(claims(key, id), key)
}

pub(super) fn signed(key: &FileDeviceKey, content: AuthorityContent) -> Result<AuthorityManifest, AuthorityError> {
    let signature = key.sign_domain(AUTHORITY_DOMAIN, &codec::content_bytes(&content)?)?;
    Ok(AuthorityManifest { content, signature })
}

pub(super) fn manifest(key: &FileDeviceKey) -> Result<AuthorityManifest, AuthorityError> {
    signed(
        key,
        AuthorityContent {
            epoch: 0,
            revision: 1,
            issued_at: NOW,
            next_update: NOW + 1000,
            certificates: vec![certificate(key, ID)?],
            revocations: CertifiedKeyRevocations::default(),
            services: Vec::new(),
        },
    )
}

#[test]
fn canonical_certificates_round_trip_every_purpose_and_subject_algorithm() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let ed = SigningKey::from_bytes(&[7; 32]);
    let audiences = [
        Audience::Publish,
        Audience::Service {
            name: ServiceName::new("compass")?,
            instance: INSTANCE,
        },
        Audience::TransportServer {
            name: ServiceName::new("compass")?,
            instance: INSTANCE,
            hostname: "compass.test.gang".into(),
        },
        Audience::TransportClient {
            hive: hive(),
            node: None,
        },
        Audience::TransportClient {
            hive: hive(),
            node: Some(device_node_id(key.public_key())),
        },
        Audience::Attest { instance: INSTANCE },
    ];
    for audience in audiences {
        let mut c = claims(&key, ID);
        c.purpose = audience.purpose();
        c.audience = audience;
        let p256 = CertifiedKey::prove_p256(c.clone(), &key)?;
        assert_eq!(CertifiedKey::decode(&p256.encode()?)?, p256);
        c.subject = SubjectKey::Ed25519(ed.verifying_key().to_bytes());
        c.custody = SubjectCustody::Synced;
        let ed25519 = CertifiedKey::prove_ed25519(c, &ed)?;
        assert_eq!(CertifiedKey::decode(&ed25519.encode()?)?, ed25519);
    }
    let m = manifest(&key)?;
    assert_eq!(AuthorityManifest::decode(&m.encode()?)?, m);
    Ok(())
}

#[test]
fn cross_hive_certificate_is_refused() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut c = claims(&key, ID);
    c.hive = HiveId::from_bytes([4; 32]);
    let mut content = manifest(&key)?.content;
    content.certificates = vec![CertifiedKey::prove_p256(c, &key)?];
    let mut verifier = AuthorityVerifier::new(hive());
    assert!(matches!(
        verifier.accept(signed(&key, content)?, key.public_key(), NOW),
        Err(AuthorityError::Issuer)
    ));
    Ok(())
}

#[test]
fn cross_instance_audience_is_refused() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let c = certificate(&key, ID)?;
    assert!(matches!(
        c.authorize(
            Purpose::Attest,
            &Audience::Attest { instance: [8; 16] },
            "sign-enrollment"
        ),
        Err(AuthorityError::Scope)
    ));
    c.authorize(Purpose::Attest, &c.claims.audience, "sign-enrollment")?;
    Ok(())
}

#[test]
fn wrong_purpose_and_unlisted_operation_are_refused() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let c = certificate(&key, ID)?;
    assert!(matches!(
        c.authorize(Purpose::Publish, &c.claims.audience, "sign-enrollment"),
        Err(AuthorityError::Scope)
    ));
    assert!(matches!(
        c.authorize(Purpose::Attest, &c.claims.audience, "serve-tls"),
        Err(AuthorityError::Scope)
    ));
    let mut v = AuthorityVerifier::new(hive());
    v.accept(manifest(&key)?, key.public_key(), NOW)?;
    assert!(v.certificate(ID, Purpose::Publish, NOW, 1000).is_err());
    Ok(())
}

#[test]
fn unknown_purpose_is_refused_at_decode() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut bytes = certificate(&key, ID)?.encode()?;
    let offset = bytes.windows(6).position(|w| w == b"attest").ok_or("purpose absent")?;
    bytes
        .get_mut(offset..offset + 6)
        .ok_or("purpose range absent")?
        .copy_from_slice(b"custom");
    assert!(matches!(
        CertifiedKey::decode(&bytes),
        Err(AuthorityError::UnknownPurpose)
    ));
    Ok(())
}

#[test]
fn incompatible_audience_is_refused_at_decode() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut bytes = certificate(&key, ID)?.encode()?;
    let offset = bytes
        .windows(6)
        .rposition(|w| w == b"attest")
        .ok_or("audience absent")?;
    // Replace tagged audience with a valid, different purpose schema. The
    // decoder must reject the mismatch before considering the possession proof.
    let start = offset.checked_sub(2).ok_or("audience start")?;
    let end = offset + 6 + 17;
    bytes.splice(start..end, [0x81, 0x67, b'p', b'u', b'b', b'l', b'i', b's', b'h']);
    assert!(matches!(CertifiedKey::decode(&bytes), Err(AuthorityError::Scope)));
    Ok(())
}

#[test]
fn replayed_possession_on_another_id_is_refused_for_both_algorithms() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut c = certificate(&key, ID)?;
    c.claims.id = [2; 16];
    assert!(matches!(c.verify_possession(), Err(AuthorityError::Possession)));
    let ed = SigningKey::from_bytes(&[7; 32]);
    let mut fields = claims(&key, ID);
    fields.subject = SubjectKey::Ed25519(ed.verifying_key().to_bytes());
    let mut c = CertifiedKey::prove_ed25519(fields, &ed)?;
    c.claims.id = [2; 16];
    assert!(matches!(c.verify_possession(), Err(AuthorityError::Possession)));
    Ok(())
}

#[test]
fn expired_certificate_is_decodable_but_not_usable() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut fields = claims(&key, ID);
    fields.not_after = NOW + 10;
    let mut content = manifest(&key)?.content;
    content.certificates = vec![CertifiedKey::prove_p256(fields, &key)?];
    let m = signed(&key, content)?;
    let mut v = AuthorityVerifier::new(hive());
    v.accept(AuthorityManifest::decode(&m.encode()?)?, key.public_key(), NOW + 11)?;
    assert!(v.certificate(ID, Purpose::Attest, NOW + 11, 1000).is_err());
    Ok(())
}

#[test]
fn revoked_then_represented_certificate_is_refused() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let original = manifest(&key)?;
    let mut content = original.content.clone();
    content.revision = 2;
    content.certificates.clear();
    content.revocations.ids = vec![ID];
    let mut v = AuthorityVerifier::new(hive());
    v.accept(original.clone(), key.public_key(), NOW)?;
    v.accept(signed(&key, content)?, key.public_key(), NOW)?;
    assert!(v.certificate(ID, Purpose::Attest, NOW, 1000).is_err());
    assert!(matches!(
        v.accept(original.clone(), key.public_key(), NOW),
        Err(AuthorityError::Older)
    ));
    let mut replay = original.content;
    replay.revision = 3;
    assert!(matches!(
        v.accept(signed(&key, replay)?, key.public_key(), NOW),
        Err(AuthorityError::RevocationRollback)
    ));
    Ok(())
}

#[test]
fn revoked_id_cannot_be_recertified_by_an_update() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let mut store = FileRevisionStore::open(temp.path().join("authority"), hive(), key.public_key())?;
    let first = AuthorityUpdate {
        add: vec![certificate(&key, ID)?],
        ..Default::default()
    }
    .apply(None, hive(), &key, &mut store, NOW, NOW + 1000)?;
    let revoked = AuthorityUpdate {
        revoke: vec![ID],
        ..Default::default()
    }
    .apply(Some(&first), hive(), &key, &mut store, NOW, NOW + 1000)?;
    let retry = AuthorityUpdate {
        add: vec![certificate(&key, ID)?],
        ..Default::default()
    }
    .apply(Some(&revoked), hive(), &key, &mut store, NOW, NOW + 1000);
    assert!(matches!(retry, Err(AuthorityError::ReusedId)));
    Ok(())
}

#[test]
fn id_reused_is_refused_even_for_an_identical_certificate() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let mut store = FileRevisionStore::open(temp.path().join("authority"), hive(), key.public_key())?;
    let update = AuthorityUpdate {
        add: vec![certificate(&key, ID)?],
        ..Default::default()
    };
    let first = update.apply(None, hive(), &key, &mut store, NOW, NOW + 1000)?;
    assert!(matches!(
        update.apply(Some(&first), hive(), &key, &mut store, NOW, NOW + 1000),
        Err(AuthorityError::ReusedId)
    ));
    Ok(())
}

#[test]
fn older_epoch_is_refused_and_advance_clears_prior_authority() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let mut store = FileRevisionStore::open(temp.path().join("authority"), hive(), key.public_key())?;
    let first = AuthorityUpdate {
        add: vec![certificate(&key, ID)?],
        revoke: vec![[7; 16]],
        ..Default::default()
    }
    .apply(None, hive(), &key, &mut store, NOW, NOW + 1000)?;
    let next = AuthorityUpdate {
        advance_epoch: true,
        ..Default::default()
    }
    .apply(Some(&first), hive(), &key, &mut store, NOW, NOW + 1000)?;
    assert_eq!(next.content.epoch, 1);
    assert!(next.content.certificates.is_empty(), "{:?}", next.content.certificates);
    assert!(
        next.content.revocations.ids.is_empty(),
        "{:?}",
        next.content.revocations.ids
    );
    let mut v = AuthorityVerifier::new(hive());
    v.accept(first.clone(), key.public_key(), NOW)?;
    v.accept(next.clone(), key.public_key(), NOW)?;
    assert!(matches!(
        v.accept(first, key.public_key(), NOW),
        Err(AuthorityError::Older)
    ));
    assert!(v.certificate(ID, Purpose::Attest, NOW, 1000).is_err());
    let mut c = claims(&key, ID);
    c.epoch = 1;
    assert!(matches!(
        AuthorityUpdate {
            add: vec![CertifiedKey::prove_p256(c, &key)?],
            ..Default::default()
        }
        .apply(Some(&next), hive(), &key, &mut store, NOW, NOW + 1000),
        Err(AuthorityError::ReusedId)
    ));
    Ok(())
}

#[test]
fn same_revision_different_content_keeps_neither_and_replays_cannot_restore_it() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let mut other = first.content.clone();
    other.next_update += 1;
    let second = signed(&key, other)?;
    let mut v = AuthorityVerifier::new(hive());
    v.accept(first.clone(), key.public_key(), NOW)?;
    assert!(matches!(
        v.accept(second.clone(), key.public_key(), NOW),
        Err(AuthorityError::Equivocation)
    ));
    for m in [first, second] {
        assert!(matches!(
            v.accept(m, key.public_key(), NOW),
            Err(AuthorityError::Equivocation)
        ));
    }
    assert!(v.certificate(ID, Purpose::Attest, NOW, 1000).is_err());
    Ok(())
}

#[test]
fn clock_six_minutes_ahead_is_refused_without_poisoning_state() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let m = manifest(&key)?;
    let mut v = AuthorityVerifier::new(hive());
    assert!(matches!(
        v.accept(m.clone(), key.public_key(), NOW - 360),
        Err(AuthorityError::Future)
    ));
    v.accept(m, key.public_key(), NOW)?;
    v.certificate(ID, Purpose::Attest, NOW, 1000)?;
    Ok(())
}

#[test]
fn freshness_is_an_intersection_and_decoding_does_not_renew_it() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut content = manifest(&key)?.content;
    content.next_update = NOW + 100;
    let bytes = signed(&key, content)?.encode()?;
    let mut v = AuthorityVerifier::new(hive());
    v.accept(AuthorityManifest::decode(&bytes)?, key.public_key(), NOW + 200)?;
    assert!(v.certificate(ID, Purpose::Attest, NOW + 200, 50).is_err());
    // Each deadline independently stops use, and inclusive boundaries pass.
    assert!(v.certificate(ID, Purpose::Attest, NOW + 101, 1000).is_err());
    assert!(v.certificate(ID, Purpose::Attest, NOW + 51, 50).is_err());
    v.certificate(ID, Purpose::Attest, NOW + 100, 100)?;
    v.accept(AuthorityManifest::decode(&bytes)?, key.public_key(), NOW + 201)?;
    assert!(v.certificate(ID, Purpose::Attest, NOW + 201, 50).is_err());
    Ok(())
}

#[test]
fn clock_rollback_past_latest_issuance_refuses_until_clock_recovers() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut v = AuthorityVerifier::new(hive());
    v.accept(manifest(&key)?, key.public_key(), NOW)?;
    assert!(v.certificate(ID, Purpose::Attest, NOW - 1, 1000).is_err());
    v.certificate(ID, Purpose::Attest, NOW, 1000)?;
    Ok(())
}

#[test]
fn sixty_five_revocations_are_refused_before_reserving() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let mut store = FileRevisionStore::open(temp.path().join("authority"), hive(), key.public_key())?;
    let ids = (0_u8..65).map(|i| [i; 16]).collect();
    let update = AuthorityUpdate {
        revoke: ids,
        ..Default::default()
    };
    assert!(matches!(
        update.apply(None, hive(), &key, &mut store, NOW, NOW + 1000),
        Err(AuthorityError::Bound)
    ));
    assert!(store.current().is_none());
    Ok(())
}

#[test]
fn encoded_manifest_above_eight_kib_is_refused() -> TestResult {
    assert!(matches!(
        AuthorityManifest::decode(&vec![0; MAX_MANIFEST_BYTES + 1]),
        Err(AuthorityError::Bound)
    ));
    let key = FileDeviceKey::generate()?;
    let mut content = manifest(&key)?.content;
    content.certificates.clear();
    for i in 0_u8..16 {
        let mut fields = claims(&key, [i; 16]);
        fields.operations = (0..16).map(|n| format!("{n:02}{}", "a".repeat(62))).collect();
        content.certificates.push(CertifiedKey::prove_p256(fields, &key)?);
    }
    assert!(matches!(signed(&key, content)?.encode(), Err(AuthorityError::Bound)));
    Ok(())
}

#[test]
fn reserve_without_commit_burns_revision_across_reopen() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("authority");
    let mut store = FileRevisionStore::open(&path, hive(), key.public_key())?;
    let mut pending = manifest(&key)?.content;
    pending.certificates.clear();
    store.reserve(None, &mut pending)?;
    assert_eq!(pending.revision, 1);
    drop(store);
    let mut reopened = FileRevisionStore::open(&path, hive(), key.public_key())?;
    assert!(reopened.current().is_none());
    let committed = AuthorityUpdate::default().apply(None, hive(), &key, &mut reopened, NOW, NOW + 1000)?;
    assert_eq!(committed.content.revision, 2);
    drop(reopened);
    let recovered = FileRevisionStore::open(&path, hive(), key.public_key())?;
    assert_eq!(recovered.current(), Some(&committed));
    Ok(())
}

#[test]
fn different_valid_signature_bytes_are_one_content_record() -> TestResult {
    use p256::ecdsa::signature::RandomizedSigner as _;
    let key = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let signing = p256::ecdsa::SigningKey::from_slice(&key.secret_bytes())?;
    let mut payload = AUTHORITY_DOMAIN.to_vec();
    payload.extend_from_slice(&codec::content_bytes(&first.content)?);
    let alternative: p256::ecdsa::Signature = signing.try_sign_with_rng(&mut OsRandom, &payload)?;
    let bytes: [u8; 64] = alternative.normalize_s().to_bytes().into();
    let second = AuthorityManifest {
        content: first.content.clone(),
        signature: DeviceSignature::from_bytes(&bytes)?,
    };
    assert_ne!(first.signature, second.signature);
    first.verify(hive(), key.public_key())?;
    second.verify(hive(), key.public_key())?;
    assert_eq!(first, second);
    let mut v = AuthorityVerifier::new(hive());
    v.accept(first, key.public_key(), NOW)?;
    v.accept(second, key.public_key(), NOW)?;
    v.certificate(ID, Purpose::Attest, NOW, 1000)?;
    Ok(())
}

struct OsRandom;
impl p256::elliptic_curve::rand_core::TryRng for OsRandom {
    type Error = getrandom::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        getrandom::u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        getrandom::u64()
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(bytes)
    }
}
impl p256::elliptic_curve::rand_core::TryCryptoRng for OsRandom {}
