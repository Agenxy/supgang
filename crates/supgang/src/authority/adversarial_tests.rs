//! Additional state, decode and scope boundaries beyond the named ADR vectors.

use super::{tests::*, *};
use crate::device_key::FileDeviceKey;

#[test]
fn possession_mutations_and_noncanonical_bytes_are_rejected() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let c = certificate(&key, ID)?;
    let mut bytes = c.encode()?;
    bytes.push(0);
    assert!(CertifiedKey::decode(&bytes).is_err());
    let mut bytes = c.encode()?;
    // Array header followed by schema version: encode 1 in a nonminimal form.
    bytes.splice(1..2, [0x18, 1]);
    assert!(matches!(
        CertifiedKey::decode(&bytes),
        Err(AuthorityError::NonCanonical)
    ));
    let mut changed = c.clone();
    changed.claims.policy = 2;
    assert!(matches!(changed.verify_possession(), Err(AuthorityError::Version)));
    let mut changed = c;
    changed.claims.operations = vec!["dial".into()];
    assert!(matches!(changed.verify_possession(), Err(AuthorityError::Possession)));
    Ok(())
}

#[test]
fn certificate_lifetimes_operation_sets_and_key_encodings_are_bounded() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut fields = claims(&key, ID);
    fields.not_after = fields.not_before + MAX_CERTIFICATE_LIFETIME;
    fields.validate()?;
    fields.not_after += 1;
    assert!(fields.validate().is_err());
    let mut fields = claims(&key, ID);
    fields.operations = vec!["dial".into(), "dial".into()];
    assert!(fields.validate().is_err());
    fields.operations = vec!["z".repeat(65)];
    assert!(fields.validate().is_err());
    fields.operations = (0..17).map(|i| format!("{i:02}")).collect();
    assert!(fields.validate().is_err());
    let mut fields = claims(&key, ID);
    fields.subject = SubjectKey::Ed25519([0; 32]);
    assert!(fields.validate().is_err());
    Ok(())
}

#[test]
fn transport_client_cannot_name_another_hive_and_server_hostname_is_exact() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut fields = claims(&key, ID);
    fields.purpose = Purpose::TransportClient;
    fields.audience = Audience::TransportClient {
        hive: HiveId::from_bytes([8; 32]),
        node: None,
    };
    assert!(matches!(fields.validate(), Err(AuthorityError::Issuer)));
    fields.purpose = Purpose::TransportServer;
    fields.operations = vec!["serve-tls".into()];
    fields.audience = Audience::TransportServer {
        name: ServiceName::new("compass")?,
        instance: INSTANCE,
        hostname: "one.test.gang".into(),
    };
    let certificate = CertifiedKey::prove_p256(fields, &key)?;
    let other = Audience::TransportServer {
        name: ServiceName::new("compass")?,
        instance: INSTANCE,
        hostname: "two.test.gang".into(),
    };
    assert!(
        certificate
            .authorize(Purpose::TransportServer, &other, "serve-tls")
            .is_err()
    );
    Ok(())
}

#[test]
fn omission_is_not_revocation_and_changed_content_cannot_reuse_an_id() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let mut content = first.content.clone();
    content.revision = 2;
    content.certificates.clear();
    let mut v = AuthorityVerifier::new(hive());
    v.accept(first.clone(), key.public_key(), NOW)?;
    v.accept(signed(&key, content)?, key.public_key(), NOW)?;
    v.certificate(ID, Purpose::Attest, NOW, 1000)?;
    let mut content = first.content;
    content.revision = 3;
    let mut fields = claims(&key, ID);
    fields.not_after += 1;
    content.certificates = vec![CertifiedKey::prove_p256(fields, &key)?];
    assert!(matches!(
        v.accept(signed(&key, content)?, key.public_key(), NOW),
        Err(AuthorityError::ReusedId)
    ));
    v.certificate(ID, Purpose::Attest, NOW, 1000)?;
    Ok(())
}

#[test]
fn invalid_signature_does_not_create_equivocation_or_advance_watermark() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let wrong = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let mut bad = first.clone();
    bad.content.next_update += 1;
    bad.signature = wrong.sign_domain(AUTHORITY_DOMAIN, &codec::content_bytes(&bad.content)?)?;
    let mut v = AuthorityVerifier::new(hive());
    v.accept(first, key.public_key(), NOW)?;
    assert!(v.accept(bad, key.public_key(), NOW).is_err());
    v.certificate(ID, Purpose::Attest, NOW, 1000)?;
    Ok(())
}

#[test]
fn store_excludes_concurrent_writers_and_rejects_stale_predecessors() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("authority");
    let mut store = FileRevisionStore::open(&path, hive(), key.public_key())?;
    assert!(FileRevisionStore::open(&path, hive(), key.public_key()).is_err());
    let first = AuthorityUpdate::default().apply(None, hive(), &key, &mut store, NOW, NOW + 1000)?;
    assert!(matches!(
        AuthorityUpdate::default().apply(None, hive(), &key, &mut store, NOW, NOW + 1000),
        Err(AuthorityError::StoreConflict)
    ));
    let second = AuthorityUpdate::default().apply(Some(&first), hive(), &key, &mut store, NOW, NOW + 1000)?;
    assert_eq!(second.content.revision, 2);
    assert!(matches!(
        AuthorityUpdate::default().apply(Some(&first), hive(), &key, &mut store, NOW, NOW + 1000),
        Err(AuthorityError::StoreConflict)
    ));
    assert!(matches!(store.commit(&second), Err(AuthorityError::StoreConflict)));
    Ok(())
}

#[test]
fn store_commits_only_exactly_reserved_content_and_is_bound_to_issuer() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("authority");
    let mut store = FileRevisionStore::open(&path, hive(), key.public_key())?;
    let mut content = manifest(&key)?.content;
    store.reserve(None, &mut content)?;
    let mut wrong = content.clone();
    wrong.next_update += 1;
    assert!(matches!(
        store.commit(&signed(&key, wrong)?),
        Err(AuthorityError::StoreConflict)
    ));
    store.commit(&signed(&key, content)?)?;
    drop(store);
    assert!(FileRevisionStore::open(&path, HiveId::from_bytes([0; 32]), key.public_key()).is_err());
    assert!(FileRevisionStore::open(&path, hive(), FileDeviceKey::generate()?.public_key()).is_err());
    Ok(())
}

#[test]
fn update_validates_services_and_manifest_deadlines_before_reserving() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let mut store = FileRevisionStore::open(temp.path().join("authority"), hive(), key.public_key())?;
    assert!(
        AuthorityUpdate::default()
            .apply(None, hive(), &key, &mut store, NOW, NOW + MAX_UPDATE_INTERVAL + 1)
            .is_err()
    );
    let update = AuthorityUpdate {
        services: Some(vec![ServiceAdvert {
            name: ServiceName::new("compass")?,
            port: 0,
            key_pin: [0; 32],
        }]),
        ..Default::default()
    };
    assert!(update.apply(None, hive(), &key, &mut store, NOW, NOW + 1000).is_err());
    let first = AuthorityUpdate::default().apply(None, hive(), &key, &mut store, NOW, NOW + 1000)?;
    assert_eq!(first.content.revision, 1);
    Ok(())
}

#[test]
fn revocation_decoder_refuses_65_unsorted_duplicate_and_indefinite_sets() -> TestResult {
    let good = CertifiedKeyRevocations {
        ids: vec![[1; 16], [2; 16]],
    };
    assert_eq!(CertifiedKeyRevocations::decode(&good.encode()?)?, good);
    for ids in [
        vec![[2; 16], [1; 16]],
        vec![[1; 16], [1; 16]],
        (0_u8..65).map(|i| [i; 16]).collect(),
    ] {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2)?.u8(1)?.array(u64::try_from(ids.len())?)?;
        for id in ids {
            e.bytes(&id)?;
        }
        assert!(CertifiedKeyRevocations::decode(&e.into_writer()).is_err());
    }
    assert!(CertifiedKeyRevocations::decode(&[0x82, 1, 0x9f, 0xff]).is_err());
    assert!(CertifiedKeyRevocations::decode(&vec![0; MAX_REVOCATION_BYTES + 1]).is_err());
    assert!(good.extends(&CertifiedKeyRevocations { ids: vec![[3; 16]] }).is_err());
    Ok(())
}

#[test]
fn manifest_decoder_bounds_declared_counts_before_allocation() -> TestResult {
    let mut content = minicbor::Encoder::new(Vec::new());
    content
        .array(8)?
        .u8(1)?
        .u64(0)?
        .u64(1)?
        .u64(NOW)?
        .u64(NOW + 100)?
        .array(u64::MAX)?;
    let key = FileDeviceKey::generate()?;
    let signature = key.sign_domain(AUTHORITY_DOMAIN, &content.clone().into_writer())?;
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)?
        .u8(1)?
        .bytes(&content.into_writer())?
        .bytes(&signature.to_bytes())?;
    assert!(matches!(
        AuthorityManifest::decode(&e.into_writer()),
        Err(AuthorityError::Bound)
    ));
    Ok(())
}

#[test]
fn recovered_reservation_cannot_commit_even_with_a_surviving_signature() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("authority");
    let mut store = FileRevisionStore::open(&path, hive(), key.public_key())?;
    let mut content = manifest(&key)?.content;
    store.reserve(None, &mut content)?;
    let signed_before_crash = signed(&key, content)?;
    drop(store);
    let mut reopened = FileRevisionStore::open(&path, hive(), key.public_key())?;
    assert!(matches!(
        reopened.commit(&signed_before_crash),
        Err(AuthorityError::StoreConflict)
    ));
    let fresh = AuthorityUpdate::default().apply(None, hive(), &key, &mut reopened, NOW, NOW + 1000)?;
    assert_eq!(fresh.content.revision, 2);
    Ok(())
}

#[test]
fn wrong_device_and_subordinate_signatures_cannot_issue_authority() -> TestResult {
    let device = FileDeviceKey::generate()?;
    let subordinate = FileDeviceKey::generate()?;
    let content = manifest(&device)?.content;
    let forged = signed(&subordinate, content)?;
    let mut verifier = AuthorityVerifier::new(hive());
    assert!(verifier.accept(forged, device.public_key(), NOW).is_err());
    assert!(verifier.certificate(ID, Purpose::Attest, NOW, 1000).is_err());
    Ok(())
}

#[test]
fn transport_client_optional_node_means_this_hive_or_exactly_one_peer() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let mut fields = claims(&key, ID);
    fields.purpose = Purpose::TransportClient;
    fields.audience = Audience::TransportClient {
        hive: hive(),
        node: None,
    };
    fields.operations = vec!["dial".into()];
    let all = CertifiedKey::prove_p256(fields.clone(), &key)?;
    let one = Audience::TransportClient {
        hive: hive(),
        node: Some(NodeId::from_bytes([4; 32])),
    };
    all.authorize(Purpose::TransportClient, &one, "dial")?;
    fields.audience = one.clone();
    let restricted = CertifiedKey::prove_p256(fields, &key)?;
    restricted.authorize(Purpose::TransportClient, &one, "dial")?;
    assert!(
        restricted
            .authorize(
                Purpose::TransportClient,
                &Audience::TransportClient {
                    hive: hive(),
                    node: Some(NodeId::from_bytes([5; 32]))
                },
                "dial"
            )
            .is_err()
    );
    assert!(
        all.authorize(
            Purpose::TransportClient,
            &Audience::TransportClient {
                hive: HiveId::from_bytes([5; 32]),
                node: None
            },
            "dial"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn equivocation_retains_the_issuance_watermark_across_epoch_recovery() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let mut other = first.content.clone();
    other.next_update += 1;
    let mut verifier = AuthorityVerifier::new(hive());
    verifier.accept(first, key.public_key(), NOW)?;
    assert!(matches!(
        verifier.accept(signed(&key, other.clone())?, key.public_key(), NOW),
        Err(AuthorityError::Equivocation)
    ));
    other.epoch += 1;
    other.certificates.clear();
    other.issued_at -= 1;
    assert!(matches!(
        verifier.accept(signed(&key, other)?, key.public_key(), NOW),
        Err(AuthorityError::Older)
    ));
    Ok(())
}

#[test]
fn certificate_count_and_epoch_reset_are_validated_before_reservation() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let temp = tempfile::tempdir()?;
    let mut store = FileRevisionStore::open(temp.path().join("authority"), hive(), key.public_key())?;
    let excessive = AuthorityUpdate {
        add: (0_u8..17)
            .map(|i| certificate(&key, [i; 16]))
            .collect::<Result<_, _>>()?,
        ..Default::default()
    };
    assert!(matches!(
        excessive.apply(None, hive(), &key, &mut store, NOW, NOW + 1000),
        Err(AuthorityError::Bound)
    ));
    let ambiguous = AuthorityUpdate {
        advance_epoch: true,
        revoke: vec![ID],
        ..Default::default()
    };
    assert!(
        ambiguous
            .apply(None, hive(), &key, &mut store, NOW, NOW + 1000)
            .is_err()
    );
    let first = AuthorityUpdate::default().apply(None, hive(), &key, &mut store, NOW, NOW + 1000)?;
    assert_eq!(first.content.revision, 1);
    Ok(())
}

#[test]
fn equivocation_cannot_erase_ids_revoked_only_in_the_conflicting_record() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let mut conflicting = first.content.clone();
    conflicting.revocations.ids = vec![[8; 16]];
    let mut verifier = AuthorityVerifier::new(hive());
    verifier.accept(first, key.public_key(), NOW)?;
    assert!(matches!(
        verifier.accept(signed(&key, conflicting.clone())?, key.public_key(), NOW),
        Err(AuthorityError::Equivocation)
    ));
    conflicting.epoch = 1;
    conflicting.revocations.ids.clear();
    let mut fields = claims(&key, [8; 16]);
    fields.epoch = 1;
    conflicting.certificates = vec![CertifiedKey::prove_p256(fields, &key)?];
    assert!(matches!(
        verifier.accept(signed(&key, conflicting)?, key.public_key(), NOW),
        Err(AuthorityError::ReusedId)
    ));
    Ok(())
}

#[test]
fn signed_equivocation_is_not_hidden_by_a_conflicting_future_timestamp() -> TestResult {
    let key = FileDeviceKey::generate()?;
    let first = manifest(&key)?;
    let mut conflicting = first.content.clone();
    conflicting.issued_at = NOW + 360;
    let mut verifier = AuthorityVerifier::new(hive());
    verifier.accept(first, key.public_key(), NOW)?;
    assert!(matches!(
        verifier.accept(signed(&key, conflicting)?, key.public_key(), NOW),
        Err(AuthorityError::Equivocation)
    ));
    assert!(verifier.certificate(ID, Purpose::Attest, NOW, 1000).is_err());
    Ok(())
}
