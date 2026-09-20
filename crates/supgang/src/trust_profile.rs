//! ADR 0003 browser-anchor profile and isolated Rustls/WebPKI confinement probes.
//!
//! This creates throwaway test identities only. It never installs an anchor or
//! issues production leaves. Results describe this verifier, not macOS, NSS or
//! browsers. DNS subtree constraints permit the apex and descendants. An email
//! SAN without a matching DNS SAN fails server-name verification; an irrelevant
//! email SAN beside an allowed DNS SAN is accepted. Trust-anchor path length is
//! not assumed to constrain intermediate CAs: the harness probes that separately.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DnType, ExtendedKeyUsagePurpose, GeneralSubtree,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, SanType,
};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier as _},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use thiserror::Error;

/// Construction failures; individual leaf rejection is a probe verdict instead.
#[derive(Debug, Error)]
pub enum TrustProfileError {
    /// A hive label must be one lowercase DNS label, 1..=63 bytes.
    #[error("hive label must be one lowercase DNS label")]
    Label,
    /// Certificate generation failed.
    #[error("test certificate generation failed")]
    Certificate(#[from] rcgen::Error),
    /// Root parsing or TLS verification setup failed.
    #[error("test verifier setup failed")]
    Tls(#[from] rustls::Error),
    /// `WebPKI` verifier could not be built.
    #[error("test verifier construction failed")]
    Verifier(#[from] rustls::client::VerifierBuilderError),
    /// A generated ASCII SAN was invalid.
    #[error("invalid test certificate name")]
    Name,
}

/// Separately generated P-256 anchor and signing material for isolated tests.
/// The private key is neither derived from a hive id nor exposed by this type.
pub struct TestTrustAnchor {
    certificate: Certificate,
    params: CertificateParams,
    key: KeyPair,
    suffix: String,
}

impl TestTrustAnchor {
    /// DER certificate with the exact ADR profile.
    #[must_use]
    pub const fn certificate(&self) -> &Certificate {
        &self.certificate
    }
}

/// Builds a throwaway anchor for `<hive-label>.gang` with all three extensions
/// critical: CA true/pathLen 0, keyCertSign only, and DNS/IP name constraints.
///
/// rcgen natively encodes excluded IPv4 /0 and IPv6 /0 subtrees.
///
/// # Errors
/// Refuses an invalid label or certificate/key-generation failure.
pub fn build_trust_anchor(hive_label: &str) -> Result<TestTrustAnchor, TrustProfileError> {
    if hive_label.is_empty()
        || hive_label.len() > 63
        || hive_label.starts_with('-')
        || hive_label.ends_with('-')
        || !hive_label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(TrustProfileError::Label);
    }
    let suffix = format!("{hive_label}.gang");
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Supgang isolated confinement anchor");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(suffix.clone())],
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let certificate = params.self_signed(&key)?;
    Ok(TestTrustAnchor {
        certificate,
        params,
        key,
        suffix,
    })
}

/// One independent server-authentication confinement probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfinementProbe {
    /// Positive control: the permitted DNS apex.
    Allowed,
    /// DNS name outside the permitted suffix.
    ForbiddenDns,
    /// IPv4 SAN, checked as that IPv4 server identity.
    Ipv4,
    /// IPv6 SAN, checked as that IPv6 server identity.
    Ipv6,
    /// Allowed and forbidden DNS names together, checked as the allowed name.
    MixedDns,
    /// An email SAN alone, checked as the allowed DNS server identity.
    EmailOnly,
    /// A CA certificate presented as the server leaf.
    SubordinateCa,
    /// Allowed DNS name plus irrelevant email SAN (ADR positive control).
    AllowedWithEmail,
    /// Child name within the permitted DNS subtree.
    ChildDns,
    /// An allowed leaf issued through a subordinate CA, probing anchor pathLen.
    ThroughSubordinateCa,
    /// Forbidden DNS leaf through the same subordinate profile as the control.
    SubordinateForbiddenDns,
    /// IPv4 leaf through a subordinate CA, verified as that IP identity.
    SubordinateIpv4,
    /// IPv6 leaf through a subordinate CA, verified as that IP identity.
    SubordinateIpv6,
    /// Mixed allowed/forbidden DNS leaf through a subordinate, checked as allowed.
    SubordinateMixedDns,
}

/// Raw Rustls/WebPKI server-auth result, without overriding verifier decisions.
#[derive(Debug)]
pub struct ConfinementVerdict {
    /// The SAN/chain scenario exercised.
    pub probe: ConfinementProbe,
    /// True only when server-auth chain and server name verification succeeded.
    pub accepted: bool,
    /// Exact verifier rejection, absent on success.
    pub rejection: Option<rustls::Error>,
}

/// Builds fourteen isolated throwaway chains and checks them as TLS server identities.
///
/// Includes the seven requested cases plus the ADR's mixed email positive
/// control, a permitted child name and five matched subordinate chains. Reports
/// raw verdicts; it never changes the verifier to manufacture confinement.
///
/// # Errors
/// Fails only if the anchor, leaf construction or verifier setup fails.
pub fn verify_confinement(anchor: &TestTrustAnchor) -> Result<Vec<ConfinementVerdict>, TrustProfileError> {
    let mut roots = RootCertStore::empty();
    roots.add(anchor.certificate.der().clone())?;
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()?;
    let probes = [
        ConfinementProbe::Allowed,
        ConfinementProbe::ForbiddenDns,
        ConfinementProbe::Ipv4,
        ConfinementProbe::Ipv6,
        ConfinementProbe::MixedDns,
        ConfinementProbe::EmailOnly,
        ConfinementProbe::SubordinateCa,
        ConfinementProbe::AllowedWithEmail,
        ConfinementProbe::ChildDns,
        ConfinementProbe::ThroughSubordinateCa,
        ConfinementProbe::SubordinateForbiddenDns,
        ConfinementProbe::SubordinateIpv4,
        ConfinementProbe::SubordinateIpv6,
        ConfinementProbe::SubordinateMixedDns,
    ];
    probes
        .into_iter()
        .map(|probe| {
            let (leaf, intermediates, name) = leaf_for(anchor, probe)?;
            let rejection = verifier
                .verify_server_cert(leaf.der(), &intermediates, &name, &[], UnixTime::now())
                .err();
            Ok(ConfinementVerdict {
                probe,
                accepted: rejection.is_none(),
                rejection,
            })
        })
        .collect()
}

fn dns(name: &str) -> Result<SanType, TrustProfileError> {
    Ok(SanType::DnsName(name.try_into().map_err(|_| TrustProfileError::Name)?))
}

fn email() -> Result<SanType, TrustProfileError> {
    Ok(SanType::Rfc822Name(
        "unused@example.invalid"
            .try_into()
            .map_err(|_| TrustProfileError::Name)?,
    ))
}

type TestChain = (Certificate, Vec<CertificateDer<'static>>, ServerName<'static>);

fn leaf_for(anchor: &TestTrustAnchor, probe: ConfinementProbe) -> Result<TestChain, TrustProfileError> {
    let mut name = anchor.suffix.clone();
    let sans = match probe {
        ConfinementProbe::ForbiddenDns | ConfinementProbe::SubordinateForbiddenDns => {
            "outside.invalid".clone_into(&mut name);
            vec![dns(&name)?]
        }
        ConfinementProbe::Ipv4 | ConfinementProbe::SubordinateIpv4 => {
            "192.0.2.1".clone_into(&mut name);
            vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))]
        }
        ConfinementProbe::Ipv6 | ConfinementProbe::SubordinateIpv6 => {
            "2001:db8::1".clone_into(&mut name);
            vec![SanType::IpAddress(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            )))]
        }
        ConfinementProbe::MixedDns | ConfinementProbe::SubordinateMixedDns => {
            vec![dns(&name)?, dns("outside.invalid")?]
        }
        ConfinementProbe::EmailOnly => vec![email()?],
        ConfinementProbe::AllowedWithEmail => vec![dns(&name)?, email()?],
        ConfinementProbe::ChildDns => {
            name = format!("child.{name}");
            vec![dns(&name)?]
        }
        _ => vec![dns(&name)?],
    };
    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if probe == ConfinementProbe::SubordinateCa {
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    }
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let issuer = Issuer::from_params(&anchor.params, &anchor.key);
    let (leaf, intermediates) = if matches!(
        probe,
        ConfinementProbe::ThroughSubordinateCa
            | ConfinementProbe::SubordinateForbiddenDns
            | ConfinementProbe::SubordinateIpv4
            | ConfinementProbe::SubordinateIpv6
            | ConfinementProbe::SubordinateMixedDns
    ) {
        let mut subordinate = CertificateParams::default();
        subordinate
            .distinguished_name
            .push(DnType::CommonName, "Throwaway subordinate CA");
        subordinate.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        subordinate.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let subkey = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let subcert = subordinate.signed_by(&subkey, &issuer)?;
        (
            params.signed_by(&key, &Issuer::from_params(&subordinate, &subkey))?,
            vec![subcert.der().clone()],
        )
    } else {
        (params.signed_by(&key, &issuer)?, Vec::new())
    };
    Ok((
        leaf,
        intermediates,
        ServerName::try_from(name).map_err(|_| TrustProfileError::Name)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{ConfinementProbe, build_trust_anchor, verify_confinement};

    #[test]
    fn exact_profile_has_critical_constraints_and_native_ip_exclusions() -> Result<(), Box<dyn std::error::Error>> {
        let anchor = build_trust_anchor("test-hive")?;
        let der = anchor.certificate.der().as_ref();
        // DER extension OID + critical TRUE + OCTET STRING payload. These
        // assertions inspect the emitted certificate, not just rcgen parameters.
        let basic = [
            0x06, 3, 0x55, 0x1d, 0x13, 1, 1, 0xff, 4, 8, 0x30, 6, 1, 1, 0xff, 2, 1, 0,
        ];
        let usage = [0x06, 3, 0x55, 0x1d, 0x0f, 1, 1, 0xff, 4, 4, 3, 2, 2, 4];
        let constraints = [0x06, 3, 0x55, 0x1d, 0x1e, 1, 1, 0xff];
        assert!(der.windows(basic.len()).any(|w| w == basic));
        assert!(der.windows(usage.len()).any(|w| w == usage));
        assert!(der.windows(constraints.len()).any(|w| w == constraints));
        let mut ipv4 = vec![0x87, 8];
        ipv4.extend_from_slice(&[0; 8]);
        let mut ipv6 = vec![0x87, 32];
        ipv6.extend_from_slice(&[0; 32]);
        assert!(der.windows(ipv4.len()).any(|w| w == ipv4));
        assert!(der.windows(ipv6.len()).any(|w| w == ipv6));
        assert!(der.windows(b"test-hive.gang".len()).any(|w| w == b"test-hive.gang"));
        Ok(())
    }

    #[test]
    fn only_allowed_leaf_passes_the_seven_requested_probes() -> Result<(), Box<dyn std::error::Error>> {
        let verdicts = verify_confinement(&build_trust_anchor("test-hive")?)?;
        assert_eq!(verdicts.len(), 14);
        for verdict in verdicts.iter().take(7) {
            assert_eq!(
                verdict.accepted,
                verdict.probe == ConfinementProbe::Allowed,
                "{verdict:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn reports_subtree_email_and_anchor_path_length_limits() -> Result<(), Box<dyn std::error::Error>> {
        let verdicts = verify_confinement(&build_trust_anchor("test-hive")?)?;
        for verdict in verdicts.iter().skip(7).take(3) {
            assert!(verdict.accepted, "raw verifier behavior changed: {verdict:?}");
        }
        Ok(())
    }

    #[test]
    fn labels_cannot_inject_a_second_dns_subtree() {
        for label in ["", "a.b", ".gang", "*.gang", "UPPER", "-a", "a-", "127.0.0.1"] {
            assert!(build_trust_anchor(label).is_err());
        }
    }

    #[test]
    fn subordinate_chains_enforce_dns_and_ip_constraints() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let verdicts = verify_confinement(&build_trust_anchor("test-hive")?)?;
        let positive = verdicts
            .iter()
            .find(|v| v.probe == ConfinementProbe::ThroughSubordinateCa)
            .ok_or("missing subordinate positive control")?;
        assert!(positive.accepted, "{positive:?}");
        assert_eq!(verdicts.iter().skip(10).count(), 4);
        for verdict in verdicts.iter().skip(10) {
            writeln!(std::io::stdout().lock(), "{:?}: {:?}", verdict.probe, verdict.rejection)?;
            assert!(!verdict.accepted, "{verdict:?}");
            assert!(verdict.rejection.is_some());
        }
        Ok(())
    }
}
