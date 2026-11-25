use proptest::prelude::*;

use super::{
    MAX_LOGGED_VERSIONS, MAX_RELEASE_FRAME_BYTES, MAX_RELEASE_VERSION_BYTES, PeerReleaseObservation, ReleaseComparison,
    ReleaseError, ReleaseIdentity, ReleaseNoticeLog, UNKNOWN_COMMIT, compare_release, compute_update_notice,
    decode_frame, encode_frame, normalize_commit, short_commit,
};
use crate::ids::NodeId;

fn commit_a() -> String {
    "a".repeat(40)
}

fn commit_b() -> String {
    "b".repeat(40)
}

fn commit_c() -> String {
    "c".repeat(40)
}

#[test]
fn local_identity_embeds_valid_version_and_commit_or_unknown() {
    let local = ReleaseIdentity::local();
    assert_eq!(local.version(), crate::VERSION);
    assert!(local.semver().is_some());
    assert!(local.commit().is_some() || local.commit_str() == UNKNOWN_COMMIT);
    assert!(crate::VERSION_DISPLAY.starts_with(crate::VERSION));
    assert!(crate::VERSION_DISPLAY.contains(local.short_commit()));
}

#[test]
fn semver_comparison_handles_prerelease_precedence_and_build_metadata() -> Result<(), ReleaseError> {
    let alpha21 = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let alpha22 = ReleaseIdentity::new("0.2.0-alpha.22", Some(commit_a()))?;
    let alpha100 = ReleaseIdentity::new("0.2.0-alpha.100", Some(commit_a()))?;
    let beta1 = ReleaseIdentity::new("0.2.0-beta.1", Some(commit_a()))?;
    let release = ReleaseIdentity::new("0.2.0", Some(commit_a()))?;
    let next_patch = ReleaseIdentity::new("0.2.1", Some(commit_a()))?;
    let with_meta_same_commit = ReleaseIdentity::new("0.2.0-alpha.21+build.1", Some(commit_a()))?;
    let with_meta_diff_commit = ReleaseIdentity::new("0.2.0-alpha.21+build.2", Some(commit_b()))?;

    // Numeric prerelease ordering (22 < 100, not lexical).
    assert_eq!(compare_release(&alpha21, &alpha22), ReleaseComparison::PeerNewer);
    assert_eq!(compare_release(&alpha22, &alpha100), ReleaseComparison::PeerNewer);
    // Identifier ordering (alpha < beta < stable release < next patch).
    assert_eq!(compare_release(&alpha100, &beta1), ReleaseComparison::PeerNewer);
    assert_eq!(compare_release(&beta1, &release), ReleaseComparison::PeerNewer);
    assert_eq!(compare_release(&release, &next_patch), ReleaseComparison::PeerNewer);
    // Older peer never triggers newer or build-differs.
    assert_eq!(compare_release(&alpha22, &alpha21), ReleaseComparison::CurrentOrOlder);
    assert_eq!(compare_release(&release, &beta1), ReleaseComparison::CurrentOrOlder);
    // Build metadata does not affect SemVer precedence; commit decides build-differs.
    assert_eq!(
        compare_release(&alpha21, &with_meta_same_commit),
        ReleaseComparison::CurrentOrOlder
    );
    assert_eq!(
        compare_release(&alpha21, &with_meta_diff_commit),
        ReleaseComparison::BuildDiffers
    );
    Ok(())
}

#[test]
fn equal_version_commit_comparison_requires_both_commits_to_be_known() -> Result<(), ReleaseError> {
    let known_a = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let known_b = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_b()))?;
    let unknown = ReleaseIdentity::new("0.2.0-alpha.21", None)?;

    assert_eq!(compare_release(&known_a, &known_a), ReleaseComparison::CurrentOrOlder);
    assert_eq!(compare_release(&known_a, &known_b), ReleaseComparison::BuildDiffers);
    assert_eq!(compare_release(&known_a, &unknown), ReleaseComparison::CurrentOrOlder);
    assert_eq!(compare_release(&unknown, &known_a), ReleaseComparison::CurrentOrOlder);
    assert_eq!(compare_release(&unknown, &unknown), ReleaseComparison::CurrentOrOlder);
    Ok(())
}

#[test]
fn compute_notice_selects_highest_newer_version_and_names_peers_without_addresses() -> Result<(), ReleaseError> {
    let local = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let older = ReleaseIdentity::new("0.2.0-alpha.20", Some(commit_b()))?;
    let same_diff = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_b()))?;
    let newer_22 = ReleaseIdentity::new("0.2.0-alpha.22", Some(commit_b()))?;
    let newer_23 = ReleaseIdentity::new("0.2.0-alpha.23", Some(commit_c()))?;

    let n1 = NodeId::from_bytes([1; 32]);
    let n2 = NodeId::from_bytes([2; 32]);
    let n3 = NodeId::from_bytes([3; 32]);
    let n4 = NodeId::from_bytes([4; 32]);

    // Strictly higher SemVer wins over build-differs and lower newer versions;
    // peers at the highest version are sorted deterministically by node_id.
    let notice = compute_update_notice(
        &local,
        &[
            PeerReleaseObservation {
                node_id: n4,
                name: "Solis",
                release: &newer_23,
            },
            PeerReleaseObservation {
                node_id: n1,
                name: "OlderMac",
                release: &older,
            },
            PeerReleaseObservation {
                node_id: n2,
                name: "MidMac",
                release: &newer_22,
            },
            PeerReleaseObservation {
                node_id: n3,
                name: "Pro",
                release: &newer_23,
            },
            PeerReleaseObservation {
                node_id: NodeId::from_bytes([5; 32]),
                name: "SameDiff",
                release: &same_diff,
            },
        ],
    )
    .ok_or(ReleaseError::InvalidFrame)?;

    assert_eq!(notice.kind, "update-available");
    assert_eq!(notice.local_version, "0.2.0-alpha.21");
    assert_eq!(notice.peer_version, "0.2.0-alpha.23");
    assert_eq!(notice.peers.len(), 2);
    assert_eq!(notice.peers.first().map(|p| p.name.as_str()), Some("Pro"));
    assert_eq!(notice.peers.get(1).map(|p| p.name.as_str()), Some("Solis"));
    assert!(notice.summary.contains("0.2.0-alpha.23"));
    assert!(notice.summary.contains("Pro"));
    assert!(notice.summary.contains("Solis"));
    Ok(())
}

#[test]
fn compute_notice_reports_build_differs_when_no_peer_is_newer() -> Result<(), ReleaseError> {
    let local = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let diff = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_b()))?;
    let older = ReleaseIdentity::new("0.2.0-alpha.20", Some(commit_c()))?;

    let notice = compute_update_notice(
        &local,
        &[
            PeerReleaseObservation {
                node_id: NodeId::from_bytes([2; 32]),
                name: "MacMarine",
                release: &diff,
            },
            PeerReleaseObservation {
                node_id: NodeId::from_bytes([1; 32]),
                name: "OldNode",
                release: &older,
            },
        ],
    )
    .ok_or(ReleaseError::InvalidFrame)?;

    assert_eq!(notice.kind, "build-differs");
    assert_eq!(notice.peer_version, "0.2.0-alpha.21");
    assert_eq!(notice.peers.len(), 1);
    assert_eq!(notice.peers.first().map(|p| p.name.as_str()), Some("MacMarine"));
    assert!(notice.summary.contains("build differs"));
    assert!(notice.summary.contains("MacMarine"));
    assert!(notice.summary.contains("bbbbbbb"));
    assert!(notice.summary.contains("aaaaaaa"));
    Ok(())
}

#[test]
fn compute_notice_is_none_when_current_or_peers_older() -> Result<(), ReleaseError> {
    let local = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let same = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let unknown = ReleaseIdentity::new("0.2.0-alpha.21", None)?;
    let older = ReleaseIdentity::new("0.2.0-alpha.20", Some(commit_b()))?;

    assert!(compute_update_notice(&local, &[]).is_none());
    assert!(
        compute_update_notice(
            &local,
            &[
                PeerReleaseObservation {
                    node_id: NodeId::from_bytes([1; 32]),
                    name: "Same",
                    release: &same,
                },
                PeerReleaseObservation {
                    node_id: NodeId::from_bytes([2; 32]),
                    name: "UnknownCommit",
                    release: &unknown,
                },
                PeerReleaseObservation {
                    node_id: NodeId::from_bytes([3; 32]),
                    name: "Older",
                    release: &older,
                },
            ],
        )
        .is_none()
    );
    Ok(())
}

#[test]
fn wire_frame_round_trips_and_enforces_strict_bounds() -> Result<(), ReleaseError> {
    let known = ReleaseIdentity::new("0.2.0-alpha.22", Some(commit_a()))?;
    let encoded = encode_frame(&known)?;
    assert!(encoded.len() <= MAX_RELEASE_FRAME_BYTES);
    assert_eq!(decode_frame(&encoded)?, known);

    let unknown = ReleaseIdentity::new("0.2.0-alpha.22", None)?;
    let encoded_unknown = encode_frame(&unknown)?;
    assert_eq!(decode_frame(&encoded_unknown)?, unknown);

    // Trailing byte fails closed.
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(decode_frame(&trailing), Err(ReleaseError::InvalidFrame));

    // Oversized frame fails closed.
    let oversized = vec![0_u8; MAX_RELEASE_FRAME_BYTES + 1];
    assert_eq!(decode_frame(&oversized), Err(ReleaseError::Oversized));

    // Version > 64 bytes fails closed.
    let overlong_version = format!("0.2.0-alpha.{}", "1".repeat(MAX_RELEASE_VERSION_BYTES));
    assert!(overlong_version.len() > MAX_RELEASE_VERSION_BYTES);
    assert_eq!(
        ReleaseIdentity::new(overlong_version, Some(commit_a())),
        Err(ReleaseError::InvalidVersion)
    );

    // Invalid semver or control chars fail closed.
    assert_eq!(
        ReleaseIdentity::new("not-semver", None),
        Err(ReleaseError::InvalidVersion)
    );
    assert_eq!(ReleaseIdentity::new("0.2.0\n", None), Err(ReleaseError::InvalidVersion));

    // Non-40-hex or uppercase commit fails closed on wire/constructor.
    assert_eq!(
        ReleaseIdentity::new("0.2.0", Some("abc1234".to_owned())),
        Err(ReleaseError::InvalidCommit)
    );
    assert_eq!(
        ReleaseIdentity::new("0.2.0", Some("A".repeat(40))),
        Err(ReleaseError::InvalidCommit)
    );
    assert_eq!(
        ReleaseIdentity::new("0.2.0", Some("g".repeat(40))),
        Err(ReleaseError::InvalidCommit)
    );
    assert_eq!(normalize_commit(&"A".repeat(40)), Some(commit_a()));
    assert_eq!(normalize_commit("unknown"), None);
    assert_eq!(short_commit(&commit_a()), "aaaaaaa");
    assert_eq!(short_commit("unknown"), "unknown");
    Ok(())
}

#[test]
fn notice_log_deduplicates_per_newer_version_and_is_bounded() -> Result<(), ReleaseError> {
    let local = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_a()))?;
    let diff = ReleaseIdentity::new("0.2.0-alpha.21", Some(commit_b()))?;
    let newer22 = ReleaseIdentity::new("0.2.0-alpha.22", Some(commit_b()))?;
    let newer22_meta = ReleaseIdentity::new("0.2.0-alpha.22+alt", Some(commit_c()))?;
    let newer23 = ReleaseIdentity::new("0.2.0-alpha.23", Some(commit_c()))?;

    let mut log = ReleaseNoticeLog::new();
    let peer1 = NodeId::from_bytes([1; 32]);
    let peer2 = NodeId::from_bytes([2; 32]);

    // Build differs does not log.
    assert!(
        log.record_if_new(
            &local,
            &PeerReleaseObservation {
                node_id: peer1,
                name: "Solis",
                release: &diff,
            }
        )
        .is_none()
    );

    // First time seeing 0.2.0-alpha.22 logs once.
    let first = log
        .record_if_new(
            &local,
            &PeerReleaseObservation {
                node_id: peer1,
                name: "Solis",
                release: &newer22,
            },
        )
        .ok_or(ReleaseError::InvalidFrame)?;
    assert!(first.contains("0.2.0-alpha.22"));
    assert!(first.contains("Solis"));

    // Repeating same version from another peer or with different build metadata does not re-log.
    assert!(
        log.record_if_new(
            &local,
            &PeerReleaseObservation {
                node_id: peer2,
                name: "Pro",
                release: &newer22,
            }
        )
        .is_none()
    );
    assert!(
        log.record_if_new(
            &local,
            &PeerReleaseObservation {
                node_id: peer2,
                name: "Pro",
                release: &newer22_meta,
            }
        )
        .is_none()
    );

    // A strictly distinct newer version logs once.
    let second = log
        .record_if_new(
            &local,
            &PeerReleaseObservation {
                node_id: peer2,
                name: "Pro",
                release: &newer23,
            },
        )
        .ok_or(ReleaseError::InvalidFrame)?;
    assert!(second.contains("0.2.0-alpha.23"));

    // Bounded at MAX_LOGGED_VERSIONS.
    let mut bounded = ReleaseNoticeLog::new();
    for index in 1..=(MAX_LOGGED_VERSIONS + 5) {
        let candidate = ReleaseIdentity::new(format!("1.0.{index}"), None)?;
        let emitted = bounded.record_if_new(
            &local,
            &PeerReleaseObservation {
                node_id: peer1,
                name: "FloodPeer",
                release: &candidate,
            },
        );
        assert_eq!(emitted.is_some(), index <= MAX_LOGGED_VERSIONS);
    }
    Ok(())
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _result = decode_frame(&bytes);
    }
}
