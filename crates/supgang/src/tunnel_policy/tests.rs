use std::{fs, os::unix::fs::PermissionsExt};

use super::{FILE_NAME, TunnelPolicy, decoded_name, encoded_name, load, save};
use crate::{record::ServiceName, state};

#[test]
fn exposures_are_opt_in_bounded_and_owner_only() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    drop(state::initialize(&path)?);
    assert!(load(&path)?.exposures.is_empty());
    let mut policy = TunnelPolicy::default();
    let ssh = ServiceName::new("ssh")?;
    policy.set(ssh.clone(), 22)?;
    save(&path, &policy)?;
    assert_eq!(load(&path)?.port(&ssh), Some(22));
    policy.set(ssh.clone(), 0)?;
    save(&path, &policy)?;
    assert_eq!(load(&path)?.port(&ssh), None);
    fs::set_permissions(path.join(FILE_NAME), fs::Permissions::from_mode(0o644))?;
    assert!(load(&path).is_err());
    assert!(save(&path, &policy).is_err());
    Ok(())
}

#[test]
fn names_and_limits_reject_ambiguous_or_unbounded_requests() -> Result<(), Box<dyn std::error::Error>> {
    let ssh = ServiceName::new("ssh")?;
    assert_eq!(decoded_name(encoded_name(&ssh))?, ssh);
    assert!(decoded_name([0; 16]).is_err());
    let mut ambiguous = encoded_name(&ssh);
    *ambiguous.last_mut().ok_or("name missing")? = b'x';
    assert!(decoded_name(ambiguous).is_err());
    let mut policy = TunnelPolicy::default();
    for index in 0..4 {
        policy.set(ServiceName::new(format!("svc{index}"))?, 22)?;
    }
    assert!(policy.set(ServiceName::new("fifth")?, 22).is_err());
    policy.total = 129;
    assert!(policy.validate().is_err());
    Ok(())
}

#[test]
fn every_permitted_tunnel_fits_the_transport_stream_budget_beside_sync_and_update() {
    let streams = usize::try_from(crate::transport::MAX_BIDIRECTIONAL_STREAMS).unwrap_or(0);
    assert_eq!(streams, super::MAX_PER_PEER + 2);
}
