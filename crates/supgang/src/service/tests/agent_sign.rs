//! Production member stream over the simulated packet network.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use super::sim_harness::{Error, Fleet, wait_connected};
use crate::{
    agent_sign_protocol::{MAX_REQUEST_BYTES, SignRequest},
    control::{self, ControlReply, ControlRequest},
    simnet::{Network, SiteSpec, V4Access},
};

#[test]
fn authenticated_member_sign_stream_returns_a_bounded_refusal_for_unknown_purpose() -> Result<(), Error> {
    let network = Network::new(112);
    let site = network.add_site(SiteSpec {
        v4: Some(V4Access::Public {
            first: Ipv4Addr::new(9, 22, 0, 1),
        }),
        v6: None,
    })?;
    let signer = network.add_host(Some(site))?;
    let requester = network.add_host(Some(site))?;
    let mut fleet = Fleet::pair(Arc::clone(&network), &[signer, requester])?;
    fleet.start_all()?;
    wait_connected(&fleet, 1, 0, Duration::from_secs(30))?.ok_or("members did not authenticate")?;
    let request = SignRequest {
        nonce: [17; 32],
        purpose: "unknown".to_owned(),
        context: "build.stage".to_owned(),
        digest: [23; 32],
        expires_at: super::super::unix_time()? + 60,
    };
    let bytes = request.encode()?;
    let mut padded = [0_u8; MAX_REQUEST_BYTES];
    padded
        .get_mut(..bytes.len())
        .ok_or("invalid request length")?
        .copy_from_slice(&bytes);
    let reply = control::request_sign(
        &fleet.computer(1)?.path,
        ControlRequest::AgentSign {
            target: fleet.computer(0)?.node,
            request: Box::new(padded),
            length: u16::try_from(bytes.len())?,
        },
    )?;
    assert!(
        matches!(&reply, Some(ControlReply::Error { message }) if message == "the signing peer refused the request"),
        "reply: {reply:?}"
    );
    Ok(())
}
