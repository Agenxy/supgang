//! Finishes bounded session tasks and credits authenticated inbound sources.

use super::{LiveSessionState, SessionTaskResult};
use crate::service::{
    ConnectionOrigin, ServiceError, active::SessionAuthorization, admission::InboundAdmission, unix_time,
};

pub(in crate::service) fn finish_ready_sessions(
    tasks: &mut tokio::task::JoinSet<SessionTaskResult>,
    inbound_admission: &mut InboundAdmission,
    outbound_in_flight: &mut bool,
    live: &mut LiveSessionState<'_>,
) -> Result<(), ServiceError> {
    while let Some(joined) = tasks.try_join_next() {
        let completed = joined?;
        if completed.claimed_outbound_slot {
            *outbound_in_flight = false;
        }
        if let Some((exchange, connection)) = completed.authenticated {
            let inbound = completed.origin == ConnectionOrigin::Inbound;
            let source = connection.remote_address();
            let peer = exchange.peer;
            let expires_at = exchange.authorization_expires_at;
            live.finish_authenticated(
                connection,
                exchange,
                completed.origin,
                completed.superseded,
                completed.registered_old,
            )?;
            if inbound
                && !live.local_state.revocations().contains(&peer)
                && SessionAuthorization::new(expires_at, unix_time()?).is_some()
            {
                inbound_admission.note_authenticated(source, tokio::time::Instant::now());
            }
        }
    }
    Ok(())
}
