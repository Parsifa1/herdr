use std::time::{Duration, Instant};

pub(super) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
// Match the remote setup allowance without extending established transport health checks.
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(60);
/// Probe deadline while the endpoint's transport reports its path as
/// recovering (a QUIC connection riding out a blackhole or an address change).
/// Long enough to cover a tunnel; the transport itself gives up at the same
/// bound, so the endpoint never sits in this state indefinitely.
pub(super) const ROAMING_GRACE: Duration = Duration::from_secs(150);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HealthAction {
    None,
    Ping,
    Expired,
}

pub(super) struct EndpointHealth {
    connected_at: Instant,
    last_received: Option<Instant>,
    ping_sent_at: Option<Instant>,
    ready: bool,
    probe_due: bool,
    recovering: bool,
}

impl EndpointHealth {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            connected_at: now,
            last_received: None,
            ping_sent_at: None,
            ready: false,
            probe_due: false,
            recovering: false,
        }
    }

    /// The local transport says the path is recovering, not lost: keep the
    /// endpoint online and stretch the probe deadline to the roaming grace.
    pub(super) fn set_recovering(&mut self, recovering: bool) {
        self.recovering = recovering;
    }

    pub(super) fn received(&mut self, now: Instant) {
        self.last_received = Some(now);
        self.ping_sent_at = None;
    }

    pub(super) fn ready(&mut self) {
        self.ready = true;
    }

    pub(super) fn resume(&mut self) {
        self.ping_sent_at = None;
        self.probe_due = true;
    }

    pub(super) fn action(&self, now: Instant) -> HealthAction {
        let initial_snapshot_expired = !self.ready
            && now.saturating_duration_since(self.connected_at) >= INITIAL_SNAPSHOT_TIMEOUT;
        let probe_timeout = if self.recovering {
            ROAMING_GRACE
        } else {
            HEARTBEAT_TIMEOUT
        };
        // Welcome precedes state-loop registration, which can postpone the first pong.
        let probe_expired = (self.ready || self.last_received.is_some())
            && self
                .ping_sent_at
                .is_some_and(|sent_at| now.saturating_duration_since(sent_at) >= probe_timeout);
        if initial_snapshot_expired || probe_expired {
            HealthAction::Expired
        } else if self.probe_due
            || (self.ping_sent_at.is_none()
                && now.saturating_duration_since(self.last_received.unwrap_or(self.connected_at))
                    >= HEARTBEAT_INTERVAL)
        {
            HealthAction::Ping
        } else {
            HealthAction::None
        }
    }

    pub(super) fn ping_sent(&mut self, now: Instant) {
        self.probe_due = false;
        self.ping_sent_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_connection_is_probed_then_expires_without_a_reply() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ready();
        assert_eq!(health.action(now), HealthAction::None);
        assert_eq!(health.action(now + HEARTBEAT_INTERVAL), HealthAction::Ping);
        health.ping_sent(now + HEARTBEAT_INTERVAL);
        assert_eq!(
            health.action(now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT),
            HealthAction::Expired
        );
    }

    #[test]
    fn pause_reprobes_without_extending_initial_readiness_budget() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.received(now);
        health.ping_sent(now);
        health.resume();
        assert_eq!(
            health.action(now + Duration::from_secs(59)),
            HealthAction::Ping
        );
        health.ping_sent(now + Duration::from_secs(59));
        health.resume();
        assert_eq!(
            health.action(now + Duration::from_secs(60)),
            HealthAction::Expired
        );
    }

    #[test]
    fn any_incoming_message_satisfies_an_outstanding_probe() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ready();
        health.ping_sent(now);
        health.received(now + HEARTBEAT_TIMEOUT - Duration::from_millis(1));
        assert_eq!(health.action(now + HEARTBEAT_TIMEOUT), HealthAction::None);
    }

    #[test]
    fn delayed_registration_can_reply_after_the_normal_probe_deadline() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ping_sent(now + HEARTBEAT_INTERVAL);
        let registered = now + Duration::from_secs(45);
        assert_eq!(health.action(registered), HealthAction::None);
        health.received(registered);
        health.ready();
        assert_eq!(health.action(registered), HealthAction::None);
    }

    #[test]
    fn a_recovering_path_stretches_the_probe_deadline_to_the_roaming_grace() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ready();
        health.set_recovering(true);
        health.ping_sent(now);
        assert_eq!(health.action(now + HEARTBEAT_TIMEOUT), HealthAction::None);
        assert_eq!(
            health.action(now + ROAMING_GRACE - Duration::from_millis(1)),
            HealthAction::None
        );
        assert_eq!(health.action(now + ROAMING_GRACE), HealthAction::Expired);

        health.set_recovering(false);
        assert_eq!(
            health.action(now + HEARTBEAT_TIMEOUT),
            HealthAction::Expired
        );
    }

    #[test]
    fn heartbeats_do_not_hide_a_missing_initial_snapshot() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ping_sent(now + HEARTBEAT_INTERVAL);
        let registered = now + Duration::from_secs(45);
        assert_eq!(health.action(registered), HealthAction::None);
        health.received(registered);
        health.ready();
        assert_eq!(health.action(registered), HealthAction::None);
    }

    #[test]
    fn responding_startup_gets_time_for_its_snapshot_but_cannot_wait_forever() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        for seconds in (5..60).step_by(5) {
            let reply = now + Duration::from_secs(seconds);
            health.received(reply);
            assert_eq!(health.action(reply), HealthAction::None);
        }
        assert_eq!(
            health.action(now + Duration::from_secs(60)),
            HealthAction::Expired
        );
    }

    #[test]
    fn startup_silence_is_bounded_and_confirmed_transport_keeps_normal_probe_timeout() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ping_sent(now + HEARTBEAT_INTERVAL);
        assert_eq!(
            health.action(now + Duration::from_secs(60)),
            HealthAction::Expired
        );

        let mut health = EndpointHealth::new(now);
        health.received(now + Duration::from_secs(6));
        health.ping_sent(now + Duration::from_secs(11));
        assert_eq!(
            health.action(now + Duration::from_secs(20)),
            HealthAction::None
        );
        assert_eq!(
            health.action(now + Duration::from_secs(21)),
            HealthAction::Expired
        );
    }
}
