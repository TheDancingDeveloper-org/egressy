use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::state::{ClientState, TrafficState};

pub const TRANSITION_CAPACITY: usize = 200;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    Enforced,
    #[default]
    Unknown,
    Violated,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    #[default]
    Starting,
    Healthy,
    Degraded,
    Unavailable,
    Recovering,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    #[default]
    Pending,
    Healthy,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Critical,
    Advisory,
    Optional,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubsystemCheck {
    pub id: String,
    pub status: CheckStatus,
    pub impact: Impact,
    pub observed_at_unix_ms: u64,
    pub changed_at_unix_ms: u64,
    pub reason_code: String,
    pub safe_message: String,
    pub consecutive_failures: u32,
    pub next_attempt_at_unix_ms: Option<u64>,
}

impl SubsystemCheck {
    pub fn pending(id: impl Into<String>, impact: Impact, now: u64) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Pending,
            impact,
            observed_at_unix_ms: now,
            changed_at_unix_ms: now,
            reason_code: "observation.pending".to_owned(),
            safe_message: "Waiting for the first observation".to_owned(),
            consecutive_failures: 0,
            next_attempt_at_unix_ms: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Transition {
    pub sequence: u64,
    pub timestamp_unix_ms: u64,
    pub component: String,
    pub from_status: CheckStatus,
    pub to_status: CheckStatus,
    pub reason_code: String,
    pub safe_message: String,
    pub recovery_attempt: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardPhase {
    #[default]
    Disabled,
    WaitingForTarget,
    Requested,
    Leased,
    Installed,
    Verified,
    TargetAmbiguous,
    LeaseLost,
    InstallFailed,
    VerificationFailed,
    Unavailable,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortForwardStatus {
    pub phase: PortForwardPhase,
    pub requested_target: Option<String>,
    pub internal_port: Option<u16>,
    pub external_port: Option<u16>,
    pub tcp_udp_agree: Option<bool>,
    pub lease_acquired_at_unix_ms: Option<u64>,
    pub lease_expires_at_unix_ms: Option<u64>,
    pub dnat_installed: bool,
    pub externally_verified: Option<bool>,
    pub change_sequence: u64,
    pub changed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryStatus {
    pub active: bool,
    pub attempt: u32,
    pub reason_code: Option<String>,
    pub next_attempt_at_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProbeStatus {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalProbeResult {
    pub status: ExternalProbeStatus,
    pub observed_at_unix_ms: Option<u64>,
    pub source_public_non_tailscale: Option<bool>,
    pub source_matches_claimed_ip: Option<bool>,
    pub tcp_port_reachable: Option<bool>,
    pub forwarded_port: Option<u16>,
    pub lease_acquired_at_unix_ms: Option<u64>,
    pub request_started_at_unix_ms: Option<u64>,
    pub reason_code: Option<String>,
    pub safe_message: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnServerLatencyStatus {
    Measured,
    Timeout,
    Unsupported,
    ResolutionFailed,
    #[default]
    Unavailable,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct VpnServerLatency {
    pub status: VpnServerLatencyStatus,
    pub sampled_at_unix_ms: Option<u64>,
    pub latest_rtt_ms: Option<f64>,
    pub recent_min_rtt_ms: Option<f64>,
    pub recent_average_rtt_ms: Option<f64>,
    pub recent_max_rtt_ms: Option<f64>,
    pub loss_ratio: Option<f64>,
    pub sample_count: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct VpnServerStatus {
    pub configured_endpoint_host: Option<String>,
    pub configured_endpoint_port: Option<u16>,
    pub configured_address_family: Option<String>,
    pub allowed_ips_posture: String,
    pub runtime_endpoint_address: Option<String>,
    pub runtime_endpoint_port: Option<u16>,
    pub provider_inferred: Option<String>,
    pub region_inferred: Option<String>,
    pub inference_source: Option<String>,
    pub inference_confidence: Option<String>,
    pub active: bool,
    pub latest_handshake_unix: Option<u64>,
    pub handshake_age_seconds: Option<u64>,
    pub observed_at_unix_ms: Option<u64>,
    pub latency: VpnServerLatency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TopologyStatus {
    pub network: String,
    pub subnet: String,
    pub gateway_address: String,
    pub host_bridge: String,
    pub policy_table: u32,
    pub client_ipv6_supported: bool,
    pub default_route_verifiable: bool,
    pub declared_route_intent_observable: bool,
    pub client_isolation: String,
}

impl Default for TopologyStatus {
    fn default() -> Self {
        Self {
            network: String::new(),
            subnet: String::new(),
            gateway_address: String::new(),
            host_bridge: String::new(),
            policy_table: 0,
            client_ipv6_supported: false,
            default_route_verifiable: false,
            declared_route_intent_observable: true,
            client_isolation: "shared_bridge_not_enforced".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CanonicalSnapshot {
    pub schema_version: u8,
    pub sequence: u64,
    pub generated_at_unix_ms: u64,
    pub protection: Protection,
    pub availability: Availability,
    pub checks: BTreeMap<String, SubsystemCheck>,
    pub transitions: VecDeque<Transition>,
    pub port_forward: PortForwardStatus,
    pub port_forwards: BTreeMap<String, PortForwardStatus>,
    pub recovery: RecoveryStatus,
    pub external_probe: ExternalProbeResult,
    pub external_probes: BTreeMap<String, ExternalProbeResult>,
    pub vpn_server: VpnServerStatus,
    pub isolation_policy: crate::isolation::IsolationPolicy,
    pub topology: TopologyStatus,
    pub clients: BTreeMap<String, ClientState>,
    pub traffic: TrafficState,
    pub last_client_path_success_at_unix_ms: Option<u64>,
    pub profile_management: crate::profile_manager::ProfileManagementStatus,
}

impl CanonicalSnapshot {
    pub fn derive_aggregate(&mut self) {
        let firewall = self.checks.get("gateway.firewall");
        let routes = self.checks.get("gateway.routes");
        self.protection = match (firewall, routes) {
            (Some(a), Some(b))
                if a.status == CheckStatus::Healthy && b.status == CheckStatus::Healthy =>
            {
                Protection::Enforced
            }
            (Some(a), _) if a.status == CheckStatus::Failed => Protection::Violated,
            (_, Some(b)) if b.status == CheckStatus::Failed => Protection::Violated,
            _ => Protection::Unknown,
        };

        if self.recovery.active {
            self.availability = Availability::Recovering;
            return;
        }
        let mut critical_failed = false;
        let mut critical_degraded = false;
        let mut critical_pending = false;
        for check in self
            .checks
            .values()
            .filter(|check| check.impact == Impact::Critical)
        {
            match check.status {
                CheckStatus::Failed => critical_failed = true,
                CheckStatus::Degraded | CheckStatus::Unknown => critical_degraded = true,
                CheckStatus::Pending => critical_pending = true,
                CheckStatus::Healthy => {}
            }
        }
        self.availability = if critical_failed {
            Availability::Unavailable
        } else if critical_degraded {
            Availability::Degraded
        } else if critical_pending {
            Availability::Starting
        } else {
            Availability::Healthy
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_and_availability_are_independent() {
        let mut snapshot = CanonicalSnapshot::default();
        snapshot.checks.insert(
            "gateway.firewall".into(),
            SubsystemCheck {
                status: CheckStatus::Healthy,
                ..SubsystemCheck::pending("gateway.firewall", Impact::Critical, 1)
            },
        );
        snapshot.checks.insert(
            "gateway.routes".into(),
            SubsystemCheck {
                status: CheckStatus::Healthy,
                ..SubsystemCheck::pending("gateway.routes", Impact::Critical, 1)
            },
        );
        snapshot.checks.insert(
            "wireguard.handshake".into(),
            SubsystemCheck {
                status: CheckStatus::Failed,
                ..SubsystemCheck::pending("wireguard.handshake", Impact::Critical, 1)
            },
        );
        snapshot.derive_aggregate();
        assert_eq!(snapshot.protection, Protection::Enforced);
        assert_eq!(snapshot.availability, Availability::Unavailable);
    }

    #[test]
    fn optional_and_advisory_failures_do_not_change_availability() {
        for (component, impact, status) in [
            ("telemetry.otel", Impact::Optional, CheckStatus::Failed),
            (
                "vpn_server.latency",
                Impact::Optional,
                CheckStatus::Degraded,
            ),
            (
                "history.persistence",
                Impact::Advisory,
                CheckStatus::Degraded,
            ),
            ("external_probe", Impact::Advisory, CheckStatus::Failed),
        ] {
            let mut snapshot = CanonicalSnapshot::default();
            snapshot.checks.insert(
                component.into(),
                SubsystemCheck {
                    status,
                    ..SubsystemCheck::pending(component, impact, 1)
                },
            );
            snapshot.derive_aggregate();
            assert_eq!(snapshot.availability, Availability::Healthy, "{component}");
            assert_eq!(snapshot.checks[component].status, status);
        }
    }

    #[test]
    fn degraded_and_unknown_critical_checks_degrade_availability() {
        for status in [CheckStatus::Degraded, CheckStatus::Unknown] {
            let mut snapshot = CanonicalSnapshot::default();
            snapshot.checks.insert(
                "critical".into(),
                SubsystemCheck {
                    status,
                    ..SubsystemCheck::pending("critical", Impact::Critical, 1)
                },
            );
            snapshot.derive_aggregate();
            assert_eq!(snapshot.availability, Availability::Degraded);
        }
    }
}
