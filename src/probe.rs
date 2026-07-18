use std::time::Duration;

use serde::Deserialize;
use tokio::time::interval;

use crate::{
    config::Config,
    control::StatePublisher,
    domain::{CheckStatus, ExternalProbeStatus, Impact, PortForwardPhase},
};

#[derive(Debug, Deserialize)]
struct ProbeResult {
    observed_at_unix_ms: u64,
    udp_dns_ok: bool,
    tcp_dns_ok: bool,
    https_egress_ok: bool,
    vpn_identity_ok: bool,
    expected_identity: String,
    reason_code: String,
    safe_message: String,
    external_probe: Option<ReportedExternalProbe>,
}

#[derive(Debug, Deserialize)]
struct ReportedExternalProbe {
    status: String,
    observed_at_unix_ms: u64,
    source_public_non_tailscale: Option<bool>,
    source_matches_claimed_ip: Option<bool>,
    tcp_port_reachable: Option<bool>,
    forwarded_port: Option<u16>,
    lease_acquired_at_unix_ms: Option<u64>,
    request_started_at_unix_ms: Option<u64>,
    reason_code: String,
    safe_message: String,
}

pub async fn monitor(config: Config, publisher: StatePublisher) -> anyhow::Result<()> {
    if !config.probe.enabled {
        futures_util::future::pending::<()>().await;
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let token = match &config.probe.token_path {
        Some(path) => Some(tokio::fs::read_to_string(path).await?.trim().to_owned()),
        None => None,
    };
    let mut ticker = interval(Duration::from_secs(config.probe.interval_seconds));
    loop {
        ticker.tick().await;
        let mut request = client.get(&config.probe.url);
        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }
        match request.send().await {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.json::<ProbeResult>().await {
                    Ok(result) => {
                        let dns_ok = result.udp_dns_ok && result.tcp_dns_ok;
                        publisher
                            .observe(
                                "client_path.dns",
                                if dns_ok {
                                    CheckStatus::Healthy
                                } else {
                                    CheckStatus::Failed
                                },
                                Impact::Critical,
                                if dns_ok {
                                    "probe.dns_healthy"
                                } else {
                                    "probe.dns_failed"
                                },
                                if dns_ok {
                                    "UDP and TCP DNS succeeded through the enrolled path"
                                } else {
                                    "DNS failed through the enrolled path"
                                },
                                None,
                                None,
                            )
                            .await;
                        let egress_ok = result.https_egress_ok && result.vpn_identity_ok;
                        let identity_matches = !config.validation.identity.enabled
                            || result.expected_identity.eq_ignore_ascii_case(
                                &config.validation.identity.matcher.expected_value(),
                            );
                        publisher
                            .observe(
                                "client_path.egress",
                                if egress_ok && identity_matches {
                                    CheckStatus::Healthy
                                } else {
                                    CheckStatus::Degraded
                                },
                                Impact::Advisory,
                                if identity_matches {
                                    &result.reason_code
                                } else {
                                    "probe.identity_configuration_mismatch"
                                },
                                if identity_matches {
                                    result.safe_message
                                } else {
                                    "The probe and daemon expected-identity settings differ"
                                        .to_owned()
                                },
                                None,
                                None,
                            )
                            .await;
                        if dns_ok && egress_ok && identity_matches {
                            publisher
                                .mutate(|state| {
                                    state.last_client_path_success_at_unix_ms =
                                        Some(result.observed_at_unix_ms)
                                })
                                .await;
                        }
                        if config.external_probe.enabled {
                            if let Some(external_probe) = result.external_probe {
                                observe_external_probe(
                                    &publisher,
                                    external_probe,
                                    external_probe_freshness_ms(&config),
                                )
                                .await;
                            } else {
                                observe_external_probe_unavailable(
                                    &publisher,
                                    "external_probe.unavailable",
                                    "The external probe is enabled but no result has been reported yet",
                                )
                                .await;
                            }
                        }
                    }
                    Err(error) => {
                        observe_unavailable(&publisher, &error.to_string()).await;
                        if config.external_probe.enabled {
                            observe_external_probe_unavailable(
                                &publisher,
                                "external_probe.invalid_response",
                                "The enrolled-path probe returned an invalid external result",
                            )
                            .await;
                        }
                    }
                },
                Err(error) => {
                    observe_unavailable(&publisher, &error.to_string()).await;
                    if config.external_probe.enabled {
                        observe_external_probe_unavailable(
                            &publisher,
                            "external_probe.unavailable",
                            "The enrolled-path probe is unavailable; external reachability is unknown",
                        )
                        .await;
                    }
                }
            },
            Err(error) => {
                observe_unavailable(&publisher, &error.to_string()).await;
                if config.external_probe.enabled {
                    observe_external_probe_unavailable(
                        &publisher,
                        "external_probe.unavailable",
                        "The enrolled-path probe is unavailable; external reachability is unknown",
                    )
                    .await;
                }
            }
        }
    }
}

async fn observe_unavailable(publisher: &StatePublisher, _error: &str) {
    publisher
        .observe(
            "client_path.egress",
            CheckStatus::Degraded,
            Impact::Advisory,
            "probe.unavailable",
            "The enrolled-path probe is unavailable; tunnel protection is unchanged",
            None,
            None,
        )
        .await;
}

fn external_probe_freshness_ms(config: &Config) -> u64 {
    config
        .external_probe
        .interval_seconds
        .saturating_add(config.external_probe.timeout_seconds)
        .saturating_add(config.probe.interval_seconds)
        .saturating_mul(1_000)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortVerification {
    Verified,
    Failed,
    Unknown,
}

fn correlate_port_verification(
    snapshot: &crate::domain::CanonicalSnapshot,
    external_probe: &ReportedExternalProbe,
    now: u64,
    freshness_ms: u64,
) -> PortVerification {
    if !snapshot.port_forward.dnat_installed {
        return PortVerification::Unknown;
    }
    let Some(request_started_at) = external_probe.request_started_at_unix_ms else {
        return PortVerification::Unknown;
    };
    let matching_mapping = external_probe.forwarded_port == snapshot.port_forward.external_port
        && external_probe.lease_acquired_at_unix_ms
            == snapshot.port_forward.lease_acquired_at_unix_ms
        && snapshot
            .port_forward
            .lease_acquired_at_unix_ms
            .is_some_and(|acquired_at| request_started_at >= acquired_at);
    let fresh = now.abs_diff(request_started_at) <= freshness_ms
        && now.abs_diff(external_probe.observed_at_unix_ms) <= freshness_ms;
    if !matching_mapping || !fresh {
        return PortVerification::Unknown;
    }

    let identity_confirmed = external_probe.source_public_non_tailscale == Some(true)
        && external_probe.source_matches_claimed_ip != Some(false);
    match (
        external_probe.status.as_str(),
        external_probe.reason_code.as_str(),
        identity_confirmed,
        external_probe.tcp_port_reachable,
    ) {
        ("healthy", "external_probe.healthy", true, Some(true)) => PortVerification::Verified,
        ("degraded", "external_probe.port_unreachable", true, Some(false)) => {
            PortVerification::Failed
        }
        _ => PortVerification::Unknown,
    }
}

async fn observe_external_probe(
    publisher: &StatePublisher,
    external_probe: ReportedExternalProbe,
    freshness_ms: u64,
) {
    let now = crate::runtime::unix_ms();
    let reported_status = match external_probe.status.as_str() {
        "healthy" => Some(ExternalProbeStatus::Healthy),
        "degraded" => Some(ExternalProbeStatus::Degraded),
        "unavailable" => Some(ExternalProbeStatus::Unavailable),
        _ => None,
    };
    let stale = now.abs_diff(external_probe.observed_at_unix_ms) > freshness_ms
        || external_probe
            .request_started_at_unix_ms
            .is_some_and(|started_at| now.abs_diff(started_at) > freshness_ms);
    let malformed = reported_status.is_none();
    let normalized_unavailable = stale || malformed;
    let status = if normalized_unavailable {
        ExternalProbeStatus::Unavailable
    } else {
        reported_status.unwrap_or(ExternalProbeStatus::Unavailable)
    };
    let effective_reason_code = if stale {
        "external_probe.unavailable"
    } else if malformed {
        "external_probe.invalid_response"
    } else {
        &external_probe.reason_code
    };
    let effective_safe_message = if stale {
        "The external probe evidence is stale; tunnel protection is unchanged"
    } else if malformed {
        "The external probe returned an invalid status"
    } else {
        &external_probe.safe_message
    };

    publisher
        .mutate(|snapshot| {
            let primary_identity = (
                snapshot.port_forward.external_port,
                snapshot.port_forward.lease_acquired_at_unix_ms,
            );
            snapshot.external_probe.status = status;
            snapshot.external_probe.observed_at_unix_ms = Some(external_probe.observed_at_unix_ms);
            snapshot.external_probe.source_public_non_tailscale = (!normalized_unavailable)
                .then_some(external_probe.source_public_non_tailscale)
                .flatten();
            snapshot.external_probe.source_matches_claimed_ip = (!normalized_unavailable)
                .then_some(external_probe.source_matches_claimed_ip)
                .flatten();
            snapshot.external_probe.tcp_port_reachable = (!normalized_unavailable)
                .then_some(external_probe.tcp_port_reachable)
                .flatten();
            snapshot.external_probe.forwarded_port = (!normalized_unavailable)
                .then_some(external_probe.forwarded_port)
                .flatten();
            snapshot.external_probe.lease_acquired_at_unix_ms = (!normalized_unavailable)
                .then_some(external_probe.lease_acquired_at_unix_ms)
                .flatten();
            snapshot.external_probe.request_started_at_unix_ms = (!normalized_unavailable)
                .then_some(external_probe.request_started_at_unix_ms)
                .flatten();
            snapshot.external_probe.reason_code = Some(effective_reason_code.to_owned());
            snapshot.external_probe.safe_message = Some(effective_safe_message.to_owned());

            match correlate_port_verification(snapshot, &external_probe, now, freshness_ms) {
                PortVerification::Verified => {
                    snapshot.port_forward.externally_verified = Some(true);
                    snapshot.port_forward.phase = PortForwardPhase::Verified;
                }
                PortVerification::Failed => {
                    snapshot.port_forward.externally_verified = Some(false);
                    snapshot.port_forward.phase = PortForwardPhase::VerificationFailed;
                }
                PortVerification::Unknown => {
                    snapshot.port_forward.externally_verified = None;
                    if snapshot.port_forward.dnat_installed {
                        snapshot.port_forward.phase = PortForwardPhase::Installed;
                    }
                }
            }
            let primary = snapshot.port_forward.clone();
            if let Some((_, status)) = snapshot.port_forwards.iter_mut().find(|(_, status)| {
                (status.external_port, status.lease_acquired_at_unix_ms) == primary_identity
                    && status.dnat_installed
            }) {
                status.phase = primary.phase;
                status.externally_verified = primary.externally_verified;
            }
        })
        .await;

    let verification = publisher
        .subscribe()
        .borrow()
        .port_forward
        .externally_verified;
    publisher
        .observe(
            "port_forward.verification",
            match verification {
                Some(true) => CheckStatus::Healthy,
                Some(false) => CheckStatus::Degraded,
                None => CheckStatus::Unknown,
            },
            Impact::Optional,
            match verification {
                Some(true) => "port_forward.externally_verified",
                Some(false) => "port_forward.verification_failed",
                None => "port_forward.verification_unknown",
            },
            match verification {
                Some(true) => "The active forwarded-port mapping was reachable externally",
                Some(false) => "The active forwarded-port mapping was explicitly unreachable",
                None => "No fresh external evidence matches the active forwarded-port mapping",
            },
            None,
            None,
        )
        .await;

    publisher
        .observe(
            "external_probe",
            if matches!(status, ExternalProbeStatus::Healthy) {
                CheckStatus::Healthy
            } else {
                CheckStatus::Degraded
            },
            Impact::Advisory,
            effective_reason_code,
            effective_safe_message,
            None,
            None,
        )
        .await;
}

async fn observe_external_probe_unavailable(
    publisher: &StatePublisher,
    reason_code: &str,
    safe_message: &str,
) {
    publisher
        .mutate(|snapshot| {
            let primary_identity = (
                snapshot.port_forward.external_port,
                snapshot.port_forward.lease_acquired_at_unix_ms,
            );
            snapshot.external_probe.status = ExternalProbeStatus::Unavailable;
            snapshot.external_probe.observed_at_unix_ms = Some(crate::runtime::unix_ms());
            snapshot.external_probe.source_public_non_tailscale = None;
            snapshot.external_probe.source_matches_claimed_ip = None;
            snapshot.external_probe.tcp_port_reachable = None;
            snapshot.external_probe.forwarded_port = None;
            snapshot.external_probe.lease_acquired_at_unix_ms = None;
            snapshot.external_probe.request_started_at_unix_ms = None;
            snapshot.external_probe.reason_code = Some(reason_code.to_owned());
            snapshot.external_probe.safe_message = Some(safe_message.to_owned());
            snapshot.port_forward.externally_verified = None;
            if snapshot.port_forward.dnat_installed {
                snapshot.port_forward.phase = PortForwardPhase::Installed;
            }
            let primary = snapshot.port_forward.clone();
            if let Some((_, status)) = snapshot.port_forwards.iter_mut().find(|(_, status)| {
                (status.external_port, status.lease_acquired_at_unix_ms) == primary_identity
                    && status.dnat_installed
            }) {
                status.phase = primary.phase;
                status.externally_verified = None;
            }
        })
        .await;

    publisher
        .observe(
            "port_forward.verification",
            CheckStatus::Unknown,
            Impact::Optional,
            "port_forward.verification_unknown",
            "No fresh external evidence matches the active forwarded-port mapping",
            None,
            None,
        )
        .await;

    publisher
        .observe(
            "external_probe",
            CheckStatus::Degraded,
            Impact::Advisory,
            reason_code,
            safe_message,
            None,
            None,
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CanonicalSnapshot, PortForwardStatus};

    const PORT: u16 = 45678;
    const LEASE_ACQUIRED_AT: u64 = 1_000;
    const FRESHNESS_MS: u64 = 60_000;

    fn publisher_with_active_lease() -> StatePublisher {
        StatePublisher::new(CanonicalSnapshot {
            port_forward: PortForwardStatus {
                phase: PortForwardPhase::Installed,
                external_port: Some(PORT),
                lease_acquired_at_unix_ms: Some(LEASE_ACQUIRED_AT),
                dnat_installed: true,
                ..PortForwardStatus::default()
            },
            ..CanonicalSnapshot::default()
        })
    }

    fn reported_result(
        status: &str,
        reachable: Option<bool>,
        reason_code: &str,
    ) -> ReportedExternalProbe {
        ReportedExternalProbe {
            status: status.to_owned(),
            observed_at_unix_ms: crate::runtime::unix_ms(),
            source_public_non_tailscale: Some(true),
            source_matches_claimed_ip: Some(true),
            tcp_port_reachable: reachable,
            forwarded_port: Some(PORT),
            lease_acquired_at_unix_ms: Some(LEASE_ACQUIRED_AT),
            request_started_at_unix_ms: Some(crate::runtime::unix_ms()),
            reason_code: reason_code.to_owned(),
            safe_message: "Safe external probe result".to_owned(),
        }
    }

    #[tokio::test]
    async fn external_probe_result_updates_canonical_state() {
        let publisher = publisher_with_active_lease();
        observe_external_probe(
            &publisher,
            reported_result("healthy", Some(true), "external_probe.healthy"),
            FRESHNESS_MS,
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.external_probe.status, ExternalProbeStatus::Healthy);
        assert_eq!(
            snapshot.external_probe.reason_code.as_deref(),
            Some("external_probe.healthy")
        );
        assert_eq!(
            snapshot.checks["external_probe"].reason_code,
            "external_probe.healthy"
        );
        assert_eq!(snapshot.port_forward.externally_verified, Some(true));
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Verified);
        assert!(snapshot.port_forward.dnat_installed);
        assert_eq!(
            snapshot.checks["port_forward.verification"].impact,
            Impact::Optional
        );
    }

    #[tokio::test]
    async fn explicit_unreachable_result_marks_matching_lease_failed() {
        let publisher = publisher_with_active_lease();
        observe_external_probe(
            &publisher,
            reported_result("degraded", Some(false), "external_probe.port_unreachable"),
            FRESHNESS_MS,
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, Some(false));
        assert_eq!(
            snapshot.port_forward.phase,
            PortForwardPhase::VerificationFailed
        );
        assert!(snapshot.port_forward.dnat_installed);
        assert!(!snapshot.recovery.active);
    }

    #[tokio::test]
    async fn verifier_loss_after_success_returns_to_installed_without_removing_dnat() {
        let publisher = publisher_with_active_lease();
        observe_external_probe(
            &publisher,
            reported_result("healthy", Some(true), "external_probe.healthy"),
            FRESHNESS_MS,
        )
        .await;
        assert_eq!(
            publisher.subscribe().borrow().port_forward.phase,
            PortForwardPhase::Verified
        );

        observe_external_probe_unavailable(
            &publisher,
            "external_probe.unavailable",
            "The external verifier is unavailable",
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(
            snapshot.external_probe.status,
            ExternalProbeStatus::Unavailable
        );
        assert_eq!(snapshot.external_probe.tcp_port_reachable, None);
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
        assert!(snapshot.port_forward.dnat_installed);
        assert!(!snapshot.recovery.active);
    }

    #[tokio::test]
    async fn identical_verification_evidence_emits_no_duplicate_transitions() {
        let publisher = publisher_with_active_lease();
        let result = reported_result("healthy", Some(true), "external_probe.healthy");
        observe_external_probe(&publisher, result, FRESHNESS_MS).await;
        let transitions = publisher.subscribe().borrow().transitions.len();

        let result = reported_result("healthy", Some(true), "external_probe.healthy");
        observe_external_probe(&publisher, result, FRESHNESS_MS).await;

        assert_eq!(
            publisher.subscribe().borrow().transitions.len(),
            transitions
        );
    }

    #[tokio::test]
    async fn non_healthy_null_result_cannot_verify_a_matching_lease() {
        let publisher = publisher_with_active_lease();
        observe_external_probe(
            &publisher,
            reported_result("unavailable", None, "external_probe.invalid_request"),
            FRESHNESS_MS,
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(
            snapshot.external_probe.status,
            ExternalProbeStatus::Unavailable
        );
        assert_eq!(snapshot.external_probe.tcp_port_reachable, None);
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
        assert!(snapshot.port_forward.dnat_installed);
    }

    #[tokio::test]
    async fn stale_result_cannot_verify_a_matching_lease() {
        let publisher = publisher_with_active_lease();
        let mut result = reported_result("healthy", Some(true), "external_probe.healthy");
        result.request_started_at_unix_ms = Some(
            crate::runtime::unix_ms()
                .saturating_sub(FRESHNESS_MS)
                .saturating_sub(1),
        );
        observe_external_probe(&publisher, result, FRESHNESS_MS).await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
    }

    #[tokio::test]
    async fn stale_service_observation_cannot_verify_a_matching_lease() {
        let publisher = publisher_with_active_lease();
        let mut result = reported_result("healthy", Some(true), "external_probe.healthy");
        result.observed_at_unix_ms = crate::runtime::unix_ms()
            .saturating_sub(FRESHNESS_MS)
            .saturating_sub(1);
        observe_external_probe(&publisher, result, FRESHNESS_MS).await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
    }

    #[tokio::test]
    async fn previous_lease_result_cannot_verify_a_renewed_lease() {
        let publisher = publisher_with_active_lease();
        let mut result = reported_result("healthy", Some(true), "external_probe.healthy");
        result.lease_acquired_at_unix_ms = Some(LEASE_ACQUIRED_AT - 1);
        observe_external_probe(&publisher, result, FRESHNESS_MS).await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
    }

    #[tokio::test]
    async fn evidence_for_verified_lease_cannot_verify_its_replacement() {
        let publisher = publisher_with_active_lease();
        let old_result = reported_result("healthy", Some(true), "external_probe.healthy");
        observe_external_probe(&publisher, old_result, FRESHNESS_MS).await;
        assert_eq!(
            publisher.subscribe().borrow().port_forward.phase,
            PortForwardPhase::Verified
        );

        publisher
            .mutate(|snapshot| {
                snapshot.port_forward.external_port = Some(PORT + 1);
                snapshot.port_forward.lease_acquired_at_unix_ms = Some(LEASE_ACQUIRED_AT + 1);
                snapshot.port_forward.phase = PortForwardPhase::Installed;
                snapshot.port_forward.externally_verified = None;
            })
            .await;
        let old_result = reported_result("healthy", Some(true), "external_probe.healthy");
        observe_external_probe(&publisher, old_result, FRESHNESS_MS).await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
        assert!(snapshot.port_forward.dnat_installed);
    }

    #[tokio::test]
    async fn malformed_status_cannot_verify_the_active_lease() {
        let publisher = publisher_with_active_lease();
        observe_external_probe(
            &publisher,
            reported_result("not-a-status", Some(true), "external_probe.healthy"),
            FRESHNESS_MS,
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(
            snapshot.external_probe.status,
            ExternalProbeStatus::Unavailable
        );
        assert_eq!(
            snapshot.external_probe.reason_code.as_deref(),
            Some("external_probe.invalid_response")
        );
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
    }

    #[tokio::test]
    async fn different_port_result_cannot_verify_the_active_lease() {
        let publisher = publisher_with_active_lease();
        let mut result = reported_result("healthy", Some(true), "external_probe.healthy");
        result.forwarded_port = Some(PORT + 1);
        observe_external_probe(&publisher, result, FRESHNESS_MS).await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
    }

    #[tokio::test]
    async fn contradictory_healthy_response_cannot_verify_the_active_lease() {
        let publisher = publisher_with_active_lease();
        observe_external_probe(
            &publisher,
            reported_result("healthy", Some(false), "external_probe.healthy"),
            FRESHNESS_MS,
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
    }

    #[tokio::test]
    async fn missing_external_probe_result_is_marked_unavailable() {
        let publisher = publisher_with_active_lease();
        observe_external_probe_unavailable(
            &publisher,
            "external_probe.unavailable",
            "The external probe has not reported yet",
        )
        .await;

        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(
            snapshot.external_probe.status,
            ExternalProbeStatus::Unavailable
        );
        assert_eq!(
            snapshot.external_probe.reason_code.as_deref(),
            Some("external_probe.unavailable")
        );
        assert_eq!(snapshot.port_forward.externally_verified, None);
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Installed);
        assert!(snapshot.port_forward.dnat_installed);
    }
}
