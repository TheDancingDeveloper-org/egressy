use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::{
    process::Command,
    signal,
    sync::{watch, RwLock},
    time::{interval, sleep},
};
use tracing::{error, info, warn};
use zeroize::Zeroize;

use crate::{
    config::Config,
    control::StatePublisher,
    docker::DockerObserver,
    domain::{
        CanonicalSnapshot, CheckStatus, Impact, PortForwardPhase, TopologyStatus,
        VpnServerLatencyStatus,
    },
    enforcement::{DnatTarget, EnforcementCoordinator},
    history::{HistoryStore, PortForwardObservation, UsageObservation},
    natpmp::{self, Client as NatPmpClient},
    state::{AppState, RouteIntentStatus, SharedState},
    web,
};

pub type SharedHistory = Arc<RwLock<Option<HistoryStore>>>;

pub async fn run(
    config: Config,
    telemetry: Option<crate::telemetry::TelemetryGuard>,
) -> anyhow::Result<()> {
    config.validate()?;
    // Install the fail-closed policy before bringing up the tunnel. Until wg0
    // exists, enrolled traffic is rejected instead of escaping via the uplink.
    let enforcement = EnforcementCoordinator::new(config.clone());
    enforcement.reconcile_base().await?;
    let profile_store = config
        .wireguard
        .storage_key_path
        .as_ref()
        .and_then(|key_path| {
            match crate::profiles::ProfileStore::open(
                &config.wireguard.profile_database_path,
                std::path::Path::new(key_path),
            ) {
                Ok(store) => Some(store),
                Err(error) => {
                    warn!(%error, "managed profile storage is unavailable; plaintext fallback is disabled");
                    None
                }
            }
        });
    let active_profile = match config.wireguard.source {
        crate::config::ProfileSource::Mounted => match load_mounted_profile(&config).await {
            Ok(profile) => profile,
            Err(error) => {
                warn!(%error, "selected mounted WireGuard profile is unusable; management remains available");
                None
            }
        },
        crate::config::ProfileSource::GuiManaged => match &profile_store {
            Some(store) => match store.active().await {
                Ok(active) => active.map(|(_, profile)| profile),
                Err(error) => {
                    warn!(%error, "selected managed WireGuard profile is unusable; management remains available");
                    None
                }
            },
            None => None,
        },
    };
    let active_profile = match active_profile {
        Some(profile) => match validate_profile_capabilities(&config, &profile) {
            Ok(()) => Some(profile),
            Err(error) => {
                warn!(%error, "selected profile is incompatible with configured capabilities; management remains available");
                None
            }
        },
        None => None,
    };
    let configured_peer = active_profile
        .as_ref()
        .and_then(configured_peer_from_profile);
    let initial_dns_upstream = dns_upstream(&config, active_profile.as_ref());
    let (dns_upstream_tx, dns_upstream_rx) = watch::channel(initial_dns_upstream);
    let state: SharedState = Arc::new(RwLock::new(AppState::default()));
    let profile_manager = crate::profile_manager::ProfileManager::new(
        config.clone(),
        profile_store,
        enforcement.clone(),
        active_profile.clone(),
        dns_upstream_tx,
    );
    profile_manager.initialize().await?;
    let publisher = StatePublisher::new(CanonicalSnapshot {
        topology: TopologyStatus {
            network: config.network.name.clone(),
            subnet: config.network.subnet.to_string(),
            gateway_address: config.network.gateway_ip.to_string(),
            host_bridge: config.network.host_bridge.clone(),
            policy_table: config.network.route_table,
            ..TopologyStatus::default()
        },
        vpn_server: configured_peer
            .as_ref()
            .map(crate::vpn_server::configured_status)
            .unwrap_or_default(),
        ..CanonicalSnapshot::default()
    });
    let history: SharedHistory = Arc::new(RwLock::new(None));
    if config.persistence.enabled {
        match open_history(config.persistence.clone()).await {
            Ok(store) => {
                *history.write().await = Some(store);
                publisher
                    .observe(
                        "history.persistence",
                        CheckStatus::Healthy,
                        Impact::Advisory,
                        "history.database_ready",
                        "App-owned history database is ready",
                        None,
                        None,
                    )
                    .await;
            }
            Err(error) => {
                warn!(%error, "history database is unavailable; the data plane will continue");
                publisher
                    .observe(
                        "history.persistence",
                        CheckStatus::Degraded,
                        Impact::Advisory,
                        "history.database_unavailable",
                        "App-owned history is unavailable; current-state operation continues",
                        None,
                        None,
                    )
                    .await;
            }
        }
    } else {
        publisher
            .observe(
                "history.persistence",
                CheckStatus::Unknown,
                Impact::Advisory,
                "history.disabled",
                "App-owned history is disabled by configuration",
                None,
                None,
            )
            .await;
    }
    let history_supervisor_task = config.persistence.enabled.then(|| {
        tokio::spawn(supervise_history(
            config.persistence.clone(),
            history.clone(),
            publisher.clone(),
        ))
    });
    let history_recorder_task = config
        .persistence
        .enabled
        .then(|| tokio::spawn(record_history(history.clone(), publisher.clone())));
    let notifications = crate::notifications::NotificationManager::start(history.clone()).await;
    let notification_monitor_task = tokio::spawn(crate::notifications::monitor_transitions(
        notifications.clone(),
        publisher.clone(),
    ));
    let telemetry_monitor_task = telemetry.as_ref().map(|telemetry| {
        tokio::spawn(monitor_telemetry(
            telemetry.status.clone(),
            crate::telemetry::TelemetryMetrics::new(),
            publisher.clone(),
        ))
    });
    let telemetry_metrics = crate::telemetry::TelemetryMetrics::new();
    let vpn_server_task = tokio::spawn(monitor_vpn_server(
        config.clone(),
        profile_manager.clone(),
        publisher.clone(),
        history.clone(),
        crate::telemetry::TelemetryMetrics::new(),
        notifications.clone(),
    ));
    publisher
        .observe(
            "telemetry.otel",
            if telemetry.is_some() {
                CheckStatus::Unknown
            } else {
                CheckStatus::Healthy
            },
            Impact::Optional,
            if telemetry.is_some() {
                "otel.awaiting_export"
            } else {
                "otel.disabled"
            },
            if telemetry.is_some() {
                "OTEL is enabled and awaiting the first export result"
            } else {
                "OTEL export is disabled"
            },
            None,
            None,
        )
        .await;
    publisher
        .observe(
            "gateway.firewall",
            if config.reconcile.apply_gateway_firewall {
                CheckStatus::Healthy
            } else {
                CheckStatus::Unknown
            },
            Impact::Critical,
            if config.reconcile.apply_gateway_firewall {
                "firewall.policy_installed"
            } else {
                "firewall.verification_disabled"
            },
            if config.reconcile.apply_gateway_firewall {
                "The owned fail-closed firewall policy is installed"
            } else {
                "Firewall application and verification are disabled"
            },
            None,
            None,
        )
        .await;
    publisher
        .observe(
            "gateway.routes",
            CheckStatus::Unknown,
            Impact::Critical,
            "routes.awaiting_profile",
            "Gateway routes are awaiting an active profile",
            None,
            None,
        )
        .await;
    state
        .write()
        .await
        .tunnel
        .interface
        .clone_from(&config.wireguard.interface);

    let observer = DockerObserver::connect(
        &config.docker_socket,
        config.network.name.clone(),
        config.network.subnet,
        config.port_forwarding.max_leases,
    )?;

    let listen: SocketAddr = config.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let app = web::router(
        state.clone(),
        publisher.clone(),
        history.clone(),
        notifications.clone(),
        profile_manager.clone(),
        web::AdminAuth::load(&config.wireguard)?,
    );
    let mut server = tokio::spawn(async move { axum::serve(listener, app).await });
    info!(%listen, "dashboard listening");
    notifications.stack_started().await;

    if config.wireguard.manage {
        if let Some(profile) = &active_profile {
            match wireguard_up(&config, profile).await {
                Ok(()) => {
                    publisher
                        .observe(
                            "gateway.routes",
                            CheckStatus::Healthy,
                            Impact::Critical,
                            "routes.policy_installed",
                            "Gateway source-policy routes were installed",
                            None,
                            None,
                        )
                        .await;
                }
                Err(error) => {
                    warn!(%error, "WireGuard startup failed; management remains available and traffic stays blocked");
                    profile_manager.mark_degraded().await;
                }
            }
        }
    }

    // Docker enrollment and tunnel changes must interrupt the NAT-PMP renewal
    // sleep so stale DNAT is removed at the reconciliation cadence rather than
    // at the provider lease-refresh cadence.
    let (port_change_tx, port_change_rx) = watch::channel(0_u64);

    let mut docker_task = tokio::spawn(reconcile_docker(
        config.clone(),
        state.clone(),
        publisher.clone(),
        observer,
        enforcement.clone(),
        port_change_tx.clone(),
    ));
    let mut tunnel_task = tokio::spawn(monitor_tunnel(
        config.clone(),
        profile_manager.clone(),
        state.clone(),
        publisher.clone(),
        enforcement.clone(),
        port_change_tx,
    ));
    let mut port_task = tokio::spawn(maintain_port_forward(
        config.clone(),
        state.clone(),
        publisher.clone(),
        enforcement.clone(),
        port_change_rx,
    ));
    let mut probe_task = tokio::spawn(crate::probe::monitor(config.clone(), publisher.clone()));
    let mut client_traffic_task = tokio::spawn(monitor_client_traffic(
        state.clone(),
        publisher.clone(),
        enforcement.clone(),
        history.clone(),
        telemetry_metrics,
    ));
    let mut dns_task = if config.dns.enabled {
        let listen = config.dns.listen.parse()?;
        publisher
            .observe(
                "dns.listener",
                CheckStatus::Healthy,
                Impact::Critical,
                "dns.listener_started",
                "UDP and TCP DNS listeners started",
                None,
                None,
            )
            .await;
        Some(tokio::spawn(crate::dns::supervise(crate::dns::Settings {
            listen,
            upstream: dns_upstream_rx,
            timeout: Duration::from_millis(config.dns.timeout_ms),
            max_concurrent_queries: config.dns.max_concurrent_queries,
            udp_attempts: config.dns.udp_attempts,
            failure_threshold: config.dns.failure_threshold,
            success_threshold: config.dns.success_threshold,
            publisher: Some(publisher.clone()),
        })))
    } else {
        None
    };

    let run_result: anyhow::Result<()> = tokio::select! {
        result = &mut server => result.context("HTTP server task panicked")?.context("HTTP server failed"),
        _ = signal::ctrl_c() => {
            info!("shutdown requested");
            Ok(())
        },
        result = &mut docker_task => flatten_task_result(result, "Docker observer task panicked"),
        result = &mut tunnel_task => flatten_task_result(result, "tunnel monitor task panicked"),
        result = &mut port_task => flatten_task_result(result, "port-forward task panicked"),
        result = &mut probe_task => flatten_task_result(result, "client-path probe monitor panicked"),
        result = &mut client_traffic_task => flatten_task_result(result, "client traffic monitor panicked"),
        result = async { dns_task.as_mut().expect("guarded by dns.enabled").await }, if dns_task.is_some() => {
            flatten_task_result(result, "DNS task panicked")
        }
    };

    // Stop every task capable of changing the data plane, and wait until it is
    // actually gone, before observability flushes or WireGuard teardown begin.
    stop_task(docker_task).await;
    stop_task(port_task).await;
    stop_task(probe_task).await;
    stop_task(client_traffic_task).await;
    if let Some(task) = dns_task {
        stop_task(task).await;
    }
    stop_task(tunnel_task).await;
    if let Some(task) = history_supervisor_task {
        stop_task(task).await;
    }
    if let Some(task) = history_recorder_task {
        stop_task(task).await;
    }
    if let Some(task) = telemetry_monitor_task {
        stop_task(task).await;
    }
    stop_task(vpn_server_task).await;
    stop_task(notification_monitor_task).await;
    stop_task(server).await;
    if let Some(store) = history.read().await.clone() {
        if let Err(error) = store.shutdown().await {
            warn!(%error, "history writer did not flush cleanly during shutdown");
        }
    }
    if let Some(telemetry) = telemetry {
        telemetry.shutdown();
    }

    if config.wireguard.manage {
        wireguard_down(&config).await;
    }
    run_result
}

fn flatten_task_result(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    panic_context: &'static str,
) -> anyhow::Result<()> {
    result.context(panic_context)?
}

async fn stop_task<T>(task: tokio::task::JoinHandle<T>) {
    // The branch selected by `tokio::select!` has already consumed its output;
    // polling that completed JoinHandle again would violate the Future contract.
    if task.is_finished() {
        return;
    }
    task.abort();
    match task.await {
        Ok(_) => {}
        Err(error) if error.is_cancelled() => {}
        Err(error) => warn!(%error, "task panicked while shutdown was in progress"),
    }
}

fn configured_peer_from_profile(
    profile: &crate::wireguard::WireGuardProfile,
) -> Option<crate::vpn_server::ConfiguredPeer> {
    crate::vpn_server::parse_wireguard_profile(&profile.render()).ok()
}

async fn monitor_vpn_server(
    config: Config,
    profiles: crate::profile_manager::ProfileManager,
    publisher: StatePublisher,
    history: SharedHistory,
    telemetry_metrics: crate::telemetry::TelemetryMetrics,
    notifications: crate::notifications::NotificationManager,
) -> anyhow::Result<()> {
    let mut ticker = interval(Duration::from_secs(config.vpn_server.interval_seconds));
    let mut window = crate::vpn_server::LatencyWindow::default();
    let mut previous_endpoint = None;
    let mut rtt_above_threshold = false;
    loop {
        ticker.tick().await;
        let Some(peer) = profiles.configured_peer().await else {
            continue;
        };
        let now_ms = unix_ms();
        let now_seconds = now_ms / 1_000;
        let handshake = wireguard_handshake(&config.wireguard.interface)
            .await
            .ok()
            .flatten();
        let active =
            handshake.is_some_and(|value| value != 0 && now_seconds.saturating_sub(value) < 180);
        match crate::vpn_server::runtime_endpoint(&config.wireguard.interface).await {
            Ok(endpoint) => {
                if previous_endpoint.is_some_and(|previous| previous != endpoint) {
                    publisher
                        .emit(
                            "vpn_server.endpoint",
                            "vpn_server.endpoint_changed",
                            "The runtime WireGuard peer endpoint changed",
                        )
                        .await;
                }
                previous_endpoint = Some(endpoint);
                let result = if config.vpn_server.latency_probe_enabled {
                    crate::vpn_server::probe_endpoint(
                        endpoint,
                        &config.wireguard.interface,
                        Duration::from_millis(config.vpn_server.timeout_ms),
                    )
                    .await
                    .unwrap_or(crate::vpn_server::ProbeResult::Unavailable)
                } else {
                    crate::vpn_server::ProbeResult::Unsupported
                };
                window.record(result.rtt());
                if let Some(rtt) = result.rtt() {
                    telemetry_metrics.record_vpn_server_rtt(
                        if endpoint.is_ipv4() { "ipv4" } else { "ipv6" },
                        rtt,
                    );
                    notifications
                        .rtt_sample(rtt, &mut rtt_above_threshold)
                        .await;
                }
                let latency = window.state(result.status(), now_ms);
                publisher
                    .mutate(|snapshot| {
                        snapshot.vpn_server.configured_endpoint_host =
                            Some(peer.endpoint_host.clone());
                        snapshot.vpn_server.configured_endpoint_port = Some(peer.endpoint_port);
                        snapshot.vpn_server.runtime_endpoint_address =
                            Some(endpoint.ip().to_string());
                        snapshot.vpn_server.runtime_endpoint_port = Some(endpoint.port());
                        snapshot.vpn_server.active = active;
                        snapshot.vpn_server.latest_handshake_unix = handshake;
                        snapshot.vpn_server.handshake_age_seconds =
                            handshake.map(|value| now_seconds.saturating_sub(value));
                        snapshot.vpn_server.observed_at_unix_ms = Some(now_ms);
                        snapshot.vpn_server.latency = latency.clone();
                    })
                    .await;
                if let Some(store) = history.read().await.clone() {
                    store.record_vpn_server(crate::history::VpnServerObservation {
                        timestamp_unix_ms: now_ms,
                        configured_endpoint_host: peer.endpoint_host.clone(),
                        runtime_endpoint_address: endpoint.ip().to_string(),
                        runtime_endpoint_port: endpoint.port(),
                        active,
                        latency_status: result.status(),
                        rtt_ms: result.rtt(),
                    });
                }
                publisher
                    .observe(
                        "vpn_server.latency",
                        match result.status() {
                            VpnServerLatencyStatus::Measured => CheckStatus::Healthy,
                            VpnServerLatencyStatus::Timeout
                            | VpnServerLatencyStatus::Unsupported
                            | VpnServerLatencyStatus::ResolutionFailed
                            | VpnServerLatencyStatus::Unavailable => CheckStatus::Unknown,
                        },
                        Impact::Optional,
                        match result.status() {
                            VpnServerLatencyStatus::Measured => "vpn_server.latency_measured",
                            VpnServerLatencyStatus::Timeout => "vpn_server.icmp_timeout",
                            VpnServerLatencyStatus::Unsupported => "vpn_server.icmp_unsupported",
                            VpnServerLatencyStatus::ResolutionFailed => {
                                "vpn_server.route_unavailable"
                            }
                            VpnServerLatencyStatus::Unavailable => "vpn_server.probe_unavailable",
                        },
                        if result.status() == VpnServerLatencyStatus::Measured {
                            "Underlay latency to the active WireGuard endpoint was measured"
                        } else {
                            "WireGuard endpoint latency is unavailable; tunnel health is independent"
                        },
                        None,
                        None,
                    )
                    .await;
            }
            Err(error) => {
                warn!(%error, "VPN-server endpoint observation is unavailable");
                window.record(None);
                publisher
                    .mutate(|snapshot| {
                        snapshot.vpn_server.active = active;
                        snapshot.vpn_server.latest_handshake_unix = handshake;
                        snapshot.vpn_server.handshake_age_seconds =
                            handshake.map(|value| now_seconds.saturating_sub(value));
                        snapshot.vpn_server.observed_at_unix_ms = Some(now_ms);
                        snapshot.vpn_server.latency =
                            window.state(VpnServerLatencyStatus::Unavailable, now_ms);
                    })
                    .await;
                publisher
                    .observe(
                        "vpn_server.latency",
                        CheckStatus::Unknown,
                        Impact::Optional,
                        "vpn_server.endpoint_unavailable",
                        "The runtime WireGuard endpoint is unavailable for advisory latency sampling",
                        None,
                        None,
                    )
                    .await;
            }
        }
    }
}

async fn monitor_telemetry(
    status: crate::telemetry::ExportStatus,
    metrics: crate::telemetry::TelemetryMetrics,
    publisher: StatePublisher,
) {
    let mut ticker = interval(Duration::from_secs(15));
    let mut observed_failures = 0;
    loop {
        ticker.tick().await;
        let failures = status.failed_exports();
        let successes = status.successful_exports();
        let last_failure = status.last_failure_unix_ms();
        let last_success = status.last_success_unix_ms();
        metrics.record_export_status(&status);
        let failed_after_success =
            last_failure.is_some_and(|failed| last_success.is_none_or(|success| failed > success));
        publisher
            .observe(
                "telemetry.otel",
                if failed_after_success || failures > observed_failures {
                    CheckStatus::Degraded
                } else if successes > 0 {
                    CheckStatus::Healthy
                } else {
                    CheckStatus::Unknown
                },
                Impact::Optional,
                if failed_after_success || failures > observed_failures {
                    "otel.export_failed"
                } else if successes > 0 {
                    "otel.export_succeeded"
                } else {
                    "otel.awaiting_export"
                },
                if failed_after_success || failures > observed_failures {
                    "One or more OTEL exports failed; local operation continues"
                } else if successes > 0 {
                    "OTEL export has succeeded"
                } else {
                    "OTEL is enabled and awaiting the first export result"
                },
                None,
                None,
            )
            .await;
        observed_failures = failures;
    }
}

async fn reconcile_docker(
    config: Config,
    state: SharedState,
    publisher: StatePublisher,
    observer: DockerObserver,
    enforcement: EnforcementCoordinator,
    port_change_tx: watch::Sender<u64>,
) -> anyhow::Result<()> {
    let mut ticker = interval(config.reconcile_interval());
    loop {
        ticker.tick().await;
        match observer.inspect_network(config.network.gateway_ip).await {
            Ok(network) => {
                let matches = network.exists && network.subnet_matches && network.gateway_attached;
                publisher.observe(
                    "topology.docker_network",
                    if matches { CheckStatus::Healthy } else { CheckStatus::Failed },
                    Impact::Critical,
                    if matches { "topology.network_matches" } else { "topology.network_mismatch" },
                    if matches { "Docker network subnet and gateway attachment match configuration" } else { "Docker network subnet or gateway attachment does not match configuration" },
                    None,
                    None,
                ).await;
                if network.ipv6_enabled {
                    publisher
                        .observe(
                            "topology.network_ipv6",
                            CheckStatus::Degraded,
                            Impact::Advisory,
                            "topology.network_ipv6_enabled",
                            "The enrolled Docker network has IPv6 enabled, which is unsupported",
                            None,
                            None,
                        )
                        .await;
                }
            }
            Err(error) => {
                warn!(%error, "Docker network inspection failed");
                publisher
                    .observe(
                        "topology.docker_network",
                        CheckStatus::Failed,
                        Impact::Critical,
                        "topology.network_missing",
                        "The configured Docker network could not be inspected",
                        None,
                        None,
                    )
                    .await;
            }
        }
        match observer.discover().await {
            Ok(clients) => {
                let target_count = clients
                    .values()
                    .filter(|client| client.port_forward_target && client.compliant)
                    .count();
                let existing_traffic = state
                    .read()
                    .await
                    .clients
                    .iter()
                    .map(|(id, client)| (id.clone(), (client.ipv4_address, client.traffic.clone())))
                    .collect::<std::collections::BTreeMap<_, _>>();
                let mut clients = clients;
                for (id, client) in &mut clients {
                    if let Some((_, traffic)) = existing_traffic
                        .get(id)
                        .filter(|(address, _)| *address == client.ipv4_address)
                    {
                        client.traffic = traffic.clone();
                    }
                }
                let old_port_inputs = {
                    let current = state.read().await;
                    port_forward_target_inputs(&current.clients)
                };
                let new_port_inputs = port_forward_target_inputs(&clients);
                let port_inputs_changed = old_port_inputs != new_port_inputs;
                enforcement
                    .reconcile_clients(&clients, port_inputs_changed)
                    .await?;
                state.write().await.clients = clients.clone();
                if port_inputs_changed {
                    notify_port_change(&port_change_tx);
                }
                let has_ipv6 = clients.values().any(|client| client.ipv6_address.is_some());
                let invalid_labels = clients
                    .values()
                    .any(|client| !client.port_forward_label_valid);
                let stopped = clients.values().any(|client| !client.running);
                let route_mismatch = clients
                    .values()
                    .any(|client| client.route_intent.status == RouteIntentStatus::Mismatch);
                let route_unknown = clients
                    .values()
                    .any(|client| client.route_intent.status == RouteIntentStatus::Unknown);
                let client_count = clients.len();
                publisher
                    .mutate(|snapshot| snapshot.clients = clients.clone())
                    .await;
                publisher
                    .observe(
                        "docker.discovery",
                        CheckStatus::Healthy,
                        Impact::Advisory,
                        "docker.discovery_fresh",
                        "Docker enrollment inventory is fresh",
                        None,
                        None,
                    )
                    .await;
                publisher
                    .observe(
                        "topology.route_intent",
                        if route_mismatch {
                            CheckStatus::Degraded
                        } else if route_unknown {
                            CheckStatus::Unknown
                        } else {
                            CheckStatus::Healthy
                        },
                        Impact::Advisory,
                        if route_mismatch {
                            "route_intent.alternate_selected"
                        } else if route_unknown {
                            "route_intent.unknown"
                        } else if client_count == 0 {
                            "route_intent.no_clients"
                        } else {
                            "route_intent.egress_selected"
                        },
                        if route_mismatch {
                            "Docker declares an alternate IPv4 default for one or more enrolled clients; effective routes are not runtime-attested"
                        } else if route_unknown {
                            "Docker gateway metadata is insufficient for one or more enrolled clients; effective routes are not runtime-attested"
                        } else if client_count == 0 {
                            "No enrolled clients require a declared-route observation"
                        } else {
                            "Docker declares the egress network as the IPv4 default for all enrolled clients; effective routes are not runtime-attested"
                        },
                        None,
                        None,
                    )
                    .await;
                publisher.observe(
                    "topology.client_ipv6",
                    if has_ipv6 { CheckStatus::Degraded } else { CheckStatus::Healthy },
                    Impact::Advisory,
                    if has_ipv6 { "topology.client_ipv6_unsupported" } else { "topology.client_ipv4_only" },
                    if has_ipv6 { "An enrolled client has an IPv6 address; client IPv6 leak protection is unsupported" } else { "No enrolled client IPv6 address was discovered" },
                    None,
                    None,
                ).await;
                publisher
                    .observe(
                        "port_forward.target_selection",
                        if invalid_labels || clients.values().any(|client| {
                            client.port_forward_target && !client.compliant
                        }) {
                            CheckStatus::Degraded
                        } else {
                            CheckStatus::Healthy
                        },
                        Impact::Optional,
                        if invalid_labels {
                            "port_forward.target_port_invalid"
                        } else if clients.values().any(|client| {
                            client.port_forward_target && !client.compliant
                        }) {
                            "port_forward.target_ineligible"
                        } else {
                            "port_forward.target_valid"
                        },
                        if invalid_labels {
                            "A forwarding target has a missing or invalid target-port label"
                        } else if clients.values().any(|client| {
                            client.port_forward_target && !client.compliant
                        }) {
                            "One or more forwarding targets are ineligible because of a duplicate target port, duplicate usage ID, lease cap, or routing compliance"
                        } else if target_count == 0 {
                            "No forwarding target is currently eligible"
                        } else {
                            "Forwarding target labels are valid and within the configured lease limit"
                        },
                        None,
                        None,
                    )
                    .await;
                publisher
                    .observe(
                        "topology.client_lifecycle",
                        if stopped {
                            CheckStatus::Degraded
                        } else {
                            CheckStatus::Healthy
                        },
                        Impact::Advisory,
                        if stopped {
                            "topology.client_not_running"
                        } else {
                            "topology.clients_running"
                        },
                        if stopped {
                            "One or more enrolled containers are not running"
                        } else {
                            "All discovered enrolled containers are running"
                        },
                        None,
                        None,
                    )
                    .await;
                publisher.observe("topology.configured", CheckStatus::Healthy, Impact::Critical, "topology.config_consistent", "Configured subnet, gateway, bridge, and policy table are internally consistent", None, None).await;
            }
            Err(error) => {
                warn!(%error, "Docker discovery failed");
                state.write().await.last_error = Some(format!("Docker discovery failed: {error}"));
                publisher
                    .observe(
                        "docker.discovery",
                        CheckStatus::Degraded,
                        Impact::Advisory,
                        "docker.discovery_failed",
                        "Docker enrollment inventory could not be refreshed",
                        None,
                        None,
                    )
                    .await;
            }
        }
        match observer.discover_isolation_candidates().await {
            Ok(candidates) => {
                let policy = crate::isolation::build_policy(
                    &config.network.name,
                    &config.network.host_bridge,
                    config.network.subnet,
                    candidates,
                    unix_ms(),
                );
                let complete = policy.eligible_for_enforcement;
                let has_participants = !policy.participants.is_empty();
                publisher
                    .mutate(|snapshot| {
                        snapshot.topology.client_isolation = if complete {
                            "policy_complete_agent_mode_external".to_owned()
                        } else if has_participants {
                            "policy_incomplete_audit_only".to_owned()
                        } else {
                            "no_running_participants".to_owned()
                        };
                        snapshot.isolation_policy = policy;
                    })
                    .await;
                publisher
                    .observe(
                        "topology.client_isolation",
                        if complete {
                            CheckStatus::Healthy
                        } else if has_participants {
                            CheckStatus::Degraded
                        } else {
                            CheckStatus::Unknown
                        },
                        Impact::Advisory,
                        if complete {
                            "isolation.policy_complete"
                        } else if has_participants {
                            "isolation.policy_incomplete"
                        } else {
                            "isolation.no_participants"
                        },
                        if complete {
                            "Every running bridge participant has a complete isolation identity and allow-list"
                        } else if has_participants {
                            "Bridge isolation policy is incomplete; enforce mode must degrade to audit"
                        } else {
                            "No running IPv4 bridge participants were discovered"
                        },
                        None,
                        None,
                    )
                    .await;
            }
            Err(error) => {
                warn!(%error, "Docker isolation inventory failed");
                publisher
                    .observe(
                        "topology.client_isolation",
                        CheckStatus::Degraded,
                        Impact::Advisory,
                        "isolation.inventory_unavailable",
                        "Bridge isolation inventory could not be refreshed",
                        None,
                        None,
                    )
                    .await;
            }
        }
    }
}

const CLIENT_TRAFFIC_HISTORY_CAPACITY: usize = 120;

async fn monitor_client_traffic(
    state: SharedState,
    publisher: StatePublisher,
    enforcement: EnforcementCoordinator,
    history: SharedHistory,
    telemetry_metrics: crate::telemetry::TelemetryMetrics,
) -> anyhow::Result<()> {
    let mut ticker = interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        match enforcement.sample_client_counters().await {
            Ok(counters) => {
                let now = unix_ms();
                let mut legacy = state.write().await;
                for (container_id, totals) in counters {
                    let Some(client) = legacy.clients.get_mut(&container_id) else {
                        continue;
                    };
                    client.traffic.download_packets = totals.download_packets;
                    client.traffic.downloaded_bytes = totals.downloaded_bytes;
                    client.traffic.upload_packets = totals.upload_packets;
                    client.traffic.uploaded_bytes = totals.uploaded_bytes;
                    client.traffic.sampled_at_unix_ms = Some(now);
                    record_client_traffic_sample(&mut client.traffic, now);
                    telemetry_metrics.record_client(
                        &client.usage_id,
                        totals.downloaded_bytes,
                        totals.uploaded_bytes,
                        totals.download_packets,
                        totals.upload_packets,
                    );
                    if let Some(store) = history.read().await.clone() {
                        store.record_usage(UsageObservation {
                            sampled_at_unix_ms: now,
                            usage_id: client.usage_id.clone(),
                            usage_id_source: client.usage_id_source,
                            container_id: container_id.clone(),
                            ipv4_address: client.ipv4_address.to_string(),
                            name: client.name.clone(),
                            download_bytes: totals.downloaded_bytes,
                            upload_bytes: totals.uploaded_bytes,
                            download_packets: totals.download_packets,
                            upload_packets: totals.upload_packets,
                        });
                    }
                }
                let clients = legacy.clients.clone();
                drop(legacy);
                publisher
                    .mutate(|snapshot| snapshot.clients = clients)
                    .await;
                publisher
                    .observe(
                        "traffic.clients",
                        CheckStatus::Healthy,
                        Impact::Advisory,
                        "traffic.client_counters_sampled",
                        "Per-client nftables counters were sampled",
                        None,
                        None,
                    )
                    .await;
            }
            Err(error) => {
                warn!(%error, "unable to sample per-client nftables counters");
                publisher
                    .observe(
                        "traffic.clients",
                        CheckStatus::Degraded,
                        Impact::Advisory,
                        "traffic.client_counters_unavailable",
                        "Per-client nftables counters are unavailable",
                        None,
                        None,
                    )
                    .await;
            }
        }
    }
}

async fn open_history(config: crate::config::PersistenceConfig) -> anyhow::Result<HistoryStore> {
    tokio::task::spawn_blocking(move || HistoryStore::open(&config))
        .await
        .context("history initialization worker panicked")?
}

async fn supervise_history(
    config: crate::config::PersistenceConfig,
    history: SharedHistory,
    publisher: StatePublisher,
) {
    let mut ticker = interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        let current = history.read().await.clone();
        if let Some(store) = current {
            match store.flush().await {
                Ok(()) => {
                    let dropped = store.dropped_writes();
                    publisher
                        .observe(
                            "history.persistence",
                            if dropped == 0 {
                                CheckStatus::Healthy
                            } else {
                                CheckStatus::Degraded
                            },
                            Impact::Advisory,
                            if dropped == 0 {
                                "history.database_ready"
                            } else {
                                "history.writer_dropped_samples"
                            },
                            if dropped == 0 {
                                "App-owned history database is ready"
                            } else {
                                "The bounded history writer dropped one or more observations"
                            },
                            None,
                            None,
                        )
                        .await;
                }
                Err(error) => {
                    warn!(%error, "history writer failed; reconnecting in the background");
                    *history.write().await = None;
                    publisher
                        .observe(
                            "history.persistence",
                            CheckStatus::Degraded,
                            Impact::Advisory,
                            "history.writer_unavailable",
                            "App-owned history writer failed; current-state operation continues",
                            None,
                            None,
                        )
                        .await;
                }
            }
        } else {
            match open_history(config.clone()).await {
                Ok(store) => {
                    *history.write().await = Some(store);
                    publisher
                        .observe(
                            "history.persistence",
                            CheckStatus::Healthy,
                            Impact::Advisory,
                            "history.database_recovered",
                            "App-owned history database recovered",
                            None,
                            None,
                        )
                        .await;
                }
                Err(error) => {
                    warn!(%error, "history database retry failed");
                }
            }
        }
    }
}

async fn record_history(history: SharedHistory, publisher: StatePublisher) {
    let mut events = publisher.subscribe_events();
    let mut snapshots = publisher.subscribe();
    let mut last_port_sequences = snapshots
        .borrow()
        .port_forwards
        .iter()
        .map(|(usage_id, status)| (usage_id.clone(), status.change_sequence))
        .collect::<BTreeMap<_, _>>();
    loop {
        tokio::select! {
            event = events.recv() => {
                if let Ok(transition) = event {
                    if let Some(store) = history.read().await.clone() {
                        store.record_transition(transition);
                    }
                }
            }
            result = snapshots.changed() => {
                if result.is_err() {
                    return;
                }
                let snapshot = snapshots.borrow().clone();
                if let Some(store) = history.read().await.clone() {
                    for (usage_id, status) in &snapshot.port_forwards {
                        if status.change_sequence == 0
                            || last_port_sequences.get(usage_id) == Some(&status.change_sequence)
                        {
                            continue;
                        }
                        last_port_sequences.insert(usage_id.clone(), status.change_sequence);
                        store.record_port_forward(PortForwardObservation {
                            timestamp_unix_ms: status
                                .changed_at_unix_ms
                                .unwrap_or(snapshot.generated_at_unix_ms),
                            usage_id: usage_id.clone(),
                            phase: status.phase,
                            external_port: status.external_port,
                        });
                    }
                }
            }
        }
    }
}

fn record_client_traffic_sample(traffic: &mut crate::state::ClientTrafficState, now: u64) {
    let changed = traffic.history.back().is_none_or(|sample| {
        sample.downloaded_bytes != traffic.downloaded_bytes
            || sample.uploaded_bytes != traffic.uploaded_bytes
    });
    if changed {
        if traffic.history.len() == CLIENT_TRAFFIC_HISTORY_CAPACITY {
            traffic.history.pop_front();
        }
        traffic
            .history
            .push_back(crate::state::ClientTrafficSample {
                sampled_at_unix_ms: now,
                downloaded_bytes: traffic.downloaded_bytes,
                uploaded_bytes: traffic.uploaded_bytes,
            });
    }
}

async fn monitor_tunnel(
    config: Config,
    profiles: crate::profile_manager::ProfileManager,
    state: SharedState,
    publisher: StatePublisher,
    enforcement: EnforcementCoordinator,
    port_change_tx: watch::Sender<u64>,
) -> anyhow::Result<()> {
    let mut ticker = interval(Duration::from_secs(1));
    let mut previous_counters = None;
    let mut samples_since_handshake = 10_u8;
    let mut tunnel_failures = 0_u32;
    let mut recovery_attempt = 0_u32;
    let mut tunnel_successes = 0_u32;
    loop {
        ticker.tick().await;
        if !profiles.has_active_profile().await {
            continue;
        }
        match read_interface_counters(&config.wireguard.interface).await {
            Ok(counters) => {
                let now = Instant::now();
                let unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
                let rates = previous_counters
                    .map(|(previous, sampled_at)| {
                        calculate_rates(previous, counters, now - sampled_at)
                    })
                    .unwrap_or_default();
                previous_counters = Some((counters, now));
                let mut state = state.write().await;
                state.traffic.download_bytes_per_second = rates.0;
                state.traffic.upload_bytes_per_second = rates.1;
                state.traffic.downloaded_bytes = counters.0;
                state.traffic.uploaded_bytes = counters.1;
                state.traffic.sampled_at_unix_ms = Some(unix_ms);
                let traffic = state.traffic.clone();
                drop(state);
                publisher
                    .mutate(|snapshot| snapshot.traffic = traffic)
                    .await;
                publisher
                    .observe(
                        "wireguard.traffic",
                        CheckStatus::Healthy,
                        Impact::Advisory,
                        "wireguard.counters_sampled",
                        "WireGuard traffic counters were sampled",
                        None,
                        None,
                    )
                    .await;
            }
            Err(error) => {
                warn!(%error, "unable to sample WireGuard traffic counters");
                publisher
                    .observe(
                        "wireguard.traffic",
                        CheckStatus::Degraded,
                        Impact::Advisory,
                        "wireguard.counters_unavailable",
                        "WireGuard traffic counters are unavailable",
                        None,
                        None,
                    )
                    .await;
            }
        }

        // Handshake inspection invokes `wg`; sampling it every ten seconds keeps
        // the traffic display responsive without spawning a process every second.
        if samples_since_handshake < 10 {
            samples_since_handshake += 1;
            continue;
        }
        samples_since_handshake = 0;
        match wireguard_handshake(&config.wireguard.interface).await {
            Ok(handshake) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let up =
                    handshake.is_some_and(|value| value != 0 && now.saturating_sub(value) < 180);
                if up {
                    profiles.mark_active().await;
                    enforcement.enable_dnat().await;
                } else {
                    profiles.mark_degraded().await;
                    enforcement.disable_dnat().await?;
                    invalidate_published_forward(&state, &publisher, PortForwardPhase::Unavailable)
                        .await;
                }
                let mut state = state.write().await;
                let tunnel_changed = state.tunnel.up != up;
                state.tunnel.up = up;
                state.tunnel.latest_handshake_unix = handshake.filter(|value| *value != 0);
                drop(state);
                if tunnel_changed {
                    notify_port_change(&port_change_tx);
                }
                publisher
                    .observe(
                        "wireguard.interface",
                        CheckStatus::Healthy,
                        Impact::Critical,
                        "wireguard.interface_present",
                        "The WireGuard interface is present",
                        None,
                        None,
                    )
                    .await;
                publisher
                    .observe(
                        "wireguard.handshake",
                        if up {
                            CheckStatus::Healthy
                        } else {
                            CheckStatus::Failed
                        },
                        Impact::Critical,
                        if up {
                            "wireguard.handshake_recent"
                        } else {
                            "wireguard.handshake_stale"
                        },
                        if up {
                            "A recent WireGuard handshake was observed"
                        } else {
                            "The WireGuard handshake is missing or stale"
                        },
                        None,
                        None,
                    )
                    .await;
                if up {
                    tunnel_failures = 0;
                    tunnel_successes = tunnel_successes.saturating_add(1);
                    if tunnel_successes >= config.recovery.success_threshold {
                        recovery_attempt = 0;
                        publisher
                            .mutate(|snapshot| snapshot.recovery = Default::default())
                            .await;
                    }
                } else {
                    tunnel_successes = 0;
                    tunnel_failures = tunnel_failures.saturating_add(1);
                }
            }
            Err(error) => {
                profiles.mark_degraded().await;
                enforcement.disable_dnat().await?;
                invalidate_published_forward(&state, &publisher, PortForwardPhase::Unavailable)
                    .await;
                let mut state = state.write().await;
                let tunnel_changed = state.tunnel.up;
                state.tunnel.up = false;
                drop(state);
                if tunnel_changed {
                    notify_port_change(&port_change_tx);
                }
                warn!(%error, "unable to inspect WireGuard tunnel");
                tunnel_failures = tunnel_failures.saturating_add(1);
                tunnel_successes = 0;
                publisher
                    .observe(
                        "wireguard.interface",
                        CheckStatus::Failed,
                        Impact::Critical,
                        "wireguard.interface_missing",
                        "The WireGuard interface could not be inspected",
                        None,
                        None,
                    )
                    .await;
            }
        }
        if config.recovery.enabled
            && config.wireguard.manage
            && tunnel_failures >= config.recovery.failure_threshold
        {
            {
                let mut state = state.write().await;
                state.tunnel.up = false;
            }
            notify_port_change(&port_change_tx);
            recovery_attempt = recovery_attempt.saturating_add(1);
            let delay = crate::recovery::retry_delay_seconds(
                recovery_attempt,
                config.recovery.maximum_backoff_seconds,
            );
            let next = unix_ms().saturating_add(delay.saturating_mul(1000));
            publisher
                .mutate(|snapshot| {
                    snapshot.recovery.active = true;
                    snapshot.recovery.attempt = recovery_attempt;
                    snapshot.recovery.reason_code = Some("wireguard.recovery_required".to_owned());
                    snapshot.recovery.next_attempt_at_unix_ms = Some(next);
                })
                .await;
            if let Err(error) = enforcement.disable_dnat().await {
                publisher
                    .observe(
                        "gateway.firewall",
                        CheckStatus::Failed,
                        Impact::Critical,
                        "firewall.reconciliation_failed",
                        "The owned firewall could not be reconciled before tunnel recovery",
                        None,
                        Some(recovery_attempt),
                    )
                    .await;
                warn!(%error, "unable to reconcile firewall for tunnel recovery");
                continue;
            }
            invalidate_published_forward(&state, &publisher, PortForwardPhase::Unavailable).await;
            notify_port_change(&port_change_tx);
            sleep(Duration::from_secs(delay)).await;
            match profiles.recover().await {
                Ok(()) => {
                    tunnel_failures = 0;
                    publisher
                        .observe(
                            "gateway.routes",
                            CheckStatus::Healthy,
                            Impact::Critical,
                            "routes.reinstalled",
                            "Gateway policy routes were reinstalled during recovery",
                            None,
                            Some(recovery_attempt),
                        )
                        .await;
                }
                Err(error) => {
                    warn!(%error, "WireGuard recovery attempt failed");
                    publisher
                        .observe(
                            "wireguard.interface",
                            CheckStatus::Failed,
                            Impact::Critical,
                            "wireguard.recovery_failed",
                            "The WireGuard recovery attempt failed",
                            None,
                            Some(recovery_attempt),
                        )
                        .await;
                    tunnel_failures = config.recovery.failure_threshold;
                }
            }
        }
    }
}

async fn read_interface_counters(interface: &str) -> anyhow::Result<(u64, u64)> {
    let base = format!("/sys/class/net/{interface}/statistics");
    let rx = tokio::fs::read_to_string(format!("{base}/rx_bytes"))
        .await?
        .trim()
        .parse()
        .context("parsing WireGuard rx_bytes")?;
    let tx = tokio::fs::read_to_string(format!("{base}/tx_bytes"))
        .await?
        .trim()
        .parse()
        .context("parsing WireGuard tx_bytes")?;
    Ok((rx, tx))
}

fn calculate_rates(previous: (u64, u64), current: (u64, u64), elapsed: Duration) -> (u64, u64) {
    let elapsed = elapsed.as_secs_f64();
    if elapsed <= 0.0 {
        return (0, 0);
    }
    (
        (current.0.saturating_sub(previous.0) as f64 / elapsed).round() as u64,
        (current.1.saturating_sub(previous.1) as f64 / elapsed).round() as u64,
    )
}

fn dnat_install_required(
    active_forward: Option<(u16, Ipv4Addr, u16)>,
    desired: (u16, Ipv4Addr, u16),
    applied: bool,
) -> bool {
    active_forward != Some(desired) || !applied
}

fn tunnel_dnat(mapping: natpmp::Mapping, target: &DnatTarget) -> (u16, Ipv4Addr, u16) {
    (mapping.internal_port, target.address, target.port)
}

#[derive(Clone, Debug)]
struct LeaseSlot {
    target_name: String,
    target: DnatTarget,
    assigned_external: Option<u16>,
    active_forward: Option<(u16, Ipv4Addr, u16)>,
}

async fn maintain_port_forward(
    config: Config,
    state: SharedState,
    publisher: StatePublisher,
    enforcement: EnforcementCoordinator,
    mut port_change_rx: watch::Receiver<u64>,
) -> anyhow::Result<()> {
    if config.port_forwarding.backend == crate::config::PortForwardingBackend::Disabled {
        futures_util::future::pending::<()>().await;
        return Ok(());
    }
    let client = NatPmpClient::new(config.port_forwarding.gateway);
    let mut leases = BTreeMap::<String, LeaseSlot>::new();

    loop {
        if !state.read().await.tunnel.up {
            deactivate_all_forwards(
                &config,
                &state,
                &publisher,
                &enforcement,
                &mut leases,
                PortForwardPhase::Unavailable,
            )
            .await?;
            wait_for_port_change(&mut port_change_rx, Duration::from_secs(2)).await;
            continue;
        }

        reconcile_lease_targets(&config, &state, &publisher, &enforcement, &mut leases).await?;
        if leases.is_empty() {
            publish_primary_forward(&config, &state, &publisher).await;
            wait_for_port_change(
                &mut port_change_rx,
                Duration::from_secs(config.port_forwarding.refresh_seconds),
            )
            .await;
            continue;
        };
        let public_ip = match client.external_address().await {
            Ok(public_ip) => public_ip,
            Err(error) => {
                record_port_error(&state, None, error.to_string()).await;
                deactivate_all_forwards(
                    &config,
                    &state,
                    &publisher,
                    &enforcement,
                    &mut leases,
                    PortForwardPhase::LeaseLost,
                )
                .await?;
                wait_for_port_change(
                    &mut port_change_rx,
                    Duration::from_secs(config.port_forwarding.refresh_seconds),
                )
                .await;
                continue;
            }
        };
        let requests = leases
            .iter()
            .map(|(usage_id, slot)| {
                let client = client.clone();
                let usage_id = usage_id.clone();
                let internal_port = slot.target.port;
                let requested_external = slot.assigned_external.unwrap_or(internal_port);
                let lifetime = config.port_forwarding.lifetime_seconds;
                async move {
                    (
                        usage_id,
                        natpmp::request_symmetric_mapping(
                            &client,
                            internal_port,
                            requested_external,
                            lifetime,
                        )
                        .await,
                    )
                }
            })
            .collect::<Vec<_>>();

        for (usage_id, result) in futures_util::future::join_all(requests).await {
            match result {
                Ok(mapping) => {
                    let slot = leases
                        .get_mut(&usage_id)
                        .expect("lease target still exists");
                    // The provider's NAT-PMP gateway translates the public
                    // external port to our requested internal lease key before
                    // the packet arrives on wg0. Match that tunnel-side port;
                    // the public external port remains the advertised status.
                    let desired_forward = tunnel_dnat(mapping, &slot.target);
                    let port_changed = slot
                        .assigned_external
                        .is_some_and(|port| port != mapping.external_port);
                    let mapping_changed =
                        slot.active_forward != Some(desired_forward) || port_changed;
                    let mapping_applied = enforcement
                        .dnat_is_applied(&usage_id, desired_forward)
                        .await;
                    let install_required = dnat_install_required(
                        slot.active_forward,
                        desired_forward,
                        mapping_applied,
                    );
                    let now = unix_ms();
                    if install_required {
                        if !enforcement
                            .set_dnat_for_target(&usage_id, desired_forward, &slot.target)
                            .await?
                        {
                            continue;
                        }
                        slot.active_forward = Some(desired_forward);
                    }
                    slot.assigned_external = Some(mapping.external_port);
                    state.write().await.port_forwards.insert(
                        usage_id.clone(),
                        crate::state::PortForwardState {
                            active: true,
                            public_ip: Some(public_ip),
                            port: Some(mapping.external_port),
                            target: Some(slot.target_name.clone()),
                            target_port: Some(slot.target.port),
                            expires_in_seconds: Some(mapping.lifetime_seconds),
                            lease_acquired_at_unix_ms: Some(now),
                        },
                    );
                    publisher
                        .mutate(|snapshot| {
                            let status =
                                snapshot.port_forwards.entry(usage_id.clone()).or_default();
                            if mapping_changed {
                                snapshot.sequence += 1;
                                status.change_sequence = snapshot.sequence;
                                status.changed_at_unix_ms = Some(now);
                            }
                            status.phase = PortForwardPhase::Installed;
                            status.requested_target = Some(slot.target_name.clone());
                            status.internal_port = Some(slot.target.port);
                            status.external_port = Some(mapping.external_port);
                            status.tcp_udp_agree = Some(true);
                            status.lease_acquired_at_unix_ms = Some(now);
                            status.lease_expires_at_unix_ms =
                                Some(now + u64::from(mapping.lifetime_seconds) * 1000);
                            status.dnat_installed = true;
                            status.externally_verified = None;
                        })
                        .await;
                    if port_changed {
                        publisher
                            .emit(
                                &format!("port_forward.{usage_id}"),
                                "port_forward.port_changed",
                                "The provider assigned a different forwarded port",
                            )
                            .await;
                    }
                    info!(%usage_id, "Proton forwarded port active");
                }
                Err(error) => {
                    record_port_error(&state, Some(&usage_id), error.to_string()).await;
                    deactivate_forward_for_usage(
                        &config,
                        &state,
                        &publisher,
                        &enforcement,
                        &usage_id,
                        PortForwardPhase::LeaseLost,
                    )
                    .await?;
                    if let Some(slot) = leases.get_mut(&usage_id) {
                        slot.active_forward = None;
                    }
                }
            }
        }
        publish_primary_forward(&config, &state, &publisher).await;
        observe_installed_forwards(&publisher, &state).await;
        wait_for_port_change(
            &mut port_change_rx,
            Duration::from_secs(config.port_forwarding.refresh_seconds),
        )
        .await;
    }
}

fn notify_port_change(sender: &watch::Sender<u64>) {
    sender.send_modify(|version| *version = version.wrapping_add(1));
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PortForwardTargetInput {
    container_id: String,
    usage_id: String,
    address: Ipv4Addr,
    target_port: Option<u16>,
    compliant: bool,
    running: bool,
}

fn port_forward_target_inputs(
    clients: &BTreeMap<String, crate::state::ClientState>,
) -> Vec<PortForwardTargetInput> {
    clients
        .values()
        .filter(|client| client.port_forward_target)
        .map(|client| PortForwardTargetInput {
            container_id: client.container_id.clone(),
            usage_id: client.usage_id.clone(),
            address: client.ipv4_address,
            target_port: client.target_port,
            compliant: client.compliant,
            running: client.running,
        })
        .collect()
}

async fn wait_for_port_change(receiver: &mut watch::Receiver<u64>, duration: Duration) {
    tokio::select! {
        _ = sleep(duration) => {}
        changed = receiver.changed() => {
            if changed.is_err() {
                futures_util::future::pending::<()>().await;
            }
        }
    }
}

async fn observe_installed_forwards(publisher: &StatePublisher, state: &SharedState) {
    let active = state
        .read()
        .await
        .port_forwards
        .values()
        .filter(|status| status.active)
        .count();
    for (component, reason) in [
        ("port_forward.dnat", "port_forward.dnat_installed"),
        ("port_forward.lifecycle", "port_forward.lease_installed"),
    ] {
        publisher
            .observe(
                component,
                CheckStatus::Healthy,
                Impact::Optional,
                reason,
                format!("{active} symmetric lease(s) are installed in the owned firewall"),
                None,
                None,
            )
            .await;
    }
}

async fn invalidate_published_forward(
    state: &SharedState,
    publisher: &StatePublisher,
    phase: PortForwardPhase,
) {
    let mut legacy = state.write().await;
    for status in legacy.port_forwards.values_mut() {
        status.active = false;
        status.lease_acquired_at_unix_ms = None;
    }
    legacy.port_forward = Default::default();
    drop(legacy);
    publisher
        .mutate(|snapshot| {
            for status in snapshot.port_forwards.values_mut() {
                status.phase = phase;
                status.dnat_installed = false;
                status.external_port = None;
                status.lease_acquired_at_unix_ms = None;
                status.lease_expires_at_unix_ms = None;
                status.externally_verified = None;
            }
            snapshot.port_forward = crate::domain::PortForwardStatus {
                phase,
                ..Default::default()
            };
        })
        .await;
}

async fn deactivate_forward_for_usage(
    config: &Config,
    state: &SharedState,
    publisher: &StatePublisher,
    enforcement: &EnforcementCoordinator,
    usage_id: &str,
    phase: PortForwardPhase,
) -> anyhow::Result<()> {
    if let Err(error) = enforcement.clear_dnat_for_usage(usage_id).await {
        publisher
            .observe(
                "gateway.firewall",
                CheckStatus::Failed,
                Impact::Critical,
                "firewall.dnat_removal_failed",
                "Optional DNAT could not be removed; forwarding state remains unresolved",
                None,
                None,
            )
            .await;
        return Err(error);
    }
    let mut legacy = state.write().await;
    let status = legacy.port_forwards.entry(usage_id.to_owned()).or_default();
    status.active = false;
    status.port = None;
    status.lease_acquired_at_unix_ms = None;
    drop(legacy);
    let now = unix_ms();
    publisher
        .mutate(|snapshot| {
            let status = snapshot
                .port_forwards
                .entry(usage_id.to_owned())
                .or_default();
            let changed = status.phase != phase || status.dnat_installed;
            if changed {
                snapshot.sequence += 1;
                status.change_sequence = snapshot.sequence;
                status.changed_at_unix_ms = Some(now);
            }
            status.phase = phase;
            status.dnat_installed = false;
            status.external_port = None;
            status.lease_acquired_at_unix_ms = None;
            status.lease_expires_at_unix_ms = None;
            status.externally_verified = None;
        })
        .await;
    publish_primary_forward(config, state, publisher).await;
    Ok(())
}

async fn deactivate_all_forwards(
    config: &Config,
    state: &SharedState,
    publisher: &StatePublisher,
    enforcement: &EnforcementCoordinator,
    leases: &mut BTreeMap<String, LeaseSlot>,
    phase: PortForwardPhase,
) -> anyhow::Result<()> {
    for usage_id in leases.keys().cloned().collect::<Vec<_>>() {
        deactivate_forward_for_usage(config, state, publisher, enforcement, &usage_id, phase)
            .await?;
        if let Some(slot) = leases.get_mut(&usage_id) {
            slot.active_forward = None;
        }
    }
    Ok(())
}

async fn reconcile_lease_targets(
    config: &Config,
    state: &SharedState,
    publisher: &StatePublisher,
    enforcement: &EnforcementCoordinator,
    leases: &mut BTreeMap<String, LeaseSlot>,
) -> anyhow::Result<()> {
    let targets = select_port_targets(state).await;
    let removed = leases
        .keys()
        .filter(|usage_id| !targets.contains_key(*usage_id))
        .cloned()
        .collect::<Vec<_>>();
    for usage_id in removed {
        deactivate_forward_for_usage(
            config,
            state,
            publisher,
            enforcement,
            &usage_id,
            PortForwardPhase::WaitingForTarget,
        )
        .await?;
        leases.remove(&usage_id);
        state.write().await.port_forwards.remove(&usage_id);
        publisher
            .mutate(|snapshot| {
                snapshot.port_forwards.remove(&usage_id);
            })
            .await;
    }
    for (usage_id, (target_name, target)) in targets {
        let replace = leases
            .get(&usage_id)
            .is_some_and(|slot| slot.target != target);
        if replace {
            deactivate_forward_for_usage(
                config,
                state,
                publisher,
                enforcement,
                &usage_id,
                PortForwardPhase::WaitingForTarget,
            )
            .await?;
            leases.remove(&usage_id);
        }
        leases.entry(usage_id).or_insert(LeaseSlot {
            target_name,
            target,
            assigned_external: None,
            active_forward: None,
        });
    }
    Ok(())
}

async fn select_port_targets(state: &SharedState) -> BTreeMap<String, (String, DnatTarget)> {
    let state = state.read().await;
    state
        .clients
        .values()
        .filter(|client| client.port_forward_target && client.compliant)
        .filter_map(|client| {
            Some((
                client.usage_id.clone(),
                (
                    client.name.clone(),
                    DnatTarget {
                        container_id: client.container_id.clone(),
                        address: client.ipv4_address,
                        port: client.target_port?,
                    },
                ),
            ))
        })
        .collect()
}

async fn publish_primary_forward(config: &Config, state: &SharedState, publisher: &StatePublisher) {
    let (legacy_primary, primary_usage_id) = {
        let state = state.read().await;
        let usage_id = select_primary_usage_id(
            config.port_forwarding.primary_usage_id.as_deref(),
            &state.port_forwards,
        );
        (
            usage_id.and_then(|id| state.port_forwards.get(id).cloned()),
            usage_id.map(str::to_owned),
        )
    };
    state.write().await.port_forward = legacy_primary.unwrap_or_default();
    publisher
        .mutate(|snapshot| {
            snapshot.port_forward = primary_usage_id
                .as_deref()
                .and_then(|id| snapshot.port_forwards.get(id))
                .cloned()
                .unwrap_or_default();
        })
        .await;
}

fn select_primary_usage_id<'a, T>(
    configured: Option<&'a str>,
    leases: &'a BTreeMap<String, T>,
) -> Option<&'a str> {
    configured
        .filter(|usage_id| leases.contains_key(*usage_id))
        .or_else(|| {
            (leases.len() == 1)
                .then(|| leases.keys().next().map(String::as_str))
                .flatten()
        })
}

async fn record_port_error(state: &SharedState, usage_id: Option<&str>, error: String) {
    warn!(usage_id = usage_id.unwrap_or("gateway"), %error, "port forwarding failed");
    let mut state = state.write().await;
    if let Some(usage_id) = usage_id {
        state
            .port_forwards
            .entry(usage_id.to_owned())
            .or_default()
            .active = false;
    }
    state.last_error = Some(format!(
        "port forwarding failed for {}: {error}",
        usage_id.unwrap_or("gateway")
    ));
}

pub(crate) async fn wireguard_up(
    config: &Config,
    profile: &crate::wireguard::WireGuardProfile,
) -> anyhow::Result<()> {
    let runtime_path = prepare_wireguard_profile(config, profile).await?;
    let runtime_path = runtime_path
        .to_str()
        .context("WireGuard runtime path is not valid UTF-8")?;
    command("wg-quick", &["up", runtime_path]).await?;
    configure_gateway_routes(config, &profile.ipv4_dns()).await
}

pub(crate) async fn load_mounted_profile(
    config: &Config,
) -> anyhow::Result<Option<crate::wireguard::WireGuardProfile>> {
    let mut profile = if let Some(encoded_path) = &config.wireguard.config_base64_path {
        let mut encoded = tokio::fs::read_to_string(encoded_path)
            .await
            .context("reading base64 WireGuard Docker secret")?;
        let decoded = STANDARD
            .decode(encoded.trim())
            .context("decoding base64 WireGuard Docker secret");
        encoded.zeroize();
        decoded?
    } else if let Some(path) = &config.wireguard.config_path {
        let metadata = match tokio::fs::metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading mounted WireGuard metadata"),
        };
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            bail!("WireGuard configuration must be a regular file no larger than 256 KiB");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("WireGuard configuration must not be readable by group or others");
            }
        }
        tokio::fs::read(path)
            .await
            .context("reading mounted WireGuard configuration")?
    } else {
        return Ok(None);
    };
    let parsed = crate::wireguard::WireGuardProfile::parse(&profile);
    profile.zeroize();
    Ok(Some(parsed?))
}

pub(crate) async fn prepare_wireguard_profile(
    config: &Config,
    profile: &crate::wireguard::WireGuardProfile,
) -> anyhow::Result<std::path::PathBuf> {
    let runtime_path =
        std::path::Path::new("/run/egressy").join(format!("{}.conf", config.wireguard.interface));
    let runtime_directory = runtime_path
        .parent()
        .context("WireGuard runtime path has no parent")?;
    tokio::fs::create_dir_all(runtime_directory).await?;
    verify_tmpfs(runtime_directory).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(runtime_directory, std::fs::Permissions::from_mode(0o700))
            .await?;
    }
    tokio::fs::write(&runtime_path, profile.render()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&runtime_path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(runtime_path)
}

async fn verify_tmpfs(directory: &std::path::Path) -> anyhow::Result<()> {
    let mounts = tokio::fs::read_to_string("/proc/self/mountinfo").await?;
    let directory = directory.to_string_lossy();
    let mounted = mounts.lines().any(|line| {
        let mut halves = line.split(" - ");
        let before = halves.next().unwrap_or_default();
        let after = halves.next().unwrap_or_default();
        before.split_whitespace().nth(4) == Some(directory.as_ref())
            && after.split_whitespace().next() == Some("tmpfs")
    });
    if !mounted {
        bail!("/run/egressy must be a dedicated tmpfs mount");
    }
    Ok(())
}

pub(crate) async fn configure_gateway_routes(
    config: &Config,
    profile_dns: &[Ipv4Addr],
) -> anyhow::Result<()> {
    let table = config.network.route_table.to_string();
    let subnet = config.network.subnet.to_string();
    let tunnel = &config.wireguard.interface;
    let service_routes = tunnel_service_routes(config, profile_dns);
    let local_gateway = config.network.gateway_ip.to_string();

    // Forwarded packets retain the enrolled container's source address, so a
    // source rule selects the tunnel without moving Egressy's management/API
    // traffic away from its ordinary Docker uplink.
    let _ = command("ip", &["rule", "del", "from", &subnet, "lookup", &table]).await;
    let _ = command(
        "ip",
        &["rule", "del", "from", &local_gateway, "lookup", "main"],
    )
    .await;
    // DNS and dashboard replies originate from the gateway's vpn-egress
    // address. Keep them on the connected bridge instead of selecting wg0.
    command(
        "ip",
        &[
            "rule",
            "add",
            "priority",
            "90",
            "from",
            &local_gateway,
            "lookup",
            "main",
        ],
    )
    .await?;
    command(
        "ip",
        &[
            "rule", "add", "priority", "100", "from", &subnet, "lookup", &table,
        ],
    )
    .await?;
    command(
        "ip",
        &[
            "route", "replace", "table", &table, "default", "dev", tunnel,
        ],
    )
    .await?;
    for destination in service_routes {
        command(
            "ip",
            &[
                "route",
                "replace",
                &destination.to_string(),
                "dev",
                tunnel,
                "scope",
                "link",
            ],
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn reconcile_gateway_routes(
    config: &Config,
    previous_profile_dns: &[Ipv4Addr],
    desired_profile_dns: &[Ipv4Addr],
) -> anyhow::Result<()> {
    configure_gateway_routes(config, desired_profile_dns).await?;
    let desired = tunnel_service_routes(config, desired_profile_dns);
    for address in previous_profile_dns {
        if desired.contains(address) {
            continue;
        }
        let address = address.to_string();
        let output = Command::new("ip")
            .args([
                "route",
                "del",
                &address,
                "dev",
                &config.wireguard.interface,
                "scope",
                "link",
            ])
            .output()
            .await?;
        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("No such process")
        {
            bail!("removing obsolete tunnel service route failed");
        }
    }
    Ok(())
}

fn tunnel_service_routes(
    config: &Config,
    profile_dns: &[Ipv4Addr],
) -> std::collections::BTreeSet<Ipv4Addr> {
    let mut routes = profile_dns
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if config.port_forwarding.backend == crate::config::PortForwardingBackend::NatPmp {
        routes.insert(config.port_forwarding.gateway);
    }
    if config.dns.enabled
        && config.dns.upstream.source == crate::config::DnsUpstreamSource::Explicit
    {
        routes.extend(
            config
                .dns
                .upstream
                .addresses
                .iter()
                .filter_map(|address| address.parse::<SocketAddr>().ok())
                .filter_map(|address| match address.ip() {
                    std::net::IpAddr::V4(address) => Some(address),
                    std::net::IpAddr::V6(_) => None,
                }),
        );
    }
    routes
}

fn dns_upstream(
    config: &Config,
    profile: Option<&crate::wireguard::WireGuardProfile>,
) -> Option<SocketAddr> {
    match config.dns.upstream.source {
        crate::config::DnsUpstreamSource::Profile => profile
            .and_then(|profile| profile.ipv4_dns().into_iter().next())
            .map(|address| SocketAddr::new(address.into(), 53)),
        crate::config::DnsUpstreamSource::Explicit => config
            .dns
            .upstream
            .addresses
            .first()
            .and_then(|address| address.parse().ok()),
    }
}

pub(crate) fn validate_profile_capabilities(
    config: &Config,
    profile: &crate::wireguard::WireGuardProfile,
) -> anyhow::Result<()> {
    if config.dns.enabled
        && config.dns.upstream.source == crate::config::DnsUpstreamSource::Profile
        && profile.ipv4_dns().is_empty()
    {
        bail!("DNS forwarding uses the profile, but the profile has no usable IPv4 DNS address");
    }
    Ok(())
}

pub(crate) async fn wireguard_down(config: &Config) {
    let runtime_path =
        std::path::Path::new("/run/egressy").join(format!("{}.conf", config.wireguard.interface));
    let runtime_path = runtime_path.to_string_lossy();
    if let Err(error) = command("wg-quick", &["down", &runtime_path]).await {
        error!(%error, "failed to stop WireGuard cleanly");
    }
}

async fn wireguard_handshake(interface: &str) -> anyhow::Result<Option<u64>> {
    let output = Command::new("wg")
        .args(["show", interface, "latest-handshakes"])
        .stderr(Stdio::piped())
        .output()
        .await?;
    if !output.status.success() {
        bail!(
            "wg show failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|value| value.parse().ok())
        .max())
}

pub(crate) async fn command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn forwarding_client(
        id: &str,
        address: &str,
        target_port: Option<u16>,
        compliant: bool,
        running: bool,
    ) -> crate::state::ClientState {
        crate::state::ClientState {
            container_id: id.into(),
            usage_id: format!("test:{id}"),
            usage_id_source: crate::state::UsageIdentitySource::ExplicitLabel,
            name: id.into(),
            ipv4_address: address.parse().unwrap(),
            port_forward_target: true,
            target_port,
            compliant,
            compliance_message: "test".into(),
            running,
            ipv6_address: None,
            networks: vec!["vpn-egress".into()],
            port_forward_label_valid: target_port.is_some(),
            route_intent: crate::state::RouteIntentState::default(),
            traffic: crate::state::ClientTrafficState::default(),
        }
    }

    #[tokio::test]
    async fn runtime_rejects_missing_firewall_owner_before_network_mutation() {
        let mut config: Config = serde_yaml::from_str("{}").unwrap();
        config.reconcile.apply_gateway_firewall = false;
        let error = run(config, None).await.unwrap_err().to_string();
        assert!(error.contains("must own the fail-closed gateway firewall"));
    }

    #[test]
    fn calculates_byte_rates_over_sample_period() {
        assert_eq!(
            calculate_rates((1_000, 2_000), (3_000, 3_000), Duration::from_millis(500)),
            (4_000, 2_000)
        );
    }

    #[test]
    fn counter_reset_does_not_underflow() {
        assert_eq!(
            calculate_rates((10_000, 10_000), (100, 200), Duration::from_secs(1)),
            (0, 0)
        );
    }

    #[test]
    fn same_mapping_after_recovery_requires_reinstall_before_publication() {
        let mapping = (45_678, "172.30.0.10".parse().unwrap(), 6881);
        assert!(dnat_install_required(Some(mapping), mapping, false));
        assert!(!dnat_install_required(Some(mapping), mapping, true));
    }

    #[test]
    fn inbound_dnat_matches_provider_translated_internal_lease_port() {
        let target = DnatTarget {
            container_id: "indexarr".to_owned(),
            address: "172.30.0.11".parse().unwrap(),
            port: 6882,
        };
        let mapping = crate::natpmp::Mapping {
            internal_port: 6882,
            external_port: 39_021,
            lifetime_seconds: 60,
        };
        assert_eq!(
            tunnel_dnat(mapping, &target),
            (6882, "172.30.0.11".parse().unwrap(), 6882)
        );
    }

    #[test]
    fn client_traffic_history_is_bounded_and_skips_unchanged_totals() {
        let mut traffic = crate::state::ClientTrafficState::default();
        for index in 0..(CLIENT_TRAFFIC_HISTORY_CAPACITY + 10) {
            traffic.downloaded_bytes = index as u64;
            traffic.uploaded_bytes = (index * 2) as u64;
            record_client_traffic_sample(&mut traffic, index as u64);
        }
        assert_eq!(traffic.history.len(), CLIENT_TRAFFIC_HISTORY_CAPACITY);
        let last_len = traffic.history.len();
        record_client_traffic_sample(&mut traffic, 999);
        assert_eq!(traffic.history.len(), last_len);
        assert_eq!(traffic.history.front().unwrap().downloaded_bytes, 10);
    }

    #[test]
    fn service_routes_are_capability_driven() {
        let disabled: Config = serde_yaml::from_str("{}").unwrap();
        assert!(tunnel_service_routes(&disabled, &[]).is_empty());
        let enabled: Config =
            serde_yaml::from_str("port_forwarding:\n  backend: nat_pmp\n  gateway: 10.2.0.1\n")
                .unwrap();
        assert!(tunnel_service_routes(&enabled, &[]).contains(&"10.2.0.1".parse().unwrap()));
    }

    #[test]
    fn explicit_and_profile_dns_routes_are_derived() {
        let explicit: Config = serde_yaml::from_str(
            "dns:\n  upstream:\n    source: explicit\n    addresses: [10.64.0.1:53]\n",
        )
        .unwrap();
        assert!(tunnel_service_routes(&explicit, &[]).contains(&"10.64.0.1".parse().unwrap()));
        let profile: Config = serde_yaml::from_str("{}").unwrap();
        assert!(
            tunnel_service_routes(&profile, &["10.7.0.1".parse().unwrap()])
                .contains(&"10.7.0.1".parse().unwrap())
        );
    }

    #[test]
    fn profile_dns_is_required_only_when_selected() {
        let profile = crate::wireguard::WireGuardProfile::parse(
            b"[Interface]\nPrivateKey=x\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=y\nAllowedIPs=0.0.0.0/0\n",
        )
        .unwrap();
        let config: Config = serde_yaml::from_str("{}").unwrap();
        assert!(validate_profile_capabilities(&config, &profile).is_err());
        let disabled: Config = serde_yaml::from_str("dns:\n  enabled: false\n").unwrap();
        assert!(validate_profile_capabilities(&disabled, &profile).is_ok());
        let explicit: Config = serde_yaml::from_str(
            "dns:\n  upstream:\n    source: explicit\n    addresses: [10.0.0.1:53]\n",
        )
        .unwrap();
        assert!(validate_profile_capabilities(&explicit, &profile).is_ok());
    }

    #[tokio::test]
    async fn installed_forward_recovers_lifecycle_check() {
        let publisher = StatePublisher::new(CanonicalSnapshot::default());
        publisher
            .observe(
                "port_forward.lifecycle",
                CheckStatus::Degraded,
                Impact::Optional,
                "port_forward.tunnel_unavailable",
                "Tunnel unavailable",
                None,
                None,
            )
            .await;
        let state: SharedState = Arc::new(RwLock::new(AppState::default()));
        observe_installed_forwards(&publisher, &state).await;
        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(
            snapshot.checks["port_forward.lifecycle"].status,
            CheckStatus::Healthy
        );
        assert_eq!(
            snapshot.checks["port_forward.lifecycle"].reason_code,
            "port_forward.lease_installed"
        );
    }

    #[test]
    fn primary_forward_selection_is_explicit_then_single_lease_compatible() {
        let leases = [
            ("personal-arr/qbittorrent".to_owned(), 1_u8),
            ("prod-indexarr/indexarr".to_owned(), 2_u8),
        ]
        .into();
        assert_eq!(
            select_primary_usage_id(Some("personal-arr/qbittorrent"), &leases),
            Some("personal-arr/qbittorrent")
        );
        assert_eq!(select_primary_usage_id(None, &leases), None);
        let single = [("only/client".to_owned(), 1_u8)].into();
        assert_eq!(select_primary_usage_id(None, &single), Some("only/client"));
    }

    #[test]
    fn per_lease_failure_state_does_not_mutate_healthy_sibling() {
        let healthy = crate::domain::PortForwardStatus {
            phase: PortForwardPhase::Installed,
            external_port: Some(45_678),
            dnat_installed: true,
            change_sequence: 7,
            ..Default::default()
        };
        let mut statuses: BTreeMap<String, crate::domain::PortForwardStatus> = [
            ("healthy".to_owned(), healthy.clone()),
            (
                "failed".to_owned(),
                crate::domain::PortForwardStatus::default(),
            ),
        ]
        .into();
        let failed = statuses.get_mut("failed").unwrap();
        failed.phase = PortForwardPhase::LeaseLost;
        failed.dnat_installed = false;
        assert_eq!(statuses["healthy"], healthy);
    }

    #[tokio::test]
    async fn enforcement_invalidation_clears_published_dnat_state() {
        let state: SharedState = Arc::new(RwLock::new(AppState::default()));
        state.write().await.port_forwards.insert(
            "test/client".to_owned(),
            crate::state::PortForwardState {
                active: true,
                ..Default::default()
            },
        );
        let mut snapshot = CanonicalSnapshot::default();
        snapshot.port_forwards.insert(
            "test/client".to_owned(),
            crate::domain::PortForwardStatus {
                phase: PortForwardPhase::Installed,
                dnat_installed: true,
                external_port: Some(45_678),
                ..Default::default()
            },
        );
        let publisher = StatePublisher::new(snapshot);

        invalidate_published_forward(&state, &publisher, PortForwardPhase::Unavailable).await;

        assert!(!state.read().await.port_forwards["test/client"].active);
        let snapshot = publisher.subscribe().borrow().clone();
        assert_eq!(snapshot.port_forward.phase, PortForwardPhase::Unavailable);
        assert!(!snapshot.port_forward.dnat_installed);
        assert_eq!(snapshot.port_forward.external_port, None);
    }

    #[tokio::test]
    async fn stopped_tasks_cannot_reconcile_natpmp_or_restart_wireguard() {
        let actions = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let mut tasks = Vec::new();
        for action in &actions {
            let action = action.clone();
            tasks.push(tokio::spawn(async move {
                sleep(Duration::from_millis(50)).await;
                action.store(true, Ordering::SeqCst);
            }));
        }
        for task in tasks {
            stop_task(task).await;
        }
        sleep(Duration::from_millis(75)).await;
        for action in actions {
            assert!(!action.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn target_change_interrupts_the_lease_refresh_wait() {
        let (sender, mut receiver) = watch::channel(0_u64);
        notify_port_change(&sender);
        tokio::time::timeout(
            Duration::from_millis(50),
            wait_for_port_change(&mut receiver, Duration::from_secs(45)),
        )
        .await
        .unwrap();
    }

    #[test]
    fn every_forwarding_target_lifecycle_change_is_observable() {
        let original = [(
            "old".to_owned(),
            forwarding_client("old", "172.30.0.10", Some(6881), true, true),
        )]
        .into();
        let baseline = port_forward_target_inputs(&original);

        let cases: Vec<BTreeMap<String, crate::state::ClientState>> = vec![
            BTreeMap::new(),
            [(
                "old".to_owned(),
                forwarding_client("old", "172.30.0.10", Some(6881), false, true),
            )]
            .into(),
            [(
                "old".to_owned(),
                forwarding_client("old", "172.30.0.10", Some(6881), true, false),
            )]
            .into(),
            [(
                "old".to_owned(),
                forwarding_client("old", "172.30.0.11", Some(6881), true, true),
            )]
            .into(),
            [
                (
                    "old".to_owned(),
                    forwarding_client("old", "172.30.0.10", Some(6881), true, true),
                ),
                (
                    "second".to_owned(),
                    forwarding_client("second", "172.30.0.11", Some(6881), true, true),
                ),
            ]
            .into(),
            [(
                "replacement".to_owned(),
                forwarding_client("replacement", "172.30.0.10", Some(6881), true, true),
            )]
            .into(),
        ];

        for inputs in cases {
            assert_ne!(baseline, port_forward_target_inputs(&inputs));
        }
    }
}
