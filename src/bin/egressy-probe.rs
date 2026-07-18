use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context};
use axum::{extract::State, routing::get, Json, Router};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::RwLock,
    time::{interval, timeout, Instant},
};
use tracing::{info, warn};

#[derive(Clone, Debug, Default, Serialize)]
struct ProbeStatus {
    observed_at_unix_ms: u64,
    udp_dns_ok: bool,
    tcp_dns_ok: bool,
    https_egress_ok: bool,
    vpn_identity_ok: bool,
    expected_identity: String,
    duration_ms: u64,
    reason_code: String,
    safe_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_probe: Option<ExternalProbeStatus>,
    #[serde(default)]
    external_probes: BTreeMap<String, ExternalProbeStatus>,
}

#[derive(Clone)]
struct AppState {
    result: SharedResult,
    token: Option<String>,
}

type SharedResult = Arc<RwLock<ProbeStatus>>;

#[derive(Clone, Debug)]
struct ExternalProbeConfig {
    instance_id: String,
    url: Url,
    interval: Duration,
    timeout: Duration,
    token: Option<String>,
    state_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExternalProbeStatus {
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

#[derive(Debug, Serialize)]
struct ExternalProbeRequest {
    instance_id: String,
    request_id: String,
    timestamp_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_public_ip: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    forwarded_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct ExternalProbeResponse {
    observed_at_unix_ms: u64,
    source_public_non_tailscale: bool,
    source_matches_claimed_ip: Option<bool>,
    tcp_port_reachable: Option<bool>,
    reason_code: String,
    safe_message: String,
}

#[derive(Debug, Deserialize)]
struct GatewayStatus {
    port_forward: GatewayPortForward,
    #[serde(default)]
    port_forwards: BTreeMap<String, GatewayPortForward>,
}

#[derive(Debug, Deserialize)]
struct GatewayPortForward {
    active: bool,
    public_ip: Option<Ipv4Addr>,
    port: Option<u16>,
    lease_acquired_at_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PortForwardClaim {
    public_ip: Option<Ipv4Addr>,
    forwarded_port: Option<u16>,
    lease_acquired_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug)]
enum IdentityMatcher {
    PlainTextContains(String),
    JsonStringContains { fields: Vec<String>, value: String },
    JsonBoolean { field: String, value: bool },
}

impl IdentityMatcher {
    fn expected_value(&self) -> String {
        match self {
            Self::PlainTextContains(value) | Self::JsonStringContains { value, .. } => {
                value.clone()
            }
            Self::JsonBoolean { value, .. } => value.to_string(),
        }
    }
}

const DNS_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_IDENTITY_CHECK_INTERVAL_SECONDS: u64 = 300;
const MAX_IDENTITY_RESPONSE_BYTES: usize = 16 * 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let listen: SocketAddr = env("EGRESSY_PROBE_LISTEN", "0.0.0.0:8081").parse()?;
    let dns: SocketAddr = env("EGRESSY_PROBE_DNS", "172.30.0.2:53").parse()?;
    let identity_enabled = env_bool("EGRESSY_PROBE_IDENTITY_ENABLED", false)?;
    let identity_url = env("EGRESSY_PROBE_IDENTITY_URL", "https://ifconfig.co/json");
    let identity_interval_seconds = env(
        "EGRESSY_PROBE_IDENTITY_INTERVAL_SECONDS",
        &DEFAULT_IDENTITY_CHECK_INTERVAL_SECONDS.to_string(),
    )
    .parse::<u64>()?;
    if identity_interval_seconds == 0 {
        bail!("EGRESSY_PROBE_IDENTITY_INTERVAL_SECONDS must be greater than zero");
    }
    let identity_matcher = load_identity_matcher()?;
    let expected_identity = if identity_enabled {
        identity_matcher.expected_value()
    } else {
        String::new()
    };
    let token = std::env::var("EGRESSY_PROBE_TOKEN").ok();
    let result = Arc::new(RwLock::new(ProbeStatus::default()));
    tokio::spawn(run_checks(
        result.clone(),
        dns,
        identity_url,
        identity_enabled,
        identity_matcher,
        expected_identity,
        Duration::from_secs(identity_interval_seconds),
    ));
    if let Some(external_probe) = load_external_probe_config()? {
        tokio::spawn(run_external_checks(result.clone(), external_probe));
    }
    let router = Router::new()
        .route("/status", get(status))
        .route("/livez", get(|| async { "ok\n" }))
        .with_state(AppState { result, token });
    axum::serve(tokio::net::TcpListener::bind(listen).await?, router).await?;
    Ok(())
}

async fn status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ProbeStatus>, axum::http::StatusCode> {
    if let Some(token) = &state.token {
        let authorized = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.strip_prefix("Bearer ") == Some(token));
        if !authorized {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }
    Ok(Json(state.result.read().await.clone()))
}

async fn run_checks(
    result: SharedResult,
    dns: SocketAddr,
    identity_url: String,
    identity_enabled: bool,
    identity_matcher: IdentityMatcher,
    expected_identity: String,
    identity_interval: Duration,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!(%error, "probe HTTP client setup failed");
            return;
        }
    };

    let dns_checks = run_dns_checks(result.clone(), dns, expected_identity.clone());
    let identity_checks = async move {
        if identity_enabled {
            run_identity_checks(
                result,
                client,
                identity_url,
                expected_identity,
                identity_matcher,
                identity_interval,
            )
            .await;
        } else {
            {
                let mut snapshot = result.write().await;
                snapshot.https_egress_ok = true;
                snapshot.vpn_identity_ok = true;
            }
            futures_util::future::pending::<()>().await;
        }
    };
    tokio::join!(dns_checks, identity_checks);
}

async fn run_dns_checks(result: SharedResult, dns: SocketAddr, expected_identity: String) {
    let mut ticker = interval(DNS_CHECK_INTERVAL);
    loop {
        ticker.tick().await;
        observe_dns(&result, dns, &expected_identity).await;
    }
}

async fn run_identity_checks(
    result: SharedResult,
    client: reqwest::Client,
    identity_url: String,
    expected_identity: String,
    matcher: IdentityMatcher,
    identity_interval: Duration,
) {
    let mut ticker = interval(identity_interval);
    loop {
        ticker.tick().await;
        observe_identity(
            &result,
            &client,
            &identity_url,
            &expected_identity,
            &matcher,
        )
        .await;
    }
}

async fn observe_dns(result: &SharedResult, dns: SocketAddr, expected_identity: &str) {
    let started = Instant::now();
    let query = dns_query();
    let udp_dns_ok = udp_dns(dns, &query).await.is_ok();
    let tcp_dns_ok = tcp_dns(dns, &query).await.is_ok();
    let mut snapshot = result.write().await;
    snapshot.observed_at_unix_ms = unix_ms();
    snapshot.udp_dns_ok = udp_dns_ok;
    snapshot.tcp_dns_ok = tcp_dns_ok;
    snapshot.expected_identity = expected_identity.to_owned();
    snapshot.duration_ms = started.elapsed().as_millis() as u64;
    update_path_summary(&mut snapshot);
}

async fn observe_identity(
    result: &SharedResult,
    client: &reqwest::Client,
    identity_url: &str,
    expected_identity: &str,
    matcher: &IdentityMatcher,
) {
    let started = Instant::now();
    let (https_egress_ok, vpn_identity_ok) = check_identity(client, identity_url, matcher).await;
    let mut snapshot = result.write().await;
    snapshot.observed_at_unix_ms = unix_ms();
    snapshot.https_egress_ok = https_egress_ok;
    snapshot.vpn_identity_ok = vpn_identity_ok;
    snapshot.expected_identity = expected_identity.to_owned();
    snapshot.duration_ms = started.elapsed().as_millis() as u64;
    update_path_summary(&mut snapshot);
}

async fn check_identity(
    client: &reqwest::Client,
    identity_url: &str,
    matcher: &IdentityMatcher,
) -> (bool, bool) {
    let mut response = match client.get(identity_url).send().await {
        Ok(response) => match response.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, "probe identity check failed");
                return (false, false);
            }
        },
        Err(error) => {
            warn!(%error, "probe identity check failed");
            return (false, false);
        }
    };

    if response
        .content_length()
        .is_some_and(|length| length > MAX_IDENTITY_RESPONSE_BYTES as u64)
    {
        warn!("probe identity response exceeded the safe size limit");
        return (true, false);
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_IDENTITY_RESPONSE_BYTES => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => {
                warn!("probe identity response exceeded the safe size limit");
                return (true, false);
            }
            Ok(None) => break,
            Err(error) => {
                warn!(%error, "probe identity response could not be read");
                return (true, false);
            }
        }
    }

    match identity_body_matches(&body, matcher) {
        Ok(matches) => (true, matches),
        Err(error) => {
            warn!(%error, "probe identity response could not be interpreted");
            (true, false)
        }
    }
}

fn identity_body_matches(body: &[u8], matcher: &IdentityMatcher) -> anyhow::Result<bool> {
    let text = std::str::from_utf8(body)?.trim();
    match matcher {
        IdentityMatcher::PlainTextContains(value) => Ok(text
            .to_ascii_lowercase()
            .contains(&value.to_ascii_lowercase())),
        IdentityMatcher::JsonStringContains { fields, value } => {
            let document: serde_json::Value = serde_json::from_str(text)?;
            Ok(fields.iter().any(|field| {
                document
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|observed| {
                        observed
                            .to_ascii_lowercase()
                            .contains(&value.to_ascii_lowercase())
                    })
            }))
        }
        IdentityMatcher::JsonBoolean { field, value } => {
            let document: serde_json::Value = serde_json::from_str(text)?;
            Ok(document.get(field).and_then(serde_json::Value::as_bool) == Some(*value))
        }
    }
}

fn load_identity_matcher() -> anyhow::Result<IdentityMatcher> {
    const FIELDS: &[&str] = &["asn_org", "as_name", "org", "mullvad_exit_ip"];
    let kind = env(
        "EGRESSY_PROBE_IDENTITY_MATCHER_TYPE",
        "json_string_contains",
    );
    match kind.as_str() {
        "plain_text_contains" => Ok(IdentityMatcher::PlainTextContains(env(
            "EGRESSY_PROBE_IDENTITY_MATCHER_VALUE",
            "Datacamp",
        ))),
        "json_string_contains" => {
            let fields = env(
                "EGRESSY_PROBE_IDENTITY_MATCHER_FIELDS",
                "asn_org,as_name,org",
            )
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>();
            if fields.is_empty() || fields.iter().any(|field| !FIELDS.contains(&field.as_str())) {
                bail!("identity matcher field is not allowlisted");
            }
            Ok(IdentityMatcher::JsonStringContains {
                fields,
                value: env("EGRESSY_PROBE_IDENTITY_MATCHER_VALUE", "Datacamp"),
            })
        }
        "json_boolean" => {
            let field = env("EGRESSY_PROBE_IDENTITY_MATCHER_FIELD", "mullvad_exit_ip");
            if !FIELDS.contains(&field.as_str()) {
                bail!("identity matcher field is not allowlisted");
            }
            Ok(IdentityMatcher::JsonBoolean {
                field,
                value: env_bool("EGRESSY_PROBE_IDENTITY_MATCHER_VALUE", true)?,
            })
        }
        _ => bail!("unsupported identity matcher type"),
    }
}

fn update_path_summary(snapshot: &mut ProbeStatus) {
    let all_ok = snapshot.udp_dns_ok
        && snapshot.tcp_dns_ok
        && snapshot.https_egress_ok
        && snapshot.vpn_identity_ok;
    snapshot.reason_code = if all_ok {
        "probe.path_healthy"
    } else {
        "probe.path_degraded"
    }
    .to_owned();
    snapshot.safe_message = if all_ok {
        "DNS and HTTPS succeeded through the enrolled path"
    } else {
        "One or more enrolled-path checks failed"
    }
    .to_owned();
}

async fn run_external_checks(result: SharedResult, config: ExternalProbeConfig) {
    // This client is only for the fixed gateway state URL. The public endpoint
    // receives a fresh, redirect-free, DNS-pinned client on every interval.
    let state_client = match reqwest::Client::builder()
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!(%error, "external probe HTTP client setup failed");
            return;
        }
    };
    let mut ticker = interval(config.interval);

    loop {
        ticker.tick().await;

        let public_client = match build_pinned_external_client(&config.url, config.timeout).await {
            Ok(client) => client,
            Err(error) => {
                warn!(%error, url = %config.url, "external probe endpoint resolution rejected");
                let unavailable = ExternalProbeStatus {
                        status: "unavailable".to_owned(),
                        observed_at_unix_ms: unix_ms(),
                        source_public_non_tailscale: None,
                        source_matches_claimed_ip: None,
                        tcp_port_reachable: None,
                        forwarded_port: None,
                        lease_acquired_at_unix_ms: None,
                        request_started_at_unix_ms: None,
                        reason_code: "external_probe.invalid_endpoint".to_owned(),
                        safe_message:
                            "The external probe endpoint did not resolve to a public non-Tailscale address"
                                .to_owned(),
                    };
                update_external_probes(&result, BTreeMap::new(), Some(unavailable)).await;
                continue;
            }
        };

        let claims = match fetch_gateway_port_forwards(&state_client, &config).await {
            Ok(claims) => claims,
            Err(error) => {
                warn!(%error, "external probe could not read gateway port-forward state");
                GatewayClaims::default()
            }
        };
        let observations =
            futures_util::future::join_all(claims.leases.iter().map(|(usage_id, claim)| {
                probe_external_claim(
                    public_client.clone(),
                    config.clone(),
                    usage_id.clone(),
                    *claim,
                )
            }))
            .await
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let primary = observations
            .values()
            .find(|observation| {
                observation.forwarded_port == claims.primary.forwarded_port
                    && observation.lease_acquired_at_unix_ms
                        == claims.primary.lease_acquired_at_unix_ms
            })
            .cloned();
        update_external_probes(&result, observations, primary).await;
    }
}

async fn probe_external_claim(
    client: reqwest::Client,
    config: ExternalProbeConfig,
    usage_id: String,
    claim: PortForwardClaim,
) -> (String, ExternalProbeStatus) {
    let request_started_at_unix_ms = unix_ms();
    let request_id = format!("external-probe-{usage_id}-{request_started_at_unix_ms}");
    let body = ExternalProbeRequest {
        instance_id: format!("{}:{usage_id}", config.instance_id),
        request_id: request_id.clone(),
        timestamp_unix_ms: request_started_at_unix_ms,
        claimed_public_ip: claim.public_ip,
        forwarded_port: claim.forwarded_port,
    };
    let mut request = client.post(config.url).json(&body);
    if let Some(token) = &config.token {
        request = request.bearer_auth(token);
    }
    let observed = match request.send().await {
        Ok(response) if redirect_is_rejected(response.status()) => unavailable_external_probe(
            "external_probe.redirect_rejected",
            "The external probe endpoint attempted a redirect",
        ),
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.json::<ExternalProbeResponse>().await {
                Ok(response) => map_external_response(response, claim, request_started_at_unix_ms),
                Err(error) => {
                    warn!(%error, %usage_id, "external probe response decode failed");
                    unavailable_external_probe(
                        "external_probe.invalid_response",
                        "The external probe returned an invalid response",
                    )
                }
            },
            Err(error) => {
                let reason = if error.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
                    "external_probe.auth_failed"
                } else {
                    "external_probe.http_failed"
                };
                unavailable_external_probe(reason, "The external probe request failed")
            }
        },
        Err(error) => unavailable_external_probe(
            if error.is_timeout() {
                "external_probe.timeout"
            } else {
                "external_probe.unavailable"
            },
            "The external probe is unavailable; tunnel protection is unchanged",
        ),
    };
    info!(%usage_id, status = observed.status, reason = observed.reason_code, "external probe result");
    (usage_id, observed)
}

async fn build_pinned_external_client(
    url: &Url,
    timeout: Duration,
) -> anyhow::Result<reqwest::Client> {
    let host = url
        .host_str()
        .context("external probe URL must include a hostname")?;
    let addresses = resolve_public_addresses(url).await?;
    build_pinned_client(host, &addresses, timeout)
}

fn build_pinned_client(
    host: &str,
    addresses: &[SocketAddr],
    timeout: Duration,
) -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        // Reqwest retains the original URL host for TLS SNI and Host while
        // connecting only to this freshly classified address set.
        .resolve_to_addrs(host, addresses)
        .build()
        .context("building pinned external probe client")
}

async fn resolve_public_addresses(url: &Url) -> anyhow::Result<Vec<SocketAddr>> {
    let host = url
        .host_str()
        .context("external probe URL must include a hostname")?;
    let port = url
        .port_or_known_default()
        .context("external probe URL must use a known port")?;
    let addresses = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>();
    validate_resolved_addresses(&addresses)?;
    Ok(addresses)
}

fn validate_resolved_addresses(addresses: &[SocketAddr]) -> anyhow::Result<()> {
    if addresses.is_empty() {
        bail!("hostname did not resolve to any addresses");
    }
    for address in addresses {
        if is_disallowed_probe_ip(address.ip()) {
            bail!("resolved to a disallowed address");
        }
    }
    Ok(())
}

fn redirect_is_rejected(status: reqwest::StatusCode) -> bool {
    status.is_redirection()
}

async fn update_external_probes(
    result: &SharedResult,
    external_probes: BTreeMap<String, ExternalProbeStatus>,
    primary: Option<ExternalProbeStatus>,
) {
    let mut result = result.write().await;
    result.external_probes = external_probes;
    result.external_probe = primary;
}

fn map_external_response(
    response: ExternalProbeResponse,
    claim: PortForwardClaim,
    request_started_at_unix_ms: u64,
) -> ExternalProbeStatus {
    // Health requires the service's explicit success reason code, not just the
    // absence of failing booleans: a response such as a stale-timestamp
    // rejection carries null check results and must not be shown as healthy.
    let checks_passed = response.source_public_non_tailscale
        && response.source_matches_claimed_ip.unwrap_or(true)
        && response.tcp_port_reachable.unwrap_or(true);
    let status = if response.reason_code == "external_probe.healthy" && checks_passed {
        "healthy"
    } else if !checks_passed {
        "degraded"
    } else {
        // The service answered but neither confirmed success nor reported a
        // failing check, so no valid observation was made.
        "unavailable"
    };
    ExternalProbeStatus {
        status: status.to_owned(),
        observed_at_unix_ms: response.observed_at_unix_ms,
        source_public_non_tailscale: Some(response.source_public_non_tailscale),
        source_matches_claimed_ip: response.source_matches_claimed_ip,
        tcp_port_reachable: response.tcp_port_reachable,
        forwarded_port: claim.forwarded_port,
        lease_acquired_at_unix_ms: claim.lease_acquired_at_unix_ms,
        request_started_at_unix_ms: Some(request_started_at_unix_ms),
        reason_code: response.reason_code,
        safe_message: response.safe_message,
    }
}

fn unavailable_external_probe(reason_code: &str, safe_message: &str) -> ExternalProbeStatus {
    ExternalProbeStatus {
        status: "unavailable".to_owned(),
        observed_at_unix_ms: unix_ms(),
        source_public_non_tailscale: None,
        source_matches_claimed_ip: None,
        tcp_port_reachable: None,
        forwarded_port: None,
        lease_acquired_at_unix_ms: None,
        request_started_at_unix_ms: None,
        reason_code: reason_code.to_owned(),
        safe_message: safe_message.to_owned(),
    }
}

#[derive(Default)]
struct GatewayClaims {
    primary: PortForwardClaim,
    leases: BTreeMap<String, PortForwardClaim>,
}

async fn fetch_gateway_port_forwards(
    client: &reqwest::Client,
    config: &ExternalProbeConfig,
) -> anyhow::Result<GatewayClaims> {
    let status = client
        .get(&config.state_url)
        .send()
        .await?
        .error_for_status()?
        .json::<GatewayStatus>()
        .await?;
    Ok(extract_port_forward_claims(&status))
}

fn extract_port_forward_claims(status: &GatewayStatus) -> GatewayClaims {
    GatewayClaims {
        primary: extract_port_forward_claim(&status.port_forward),
        leases: status
            .port_forwards
            .iter()
            .filter_map(|(usage_id, lease)| {
                let claim = extract_port_forward_claim(lease);
                claim.forwarded_port.map(|_| (usage_id.clone(), claim))
            })
            .collect(),
    }
}

fn extract_port_forward_claim(status: &GatewayPortForward) -> PortForwardClaim {
    // An inactive lease can retain the previous tunnel's exit address, and
    // claiming a stale address produces a false claimed_ip_mismatch result.
    if !status.active {
        return PortForwardClaim::default();
    }
    let public_ip = status
        .public_ip
        .filter(|ip| !is_disallowed_probe_ip(IpAddr::V4(*ip)));
    let complete_mapping = status.port.zip(status.lease_acquired_at_unix_ms);
    PortForwardClaim {
        public_ip,
        forwarded_port: complete_mapping.map(|(port, _)| port),
        lease_acquired_at_unix_ms: complete_mapping.map(|(_, acquired_at)| acquired_at),
    }
}

async fn udp_dns(server: SocketAddr, query: &[u8]) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(query, server).await?;
    let mut response = [0_u8; 512];
    let (length, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut response))
        .await
        .context("UDP DNS timed out")??;
    validate_response(query, &response[..length])
}

async fn tcp_dns(server: SocketAddr, query: &[u8]) -> anyhow::Result<()> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(server)).await??;
    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query).await?;
    let length = timeout(Duration::from_secs(5), stream.read_u16()).await?? as usize;
    let mut response = vec![0; length];
    timeout(Duration::from_secs(5), stream.read_exact(&mut response)).await??;
    validate_response(query, &response)
}

fn dns_query() -> Vec<u8> {
    vec![
        0x45, 0x47, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]
}

fn validate_response(query: &[u8], response: &[u8]) -> anyhow::Result<()> {
    if response.len() < 12 || response[..2] != query[..2] || response[2] & 0x80 == 0 {
        bail!("invalid DNS response");
    }
    Ok(())
}

fn env(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn env_bool(name: &str, fallback: bool) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => bail!("{name} must be true or false"),
        },
        Err(std::env::VarError::NotPresent) => Ok(fallback),
        Err(error) => Err(error.into()),
    }
}

fn load_external_probe_config() -> anyhow::Result<Option<ExternalProbeConfig>> {
    if !env("EGRESSY_EXTERNAL_PROBE_ENABLED", "false").eq_ignore_ascii_case("true") {
        return Ok(None);
    }

    let url = Url::parse(&env("EGRESSY_EXTERNAL_PROBE_URL", ""))
        .context("invalid EGRESSY_EXTERNAL_PROBE_URL")?;
    if url.scheme() != "https" {
        bail!("EGRESSY_EXTERNAL_PROBE_URL must use https");
    }
    let host = url
        .host_str()
        .context("EGRESSY_EXTERNAL_PROBE_URL must include a hostname")?;
    if host.parse::<IpAddr>().is_ok() {
        bail!("EGRESSY_EXTERNAL_PROBE_URL must use a DNS hostname, not a raw IP");
    }
    if host.ends_with(".ts.net") {
        bail!("EGRESSY_EXTERNAL_PROBE_URL must not use a Tailscale hostname");
    }

    let interval_seconds = env("EGRESSY_EXTERNAL_PROBE_INTERVAL_SECONDS", "10")
        .parse::<u64>()
        .context("invalid EGRESSY_EXTERNAL_PROBE_INTERVAL_SECONDS")?;
    let timeout_seconds = env("EGRESSY_EXTERNAL_PROBE_TIMEOUT_SECONDS", "5")
        .parse::<u64>()
        .context("invalid EGRESSY_EXTERNAL_PROBE_TIMEOUT_SECONDS")?;
    if interval_seconds == 0 {
        bail!("EGRESSY_EXTERNAL_PROBE_INTERVAL_SECONDS must be greater than zero");
    }
    if timeout_seconds == 0 || timeout_seconds >= interval_seconds {
        bail!(
            "EGRESSY_EXTERNAL_PROBE_TIMEOUT_SECONDS must be greater than zero and shorter than the interval"
        );
    }

    let token = load_external_probe_token()?;

    Ok(Some(ExternalProbeConfig {
        instance_id: env("EGRESSY_EXTERNAL_PROBE_INSTANCE_ID", "egressy"),
        url,
        interval: Duration::from_secs(interval_seconds),
        timeout: Duration::from_secs(timeout_seconds),
        token: Some(token),
        state_url: env(
            "EGRESSY_EXTERNAL_PROBE_STATE_URL",
            "http://172.30.0.2:8080/api/v1/status",
        ),
    }))
}

fn is_disallowed_probe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || (Ipv4Addr::new(100, 64, 0, 0)..=Ipv4Addr::new(100, 127, 255, 255)).contains(&ip)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

fn load_external_probe_token() -> anyhow::Result<String> {
    let token = match std::env::var("EGRESSY_EXTERNAL_PROBE_TOKEN") {
        Ok(token) => token,
        Err(_) => {
            let path = std::env::var("EGRESSY_EXTERNAL_PROBE_TOKEN_PATH").context(
                "EGRESSY_EXTERNAL_PROBE_TOKEN or EGRESSY_EXTERNAL_PROBE_TOKEN_PATH is required",
            )?;
            std::fs::read_to_string(&path).with_context(|| {
                format!("failed to read EGRESSY_EXTERNAL_PROBE_TOKEN_PATH {path}")
            })?
        }
    };
    let token = token.trim().to_owned();
    if token.is_empty() {
        bail!("external probe token must not be empty");
    }
    Ok(token)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> PortForwardClaim {
        PortForwardClaim {
            public_ip: Some("203.0.113.10".parse().unwrap()),
            forwarded_port: Some(45678),
            lease_acquired_at_unix_ms: Some(100),
        }
    }

    #[test]
    fn matches_ifconfig_json_asn_organization() {
        let body = br#"{"ip":"198.51.100.8","asn":"AS212238","asn_org":"Datacamp Limited"}"#;
        let matcher = IdentityMatcher::JsonStringContains {
            fields: vec!["asn_org".into()],
            value: "Datacamp".into(),
        };
        assert!(identity_body_matches(body, &matcher).unwrap());
    }

    #[test]
    fn rejects_unexpected_ifconfig_json_identity() {
        let body = br#"{"ip":"198.51.100.8","asn":"AS64500","asn_org":"Example ISP"}"#;
        let matcher = IdentityMatcher::JsonStringContains {
            fields: vec!["asn_org".into()],
            value: "Datacamp".into(),
        };
        assert!(!identity_body_matches(body, &matcher).unwrap());
    }

    #[test]
    fn preserves_plain_text_identity_endpoint_compatibility() {
        assert!(identity_body_matches(
            b"AS212238 Datacamp Limited\n",
            &IdentityMatcher::PlainTextContains("datacamp".into())
        )
        .unwrap());
    }

    #[test]
    fn rejects_identity_json_without_an_organization_field() {
        let matcher = IdentityMatcher::JsonStringContains {
            fields: vec!["asn_org".into()],
            value: "Datacamp".into(),
        };
        assert!(!identity_body_matches(br#"{"ip":"198.51.100.8"}"#, &matcher).unwrap());
    }

    #[test]
    fn matches_allowlisted_json_boolean() {
        assert!(identity_body_matches(
            br#"{"mullvad_exit_ip":true}"#,
            &IdentityMatcher::JsonBoolean {
                field: "mullvad_exit_ip".into(),
                value: true
            },
        )
        .unwrap());
    }

    #[test]
    fn rejects_link_local_ipv6_probe_endpoint() {
        assert!(is_disallowed_probe_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn rejects_mixed_public_and_disallowed_dns_answers() {
        let addresses = [
            "203.0.113.10:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert!(validate_resolved_addresses(&addresses).is_err());
    }

    #[test]
    fn accepts_only_public_dns_answers_for_pinning() {
        let addresses = [
            "203.0.113.10:443".parse().unwrap(),
            "[2001:db8::10]:443".parse().unwrap(),
        ];
        assert!(validate_resolved_addresses(&addresses).is_ok());
    }

    #[tokio::test]
    async fn pinned_client_preserves_host_and_refuses_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let length = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(request.contains("host: probe.example"));
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let client =
            build_pinned_client("probe.example", &[address], Duration::from_secs(1)).unwrap();
        let response = client
            .get(format!("http://probe.example:{}/check", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert!(redirect_is_rejected(response.status()));
        server.await.unwrap();
    }

    #[test]
    fn maps_failed_external_checks_to_degraded() {
        let status = map_external_response(
            ExternalProbeResponse {
                observed_at_unix_ms: 123,
                source_public_non_tailscale: true,
                source_matches_claimed_ip: Some(false),
                tcp_port_reachable: None,
                reason_code: "external_probe.claimed_ip_mismatch".to_owned(),
                safe_message: "The claimed public address did not match the source.".to_owned(),
            },
            claim(),
            110,
        );
        assert_eq!(status.status, "degraded");
        assert_eq!(status.reason_code, "external_probe.claimed_ip_mismatch");
    }

    #[test]
    fn maps_passing_checks_with_healthy_reason_to_healthy() {
        let status = map_external_response(
            ExternalProbeResponse {
                observed_at_unix_ms: 123,
                source_public_non_tailscale: true,
                source_matches_claimed_ip: Some(true),
                tcp_port_reachable: Some(true),
                reason_code: "external_probe.healthy".to_owned(),
                safe_message: "Public HTTPS path succeeded.".to_owned(),
            },
            claim(),
            110,
        );
        assert_eq!(status.status, "healthy");
        assert_eq!(status.forwarded_port, Some(45678));
        assert_eq!(status.lease_acquired_at_unix_ms, Some(100));
        assert_eq!(status.request_started_at_unix_ms, Some(110));
    }

    #[test]
    fn stale_timestamp_response_is_unavailable_not_healthy() {
        // A clock-skewed request is rejected by the service with null check
        // results; it must never surface as a healthy observation.
        let status = map_external_response(
            ExternalProbeResponse {
                observed_at_unix_ms: 123,
                source_public_non_tailscale: true,
                source_matches_claimed_ip: None,
                tcp_port_reachable: None,
                reason_code: "external_probe.invalid_request".to_owned(),
                safe_message: "The request timestamp was outside the allowed window.".to_owned(),
            },
            claim(),
            110,
        );
        assert_eq!(status.status, "unavailable");
        assert_eq!(status.reason_code, "external_probe.invalid_request");
    }

    #[test]
    fn inactive_lease_claims_no_public_ip_or_port() {
        let claim = extract_port_forward_claim(&GatewayPortForward {
            active: false,
            public_ip: Some("203.0.113.10".parse().unwrap()),
            port: Some(45678),
            lease_acquired_at_unix_ms: Some(100),
        });
        assert_eq!(claim, PortForwardClaim::default());
    }

    #[test]
    fn active_lease_claims_public_ip_and_port() {
        let claim = extract_port_forward_claim(&GatewayPortForward {
            active: true,
            public_ip: Some("203.0.113.10".parse().unwrap()),
            port: Some(45678),
            lease_acquired_at_unix_ms: Some(100),
        });
        assert_eq!(claim.public_ip, Some("203.0.113.10".parse().unwrap()));
        assert_eq!(claim.forwarded_port, Some(45678));
        assert_eq!(claim.lease_acquired_at_unix_ms, Some(100));
    }

    #[test]
    fn gateway_claims_include_every_complete_active_lease() {
        let status = GatewayStatus {
            port_forward: GatewayPortForward {
                active: true,
                public_ip: Some("203.0.113.10".parse().unwrap()),
                port: Some(45_678),
                lease_acquired_at_unix_ms: Some(100),
            },
            port_forwards: BTreeMap::from([
                (
                    "qbit".to_owned(),
                    GatewayPortForward {
                        active: true,
                        public_ip: Some("203.0.113.10".parse().unwrap()),
                        port: Some(45_678),
                        lease_acquired_at_unix_ms: Some(100),
                    },
                ),
                (
                    "indexarr".to_owned(),
                    GatewayPortForward {
                        active: true,
                        public_ip: Some("203.0.113.10".parse().unwrap()),
                        port: Some(39_021),
                        lease_acquired_at_unix_ms: Some(101),
                    },
                ),
            ]),
        };
        let claims = extract_port_forward_claims(&status);
        assert_eq!(claims.primary.forwarded_port, Some(45_678));
        assert_eq!(claims.leases["qbit"].forwarded_port, Some(45_678));
        assert_eq!(claims.leases["indexarr"].forwarded_port, Some(39_021));
    }

    #[test]
    fn active_lease_with_non_public_ip_claims_port_only() {
        let claim = extract_port_forward_claim(&GatewayPortForward {
            active: true,
            public_ip: Some("10.2.0.2".parse().unwrap()),
            port: Some(45678),
            lease_acquired_at_unix_ms: Some(100),
        });
        assert_eq!(claim.public_ip, None);
        assert_eq!(claim.forwarded_port, Some(45678));
    }

    #[test]
    fn incomplete_active_lease_omits_forwarding_claim() {
        let claim = extract_port_forward_claim(&GatewayPortForward {
            active: true,
            public_ip: Some("203.0.113.10".parse().unwrap()),
            port: Some(45678),
            lease_acquired_at_unix_ms: None,
        });
        assert_eq!(claim.public_ip, Some("203.0.113.10".parse().unwrap()));
        assert_eq!(claim.forwarded_port, None);
        assert_eq!(claim.lease_acquired_at_unix_ms, None);
    }
}
