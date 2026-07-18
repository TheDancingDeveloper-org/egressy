use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    time::Duration,
};

use anyhow::{bail, Context};
use ipnet::Ipv4Net;
use serde::Deserialize;

fn default_listen() -> String {
    "0.0.0.0:8080".to_owned()
}

fn default_docker_socket() -> String {
    "http://169.254.254.2:2375".to_owned()
}

fn default_network() -> String {
    "vpn-egress".to_owned()
}

fn default_subnet() -> Ipv4Net {
    "172.30.0.0/24".parse().expect("static subnet is valid")
}

fn default_gateway_ip() -> Ipv4Addr {
    Ipv4Addr::new(172, 30, 0, 2)
}

fn default_bridge() -> String {
    "br-vpn-egress".to_owned()
}

fn default_table() -> u32 {
    200
}

fn default_tunnel() -> String {
    "wg0".to_owned()
}

fn default_wg_config() -> String {
    "/run/secrets/wg0.conf".to_owned()
}

fn default_port_forward_gateway() -> Ipv4Addr {
    Ipv4Addr::new(10, 2, 0, 1)
}

fn default_refresh_seconds() -> u64 {
    45
}

fn default_lifetime_seconds() -> u32 {
    60
}

fn default_dns_listen() -> String {
    "172.30.0.2:53".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_dns_timeout_ms() -> u64 {
    2_000
}

fn default_dns_concurrency() -> usize {
    128
}

fn default_dns_udp_attempts() -> u32 {
    2
}

fn default_dns_failure_threshold() -> u32 {
    3
}

fn default_dns_success_threshold() -> u32 {
    2
}

fn default_probe_url() -> String {
    "http://172.30.0.5:8081/status".to_owned()
}

fn default_external_probe_enabled() -> bool {
    false
}

fn default_external_probe_instance_id() -> String {
    "egressy".to_owned()
}

fn default_external_probe_interval_seconds() -> u64 {
    10
}

fn default_external_probe_timeout_seconds() -> u64 {
    5
}

fn default_history_path() -> String {
    "/var/lib/egressy/egressy.sqlite3".to_owned()
}

fn default_history_retention_days() -> u32 {
    365
}

fn default_history_bucket_seconds() -> u64 {
    60
}

fn default_history_writer_capacity() -> usize {
    1_024
}

fn default_otel_timeout_seconds() -> u64 {
    10
}

fn default_otel_service_name() -> String {
    "egressy".to_owned()
}

fn default_vpn_server_probe_interval_seconds() -> u64 {
    30
}

fn default_vpn_server_probe_timeout_ms() -> u64 {
    1_500
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_docker_socket")]
    pub docker_socket: String,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub wireguard: WireGuardConfig,
    #[serde(default)]
    pub port_forwarding: PortForwardingConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default)]
    pub external_probe: ExternalProbeConfig,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub otel: OtelConfig,
    #[serde(default)]
    pub vpn_server: VpnServerConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
    #[serde(default)]
    pub reconcile: ReconcileConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub name: String,
    pub subnet: Ipv4Net,
    pub gateway_ip: Ipv4Addr,
    pub host_bridge: String,
    pub route_table: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            name: default_network(),
            subnet: default_subnet(),
            gateway_ip: default_gateway_ip(),
            host_bridge: default_bridge(),
            route_table: default_table(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WireGuardConfig {
    pub interface: String,
    pub source: ProfileSource,
    pub config_path: Option<String>,
    pub config_base64_path: Option<String>,
    pub manage: bool,
    pub profile_database_path: String,
    pub storage_key_path: Option<String>,
    pub admin_token_path: Option<String>,
    pub trusted_origins: Vec<String>,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            interface: default_tunnel(),
            source: ProfileSource::Mounted,
            config_path: Some(default_wg_config()),
            config_base64_path: None,
            manage: true,
            profile_database_path: "/var/lib/egressy/profiles.sqlite3".to_owned(),
            storage_key_path: None,
            admin_token_path: None,
            trusted_origins: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSource {
    #[default]
    Mounted,
    GuiManaged,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardingBackend {
    #[default]
    Disabled,
    NatPmp,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortForwardingConfig {
    pub backend: PortForwardingBackend,
    pub gateway: Ipv4Addr,
    pub refresh_seconds: u64,
    pub lifetime_seconds: u32,
    pub max_leases: usize,
    pub primary_usage_id: Option<String>,
}

impl Default for PortForwardingConfig {
    fn default() -> Self {
        Self {
            backend: PortForwardingBackend::Disabled,
            gateway: default_port_forward_gateway(),
            refresh_seconds: default_refresh_seconds(),
            lifetime_seconds: default_lifetime_seconds(),
            max_leases: 5,
            primary_usage_id: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: String,
    pub upstream: DnsUpstreamConfig,
    pub timeout_ms: u64,
    pub max_concurrent_queries: usize,
    pub udp_attempts: u32,
    pub failure_threshold: u32,
    pub success_threshold: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_dns_listen(),
            upstream: DnsUpstreamConfig::default(),
            timeout_ms: default_dns_timeout_ms(),
            max_concurrent_queries: default_dns_concurrency(),
            udp_attempts: default_dns_udp_attempts(),
            failure_threshold: default_dns_failure_threshold(),
            success_threshold: default_dns_success_threshold(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsUpstreamSource {
    #[default]
    Profile,
    Explicit,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsUpstreamConfig {
    pub source: DnsUpstreamSource,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProbeConfig {
    pub enabled: bool,
    pub url: String,
    pub interval_seconds: u64,
    pub token_path: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            url: default_probe_url(),
            interval_seconds: 30,
            token_path: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ValidationConfig {
    pub identity: IdentityValidationConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityValidationConfig {
    pub enabled: bool,
    pub url: String,
    pub matcher: IdentityMatcher,
}

impl Default for IdentityValidationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            matcher: IdentityMatcher::PlainTextContains {
                value: String::new(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IdentityMatcher {
    PlainTextContains { value: String },
    JsonStringContains { fields: Vec<String>, value: String },
    JsonBoolean { field: String, value: bool },
}

impl IdentityMatcher {
    pub fn expected_value(&self) -> String {
        match self {
            Self::PlainTextContains { value } | Self::JsonStringContains { value, .. } => {
                value.clone()
            }
            Self::JsonBoolean { value, .. } => value.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExternalProbeConfig {
    pub enabled: bool,
    pub instance_id: String,
    pub url: String,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub token_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub path: String,
    pub retention_days: u32,
    pub bucket_seconds: u64,
    pub writer_capacity: usize,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_history_path(),
            retention_days: default_history_retention_days(),
            bucket_seconds: default_history_bucket_seconds(),
            writer_capacity: default_history_writer_capacity(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OtelConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub protocol: String,
    pub timeout_seconds: u64,
    pub service_name: String,
    pub headers_path: Option<String>,
    pub insecure: bool,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            protocol: "http/protobuf".to_owned(),
            timeout_seconds: default_otel_timeout_seconds(),
            service_name: default_otel_service_name(),
            headers_path: None,
            insecure: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VpnServerConfig {
    pub latency_probe_enabled: bool,
    pub interval_seconds: u64,
    pub timeout_ms: u64,
}

impl Default for VpnServerConfig {
    fn default() -> Self {
        Self {
            latency_probe_enabled: true,
            interval_seconds: default_vpn_server_probe_interval_seconds(),
            timeout_ms: default_vpn_server_probe_timeout_ms(),
        }
    }
}

impl Default for ExternalProbeConfig {
    fn default() -> Self {
        Self {
            enabled: default_external_probe_enabled(),
            instance_id: default_external_probe_instance_id(),
            url: String::new(),
            interval_seconds: default_external_probe_interval_seconds(),
            timeout_seconds: default_external_probe_timeout_seconds(),
            token_path: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub maximum_backoff_seconds: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 3,
            success_threshold: 2,
            maximum_backoff_seconds: 300,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReconcileConfig {
    pub interval_seconds: u64,
    pub apply_gateway_firewall: bool,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 5,
            apply_gateway_firewall: default_true(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&raw).context("parsing YAML")?;
        config.apply_otel_environment()?;
        Ok(config)
    }

    fn apply_otel_environment(&mut self) -> anyhow::Result<()> {
        if let Some(value) = env_var("EGRESSY_OTEL_ENABLED") {
            self.otel.enabled = parse_env_bool("EGRESSY_OTEL_ENABLED", &value)?;
        }
        if let Some(value) = env_var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            self.otel.endpoint = value;
        }
        if let Some(value) = env_var("OTEL_EXPORTER_OTLP_PROTOCOL") {
            self.otel.protocol = value;
        }
        if let Some(value) = env_var("OTEL_EXPORTER_OTLP_TIMEOUT") {
            self.otel.timeout_seconds = parse_otel_timeout(&value)?;
        }
        if let Some(value) = env_var("OTEL_SERVICE_NAME") {
            self.otel.service_name = value;
        }
        if let Some(value) = env_var("EGRESSY_OTEL_HEADERS_PATH") {
            self.otel.headers_path = (!value.is_empty()).then_some(value);
        }
        if let Some(value) = env_var("EGRESSY_OTEL_INSECURE") {
            self.otel.insecure = parse_env_bool("EGRESSY_OTEL_INSECURE", &value)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !(self.docker_socket.starts_with("http://")
            || self.docker_socket.starts_with("tcp://")
            || self.docker_socket.starts_with("unix://")
            || self.docker_socket.starts_with('/'))
        {
            bail!("docker_socket must be an http:// proxy endpoint or Unix socket path");
        }
        if !self.network.subnet.contains(&self.network.gateway_ip) {
            bail!("network.gateway_ip must be inside network.subnet");
        }
        if self.network.gateway_ip == self.network.subnet.network()
            || self.network.gateway_ip == self.network.subnet.broadcast()
        {
            bail!("network.gateway_ip cannot be the network or broadcast address");
        }
        if self.network.route_table == 0 || self.network.route_table == 253 {
            bail!("network.route_table must be a dedicated non-zero policy table");
        }
        if self.port_forwarding.backend == PortForwardingBackend::NatPmp
            && self.port_forwarding.refresh_seconds
                >= u64::from(self.port_forwarding.lifetime_seconds)
        {
            bail!("port_forwarding.refresh_seconds must be shorter than port_forwarding.lifetime_seconds");
        }
        if self.port_forwarding.max_leases == 0 || self.port_forwarding.max_leases > 5 {
            bail!("port_forwarding.max_leases must be between 1 and 5");
        }
        if self
            .port_forwarding
            .primary_usage_id
            .as_deref()
            .is_some_and(|usage_id| usage_id.trim().is_empty())
        {
            bail!("port_forwarding.primary_usage_id must not be empty");
        }
        if self.reconcile.interval_seconds == 0 {
            bail!("reconcile.interval_seconds must be greater than zero");
        }
        if !self.reconcile.apply_gateway_firewall {
            bail!(
                "reconcile.apply_gateway_firewall=false is unsafe: Egressy must own the fail-closed gateway firewall"
            );
        }
        if self.dns.timeout_ms == 0
            || self.dns.max_concurrent_queries == 0
            || self.dns.udp_attempts == 0
            || self.dns.failure_threshold == 0
            || self.dns.success_threshold == 0
        {
            bail!("dns timeout, concurrency, attempts, and thresholds must be greater than zero");
        }
        if self.recovery.failure_threshold == 0 || self.recovery.success_threshold == 0 {
            bail!("recovery thresholds must be greater than zero");
        }
        if self.probe.enabled {
            reqwest::Url::parse(&self.probe.url).context("invalid probe.url")?;
            if self.probe.interval_seconds == 0 {
                bail!("probe.interval_seconds must be greater than zero");
            }
        }
        if self.external_probe.enabled {
            let url = reqwest::Url::parse(&self.external_probe.url)
                .context("invalid external_probe.url")?;
            if url.scheme() != "https" {
                bail!("external_probe.url must use https");
            }
            let host = url
                .host_str()
                .context("external_probe.url must include a hostname")?;
            if host.parse::<IpAddr>().is_ok() {
                bail!("external_probe.url must use a DNS hostname, not a raw IP");
            }
            if host.ends_with(".ts.net") {
                bail!("external_probe.url must not use a Tailscale hostname");
            }
            if self.external_probe.instance_id.trim().is_empty() {
                bail!("external_probe.instance_id must not be empty");
            }
            if self.external_probe.interval_seconds == 0 {
                bail!("external_probe.interval_seconds must be greater than zero");
            }
            if self.external_probe.timeout_seconds == 0 {
                bail!("external_probe.timeout_seconds must be greater than zero");
            }
            if self.external_probe.timeout_seconds >= self.external_probe.interval_seconds {
                bail!(
                    "external_probe.timeout_seconds must be shorter than external_probe.interval_seconds"
                );
            }
            if self.port_forwarding.backend == PortForwardingBackend::NatPmp
                && self
                    .external_probe
                    .interval_seconds
                    .saturating_add(self.external_probe.timeout_seconds)
                    .saturating_add(self.probe.interval_seconds)
                    >= self.port_forwarding.refresh_seconds
            {
                bail!(
                    "external probe interval, timeout, and daemon poll interval must total less than port_forwarding.refresh_seconds"
                );
            }
        }
        if self.validation.identity.enabled {
            let url = reqwest::Url::parse(&self.validation.identity.url)
                .context("invalid validation.identity.url")?;
            if url.scheme() != "https" || url.host_str().is_none() {
                bail!("validation.identity.url must be an HTTPS URL with a hostname");
            }
            const FIELDS: &[&str] = &["asn_org", "as_name", "org", "mullvad_exit_ip"];
            match &self.validation.identity.matcher {
                IdentityMatcher::PlainTextContains { value } => validate_match_value(value)?,
                IdentityMatcher::JsonStringContains { fields, value } => {
                    validate_match_value(value)?;
                    if fields.is_empty()
                        || fields.len() > 8
                        || fields.iter().any(|field| !FIELDS.contains(&field.as_str()))
                    {
                        bail!("validation identity JSON fields must use the bounded allowlist");
                    }
                }
                IdentityMatcher::JsonBoolean { field, .. } if !FIELDS.contains(&field.as_str()) => {
                    bail!("validation identity JSON boolean field must use the bounded allowlist");
                }
                IdentityMatcher::JsonBoolean { .. } => {}
            }
        }
        if self.persistence.enabled {
            if self.persistence.path.trim().is_empty() {
                bail!("persistence.path must not be empty when persistence is enabled");
            }
            if self.persistence.retention_days == 0 {
                bail!("persistence.retention_days must be greater than zero");
            }
            if self.persistence.bucket_seconds == 0 || 86_400 % self.persistence.bucket_seconds != 0
            {
                bail!("persistence.bucket_seconds must be a non-zero divisor of 86400");
            }
            if self.persistence.writer_capacity < 16 {
                bail!("persistence.writer_capacity must be at least 16");
            }
        }
        if self.otel.enabled {
            let endpoint = reqwest::Url::parse(&self.otel.endpoint)
                .context("OTEL_EXPORTER_OTLP_ENDPOINT must be a valid URL when OTEL is enabled")?;
            if self.otel.protocol != "http/protobuf" {
                bail!("OTEL_EXPORTER_OTLP_PROTOCOL currently supports only http/protobuf");
            }
            if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && self.otel.insecure)
            {
                bail!("OTEL endpoint must use https unless EGRESSY_OTEL_INSECURE=true");
            }
            if endpoint.host_str().is_none() {
                bail!("OTEL endpoint must include a hostname");
            }
            if self.otel.timeout_seconds == 0 || self.otel.timeout_seconds > 60 {
                bail!("OTEL timeout must be between 1 and 60 seconds");
            }
            if self.otel.service_name.is_empty()
                || self.otel.service_name.len() > 64
                || !self.otel.service_name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                })
            {
                bail!("OTEL service name must be 1-64 safe ASCII characters");
            }
            if let Some(path) = &self.otel.headers_path {
                let metadata = fs::metadata(path)
                    .with_context(|| "reading protected OTEL headers file metadata")?;
                if !metadata.is_file() || metadata.len() > 16_384 {
                    bail!("OTEL headers path must be a regular file no larger than 16 KiB");
                }
            }
        }
        if self.vpn_server.interval_seconds == 0
            || self.vpn_server.timeout_ms == 0
            || self.vpn_server.timeout_ms >= self.vpn_server.interval_seconds * 1_000
        {
            bail!("vpn_server timeout must be non-zero and shorter than its interval");
        }
        for value in [
            &self.network.name,
            &self.network.host_bridge,
            &self.wireguard.interface,
        ] {
            if value.is_empty()
                || !value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
            {
                bail!("network and interface names may only contain ASCII letters, digits, -, _, and .");
            }
        }
        self.listen
            .parse::<std::net::SocketAddr>()
            .context("invalid listen address")?;
        self.dns
            .listen
            .parse::<std::net::SocketAddr>()
            .context("invalid dns.listen")?;
        if self.dns.enabled && self.dns.upstream.source == DnsUpstreamSource::Explicit {
            if self.dns.upstream.addresses.is_empty() {
                bail!("dns.upstream.addresses must not be empty for an explicit upstream");
            }
            for address in &self.dns.upstream.addresses {
                address
                    .parse::<std::net::SocketAddr>()
                    .context("invalid dns.upstream.addresses entry")?;
            }
        }
        if self.wireguard.source == ProfileSource::Mounted
            && self.wireguard.config_path.is_some()
            && self.wireguard.config_base64_path.is_some()
        {
            bail!(
                "wireguard mounted source must select config_path or config_base64_path, not both"
            );
        }
        if self.wireguard.source == ProfileSource::GuiManaged {
            if self.wireguard.profile_database_path.trim().is_empty() {
                bail!("wireguard.profile_database_path must not be empty");
            }
            if self.wireguard.config_base64_path.is_some() {
                bail!("wireguard.config_base64_path is only valid for mounted source");
            }
        }
        for origin in &self.wireguard.trusted_origins {
            let url =
                reqwest::Url::parse(origin).context("invalid wireguard.trusted_origins entry")?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                bail!("wireguard.trusted_origins entries must be HTTP(S) origins");
            }
        }
        Ok(())
    }

    pub fn reconcile_interval(&self) -> Duration {
        Duration::from_secs(self.reconcile.interval_seconds)
    }
}

fn validate_match_value(value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() || value.len() > 128 {
        bail!("validation identity match values must contain 1-128 characters");
    }
    Ok(())
}

fn env_var(name: &str) -> Option<String> {
    env::var_os(name).map(|value| value.to_string_lossy().into_owned())
}

fn parse_env_bool(name: &str, value: &str) -> anyhow::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => bail!("{name} must be true or false"),
    }
}

fn parse_otel_timeout(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim();
    let seconds = if let Some(milliseconds) = trimmed.strip_suffix("ms") {
        milliseconds
            .parse::<u64>()
            .map(|value| value.div_ceil(1_000))
    } else if let Some(seconds) = trimmed.strip_suffix('s') {
        seconds.parse::<u64>()
    } else {
        // The OpenTelemetry environment-variable specification defines bare
        // timeout integers as milliseconds. Accept explicit suffixes as a
        // convenience for Compose users, but keep the standard form exact.
        trimmed.parse::<u64>().map(|value| value.div_ceil(1_000))
    }
    .context("OTEL_EXPORTER_OTLP_TIMEOUT must be milliseconds, Ns, or Nms")?;
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_gateway_outside_subnet() {
        let config: Config =
            serde_yaml::from_str("network:\n  subnet: 172.30.0.0/24\n  gateway_ip: 172.31.0.2\n")
                .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn defaults_to_restricted_docker_proxy() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        assert_eq!(config.docker_socket, "http://169.254.254.2:2375");
    }

    #[test]
    fn rejects_unsupported_docker_endpoint_scheme() {
        let config: Config = serde_yaml::from_str("docker_socket: ftp://docker.example\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_managed_runtime_without_gateway_firewall_owner() {
        let config: Config = serde_yaml::from_str(
            "wireguard:\n  manage: true\nreconcile:\n  apply_gateway_firewall: false\n",
        )
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("must own the fail-closed gateway firewall"));
    }

    #[test]
    fn external_probe_is_disabled_by_default() {
        // Guardrail: the external probe sends deployment identity to an
        // external endpoint and must stay strictly opt-in. Do not change this
        // default without explicit operator sign-off.
        let config: Config = serde_yaml::from_str("{}").unwrap();
        assert!(!config.external_probe.enabled);
        assert_eq!(config.external_probe.interval_seconds, 10);
        assert_eq!(config.external_probe.timeout_seconds, 5);
    }

    #[test]
    fn persistence_is_enabled_with_durable_defaults() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        assert!(config.persistence.enabled);
        assert_eq!(config.persistence.path, "/var/lib/egressy/egressy.sqlite3");
        assert_eq!(config.persistence.retention_days, 365);
        config.validate().unwrap();
    }

    #[test]
    fn port_forwarding_defaults_bound_concurrent_leases() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        assert_eq!(config.port_forwarding.max_leases, 5);
        assert_eq!(config.port_forwarding.primary_usage_id, None);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_port_forwarding_lease_limits_and_primary() {
        for yaml in [
            "port_forwarding:\n  max_leases: 0\n",
            "port_forwarding:\n  max_leases: 6\n",
            "port_forwarding:\n  primary_usage_id: ''\n",
        ] {
            let config: Config = serde_yaml::from_str(yaml).unwrap();
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn rejects_invalid_enabled_persistence_settings() {
        let config: Config = serde_yaml::from_str(
            "persistence:\n  enabled: true\n  retention_days: 0\n  bucket_seconds: 7\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn otel_is_disabled_by_default_and_ignores_empty_endpoint() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        assert!(!config.otel.enabled);
        config.validate().unwrap();
    }

    #[test]
    fn validates_enabled_otel_and_requires_explicit_insecure_http() {
        let secure: Config = serde_yaml::from_str(
            "otel:\n  enabled: true\n  endpoint: https://collector.example.com:4318\n",
        )
        .unwrap();
        secure.validate().unwrap();
        let insecure: Config =
            serde_yaml::from_str("otel:\n  enabled: true\n  endpoint: http://collector:4318\n")
                .unwrap();
        assert!(insecure.validate().is_err());
        let allowed: Config = serde_yaml::from_str(
            "otel:\n  enabled: true\n  endpoint: http://collector:4318\n  insecure: true\n",
        )
        .unwrap();
        allowed.validate().unwrap();
    }

    #[test]
    fn otel_timeout_uses_standard_millisecond_units() {
        assert_eq!(parse_otel_timeout("10000").unwrap(), 10);
        assert_eq!(parse_otel_timeout("1500").unwrap(), 2);
        assert_eq!(parse_otel_timeout("10s").unwrap(), 10);
        assert_eq!(parse_otel_timeout("1500ms").unwrap(), 2);
    }

    #[test]
    fn rejects_external_probe_raw_ip_host() {
        let config: Config = serde_yaml::from_str(
            "external_probe:\n  enabled: true\n  url: https://100.92.4.57/api/v1/check\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_external_probe_tailscale_hostname() {
        let config: Config = serde_yaml::from_str(
            "external_probe:\n  enabled: true\n  url: https://probe.tailc7d3c.ts.net/api/v1/check\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_external_probe_non_https_url() {
        let config: Config = serde_yaml::from_str(
            "external_probe:\n  enabled: true\n  url: http://probe.example.com/api/v1/check\n",
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn external_verification_cycle_must_fit_before_natpmp_renewal() {
        let valid: Config = serde_yaml::from_str(
            "port_forwarding:\n  backend: nat_pmp\n  refresh_seconds: 45\nexternal_probe:\n  enabled: true\n  url: https://probe.example.com/api/v1/check\n  interval_seconds: 10\n  timeout_seconds: 5\nprobe:\n  interval_seconds: 10\n",
        )
        .unwrap();
        valid.validate().unwrap();

        let invalid: Config = serde_yaml::from_str(
            "port_forwarding:\n  backend: nat_pmp\n  refresh_seconds: 45\nexternal_probe:\n  enabled: true\n  url: https://probe.example.com/api/v1/check\n  interval_seconds: 20\n  timeout_seconds: 10\nprobe:\n  interval_seconds: 15\n",
        )
        .unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn identity_validation_is_disabled_by_default_and_matchers_are_bounded() {
        let disabled: Config = serde_yaml::from_str("{}").unwrap();
        assert!(!disabled.validation.identity.enabled);
        let mullvad: Config = serde_yaml::from_str(
            "validation:\n  identity:\n    enabled: true\n    url: https://am.i.mullvad.net/json\n    matcher:\n      type: json_boolean\n      field: mullvad_exit_ip\n      value: true\n",
        )
        .unwrap();
        mullvad.validate().unwrap();
        let arbitrary: Config = serde_yaml::from_str(
            "validation:\n  identity:\n    enabled: true\n    url: https://example.test/json\n    matcher:\n      type: json_string_contains\n      fields: [password]\n      value: secret\n",
        )
        .unwrap();
        assert!(arbitrary.validate().is_err());
    }
}
