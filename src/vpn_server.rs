use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    process::Stdio,
    time::Duration,
};

use anyhow::{bail, Context};
use tokio::process::Command;

use crate::domain::{VpnServerLatency, VpnServerLatencyStatus, VpnServerStatus};

const RECENT_SAMPLE_CAPACITY: usize = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredPeer {
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub address_family: String,
    pub allowed_ips_posture: String,
    pub provider_inferred: Option<String>,
    pub region_inferred: Option<String>,
    pub inference_source: Option<String>,
    pub inference_confidence: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LatencyWindow {
    samples: VecDeque<Option<f64>>,
    total_samples: u64,
}

impl Default for LatencyWindow {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(RECENT_SAMPLE_CAPACITY),
            total_samples: 0,
        }
    }
}

impl LatencyWindow {
    pub fn record(&mut self, sample: Option<f64>) {
        if self.samples.len() == RECENT_SAMPLE_CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        self.total_samples = self.total_samples.saturating_add(1);
    }

    pub fn state(&self, status: VpnServerLatencyStatus, sampled_at: u64) -> VpnServerLatency {
        let measured = self
            .samples
            .iter()
            .filter_map(|sample| *sample)
            .collect::<Vec<_>>();
        let minimum = measured.iter().copied().reduce(f64::min);
        let maximum = measured.iter().copied().reduce(f64::max);
        let average =
            (!measured.is_empty()).then(|| measured.iter().sum::<f64>() / measured.len() as f64);
        let loss_ratio = (!self.samples.is_empty()).then(|| {
            self.samples
                .iter()
                .filter(|sample| sample.is_none())
                .count() as f64
                / self.samples.len() as f64
        });
        VpnServerLatency {
            status,
            sampled_at_unix_ms: Some(sampled_at),
            latest_rtt_ms: self.samples.back().copied().flatten(),
            recent_min_rtt_ms: minimum,
            recent_average_rtt_ms: average,
            recent_max_rtt_ms: maximum,
            loss_ratio,
            sample_count: self.total_samples,
        }
    }
}

pub fn parse_wireguard_profile(profile: &str) -> anyhow::Result<ConfiguredPeer> {
    let mut in_peer = false;
    let mut peer_count = 0;
    let mut endpoint = None;
    let mut allowed_ips = None;
    for raw_line in profile.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.eq_ignore_ascii_case("[Peer]") {
            peer_count += 1;
            in_peer = true;
            continue;
        }
        if line.starts_with('[') {
            in_peer = false;
            continue;
        }
        if !in_peer {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "endpoint" => endpoint = Some(value.trim().to_owned()),
            "allowedips" => allowed_ips = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    if peer_count != 1 {
        bail!("exactly one WireGuard peer is required for VPN-server reporting");
    }
    let (host, port) = parse_endpoint(endpoint.as_deref().context("peer has no Endpoint")?)?;
    let address_family = host
        .parse::<IpAddr>()
        .map(|address| match address {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        })
        .unwrap_or("hostname")
        .to_owned();
    let allowed_ips_posture = summarize_allowed_ips(allowed_ips.as_deref().unwrap_or_default());
    let (provider_inferred, region_inferred, inference_source, inference_confidence) =
        infer_endpoint(&host);
    Ok(ConfiguredPeer {
        endpoint_host: host,
        endpoint_port: port,
        address_family,
        allowed_ips_posture,
        provider_inferred,
        region_inferred,
        inference_source,
        inference_confidence,
    })
}

fn parse_endpoint(endpoint: &str) -> anyhow::Result<(String, u16)> {
    if let Ok(socket) = endpoint.parse::<SocketAddr>() {
        return Ok((socket.ip().to_string(), socket.port()));
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .context("WireGuard Endpoint must contain a port")?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty()
        || host.len() > 253
        || !host.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | ':')
        })
    {
        bail!("WireGuard Endpoint host is empty, unsafe, or too long");
    }
    Ok((host.to_ascii_lowercase(), port.parse()?))
}

fn summarize_allowed_ips(value: &str) -> String {
    let entries = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    let ipv4_default = entries.contains(&"0.0.0.0/0");
    let ipv6_default = entries.contains(&"::/0");
    match (ipv4_default, ipv6_default) {
        (true, true) => "ipv4_ipv6_default".to_owned(),
        (true, false) => "ipv4_default".to_owned(),
        (false, true) => "ipv6_default".to_owned(),
        (false, false) if entries.is_empty() => "unspecified".to_owned(),
        (false, false) => "restricted_prefixes".to_owned(),
    }
}

fn infer_endpoint(
    host: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let lower = host.to_ascii_lowercase();
    if !(lower.ends_with(".protonvpn.net") || lower.ends_with(".protonvpn.com")) {
        return (None, None, None, None);
    }
    let first = lower.split('.').next().unwrap_or_default();
    let region = first
        .split('-')
        .next()
        .filter(|value| {
            value.len() == 2
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphabetic())
        })
        .map(str::to_ascii_uppercase);
    (
        Some("Proton VPN".to_owned()),
        region,
        Some("configured_endpoint_hostname".to_owned()),
        Some("low".to_owned()),
    )
}

pub async fn runtime_endpoint(interface: &str) -> anyhow::Result<SocketAddr> {
    let output = Command::new("wg")
        .args(["show", interface, "endpoints"])
        .stderr(Stdio::piped())
        .output()
        .await?;
    if !output.status.success() {
        bail!("wg endpoint query failed");
    }
    let output_text = String::from_utf8_lossy(&output.stdout);
    let endpoints = output_text
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter(|value| *value != "(none)")
        .collect::<Vec<_>>();
    if endpoints.len() != 1 {
        bail!("runtime WireGuard endpoint is missing or ambiguous");
    }
    endpoints[0]
        .parse::<SocketAddr>()
        .context("runtime WireGuard endpoint is malformed")
}

pub async fn probe_endpoint(
    endpoint: SocketAddr,
    tunnel_interface: &str,
    timeout: Duration,
) -> anyhow::Result<ProbeResult> {
    let address = endpoint.ip().to_string();
    let route = Command::new("ip")
        .args(["route", "get", &address])
        .stderr(Stdio::piped())
        .output()
        .await?;
    if !route.status.success() {
        return Ok(ProbeResult::ResolutionFailed);
    }
    let route = String::from_utf8_lossy(&route.stdout);
    if route
        .split_whitespace()
        .any(|part| part == tunnel_interface)
    {
        bail!("refusing to probe the WireGuard endpoint through the tunnel itself");
    }
    let timeout_seconds = timeout.as_secs().max(1).saturating_add(1).to_string();
    let output = tokio::time::timeout(
        timeout,
        Command::new("ping")
            .args(["-n", "-c", "1", "-W", &timeout_seconds, &address])
            .stderr(Stdio::piped())
            .output(),
    )
    .await;
    match output {
        Ok(Ok(output)) if output.status.success() => {
            parse_ping_rtt(&String::from_utf8_lossy(&output.stdout))
                .map(ProbeResult::Measured)
                .context("ping succeeded without a parseable RTT")
        }
        Ok(Ok(output)) if output.status.code() == Some(1) => Ok(ProbeResult::Timeout),
        Ok(Ok(_)) => Ok(ProbeResult::Unsupported),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(ProbeResult::Unsupported)
        }
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Ok(ProbeResult::Timeout),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProbeResult {
    Measured(f64),
    Timeout,
    Unsupported,
    ResolutionFailed,
    Unavailable,
}

impl ProbeResult {
    pub fn status(self) -> VpnServerLatencyStatus {
        match self {
            ProbeResult::Measured(_) => VpnServerLatencyStatus::Measured,
            ProbeResult::Timeout => VpnServerLatencyStatus::Timeout,
            ProbeResult::Unsupported => VpnServerLatencyStatus::Unsupported,
            ProbeResult::ResolutionFailed => VpnServerLatencyStatus::ResolutionFailed,
            ProbeResult::Unavailable => VpnServerLatencyStatus::Unavailable,
        }
    }

    pub fn rtt(self) -> Option<f64> {
        match self {
            ProbeResult::Measured(value) => Some(value),
            _ => None,
        }
    }
}

fn parse_ping_rtt(output: &str) -> Option<f64> {
    output.lines().find_map(|line| {
        line.split_whitespace()
            .find_map(|field| field.strip_prefix("time="))
            .and_then(|value| value.parse().ok())
    })
}

pub fn configured_status(peer: &ConfiguredPeer) -> VpnServerStatus {
    VpnServerStatus {
        configured_endpoint_host: Some(peer.endpoint_host.clone()),
        configured_endpoint_port: Some(peer.endpoint_port),
        configured_address_family: Some(peer.address_family.clone()),
        allowed_ips_posture: peer.allowed_ips_posture.clone(),
        provider_inferred: peer.provider_inferred.clone(),
        region_inferred: peer.region_inferred.clone(),
        inference_source: peer.inference_source.clone(),
        inference_confidence: peer.inference_confidence.clone(),
        ..VpnServerStatus::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "[Interface]\nPrivateKey = secret-never-return\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = peer-secret-never-return\nEndpoint = us-ny-01.protonvpn.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";

    #[test]
    fn parses_safe_peer_metadata_without_keys() {
        let peer = parse_wireguard_profile(PROFILE).unwrap();
        assert_eq!(peer.endpoint_host, "us-ny-01.protonvpn.net");
        assert_eq!(peer.endpoint_port, 51820);
        assert_eq!(peer.provider_inferred.as_deref(), Some("Proton VPN"));
        assert_eq!(peer.region_inferred.as_deref(), Some("US"));
        assert_eq!(peer.allowed_ips_posture, "ipv4_ipv6_default");
        let serialized = serde_json::to_string(&configured_status(&peer)).unwrap();
        assert!(!serialized.contains("secret-never-return"));
    }

    #[test]
    fn parses_bracketed_ipv6_and_rejects_multiple_peers() {
        let ipv6 = parse_wireguard_profile(
            "[Interface]\nAddress=10.0.0.2\n[Peer]\nEndpoint=[2001:db8::1]:443\nAllowedIPs=0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(ipv6.address_family, "ipv6");
        assert!(parse_wireguard_profile(&format!("{PROFILE}[Peer]\nEndpoint=x:1\n")).is_err());
    }

    #[test]
    fn raw_ip_does_not_manufacture_provider_or_region() {
        let peer = parse_wireguard_profile(
            "[Interface]\nAddress=10.0.0.2\n[Peer]\nEndpoint=198.51.100.4:51820\nAllowedIPs=0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(peer.provider_inferred, None);
        assert_eq!(peer.region_inferred, None);
    }

    #[test]
    fn parses_ping_rtt_and_calculates_loss_window() {
        assert_eq!(
            parse_ping_rtt("64 bytes from 1.2.3.4: time=23.4 ms"),
            Some(23.4)
        );
        let mut window = LatencyWindow::default();
        window.record(Some(10.0));
        window.record(None);
        window.record(Some(20.0));
        let state = window.state(VpnServerLatencyStatus::Measured, 1);
        assert_eq!(state.recent_min_rtt_ms, Some(10.0));
        assert_eq!(state.recent_average_rtt_ms, Some(15.0));
        assert_eq!(state.recent_max_rtt_ms, Some(20.0));
        assert_eq!(state.loss_ratio, Some(1.0 / 3.0));
    }
}
