use std::{
    collections::{BTreeMap, VecDeque},
    net::Ipv4Addr,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppState {
    pub tunnel: TunnelState,
    pub traffic: TrafficState,
    pub port_forward: PortForwardState,
    pub clients: BTreeMap<String, ClientState>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TrafficState {
    /// Bytes per second received through WireGuard.
    pub download_bytes_per_second: u64,
    /// Bytes per second sent through WireGuard.
    pub upload_bytes_per_second: u64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub sampled_at_unix_ms: Option<u128>,
}

pub type SharedState = Arc<RwLock<AppState>>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TunnelState {
    pub up: bool,
    pub interface: String,
    pub latest_handshake_unix: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PortForwardState {
    pub active: bool,
    pub public_ip: Option<Ipv4Addr>,
    pub port: Option<u16>,
    pub target: Option<String>,
    pub target_port: Option<u16>,
    pub expires_in_seconds: Option<u32>,
    /// Correlation identity for the current NAT-PMP lease acquisition. This
    /// changes on every successful renewal even when the port stays the same.
    pub lease_acquired_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientState {
    pub container_id: String,
    /// Stable key used for app-owned history and optional telemetry export.
    pub usage_id: String,
    pub usage_id_source: UsageIdentitySource,
    pub name: String,
    pub ipv4_address: Ipv4Addr,
    pub port_forward_target: bool,
    pub target_port: Option<u16>,
    pub compliant: bool,
    pub compliance_message: String,
    pub running: bool,
    pub ipv6_address: Option<String>,
    pub networks: Vec<String>,
    pub port_forward_label_valid: bool,
    /// Docker's declared default-gateway selection. This is metadata about
    /// route intent, not proof of the effective route in the container.
    pub route_intent: RouteIntentState,
    pub traffic: ClientTrafficState,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageIdentitySource {
    ExplicitLabel,
    ComposeService,
    #[default]
    ContainerLifetime,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientTrafficSample {
    pub sampled_at_unix_ms: u64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientTrafficState {
    pub download_packets: u64,
    pub downloaded_bytes: u64,
    pub upload_packets: u64,
    pub uploaded_bytes: u64,
    pub sampled_at_unix_ms: Option<u64>,
    pub history: VecDeque<ClientTrafficSample>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntentStatus {
    Verified,
    Mismatch,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteIntentState {
    pub status: RouteIntentStatus,
    pub ipv4_default_network: Option<String>,
    pub ipv6_default_network: Option<String>,
    pub egress_gateway_priority: Option<i64>,
    pub gateway_priorities: BTreeMap<String, Option<i64>>,
    pub reason_code: String,
    pub safe_message: String,
}
