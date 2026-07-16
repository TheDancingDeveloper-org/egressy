use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Context;
use bollard::{models::EndpointSettings, query_parameters::ListContainersOptionsBuilder, Docker};
use ipnet::Ipv4Net;

use crate::isolation::{IsolationCandidate, ISOLATION_ALLOW_LABEL, ISOLATION_ID_LABEL};
use crate::state::{ClientState, RouteIntentState, RouteIntentStatus, UsageIdentitySource};

pub const ENABLE_LABEL: &str = "egressy.enabled";
pub const PORT_FORWARD_LABEL: &str = "egressy.port-forward";
pub const TARGET_PORT_LABEL: &str = "egressy.target-port";
pub const USAGE_ID_LABEL: &str = "egressy.usage-id";
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";

pub struct DockerObserver {
    docker: Docker,
    network_name: String,
    subnet: Ipv4Net,
}

#[derive(Clone, Debug)]
pub struct NetworkObservation {
    pub exists: bool,
    pub subnet_matches: bool,
    pub gateway_attached: bool,
    pub ipv6_enabled: bool,
}

impl DockerObserver {
    pub fn connect(socket: &str, network_name: String, subnet: Ipv4Net) -> anyhow::Result<Self> {
        let docker = if socket.starts_with("http://") || socket.starts_with("tcp://") {
            Docker::connect_with_http(socket, 120, bollard::API_DEFAULT_VERSION)
        } else if socket == "/var/run/docker.sock" {
            Docker::connect_with_local_defaults()
        } else {
            Docker::connect_with_unix(socket, 120, bollard::API_DEFAULT_VERSION)
        }
        .context("connecting to Docker")?;
        Ok(Self {
            docker,
            network_name,
            subnet,
        })
    }

    pub async fn discover(&self) -> anyhow::Result<BTreeMap<String, ClientState>> {
        let options = ListContainersOptionsBuilder::default().all(true).build();
        let containers = self.docker.list_containers(Some(options)).await?;
        let mut clients = BTreeMap::new();

        for container in containers {
            let labels = container.labels.unwrap_or_default();
            if !label_is_true(labels.get(ENABLE_LABEL)) {
                continue;
            }
            let id = container.id.unwrap_or_default();
            let name = container
                .names
                .unwrap_or_default()
                .into_iter()
                .next()
                .unwrap_or_else(|| id.clone())
                .trim_start_matches('/')
                .to_owned();
            let running = container
                .state
                .is_some_and(|state| state.to_string() == "running");
            let networks = container
                .network_settings
                .and_then(|settings| settings.networks)
                .unwrap_or_default();
            let mut network_names = networks.keys().cloned().collect::<Vec<_>>();
            network_names.sort();
            let endpoint = networks.get(&self.network_name);
            let address = endpoint
                .and_then(|endpoint| endpoint.ip_address.clone())
                .and_then(|address| address.parse::<Ipv4Addr>().ok());
            let ipv6_address = endpoint
                .and_then(|endpoint| endpoint.global_ipv6_address.clone())
                .filter(|address| !address.is_empty());
            let route_intent = derive_route_intent(&self.network_name, &networks);
            let port_forward_target = label_is_true(labels.get(PORT_FORWARD_LABEL));
            let target_port = labels
                .get(TARGET_PORT_LABEL)
                .and_then(|port| port.parse().ok());
            let port_forward_label_valid = !port_forward_target || target_port.is_some();
            let (usage_id, usage_id_source) = derive_usage_identity(&labels, &id);

            let (ipv4_address, attached, mut compliance_message) = match address {
                Some(address) if self.subnet.contains(&address) => {
                    (
                        address,
                        true,
                        "attached to the egress network; effective default route is not runtime-attested"
                            .to_owned(),
                    )
                }
                _ => (
                    Ipv4Addr::UNSPECIFIED,
                    false,
                    format!(
                        "labelled for egress but not attached to {}",
                        self.network_name
                    ),
                ),
            };
            let route_matches = route_intent_is_compatible(&route_intent);
            let compliant = attached && running && port_forward_label_valid && route_matches;
            if attached && !running {
                compliance_message = "enrolled container is not running".to_owned();
            } else if attached && !port_forward_label_valid {
                compliance_message =
                    "port forwarding requested without a valid egressy.target-port".to_owned();
            } else if attached && !route_matches {
                compliance_message = "Docker declares an alternate IPv4 default network; the client is ineligible for compliant routing and port forwarding".to_owned();
            } else if attached && ipv6_address.is_some() {
                compliance_message.push_str("; IPv6 address present and unsupported");
            }

            clients.insert(
                id.clone(),
                ClientState {
                    container_id: id,
                    usage_id,
                    usage_id_source,
                    name,
                    ipv4_address,
                    port_forward_target,
                    target_port,
                    compliant,
                    compliance_message,
                    running,
                    ipv6_address,
                    networks: network_names,
                    port_forward_label_valid,
                    route_intent,
                    traffic: crate::state::ClientTrafficState::default(),
                },
            );
        }
        Ok(clients)
    }

    pub async fn discover_isolation_candidates(&self) -> anyhow::Result<Vec<IsolationCandidate>> {
        let options = ListContainersOptionsBuilder::default().all(true).build();
        let containers = self.docker.list_containers(Some(options)).await?;
        let mut candidates = containers
            .into_iter()
            .filter_map(|container| {
                let running = container
                    .state
                    .is_some_and(|state| state.to_string() == "running");
                if !running {
                    return None;
                }
                let labels = container.labels.unwrap_or_default();
                let id = container.id.unwrap_or_default();
                let name = container
                    .names
                    .unwrap_or_default()
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| id.clone())
                    .trim_start_matches('/')
                    .to_owned();
                let address = container
                    .network_settings
                    .and_then(|settings| settings.networks)
                    .and_then(|networks| networks.get(&self.network_name).cloned())
                    .and_then(|endpoint| endpoint.ip_address)
                    .and_then(|address| address.parse::<Ipv4Addr>().ok())
                    .filter(|address| self.subnet.contains(address))?;
                Some(IsolationCandidate {
                    container_id: id,
                    name,
                    ipv4_address: address,
                    isolation_id: labels.get(ISOLATION_ID_LABEL).cloned(),
                    allow: labels.get(ISOLATION_ALLOW_LABEL).cloned(),
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.ipv4_address
                .cmp(&right.ipv4_address)
                .then_with(|| left.container_id.cmp(&right.container_id))
        });
        Ok(candidates)
    }

    pub async fn inspect_network(&self, gateway: Ipv4Addr) -> anyhow::Result<NetworkObservation> {
        let network = self
            .docker
            .inspect_network(&self.network_name, None)
            .await?;
        let subnet_matches = network
            .ipam
            .and_then(|ipam| ipam.config)
            .unwrap_or_default()
            .iter()
            .any(|config| config.subnet.as_deref() == Some(&self.subnet.to_string()));
        let gateway_attached = network
            .containers
            .unwrap_or_default()
            .values()
            .filter_map(|endpoint| endpoint.ipv4_address.as_deref())
            .any(|address| address.split('/').next() == Some(&gateway.to_string()));
        Ok(NetworkObservation {
            exists: true,
            subnet_matches,
            gateway_attached,
            ipv6_enabled: network.enable_ipv6.unwrap_or(false),
        })
    }
}

fn derive_usage_identity(
    labels: &std::collections::HashMap<String, String>,
    container_id: &str,
) -> (String, UsageIdentitySource) {
    if let Some(identity) = labels
        .get(USAGE_ID_LABEL)
        .map(String::as_str)
        .filter(|identity| valid_usage_identity(identity))
    {
        return (identity.to_owned(), UsageIdentitySource::ExplicitLabel);
    }
    if let (Some(project), Some(service)) = (
        labels.get(COMPOSE_PROJECT_LABEL),
        labels.get(COMPOSE_SERVICE_LABEL),
    ) {
        let identity = format!("compose:{project}/{service}");
        if valid_usage_identity(&identity) {
            return (identity, UsageIdentitySource::ComposeService);
        }
    }
    (
        format!("container:{container_id}"),
        UsageIdentitySource::ContainerLifetime,
    )
}

fn valid_usage_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '/')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DefaultSelection {
    Selected(String),
    Unknown,
}

fn derive_route_intent(
    egress_network: &str,
    networks: &std::collections::HashMap<String, EndpointSettings>,
) -> RouteIntentState {
    let gateway_priorities = networks
        .iter()
        .map(|(name, endpoint)| (name.clone(), endpoint.gw_priority))
        .collect::<BTreeMap<_, _>>();
    let ipv4_selection = select_default_network(networks, endpoint_has_ipv4_gateway);
    let ipv6_selection = select_default_network(networks, endpoint_has_ipv6_gateway);
    let ipv4_default_network = match &ipv4_selection {
        DefaultSelection::Selected(network) => Some(network.clone()),
        DefaultSelection::Unknown => None,
    };
    let ipv6_default_network = match ipv6_selection {
        DefaultSelection::Selected(network) => Some(network),
        DefaultSelection::Unknown => None,
    };
    let egress_gateway_priority = networks
        .get(egress_network)
        .and_then(|endpoint| endpoint.gw_priority);

    let (status, reason_code, safe_message) = match ipv4_selection {
        DefaultSelection::Selected(network) if network == egress_network => (
            RouteIntentStatus::Verified,
            "route_intent.egress_selected",
            "Docker declares the egress network as the selected IPv4 default; the effective in-container route is not runtime-attested".to_owned(),
        ),
        DefaultSelection::Selected(network) => (
            RouteIntentStatus::Mismatch,
            "route_intent.alternate_selected",
            format!(
                "Docker declares {network} as the selected IPv4 default instead of {egress_network}; this advisory metadata is not runtime attestation"
            ),
        ),
        DefaultSelection::Unknown => (
            RouteIntentStatus::Unknown,
            "route_intent.unknown",
            "Docker gateway metadata is insufficient to determine the declared IPv4 default; the effective in-container route is not runtime-attested".to_owned(),
        ),
    };

    RouteIntentState {
        status,
        ipv4_default_network,
        ipv6_default_network,
        egress_gateway_priority,
        gateway_priorities,
        reason_code: reason_code.to_owned(),
        safe_message,
    }
}

fn route_intent_is_compatible(route_intent: &RouteIntentState) -> bool {
    route_intent.status != RouteIntentStatus::Mismatch
}

fn select_default_network(
    networks: &std::collections::HashMap<String, EndpointSettings>,
    is_candidate: impl Fn(&EndpointSettings) -> bool,
) -> DefaultSelection {
    let mut candidates = networks
        .iter()
        .filter(|(_, endpoint)| is_candidate(endpoint))
        .map(|(name, endpoint)| (name.as_str(), endpoint.gw_priority))
        .collect::<Vec<_>>();
    match candidates.len() {
        0 => DefaultSelection::Unknown,
        1 => DefaultSelection::Selected(candidates[0].0.to_owned()),
        _ if candidates.iter().any(|(_, priority)| priority.is_none()) => DefaultSelection::Unknown,
        _ => {
            candidates.sort_by(|(left_name, left_priority), (right_name, right_priority)| {
                right_priority
                    .cmp(left_priority)
                    .then_with(|| left_name.cmp(right_name))
            });
            DefaultSelection::Selected(candidates[0].0.to_owned())
        }
    }
}

fn endpoint_has_ipv4_gateway(endpoint: &EndpointSettings) -> bool {
    endpoint
        .ip_address
        .as_deref()
        .and_then(|address| address.parse::<Ipv4Addr>().ok())
        .is_some_and(|address| !address.is_unspecified())
        && endpoint
            .gateway
            .as_deref()
            .and_then(|address| address.parse::<Ipv4Addr>().ok())
            .is_some_and(|address| !address.is_unspecified())
}

fn endpoint_has_ipv6_gateway(endpoint: &EndpointSettings) -> bool {
    endpoint
        .global_ipv6_address
        .as_deref()
        .and_then(|address| address.parse::<Ipv6Addr>().ok())
        .is_some_and(|address| !address.is_unspecified())
        && endpoint
            .ipv6_gateway
            .as_deref()
            .and_then(|address| address.parse::<Ipv6Addr>().ok())
            .is_some_and(|address| !address.is_unspecified())
}

fn label_is_true(value: Option<&String>) -> bool {
    value.is_some_and(|value| matches!(value.as_str(), "1" | "true" | "on" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(priority: Option<i64>, ipv4: bool, ipv6: bool) -> EndpointSettings {
        EndpointSettings {
            gw_priority: priority,
            gateway: ipv4.then(|| "172.30.0.1".to_owned()),
            ip_address: ipv4.then(|| "172.30.0.10".to_owned()),
            ipv6_gateway: ipv6.then(|| "2001:db8::1".to_owned()),
            global_ipv6_address: ipv6.then(|| "2001:db8::10".to_owned()),
            ..EndpointSettings::default()
        }
    }

    fn networks(
        entries: &[(&str, EndpointSettings)],
    ) -> std::collections::HashMap<String, EndpointSettings> {
        entries
            .iter()
            .map(|(name, endpoint)| ((*name).to_owned(), endpoint.clone()))
            .collect()
    }

    #[test]
    fn recognizes_only_explicit_true_values() {
        for value in ["1", "true", "on", "yes"] {
            assert!(label_is_true(Some(&value.to_owned())));
        }
        assert!(!label_is_true(Some(&"false".to_owned())));
        assert!(!label_is_true(None));
    }

    #[test]
    fn explicit_usage_identity_precedes_compose_fallback() {
        let labels = [
            (USAGE_ID_LABEL.to_owned(), "media/qbittorrent".to_owned()),
            (COMPOSE_PROJECT_LABEL.to_owned(), "arr".to_owned()),
            (COMPOSE_SERVICE_LABEL.to_owned(), "qbittorrent".to_owned()),
        ]
        .into();
        assert_eq!(
            derive_usage_identity(&labels, "container-id"),
            (
                "media/qbittorrent".to_owned(),
                UsageIdentitySource::ExplicitLabel
            )
        );
    }

    #[test]
    fn compose_and_container_lifetime_usage_fallbacks_are_explicit() {
        let labels = [
            (COMPOSE_PROJECT_LABEL.to_owned(), "arr".to_owned()),
            (COMPOSE_SERVICE_LABEL.to_owned(), "qbittorrent".to_owned()),
        ]
        .into();
        assert_eq!(
            derive_usage_identity(&labels, "container-id"),
            (
                "compose:arr/qbittorrent".to_owned(),
                UsageIdentitySource::ComposeService
            )
        );
        assert_eq!(
            derive_usage_identity(&std::collections::HashMap::new(), "container-id"),
            (
                "container:container-id".to_owned(),
                UsageIdentitySource::ContainerLifetime
            )
        );
    }

    #[test]
    fn accepts_restricted_proxy_http_endpoint() {
        assert!(DockerObserver::connect(
            "http://docker-api-proxy:2375",
            "vpn-egress".to_owned(),
            "172.30.0.0/24".parse().unwrap(),
        )
        .is_ok());
    }

    #[test]
    fn sole_ipv4_network_is_selected_without_priority_metadata() {
        let observation = derive_route_intent(
            "vpn-egress",
            &networks(&[("vpn-egress", endpoint(None, true, false))]),
        );
        assert_eq!(observation.status, RouteIntentStatus::Verified);
        assert_eq!(
            observation.ipv4_default_network.as_deref(),
            Some("vpn-egress")
        );
        assert_eq!(observation.egress_gateway_priority, None);
    }

    #[test]
    fn highest_ipv4_gateway_priority_selects_egress() {
        let observation = derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("app", endpoint(Some(0), true, false)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        );
        assert_eq!(observation.status, RouteIntentStatus::Verified);
        assert_eq!(observation.egress_gateway_priority, Some(100));
    }

    #[test]
    fn known_route_mismatch_is_not_compatible_but_unknown_is() {
        assert!(!route_intent_is_compatible(&derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("app", endpoint(Some(200), true, false)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        )));
        assert!(route_intent_is_compatible(&derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("app", endpoint(None, true, false)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        )));
    }

    #[test]
    fn equal_priorities_use_docker_lexicographic_tie_break() {
        let observation = derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("alpha", endpoint(Some(100), true, false)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        );
        assert_eq!(observation.status, RouteIntentStatus::Mismatch);
        assert_eq!(observation.ipv4_default_network.as_deref(), Some("alpha"));
    }

    #[test]
    fn missing_priority_on_a_multi_network_container_is_unknown() {
        let observation = derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("app", endpoint(None, true, false)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        );
        assert_eq!(observation.status, RouteIntentStatus::Unknown);
        assert_eq!(observation.ipv4_default_network, None);
    }

    #[test]
    fn higher_priority_alternate_network_is_a_mismatch() {
        let observation = derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("app", endpoint(Some(200), true, false)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        );
        assert_eq!(observation.status, RouteIntentStatus::Mismatch);
        assert_eq!(observation.ipv4_default_network.as_deref(), Some("app"));
    }

    #[test]
    fn ipv6_selection_is_reported_without_changing_ipv4_route_intent() {
        let observation = derive_route_intent(
            "vpn-egress",
            &networks(&[
                ("ipv6-app", endpoint(Some(200), false, true)),
                ("vpn-egress", endpoint(Some(100), true, false)),
            ]),
        );
        assert_eq!(observation.status, RouteIntentStatus::Verified);
        assert_eq!(
            observation.ipv4_default_network.as_deref(),
            Some("vpn-egress")
        );
        assert_eq!(
            observation.ipv6_default_network.as_deref(),
            Some("ipv6-app")
        );
    }
}
