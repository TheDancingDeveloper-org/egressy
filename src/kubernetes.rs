//! Read-only discovery of Kubernetes pods attached to the enrolled bridge.
//!
//! Pods join the bridge through a Multus network attachment and are enrolled
//! by annotations that mirror the Docker labels. Egressy only lists pods on
//! its own node; it never creates, patches, or deletes anything.

use std::{
    collections::{BTreeMap, HashMap},
    net::Ipv4Addr,
    time::Duration,
};

use anyhow::Context;
use ipnet::Ipv4Net;
use serde::Deserialize;

use crate::config::KubernetesConfig;
use crate::docker::{ENABLE_LABEL, PORT_FORWARD_LABEL, TARGET_PORT_LABEL, USAGE_ID_LABEL};
use crate::isolation::{IsolationCandidate, ISOLATION_ALLOW_LABEL, ISOLATION_ID_LABEL};
use crate::state::{
    ClientState, ClientTrafficState, RouteIntentState, RouteIntentStatus, UsageIdentitySource,
};

pub const NETWORK_STATUS_ANNOTATION: &str = "k8s.v1.cni.cncf.io/network-status";
const IN_CLUSTER_HOST: &str = "KUBERNETES_SERVICE_HOST";
const IN_CLUSTER_PORT: &str = "KUBERNETES_SERVICE_PORT";
/// Pod client IDs carry this prefix so they never collide with Docker IDs.
pub const CLIENT_ID_PREFIX: &str = "k8s-";

/// What one pod listing yields: enrolled clients and bridge participants.
#[derive(Clone, Debug, Default)]
pub struct KubernetesSnapshot {
    pub clients: BTreeMap<String, ClientState>,
    pub candidates: Vec<IsolationCandidate>,
}

pub struct KubernetesObserver {
    client: reqwest::Client,
    pods_url: reqwest::Url,
    token_path: String,
    scope: DiscoveryScope,
}

/// The parts of configuration that decide how a pod is read.
#[derive(Clone, Debug)]
pub struct DiscoveryScope {
    pub network_attachment: String,
    pub subnet: Ipv4Net,
    pub address_range: Ipv4Net,
    pub gateway_ip: Ipv4Addr,
}

impl KubernetesObserver {
    pub fn connect(
        config: &KubernetesConfig,
        subnet: Ipv4Net,
        gateway_ip: Ipv4Addr,
    ) -> anyhow::Result<Self> {
        let base = match config.api_url.as_deref().filter(|url| !url.is_empty()) {
            Some(url) => url.to_owned(),
            None => {
                let host = std::env::var(IN_CLUSTER_HOST).context(
                    "kubernetes.api_url is unset and KUBERNETES_SERVICE_HOST is missing",
                )?;
                let port = std::env::var(IN_CLUSTER_PORT).unwrap_or_else(|_| "443".to_owned());
                if host.contains(':') {
                    format!("https://[{host}]:{port}")
                } else {
                    format!("https://{host}:{port}")
                }
            }
        };
        let mut pods_url = reqwest::Url::parse(&base)
            .context("invalid Kubernetes API URL")?
            .join("/api/v1/pods")?;
        pods_url.query_pairs_mut().append_pair(
            "fieldSelector",
            &format!("spec.nodeName={}", config.node_name),
        );
        let ca = std::fs::read(&config.ca_path)
            .with_context(|| format!("reading Kubernetes CA from {}", config.ca_path))?;
        let client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca).context("parsing Kubernetes CA")?,
            )
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()?;
        Ok(Self {
            client,
            pods_url,
            token_path: config.token_path.clone(),
            scope: DiscoveryScope {
                network_attachment: config.network_attachment.clone(),
                subnet,
                address_range: config
                    .address_range
                    .context("kubernetes.address_range is required")?,
                gateway_ip,
            },
        })
    }

    pub async fn discover(&self) -> anyhow::Result<KubernetesSnapshot> {
        // Projected service-account tokens rotate, so read it every time.
        let token = std::fs::read_to_string(&self.token_path)
            .context("reading the Kubernetes service-account token")?;
        let response = self
            .client
            .get(self.pods_url.clone())
            .bearer_auth(token.trim())
            .send()
            .await
            .context("listing pods")?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("listing pods returned HTTP {status}");
        }
        let list: PodList = response.json().await.context("decoding the pod list")?;
        Ok(snapshot_from_pods(&self.scope, list.items))
    }
}

#[derive(Debug, Deserialize)]
pub struct PodList {
    #[serde(default)]
    pub items: Vec<Pod>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Pod {
    #[serde(default)]
    pub metadata: PodMetadata,
    #[serde(default)]
    pub status: PodStatus,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    pub deletion_timestamp: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PodStatus {
    #[serde(default)]
    pub phase: String,
}

#[derive(Debug, Deserialize)]
struct NetworkStatus {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    gateway: Vec<String>,
}

/// The pod's address on the egress attachment, as Multus reported it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub ipv4_address: Ipv4Addr,
    pub mac: String,
    pub has_ipv6: bool,
    pub default_via_gateway: bool,
}

/// Find the configured attachment in a network-status annotation.
pub fn parse_attachment(
    raw: &str,
    network_attachment: &str,
    gateway_ip: Ipv4Addr,
) -> Result<Attachment, String> {
    let entries: Vec<NetworkStatus> = serde_json::from_str(raw)
        .map_err(|_| "network-status annotation is not valid JSON".to_owned())?;
    let mut matching = entries
        .into_iter()
        .filter(|entry| entry.name == network_attachment);
    let entry = matching
        .next()
        .ok_or_else(|| format!("no {network_attachment} attachment in network-status"))?;
    if matching.next().is_some() {
        return Err(format!("{network_attachment} is attached more than once"));
    }
    let mut ipv4 = entry
        .ips
        .iter()
        .filter_map(|address| address.parse::<Ipv4Addr>().ok());
    let ipv4_address = ipv4
        .next()
        .ok_or_else(|| format!("{network_attachment} attachment has no IPv4 address"))?;
    if ipv4.next().is_some() {
        return Err(format!(
            "{network_attachment} attachment has more than one IPv4 address"
        ));
    }
    let mac = normalize_mac(&entry.mac)
        .ok_or_else(|| format!("{network_attachment} attachment has no valid MAC address"))?;
    Ok(Attachment {
        ipv4_address,
        mac,
        has_ipv6: entry
            .ips
            .iter()
            .any(|address| address.parse::<std::net::Ipv6Addr>().is_ok()),
        default_via_gateway: entry
            .gateway
            .iter()
            .any(|address| address.parse::<Ipv4Addr>().ok() == Some(gateway_ip)),
    })
}

/// A unicast MAC in canonical lower-case colon form, or `None`. The result is
/// rendered into nftables, so nothing but hex digits and colons gets through.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let octets = raw
        .split(':')
        .map(|octet| {
            (octet.len() == 2 && octet.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| u8::from_str_radix(octet, 16).ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 6 || octets[0] & 1 == 1 || octets.iter().all(|octet| *octet == 0) {
        return None;
    }
    Some(
        octets
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub fn snapshot_from_pods(scope: &DiscoveryScope, pods: Vec<Pod>) -> KubernetesSnapshot {
    let mut snapshot = KubernetesSnapshot::default();
    for pod in pods {
        let metadata = &pod.metadata;
        if metadata.uid.is_empty() || metadata.name.is_empty() {
            continue;
        }
        let annotations = &metadata.annotations;
        let running = pod.status.phase == "Running" && metadata.deletion_timestamp.is_none();
        let attachment = annotations
            .get(NETWORK_STATUS_ANNOTATION)
            .ok_or_else(|| "pod has no network-status annotation".to_owned())
            .and_then(|raw| parse_attachment(raw, &scope.network_attachment, scope.gateway_ip));
        let id = format!("{CLIENT_ID_PREFIX}{}", metadata.uid);
        let in_range = attachment
            .as_ref()
            .is_ok_and(|attachment| scope.address_range.contains(&attachment.ipv4_address));

        if let (true, true, Ok(attachment)) = (running, in_range, &attachment) {
            snapshot.candidates.push(IsolationCandidate {
                container_id: id.clone(),
                name: metadata.name.clone(),
                ipv4_address: attachment.ipv4_address,
                isolation_id: annotations.get(ISOLATION_ID_LABEL).cloned(),
                allow: annotations.get(ISOLATION_ALLOW_LABEL).cloned(),
                mac: Some(attachment.mac.clone()),
            });
        }
        if !annotation_is_true(annotations.get(ENABLE_LABEL)) {
            continue;
        }
        snapshot.clients.insert(
            id.clone(),
            client_from_pod(scope, &pod, id, running, &attachment),
        );
    }
    snapshot.candidates.sort_by(|left, right| {
        left.ipv4_address
            .cmp(&right.ipv4_address)
            .then_with(|| left.container_id.cmp(&right.container_id))
    });
    snapshot
}

fn client_from_pod(
    scope: &DiscoveryScope,
    pod: &Pod,
    id: String,
    running: bool,
    attachment: &Result<Attachment, String>,
) -> ClientState {
    let metadata = &pod.metadata;
    let annotations = &metadata.annotations;
    let port_forward_target = annotation_is_true(annotations.get(PORT_FORWARD_LABEL));
    let target_port = annotations
        .get(TARGET_PORT_LABEL)
        .and_then(|port| port.parse().ok())
        .filter(|port| *port != 0);
    let port_forward_label_valid = !port_forward_target || target_port.is_some();
    let (usage_id, usage_id_source) = match annotations
        .get(USAGE_ID_LABEL)
        .filter(|identity| crate::docker::valid_usage_identity(identity))
    {
        Some(identity) => (identity.clone(), UsageIdentitySource::ExplicitLabel),
        None => (
            format!("pod:{}/{}", metadata.namespace, metadata.name),
            UsageIdentitySource::ContainerLifetime,
        ),
    };
    let route_intent = route_intent(&scope.network_attachment, attachment.as_ref().ok());

    let (ipv4_address, attached, mut message) = match attachment {
        Ok(attachment) if !scope.subnet.contains(&attachment.ipv4_address) => (
            Ipv4Addr::UNSPECIFIED,
            false,
            format!(
                "{} address is outside the egress subnet",
                scope.network_attachment
            ),
        ),
        Ok(attachment) if !scope.address_range.contains(&attachment.ipv4_address) => (
            Ipv4Addr::UNSPECIFIED,
            false,
            format!(
                "{} address is outside kubernetes.address_range",
                scope.network_attachment
            ),
        ),
        Ok(attachment) => (
            attachment.ipv4_address,
            true,
            "attached to the egress network through Multus; effective default route is not runtime-attested"
                .to_owned(),
        ),
        Err(problem) => (
            Ipv4Addr::UNSPECIFIED,
            false,
            format!("annotated for egress but not attached: {problem}"),
        ),
    };
    if attached && !running {
        message = "enrolled pod is not running".to_owned();
    } else if attached && !port_forward_label_valid {
        message = "port forwarding requested without a valid egressy.target-port".to_owned();
    } else if attachment
        .as_ref()
        .is_ok_and(|attachment| attachment.has_ipv6)
        && attached
    {
        message.push_str("; IPv6 address present and rejected");
    }
    ClientState {
        container_id: id,
        usage_id,
        usage_id_source,
        name: metadata.name.clone(),
        ipv4_address,
        port_forward_target,
        target_port,
        compliant: attached && running && port_forward_label_valid,
        compliance_message: message,
        running,
        ipv6_address: None,
        networks: vec![scope.network_attachment.clone()],
        port_forward_label_valid,
        route_intent,
        traffic: ClientTrafficState::default(),
    }
}

fn route_intent(network_attachment: &str, attachment: Option<&Attachment>) -> RouteIntentState {
    match attachment {
        Some(attachment) if attachment.default_via_gateway => RouteIntentState {
            status: RouteIntentStatus::Verified,
            ipv4_default_network: Some(network_attachment.to_owned()),
            reason_code: "route_intent.kubernetes_default_route".to_owned(),
            safe_message: "Multus reports the egress gateway as the pod's default route"
                .to_owned(),
            ..RouteIntentState::default()
        },
        _ => RouteIntentState {
            status: RouteIntentStatus::Unknown,
            reason_code: "route_intent.kubernetes_unattested".to_owned(),
            safe_message: "Multus does not report the pod's default route; it may come from static IPAM routes".to_owned(),
            ..RouteIntentState::default()
        },
    }
}

fn annotation_is_true(value: Option<&String>) -> bool {
    value.is_some_and(|value| matches!(value.as_str(), "1" | "true" | "on" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> DiscoveryScope {
        DiscoveryScope {
            network_attachment: "personal-arr/vpn-egress".to_owned(),
            subnet: "172.30.0.0/24".parse().unwrap(),
            address_range: "172.30.0.192/26".parse().unwrap(),
            gateway_ip: "172.30.0.2".parse().unwrap(),
        }
    }

    fn network_status(address: &str, mac: &str) -> String {
        format!(
            r#"[{{"name":"cbr0","interface":"eth0","ips":["10.42.0.9"],"mac":"aa:aa:aa:aa:aa:aa","default":true}},{{"name":"personal-arr/vpn-egress","interface":"net1","ips":["{address}"],"mac":"{mac}","gateway":["172.30.0.2"]}}]"#
        )
    }

    fn pod(name: &str, address: &str, mac: &str, annotations: &[(&str, &str)]) -> Pod {
        let mut map = annotations
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        map.insert(
            NETWORK_STATUS_ANNOTATION.to_owned(),
            network_status(address, mac),
        );
        Pod {
            metadata: PodMetadata {
                name: name.to_owned(),
                namespace: "personal-arr".to_owned(),
                uid: format!("uid-{name}"),
                annotations: map,
                deletion_timestamp: None,
            },
            status: PodStatus {
                phase: "Running".to_owned(),
            },
        }
    }

    #[test]
    fn parses_the_configured_attachment_only() {
        let attachment = parse_attachment(
            &network_status("172.30.0.200", "0A:58:AC:1E:00:C8"),
            "personal-arr/vpn-egress",
            "172.30.0.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            attachment.ipv4_address,
            "172.30.0.200".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(attachment.mac, "0a:58:ac:1e:00:c8");
        assert!(attachment.default_via_gateway);
        assert!(!attachment.has_ipv6);
        assert!(parse_attachment(
            &network_status("172.30.0.200", "0a:58:ac:1e:00:c8"),
            "other/net",
            "172.30.0.2".parse().unwrap()
        )
        .is_err());
    }

    #[test]
    fn rejects_malformed_network_status() {
        let gateway = "172.30.0.2".parse().unwrap();
        for raw in [
            "not json",
            r#"[{"name":"personal-arr/vpn-egress","ips":[],"mac":"0a:58:ac:1e:00:c8"}]"#,
            r#"[{"name":"personal-arr/vpn-egress","ips":["172.30.0.200","172.30.0.201"],"mac":"0a:58:ac:1e:00:c8"}]"#,
            r#"[{"name":"personal-arr/vpn-egress","ips":["172.30.0.200"],"mac":"0a:58:ac:1e:00:c8"},{"name":"personal-arr/vpn-egress","ips":["172.30.0.201"],"mac":"0a:58:ac:1e:00:c9"}]"#,
        ] {
            assert!(
                parse_attachment(raw, "personal-arr/vpn-egress", gateway).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn mac_addresses_are_strictly_validated() {
        assert_eq!(
            normalize_mac("0A:58:ac:1e:00:C8").as_deref(),
            Some("0a:58:ac:1e:00:c8")
        );
        for raw in [
            "",
            "0a:58:ac:1e:00",
            "0a:58:ac:1e:00:c8:01",
            "0a-58-ac-1e-00-c8",
            "0a:58:ac:1e:00:zz",
            "0a:58:ac:1e:00:c8 drop",
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "+a:58:ac:1e:00:c8",
        ] {
            assert!(normalize_mac(raw).is_none(), "{raw}");
        }
    }

    #[test]
    fn annotated_pod_becomes_a_client_like_a_labelled_container() {
        let snapshot = snapshot_from_pods(
            &scope(),
            vec![pod(
                "qbittorrent-0",
                "172.30.0.200",
                "0a:58:ac:1e:00:c8",
                &[
                    ("egressy.enabled", "true"),
                    ("egressy.port-forward", "true"),
                    ("egressy.target-port", "6881"),
                    ("egressy.usage-id", "qbittorrent"),
                    ("egressy.isolation-id", "qbit"),
                ],
            )],
        );
        let client = &snapshot.clients["k8s-uid-qbittorrent-0"];
        assert!(client.compliant, "{}", client.compliance_message);
        assert_eq!(client.target_port, Some(6881));
        assert_eq!(client.usage_id, "qbittorrent");
        assert_eq!(client.usage_id_source, UsageIdentitySource::ExplicitLabel);
        assert_eq!(client.route_intent.status, RouteIntentStatus::Verified);
        let candidate = &snapshot.candidates[0];
        assert_eq!(candidate.isolation_id.as_deref(), Some("qbit"));
        assert_eq!(candidate.mac.as_deref(), Some("0a:58:ac:1e:00:c8"));
    }

    #[test]
    fn unannotated_attached_pod_is_a_participant_but_not_a_client() {
        let snapshot = snapshot_from_pods(
            &scope(),
            vec![pod("stray", "172.30.0.201", "0a:58:ac:1e:00:c9", &[])],
        );
        assert!(snapshot.clients.is_empty());
        assert_eq!(snapshot.candidates.len(), 1);
        assert!(snapshot.candidates[0].isolation_id.is_none());
    }

    #[test]
    fn address_outside_the_pod_range_is_not_compliant_or_bound() {
        let snapshot = snapshot_from_pods(
            &scope(),
            vec![pod(
                "squatter",
                "172.30.0.10",
                "0a:58:ac:1e:00:0a",
                &[("egressy.enabled", "true")],
            )],
        );
        let client = &snapshot.clients["k8s-uid-squatter"];
        assert!(!client.compliant);
        assert!(client
            .compliance_message
            .contains("kubernetes.address_range"));
        assert!(snapshot.candidates.is_empty());
    }

    #[test]
    fn stopped_or_terminating_pods_are_not_participants() {
        let mut pending = pod(
            "pending",
            "172.30.0.202",
            "0a:58:ac:1e:00:ca",
            &[("egressy.enabled", "true")],
        );
        pending.status.phase = "Pending".to_owned();
        let mut leaving = pod("leaving", "172.30.0.203", "0a:58:ac:1e:00:cb", &[]);
        leaving.metadata.deletion_timestamp = Some("2026-11-04T00:00:00Z".to_owned());
        let snapshot = snapshot_from_pods(&scope(), vec![pending, leaving]);
        assert!(snapshot.candidates.is_empty());
        let client = &snapshot.clients["k8s-uid-pending"];
        assert!(!client.compliant);
        assert_eq!(client.compliance_message, "enrolled pod is not running");
    }

    #[test]
    fn missing_attachment_and_bad_target_port_are_reported() {
        let mut detached = pod(
            "detached",
            "172.30.0.204",
            "0a:58:ac:1e:00:cc",
            &[("egressy.enabled", "true")],
        );
        detached
            .metadata
            .annotations
            .remove(NETWORK_STATUS_ANNOTATION);
        let bad_port = pod(
            "badport",
            "172.30.0.205",
            "0a:58:ac:1e:00:cd",
            &[
                ("egressy.enabled", "true"),
                ("egressy.port-forward", "true"),
                ("egressy.target-port", "0"),
            ],
        );
        let snapshot = snapshot_from_pods(&scope(), vec![detached, bad_port]);
        assert!(!snapshot.clients["k8s-uid-detached"].compliant);
        assert!(snapshot.clients["k8s-uid-detached"]
            .compliance_message
            .contains("not attached"));
        let bad_port = &snapshot.clients["k8s-uid-badport"];
        assert!(!bad_port.compliant);
        assert!(!bad_port.port_forward_label_valid);
        assert_eq!(bad_port.usage_id, "pod:personal-arr/badport");
    }

    #[test]
    fn decodes_a_pod_list_from_the_api_shape() {
        let raw = format!(
            r#"{{"kind":"PodList","items":[{{"metadata":{{"name":"sonarr-7d9","namespace":"personal-arr","uid":"1234","annotations":{{"egressy.enabled":"true","{NETWORK_STATUS_ANNOTATION}":{}}}}},"spec":{{"nodeName":"node-b"}},"status":{{"phase":"Running"}}}}]}}"#,
            serde_json::to_string(&network_status("172.30.0.210", "0a:58:ac:1e:00:d2")).unwrap()
        );
        let list: PodList = serde_json::from_str(&raw).unwrap();
        let snapshot = snapshot_from_pods(&scope(), list.items);
        assert!(snapshot.clients["k8s-1234"].compliant);
    }
}
