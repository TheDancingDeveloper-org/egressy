use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

pub const ISOLATION_ID_LABEL: &str = "egressy.isolation-id";
pub const ISOLATION_ALLOW_LABEL: &str = "egressy.isolation-allow";
/// Source identities a participant accepts allowances from. A Kubernetes
/// pod's allowance only opens a destination that names it here.
pub const ISOLATION_ACCEPT_LABEL: &str = "egressy.isolation-accept";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    #[default]
    Disabled,
    Audit,
    Enforce,
}

impl std::str::FromStr for IsolationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "audit" => Ok(Self::Audit),
            "enforce" => Ok(Self::Enforce),
            _ => Err("isolation mode must be disabled, audit, or enforce".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationProtocol {
    Tcp,
    Udp,
}

impl IsolationProtocol {
    pub fn nft_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IsolationAllowance {
    pub destination_id: String,
    pub destination_address: Ipv4Addr,
    pub port: u16,
    pub protocol: IsolationProtocol,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IsolationParticipant {
    pub container_id: String,
    pub name: String,
    pub isolation_id: Option<String>,
    pub ipv4_address: Ipv4Addr,
    pub allowances: Vec<IsolationAllowance>,
    /// When set, the host agent drops frames that carry this participant's
    /// address from any other MAC, and frames from this MAC with any other
    /// address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IsolationPolicy {
    pub schema_version: u8,
    pub generated_at_unix_ms: u64,
    pub network: String,
    pub bridge: String,
    pub subnet: String,
    pub eligible_for_enforcement: bool,
    pub reason_code: String,
    pub safe_message: String,
    pub issues: Vec<String>,
    pub participants: Vec<IsolationParticipant>,
    /// Set when the bridge carries routed IPv6, which then needs isolating too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_subnet: Option<String>,
    /// An address range (the Kubernetes pod range) whose every source address
    /// must belong to a participant bound by MAC; anything else is dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_range: Option<String>,
    /// The egress gateway's address. The gateway forwards return traffic with
    /// outside source addresses, so its MAC is not held to its own address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<Ipv4Addr>,
    /// Kubernetes candidates and allowances left out of the policy because
    /// they conflict with a Docker participant, with each other, or were not
    /// accepted. A pod cannot degrade the bridge, so these are not issues;
    /// a left-out pod is unbound, and its address fails closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<String>,
}

/// Where a candidate was discovered. Docker labels are written by the host's
/// operator; pod annotations by the pod's author, so they are trusted less.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CandidateSource {
    #[default]
    Docker,
    Kubernetes,
}

#[derive(Clone, Debug)]
pub struct IsolationCandidate {
    pub container_id: String,
    pub name: String,
    pub ipv4_address: Ipv4Addr,
    pub isolation_id: Option<String>,
    pub allow: Option<String>,
    /// The attachment's MAC address, when the source reports one. Used to bind
    /// the address to the client so another bridge port cannot claim it.
    pub mac: Option<String>,
    pub source: CandidateSource,
    /// The raw `egressy.isolation-accept` value.
    pub accept: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AllowSpec {
    destination_id: String,
    port: u16,
    protocol: IsolationProtocol,
}

pub fn build_policy(
    network: &str,
    bridge: &str,
    subnet: Ipv4Net,
    candidates: Vec<IsolationCandidate>,
    now: u64,
) -> IsolationPolicy {
    let (candidates, mut rejected) = screen_kubernetes_candidates(candidates);
    let mut issues = Vec::new();
    let mut identities = BTreeMap::<String, Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        match candidate.isolation_id.as_deref() {
            Some(identity) if valid_identity(identity) => {
                identities
                    .entry(identity.to_owned())
                    .or_default()
                    .push(index);
            }
            Some(_) => issues.push(format!(
                "{} has an invalid egressy.isolation-id",
                candidate.name
            )),
            None => issues.push(format!(
                "{} is attached without egressy.isolation-id",
                candidate.name
            )),
        }
    }
    for (identity, indexes) in &identities {
        if indexes.len() > 1 {
            issues.push(format!("isolation identity {identity} is duplicated"));
        }
    }

    // An address or MAC claimed by more than one participant cannot be bound
    // to either; the claim itself is the problem an operator must resolve.
    let mut address_claims = BTreeMap::<Ipv4Addr, usize>::new();
    let mut mac_claims = BTreeMap::<String, BTreeSet<Ipv4Addr>>::new();
    for candidate in &candidates {
        *address_claims.entry(candidate.ipv4_address).or_default() += 1;
        if let Some(mac) = candidate.mac.as_deref().and_then(normalize_mac) {
            mac_claims
                .entry(mac)
                .or_default()
                .insert(candidate.ipv4_address);
        }
    }
    for (address, claims) in &address_claims {
        if *claims > 1 {
            issues.push(format!(
                "address {address} is claimed by more than one participant"
            ));
        }
    }
    for (mac, addresses) in &mac_claims {
        if addresses.len() > 1 {
            issues.push(format!("MAC {mac} is claimed by more than one address"));
        }
    }

    let unique_addresses = identities
        .iter()
        .filter(|(_, indexes)| indexes.len() == 1)
        .map(|(identity, indexes)| (identity.clone(), candidates[indexes[0]].ipv4_address))
        .collect::<BTreeMap<_, _>>();

    // What each uniquely identified destination accepts. A malformed entry
    // accepts nothing; it is reported like a malformed allowance.
    let mut accepts = BTreeMap::<String, BTreeSet<String>>::new();
    for candidate in &candidates {
        let Some(identity) = candidate.isolation_id.as_deref() else {
            continue;
        };
        if !unique_addresses.contains_key(identity) {
            continue;
        }
        let mut accepted = BTreeSet::new();
        for entry in candidate
            .accept
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            if valid_identity(entry) {
                accepted.insert(entry.to_owned());
            } else {
                let problem = format!("{}: invalid isolation accept entry {entry}", candidate.name);
                match candidate.source {
                    CandidateSource::Docker => issues.push(problem),
                    CandidateSource::Kubernetes => rejected.push(problem),
                }
            }
        }
        accepts.insert(identity.to_owned(), accepted);
    }

    let mut participants = Vec::new();
    for candidate in candidates {
        let mut allowances = BTreeSet::new();
        // A pod's bad allowance is dropped, never an issue: an annotation must
        // not be able to drop enforce to audit for the whole bridge.
        let mut problems = Vec::new();
        if let Some(raw) = candidate.allow.as_deref() {
            match parse_allow_list(raw) {
                Ok(specs) => {
                    for spec in specs {
                        let Some(address) = unique_addresses.get(&spec.destination_id) else {
                            problems.push(format!(
                                "{} allows unresolved isolation identity {}",
                                candidate.name, spec.destination_id
                            ));
                            continue;
                        };
                        if candidate.source == CandidateSource::Kubernetes {
                            let accepted =
                                candidate.isolation_id.as_deref().is_some_and(|source| {
                                    accepts
                                        .get(&spec.destination_id)
                                        .is_some_and(|accepted| accepted.contains(source))
                                });
                            if !accepted {
                                rejected.push(format!(
                                    "{} allows {} but {} does not accept it",
                                    candidate.name, spec.destination_id, spec.destination_id
                                ));
                                continue;
                            }
                        }
                        allowances.insert((
                            spec.destination_id,
                            *address,
                            spec.port,
                            spec.protocol,
                        ));
                    }
                }
                Err(error) => problems.push(format!("{}: {error}", candidate.name)),
            }
        }
        match candidate.source {
            CandidateSource::Docker => issues.extend(problems),
            CandidateSource::Kubernetes => rejected.extend(problems),
        }
        let mac = candidate
            .mac
            .as_deref()
            .and_then(normalize_mac)
            .filter(|mac| {
                address_claims.get(&candidate.ipv4_address) == Some(&1)
                    && mac_claims
                        .get(mac)
                        .is_some_and(|addresses| addresses.len() == 1)
            });
        participants.push(IsolationParticipant {
            mac,
            container_id: candidate.container_id,
            name: candidate.name,
            isolation_id: candidate.isolation_id.filter(|value| valid_identity(value)),
            ipv4_address: candidate.ipv4_address,
            allowances: allowances
                .into_iter()
                .map(
                    |(destination_id, destination_address, port, protocol)| IsolationAllowance {
                        destination_id,
                        destination_address,
                        port,
                        protocol,
                    },
                )
                .collect(),
        });
    }
    participants.sort_by(|left, right| {
        left.ipv4_address
            .cmp(&right.ipv4_address)
            .then_with(|| left.container_id.cmp(&right.container_id))
    });
    issues.sort();
    issues.dedup();
    rejected.sort();
    rejected.dedup();
    let eligible = !participants.is_empty() && issues.is_empty();
    IsolationPolicy {
        schema_version: 1,
        generated_at_unix_ms: now,
        network: network.to_owned(),
        bridge: bridge.to_owned(),
        subnet: subnet.to_string(),
        eligible_for_enforcement: eligible,
        reason_code: if eligible {
            "isolation.policy_complete"
        } else if participants.is_empty() {
            "isolation.no_participants"
        } else {
            "isolation.policy_incomplete"
        }
        .to_owned(),
        safe_message: if eligible {
            "Every current bridge participant has a unique valid isolation identity and resolved allow-list"
        } else if participants.is_empty() {
            "No running IPv4 participants are attached to the enrolled bridge"
        } else {
            "The isolation policy is incomplete; enforce mode must degrade to audit"
        }
        .to_owned(),
        issues,
        participants,
        ipv6_subnet: None,
        bound_range: None,
        gateway_address: None,
        rejected,
    }
}

/// Leave out every Kubernetes candidate that lacks a valid isolation
/// identity, or claims an address, MAC or identity a Docker participant or
/// another pod also claims. Docker wins; conflicting pods all lose. Docker
/// candidates are passed through untouched, so Docker-only policy is
/// unchanged.
fn screen_kubernetes_candidates(
    candidates: Vec<IsolationCandidate>,
) -> (Vec<IsolationCandidate>, Vec<String>) {
    let (docker, pods): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|candidate| candidate.source == CandidateSource::Docker);
    if pods.is_empty() {
        return (docker, Vec::new());
    }
    let mac_of = |candidate: &IsolationCandidate| candidate.mac.as_deref().and_then(normalize_mac);
    let docker_addresses = docker
        .iter()
        .map(|candidate| candidate.ipv4_address)
        .collect::<BTreeSet<_>>();
    let docker_macs = docker.iter().filter_map(mac_of).collect::<BTreeSet<_>>();
    let docker_identities = docker
        .iter()
        .filter_map(|candidate| candidate.isolation_id.clone())
        .collect::<BTreeSet<_>>();

    let mut rejected = Vec::new();
    let mut remaining = Vec::new();
    for pod in pods {
        let identity = pod.isolation_id.as_deref();
        let mac = mac_of(&pod);
        let problem = if !identity.is_some_and(valid_identity) {
            Some("has no valid egressy.isolation-id")
        } else if docker_addresses.contains(&pod.ipv4_address) {
            Some("claims a Docker participant's address")
        } else if mac.as_ref().is_some_and(|mac| docker_macs.contains(mac)) {
            Some("claims a Docker participant's MAC")
        } else if identity.is_some_and(|identity| docker_identities.contains(identity)) {
            Some("claims a Docker participant's isolation identity")
        } else {
            None
        };
        match problem {
            Some(problem) => rejected.push(format!("pod {} {problem}", pod.name)),
            None => remaining.push(pod),
        }
    }

    let mut addresses = BTreeMap::<Ipv4Addr, usize>::new();
    let mut macs = BTreeMap::<String, usize>::new();
    let mut identities = BTreeMap::<String, usize>::new();
    for pod in &remaining {
        *addresses.entry(pod.ipv4_address).or_default() += 1;
        if let Some(mac) = mac_of(pod) {
            *macs.entry(mac).or_default() += 1;
        }
        if let Some(identity) = &pod.isolation_id {
            *identities.entry(identity.clone()).or_default() += 1;
        }
    }
    let mut kept = docker;
    for pod in remaining {
        let duplicated = addresses[&pod.ipv4_address] > 1
            || mac_of(&pod).is_some_and(|mac| macs[&mac] > 1)
            || pod
                .isolation_id
                .as_ref()
                .is_some_and(|identity| identities[identity] > 1);
        if duplicated {
            rejected.push(format!(
                "pod {} shares an address, MAC or isolation identity with another pod",
                pod.name
            ));
        } else {
            kept.push(pod);
        }
    }
    kept.sort_by(|left, right| {
        left.ipv4_address
            .cmp(&right.ipv4_address)
            .then_with(|| left.container_id.cmp(&right.container_id))
    });
    (kept, rejected)
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

/// Anti-spoof rules: bind each participant's address to its MAC, and admit
/// sources in the bound range only from a bound participant. These drop in
/// audit mode too; a forged address is never a policy gap to observe. Only
/// rendered when a bound range is set (Kubernetes discovery is on), so a
/// Docker-only bridge keeps its existing policy.
fn render_address_bindings(policy: &IsolationPolicy) -> String {
    let Some(range) = policy
        .bound_range
        .as_deref()
        .and_then(|range| range.parse::<Ipv4Net>().ok())
    else {
        return String::new();
    };
    let mut rules = String::new();
    let mut bound = BTreeSet::new();
    for participant in &policy.participants {
        let Some(mac) = participant.mac.as_deref().and_then(normalize_mac) else {
            continue;
        };
        let address = participant.ipv4_address;
        bound.insert(address);
        rules.push_str(&format!(
            "    ip saddr {address} ether saddr != {mac} counter name isolation_spoofed drop\n    arp saddr ip {address} ether saddr != {mac} counter name isolation_spoofed drop\n"
        ));
        if policy.gateway_address != Some(address) {
            rules.push_str(&format!(
                "    ether saddr {mac} ip saddr != {address} counter name isolation_spoofed drop\n    ether saddr {mac} arp saddr ip != {{ {address}, 0.0.0.0 }} counter name isolation_spoofed drop\n"
            ));
        }
    }
    let members = bound
        .iter()
        .filter(|address| range.contains(*address))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if members.is_empty() {
        rules.push_str(&format!(
            "    ip saddr {range} counter name isolation_spoofed drop\n    arp saddr ip {range} counter name isolation_spoofed drop\n"
        ));
    } else {
        let members = members.join(", ");
        rules.push_str(&format!(
            "    ip saddr {range} ip saddr != {{ {members} }} counter name isolation_spoofed drop\n    arp saddr ip {range} arp saddr ip != {{ {members} }} counter name isolation_spoofed drop\n"
        ));
    }
    rules
}

fn parse_allow_list(raw: &str) -> Result<Vec<AllowSpec>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(str::trim)
        .map(|entry| {
            let (destination_id, service) = entry
                .split_once(':')
                .ok_or_else(|| format!("invalid isolation allowance {entry}"))?;
            let (port, protocol) = service
                .split_once('/')
                .ok_or_else(|| format!("invalid isolation allowance {entry}"))?;
            if !valid_identity(destination_id) {
                return Err(format!("invalid isolation destination {destination_id}"));
            }
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| format!("invalid isolation port in {entry}"))?;
            let protocol = match protocol {
                "tcp" => IsolationProtocol::Tcp,
                "udp" => IsolationProtocol::Udp,
                _ => return Err(format!("invalid isolation protocol in {entry}")),
            };
            Ok(AllowSpec {
                destination_id: destination_id.to_owned(),
                port,
                protocol,
            })
        })
        .collect()
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
        })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CounterValue {
    pub packets: u64,
    pub bytes: u64,
}

pub fn render_bridge_policy(
    policy: &IsolationPolicy,
    requested_mode: IsolationMode,
    counters: &BTreeMap<String, CounterValue>,
) -> (IsolationMode, String) {
    let effective_mode = match requested_mode {
        IsolationMode::Enforce if !policy.eligible_for_enforcement => IsolationMode::Audit,
        mode => mode,
    };
    if effective_mode == IsolationMode::Disabled {
        return (effective_mode, String::new());
    }
    let subnet = policy
        .subnet
        .parse::<Ipv4Net>()
        .expect("validated policy subnet");
    let bridge_gateway = subnet
        .hosts()
        .next()
        .expect("isolation subnet has a Docker bridge gateway");
    let broadcast = subnet.broadcast();
    let mut objects = String::new();
    let mut pair_rules = String::new();
    for source in &policy.participants {
        for destination in &policy.participants {
            if source.ipv4_address == destination.ipv4_address {
                continue;
            }
            let name = pair_counter_name(&source.container_id, &destination.container_id);
            let value = counters.get(&name).copied().unwrap_or_default();
            objects.push_str(&format!(
                "  counter {name} {{ packets {} bytes {}; }}\n",
                value.packets, value.bytes
            ));
            pair_rules.push_str(&format!(
                "    ip saddr {} ip daddr {} counter name {name} {}\n",
                source.ipv4_address,
                destination.ipv4_address,
                verdict(effective_mode)
            ));
        }
    }
    let unresolved = counters
        .get("isolation_unresolved")
        .copied()
        .unwrap_or_default();
    objects.push_str(&format!(
        "  counter isolation_unresolved {{ packets {} bytes {}; }}\n",
        unresolved.packets, unresolved.bytes
    ));
    // Only a bridge with a bound range has anti-spoof rules to count, so a
    // Docker-only ruleset is unchanged.
    if policy.bound_range.is_some() {
        let spoofed = counters
            .get("isolation_spoofed")
            .copied()
            .unwrap_or_default();
        objects.push_str(&format!(
            "  counter isolation_spoofed {{ packets {} bytes {}; }}\n",
            spoofed.packets, spoofed.bytes
        ));
    }
    let bindings = render_address_bindings(policy);
    let allowances = policy
        .participants
        .iter()
        .flat_map(|source| {
            source.allowances.iter().map(move |allowance| {
                format!(
                    "    ip saddr {} ip daddr {} {} dport {} accept\n",
                    source.ipv4_address,
                    allowance.destination_address,
                    allowance.protocol.nft_name(),
                    allowance.port
                )
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<String>();
    let ipv6_rules = policy
        .ipv6_subnet
        .as_deref()
        .map(|subnet| {
            let subnet = subnet
                .parse::<Ipv6Net>()
                .expect("validated policy IPv6 subnet");
            // Allowances are IPv4 addresses, so no peer-to-peer IPv6 is allowed.
            // Link-local and multicast are included because every peer has an
            // address there. Tunnel traffic has an outside source or destination,
            // and only the ICMPv6 a working path depends on is let through.
            format!(
                "    icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, destination-unreachable }} accept\n    ip6 saddr {{ {subnet}, fe80::/10 }} ip6 daddr {{ {subnet}, fe80::/10, ff00::/8 }} counter name isolation_unresolved {}\n",
                verdict(effective_mode)
            )
        })
        .unwrap_or_default();
    let rules = format!(
        "table bridge egressy_isolation {{\n{objects}  chain forward {{\n    type filter hook forward priority -10; policy accept;\n{bindings}    ct state established,related accept\n    ct status dnat accept\n    ip saddr {bridge_gateway} ip daddr {broadcast} accept\n{allowances}{pair_rules}    ip saddr {subnet} ip daddr {subnet} counter name isolation_unresolved {}\n{ipv6_rules}  }}\n}}\n",
        verdict(effective_mode)
    );
    (effective_mode, rules)
}

fn verdict(mode: IsolationMode) -> &'static str {
    match mode {
        IsolationMode::Audit => "accept",
        IsolationMode::Enforce => "drop",
        IsolationMode::Disabled => "accept",
    }
}

pub fn pair_counter_name(source_id: &str, destination_id: &str) -> String {
    format!(
        "isop_{}_{}",
        safe_counter_component(source_id),
        safe_counter_component(destination_id)
    )
}

fn safe_counter_component(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, address: &str, allow: Option<&str>) -> IsolationCandidate {
        IsolationCandidate {
            container_id: format!("container{id}"),
            name: id.to_owned(),
            ipv4_address: address.parse().unwrap(),
            isolation_id: Some(id.to_owned()),
            allow: allow.map(str::to_owned),
            mac: None,
            source: CandidateSource::Docker,
            accept: None,
        }
    }

    fn policy(candidates: Vec<IsolationCandidate>) -> IsolationPolicy {
        build_policy(
            "vpn-egress",
            "br-vpn-egress",
            "172.30.0.0/24".parse().unwrap(),
            candidates,
            100,
        )
    }

    #[test]
    fn resolves_valid_allowances() {
        let policy = policy(vec![
            candidate("proxy", "172.30.0.10", Some("app:8083/tcp")),
            candidate("app", "172.30.0.11", None),
        ]);
        assert!(policy.eligible_for_enforcement);
        assert_eq!(
            policy.participants[0].allowances[0].destination_address,
            "172.30.0.11".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn duplicate_identity_is_ineligible() {
        let policy = policy(vec![
            candidate("same", "172.30.0.10", None),
            candidate("same", "172.30.0.11", None),
        ]);
        assert!(!policy.eligible_for_enforcement);
        assert!(policy.issues[0].contains("duplicated"));
    }

    #[test]
    fn missing_identity_is_ineligible() {
        let mut missing = candidate("app", "172.30.0.10", None);
        missing.isolation_id = None;
        assert!(!policy(vec![missing]).eligible_for_enforcement);
    }

    #[test]
    fn invalid_allowance_is_ineligible() {
        let policy = policy(vec![candidate("app", "172.30.0.10", Some("peer:0/tcp"))]);
        assert!(!policy.eligible_for_enforcement);
        assert!(policy.issues[0].contains("invalid isolation port"));
    }

    #[test]
    fn unresolved_destination_is_ineligible() {
        let policy = policy(vec![candidate(
            "app",
            "172.30.0.10",
            Some("missing:80/tcp"),
        )]);
        assert!(!policy.eligible_for_enforcement);
        assert!(policy.issues[0].contains("unresolved"));
    }

    #[test]
    fn incomplete_enforce_policy_degrades_to_audit() {
        let mut policy = policy(vec![candidate("app", "172.30.0.10", None)]);
        policy.eligible_for_enforcement = false;
        let (mode, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert_eq!(mode, IsolationMode::Audit);
        assert!(rules.contains("counter name isolation_unresolved accept"));
        assert!(!rules.contains("counter name isolation_unresolved drop"));
    }

    #[test]
    fn enforce_orders_return_dnat_and_allowances_before_pair_drop() {
        let policy = policy(vec![
            candidate("proxy", "172.30.0.10", Some("app:8083/tcp")),
            candidate("app", "172.30.0.11", None),
        ]);
        let (mode, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert_eq!(mode, IsolationMode::Enforce);
        let established = rules.find("ct state established,related accept").unwrap();
        let dnat = rules.find("ct status dnat accept").unwrap();
        let bridge_broadcast = rules
            .find("ip saddr 172.30.0.1 ip daddr 172.30.0.255 accept")
            .unwrap();
        let allowed = rules.find("tcp dport 8083 accept").unwrap();
        let dropped = rules.find("counter name isop_").unwrap();
        assert!(
            established < dnat
                && dnat < bridge_broadcast
                && bridge_broadcast < allowed
                && allowed < dropped
        );
        assert!(rules.contains("counter name isolation_unresolved drop"));
    }

    #[test]
    fn ipv6_peer_traffic_is_isolated_only_when_ipv6_is_routed() {
        let mut policy = policy(vec![candidate("app", "172.30.0.10", None)]);
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert!(!rules.contains("ip6 "));
        assert!(!rules.contains("icmpv6"));

        policy.ipv6_subnet = Some("fd30:172:30::/64".to_owned());
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        let discovery = rules.find("nd-neighbor-solicit").unwrap();
        let drop = rules
            .find("ip6 saddr { fd30:172:30::/64, fe80::/10 } ip6 daddr { fd30:172:30::/64, fe80::/10, ff00::/8 } counter name isolation_unresolved drop")
            .unwrap();
        assert!(discovery < drop);

        let (_, audit) = render_bridge_policy(&policy, IsolationMode::Audit, &BTreeMap::new());
        assert!(audit.contains("ff00::/8 } counter name isolation_unresolved accept"));
    }

    #[test]
    fn seeded_pair_counters_are_rendered() {
        let policy = policy(vec![
            candidate("one", "172.30.0.10", None),
            candidate("two", "172.30.0.11", None),
        ]);
        let name = pair_counter_name("containerone", "containertwo");
        let counters = [(
            name.clone(),
            CounterValue {
                packets: 3,
                bytes: 99,
            },
        )]
        .into();
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Audit, &counters);
        assert!(rules.contains(&format!("counter {name} {{ packets 3 bytes 99; }}")));
    }

    fn bound(id: &str, address: &str, mac: &str, allow: Option<&str>) -> IsolationCandidate {
        IsolationCandidate {
            mac: Some(mac.to_owned()),
            ..candidate(id, address, allow)
        }
    }

    fn pod(id: &str, address: &str, mac: &str, allow: Option<&str>) -> IsolationCandidate {
        IsolationCandidate {
            container_id: format!("k8s-{id}"),
            source: CandidateSource::Kubernetes,
            ..bound(id, address, mac, allow)
        }
    }

    fn accepting(candidate: IsolationCandidate, accept: &str) -> IsolationCandidate {
        IsolationCandidate {
            accept: Some(accept.to_owned()),
            ..candidate
        }
    }

    /// Docker gateway and app plus two Multus pods in the bound range.
    fn mixed_policy() -> IsolationPolicy {
        let mut policy = policy(vec![
            accepting(
                bound("gateway", "172.30.0.2", "02:42:ac:1e:00:02", None),
                "qbit",
            ),
            bound(
                "probe",
                "172.30.0.5",
                "02:42:ac:1e:00:05",
                Some("gateway:53/udp"),
            ),
            pod(
                "sonarr",
                "172.30.0.200",
                "0a:58:ac:1e:00:c8",
                Some("qbit:8080/tcp"),
            ),
            accepting(
                pod(
                    "qbit",
                    "172.30.0.201",
                    "0a:58:ac:1e:00:c9",
                    Some("gateway:53/udp"),
                ),
                "sonarr",
            ),
        ]);
        policy.bound_range = Some("172.30.0.192/26".to_owned());
        policy.gateway_address = Some("172.30.0.2".parse().unwrap());
        policy
    }

    #[test]
    fn normalizes_only_unicast_colon_macs() {
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
            "+a:58:ac:1e:00:c8",
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(normalize_mac(raw).is_none(), "{raw}");
        }
    }

    #[test]
    fn mixed_docker_and_kubernetes_clients_share_one_policy() {
        let policy = mixed_policy();
        assert!(policy.eligible_for_enforcement, "{:?}", policy.issues);
        let (mode, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert_eq!(mode, IsolationMode::Enforce);
        // Allowances resolve across sources, in both directions.
        assert!(rules.contains("ip saddr 172.30.0.200 ip daddr 172.30.0.201 tcp dport 8080 accept"));
        assert!(rules.contains("ip saddr 172.30.0.201 ip daddr 172.30.0.2 udp dport 53 accept"));
        assert!(rules.contains("ip saddr 172.30.0.5 ip daddr 172.30.0.2 udp dport 53 accept"));
        // Lateral pairs between a container and a pod are dropped like any pair.
        let pod_to_container = pair_counter_name("k8s-sonarr", "containerprobe");
        assert!(rules.contains(&format!(
            "ip saddr 172.30.0.200 ip daddr 172.30.0.5 counter name {pod_to_container} drop"
        )));
    }

    #[test]
    fn bindings_drop_forged_addresses_before_anything_is_accepted() {
        let (_, rules) =
            render_bridge_policy(&mixed_policy(), IsolationMode::Enforce, &BTreeMap::new());
        let first_binding = rules.find("counter name isolation_spoofed drop").unwrap();
        let established = rules.find("ct state established,related accept").unwrap();
        assert!(first_binding < established);
        for (address, mac) in [
            ("172.30.0.5", "02:42:ac:1e:00:05"),
            ("172.30.0.200", "0a:58:ac:1e:00:c8"),
        ] {
            assert!(rules.contains(&format!(
                "ip saddr {address} ether saddr != {mac} counter name isolation_spoofed drop"
            )));
            assert!(rules.contains(&format!(
                "ether saddr {mac} ip saddr != {address} counter name isolation_spoofed drop"
            )));
            assert!(rules.contains(&format!(
                "arp saddr ip {address} ether saddr != {mac} counter name isolation_spoofed drop"
            )));
        }
        // Unknown senders in the pod range are dropped.
        assert!(rules.contains(
            "ip saddr 172.30.0.192/26 ip saddr != { 172.30.0.200, 172.30.0.201 } counter name isolation_spoofed drop"
        ));
        assert!(rules.contains(
            "arp saddr ip 172.30.0.192/26 arp saddr ip != { 172.30.0.200, 172.30.0.201 } counter name isolation_spoofed drop"
        ));
    }

    #[test]
    fn the_gateway_may_forward_other_sources_but_its_address_stays_bound() {
        let (_, rules) =
            render_bridge_policy(&mixed_policy(), IsolationMode::Enforce, &BTreeMap::new());
        assert!(rules.contains(
            "ip saddr 172.30.0.2 ether saddr != 02:42:ac:1e:00:02 counter name isolation_spoofed drop"
        ));
        assert!(!rules.contains("ether saddr 02:42:ac:1e:00:02 ip saddr !="));
    }

    #[test]
    fn bindings_drop_even_when_enforce_degrades_to_audit() {
        let mut policy = mixed_policy();
        policy.eligible_for_enforcement = false;
        let (mode, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert_eq!(mode, IsolationMode::Audit);
        assert!(
            rules.contains("ether saddr != 0a:58:ac:1e:00:c8 counter name isolation_spoofed drop")
        );
        assert!(rules.contains("counter name isolation_unresolved accept"));
    }

    #[test]
    fn an_empty_pod_range_drops_every_source_in_it() {
        let mut policy = policy(vec![bound(
            "probe",
            "172.30.0.5",
            "02:42:ac:1e:00:05",
            None,
        )]);
        policy.bound_range = Some("172.30.0.192/26".to_owned());
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Audit, &BTreeMap::new());
        assert!(
            rules.contains("    ip saddr 172.30.0.192/26 counter name isolation_spoofed drop\n")
        );
    }

    #[test]
    fn docker_only_bridges_render_no_bindings() {
        let policy = policy(vec![bound(
            "probe",
            "172.30.0.5",
            "02:42:ac:1e:00:05",
            None,
        )]);
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert!(!rules.contains("ether saddr"));
        assert!(!rules.contains("isolation_spoofed drop"));
    }

    #[test]
    fn a_claimed_address_or_mac_is_never_bound() {
        let mut policy = policy(vec![
            bound("victim", "172.30.0.200", "0a:58:ac:1e:00:c8", None),
            bound("forger", "172.30.0.200", "0a:58:ac:1e:00:ff", None),
            bound("one", "172.30.0.210", "0a:58:ac:1e:00:d2", None),
            bound("two", "172.30.0.211", "0a:58:ac:1e:00:d2", None),
        ]);
        assert!(!policy.eligible_for_enforcement);
        assert!(policy
            .issues
            .iter()
            .any(|issue| issue.contains("172.30.0.200 is claimed")));
        assert!(policy
            .issues
            .iter()
            .any(|issue| issue.contains("MAC 0a:58:ac:1e:00:d2")));
        assert!(policy
            .participants
            .iter()
            .all(|participant| participant.mac.is_none()));
        policy.bound_range = Some("172.30.0.192/26".to_owned());
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        // With nothing bound, the whole range fails closed.
        assert!(
            rules.contains("    ip saddr 172.30.0.192/26 counter name isolation_spoofed drop\n")
        );
    }

    #[test]
    fn a_pod_allowance_needs_the_destination_to_accept_it() {
        let policy = policy(vec![
            bound("gateway", "172.30.0.2", "02:42:ac:1e:00:02", None),
            bound("admin", "172.30.0.5", "02:42:ac:1e:00:05", None),
            pod(
                "sonarr",
                "172.30.0.200",
                "0a:58:ac:1e:00:c8",
                Some("admin:9000/tcp,gateway:53/udp,ghost:1/tcp"),
            ),
        ]);
        // Nothing the pod asked for is granted, and the bridge stays enforceable.
        assert!(policy.eligible_for_enforcement, "{:?}", policy.issues);
        let sonarr = policy
            .participants
            .iter()
            .find(|participant| participant.name == "sonarr")
            .unwrap();
        assert!(sonarr.allowances.is_empty());
        assert!(policy
            .rejected
            .iter()
            .any(|note| note.contains("allows admin but admin does not accept it")));
        // Docker allowances stay source-only, as before.
        let policy = super::tests::policy(vec![
            bound("gateway", "172.30.0.2", "02:42:ac:1e:00:02", None),
            bound(
                "admin",
                "172.30.0.5",
                "02:42:ac:1e:00:05",
                Some("gateway:53/udp"),
            ),
        ]);
        assert_eq!(policy.participants[1].allowances.len(), 1);
    }

    #[test]
    fn a_pod_conflicting_with_docker_is_left_out_and_docker_keeps_its_binding() {
        for forger in [
            pod("forger", "172.30.0.5", "0a:58:ac:1e:00:ff", None),
            pod("forger", "172.30.0.200", "02:42:ac:1e:00:05", None),
            pod("admin", "172.30.0.200", "0a:58:ac:1e:00:ff", None),
        ] {
            let name = forger.name.clone();
            let mut policy = policy(vec![
                bound("admin", "172.30.0.5", "02:42:ac:1e:00:05", None),
                forger,
            ]);
            assert!(
                policy.eligible_for_enforcement,
                "{name}: {:?}",
                policy.issues
            );
            assert_eq!(policy.participants.len(), 1, "{name}");
            assert_eq!(
                policy.participants[0].mac.as_deref(),
                Some("02:42:ac:1e:00:05")
            );
            assert_eq!(policy.rejected.len(), 1, "{name}");
            policy.bound_range = Some("172.30.0.192/26".to_owned());
            let (mode, rules) =
                render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
            assert_eq!(mode, IsolationMode::Enforce, "{name}");
            assert!(rules.contains("ip saddr 172.30.0.5 ether saddr != 02:42:ac:1e:00:05"));
            // The left-out pod is unbound, so its range address fails closed.
            assert!(rules
                .contains("    ip saddr 172.30.0.192/26 counter name isolation_spoofed drop\n"));
        }
    }

    #[test]
    fn conflicting_or_unidentified_pods_are_left_out_without_degrading() {
        let mut nameless = pod("nameless", "172.30.0.230", "0a:58:ac:1e:00:e6", None);
        nameless.isolation_id = None;
        let policy = policy(vec![
            bound("admin", "172.30.0.5", "02:42:ac:1e:00:05", None),
            pod("one", "172.30.0.210", "0a:58:ac:1e:00:d2", None),
            pod("two", "172.30.0.211", "0a:58:ac:1e:00:d2", None),
            pod("three", "172.30.0.212", "0a:58:ac:1e:00:d4", None),
            nameless,
        ]);
        assert!(policy.eligible_for_enforcement, "{:?}", policy.issues);
        let names = policy
            .participants
            .iter()
            .map(|participant| participant.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["admin", "three"]);
        assert_eq!(policy.rejected.len(), 3);
    }

    #[test]
    fn docker_only_ruleset_text_is_unchanged() {
        let policy = policy(vec![
            bound("gateway", "172.30.0.2", "02:42:ac:1e:00:02", None),
            bound(
                "probe",
                "172.30.0.5",
                "02:42:ac:1e:00:05",
                Some("gateway:53/udp"),
            ),
        ]);
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        let forward = pair_counter_name("containerprobe", "containergateway");
        let back = pair_counter_name("containergateway", "containerprobe");
        assert_eq!(
            rules,
            format!(
                "table bridge egressy_isolation {{\n  counter {back} {{ packets 0 bytes 0; }}\n  counter {forward} {{ packets 0 bytes 0; }}\n  counter isolation_unresolved {{ packets 0 bytes 0; }}\n  chain forward {{\n    type filter hook forward priority -10; policy accept;\n    ct state established,related accept\n    ct status dnat accept\n    ip saddr 172.30.0.1 ip daddr 172.30.0.255 accept\n    ip saddr 172.30.0.5 ip daddr 172.30.0.2 udp dport 53 accept\n    ip saddr 172.30.0.2 ip daddr 172.30.0.5 counter name {back} drop\n    ip saddr 172.30.0.5 ip daddr 172.30.0.2 counter name {forward} drop\n    ip saddr 172.30.0.0/24 ip daddr 172.30.0.0/24 counter name isolation_unresolved drop\n  }}\n}}\n"
            )
        );
    }

    #[test]
    fn a_malformed_mac_in_a_published_policy_is_not_rendered() {
        let mut policy = mixed_policy();
        policy.participants[2].mac = Some("0a:58:ac:1e:00:c8 accept".to_owned());
        let (_, rules) = render_bridge_policy(&policy, IsolationMode::Enforce, &BTreeMap::new());
        assert!(!rules.contains("accept counter"));
        assert!(rules.contains("ip saddr != { 172.30.0.201 }"));
    }

    #[test]
    fn policy_without_binding_fields_still_decodes() {
        let policy = mixed_policy();
        let mut json = serde_json::to_value(&policy).unwrap();
        let object = json.as_object_mut().unwrap();
        object.remove("bound_range");
        object.remove("gateway_address");
        for participant in object["participants"].as_array_mut().unwrap() {
            participant.as_object_mut().unwrap().remove("mac");
        }
        let decoded: IsolationPolicy = serde_json::from_value(json).unwrap();
        assert!(decoded.bound_range.is_none());
        assert!(decoded
            .participants
            .iter()
            .all(|participant| participant.mac.is_none()));
    }
}
