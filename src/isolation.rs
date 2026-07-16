use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub const ISOLATION_ID_LABEL: &str = "egressy.isolation-id";
pub const ISOLATION_ALLOW_LABEL: &str = "egressy.isolation-allow";

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
}

#[derive(Clone, Debug)]
pub struct IsolationCandidate {
    pub container_id: String,
    pub name: String,
    pub ipv4_address: Ipv4Addr,
    pub isolation_id: Option<String>,
    pub allow: Option<String>,
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

    let unique_addresses = identities
        .iter()
        .filter(|(_, indexes)| indexes.len() == 1)
        .map(|(identity, indexes)| (identity.clone(), candidates[indexes[0]].ipv4_address))
        .collect::<BTreeMap<_, _>>();

    let mut participants = Vec::new();
    for candidate in candidates {
        let mut allowances = BTreeSet::new();
        if let Some(raw) = candidate.allow.as_deref() {
            match parse_allow_list(raw) {
                Ok(specs) => {
                    for spec in specs {
                        if let Some(address) = unique_addresses.get(&spec.destination_id) {
                            allowances.insert((
                                spec.destination_id,
                                *address,
                                spec.port,
                                spec.protocol,
                            ));
                        } else {
                            issues.push(format!(
                                "{} allows unresolved isolation identity {}",
                                candidate.name, spec.destination_id
                            ));
                        }
                    }
                }
                Err(error) => issues.push(format!("{}: {error}", candidate.name)),
            }
        }
        participants.push(IsolationParticipant {
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
    }
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
    let rules = format!(
        "table bridge egressy_isolation {{\n{objects}  chain forward {{\n    type filter hook forward priority -10; policy accept;\n    ct state established,related accept\n    ct status dnat accept\n    ip saddr {bridge_gateway} ip daddr {broadcast} accept\n{allowances}{pair_rules}    ip saddr {subnet} ip daddr {subnet} counter name isolation_unresolved {}\n  }}\n}}\n",
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
}
