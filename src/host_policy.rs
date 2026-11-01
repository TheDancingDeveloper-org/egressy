//! The host-side egress policy: the source policy-routing rule, its route
//! table, and the nftables chain that rejects enrolled traffic leaving by any
//! interface other than the enrolled bridge.
//!
//! This state lives in the host network namespace, outside the gateway's own
//! namespace, so the gateway cannot install or observe it directly. It was
//! historically installed once by `render-host-setup` and never checked again,
//! which meant anything that rebuilt host netfilter state — a Docker daemon
//! restart, for instance — silently removed the fail-closed guarantee while the
//! gateway carried on serving DNS and renewing port-forward leases.
//!
//! The types here are the shared contract between the gateway, which derives
//! the desired policy from its configuration and publishes it, and the
//! host-network agent, which owns the namespace and reconciles reality to it.

use serde::{Deserialize, Serialize};

/// nftables table owned by this policy, in the `inet` family.
pub const HOST_POLICY_TABLE: &str = "egressy_host";

/// Routing rule priority. Low enough to be consulted before the main table.
pub const RULE_PRIORITY: u32 = 100;

/// Wire schema version for the published policy document.
pub const SCHEMA_VERSION: u8 = 1;

/// The desired host-side policy, published by the gateway for the agent.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostPolicy {
    pub schema_version: u8,
    pub generated_at_unix_ms: u64,
    pub subnet: String,
    pub bridge: String,
    pub gateway_ip: String,
    pub route_table: u32,
    pub rule_priority: u32,
}

impl HostPolicy {
    pub fn new(
        generated_at_unix_ms: u64,
        subnet: String,
        bridge: String,
        gateway_ip: String,
        route_table: u32,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at_unix_ms,
            subnet,
            bridge,
            gateway_ip,
            route_table,
            rule_priority: RULE_PRIORITY,
        }
    }

    /// `ip rule add` arguments for the source policy-routing rule.
    pub fn rule_add_args(&self) -> Vec<String> {
        vec![
            "rule".into(),
            "add".into(),
            "priority".into(),
            self.rule_priority.to_string(),
            "from".into(),
            self.subnet.clone(),
            "lookup".into(),
            self.route_table.to_string(),
        ]
    }

    /// `ip route replace` argument sets, in the order they must be applied.
    pub fn route_replace_args(&self) -> Vec<Vec<String>> {
        vec![
            vec![
                "route".into(),
                "replace".into(),
                "table".into(),
                self.route_table.to_string(),
                self.subnet.clone(),
                "dev".into(),
                self.bridge.clone(),
                "scope".into(),
                "link".into(),
            ],
            vec![
                "route".into(),
                "replace".into(),
                "table".into(),
                self.route_table.to_string(),
                "default".into(),
                "via".into(),
                self.gateway_ip.clone(),
                "dev".into(),
                self.bridge.clone(),
                "onlink".into(),
            ],
        ]
    }

    /// The fail-closed nftables table. Enrolled source addresses leaving by any
    /// interface other than the enrolled bridge are rejected, not dropped, so
    /// clients fail fast rather than hanging.
    pub fn render_nft(&self) -> String {
        format!(
            r#"table inet {table} {{
  chain forward {{
    type filter hook forward priority -5; policy accept;
    ip saddr {subnet} oifname != "{bridge}" counter reject with icmp type admin-prohibited
  }}
}}
"#,
            table = HOST_POLICY_TABLE,
            subnet = self.subnet,
            bridge = self.bridge,
        )
    }
}

/// One `ip -j rule show` entry, narrowed to the fields that identify our rule.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IpRuleEntry {
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub src: Option<String>,
    #[serde(default)]
    pub srclen: Option<u8>,
    #[serde(default)]
    pub table: Option<String>,
}

/// One `ip -j route show table N` entry.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IpRouteEntry {
    #[serde(default)]
    pub dst: Option<String>,
    #[serde(default)]
    pub dev: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// What is missing from the host, if anything.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostPolicyDrift {
    pub rule_missing: bool,
    pub subnet_route_missing: bool,
    pub default_route_missing: bool,
    pub nft_table_missing: bool,
}

impl HostPolicyDrift {
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }

    /// Human-readable list of what is absent, for logs and health reasons.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.rule_missing {
            missing.push("policy routing rule");
        }
        if self.subnet_route_missing {
            missing.push("subnet route");
        }
        if self.default_route_missing {
            missing.push("tunnel default route");
        }
        if self.nft_table_missing {
            missing.push("fail-closed nftables table");
        }
        missing
    }
}

/// Is the source policy-routing rule installed?
///
/// The rule is matched on priority, source prefix and target table. `ip` renders
/// the table as a name when one is mapped in `rt_tables`, so a numeric match is
/// accepted either way round.
pub fn rule_present(rules: &[IpRuleEntry], policy: &HostPolicy) -> bool {
    let Some((subnet_address, subnet_length)) = split_prefix(&policy.subnet) else {
        return false;
    };
    rules.iter().any(|rule| {
        rule.priority == Some(policy.rule_priority)
            && rule.src.as_deref() == Some(subnet_address)
            && rule.srclen == Some(subnet_length)
            && rule
                .table
                .as_deref()
                .is_some_and(|table| table == policy.route_table.to_string())
    })
}

/// Are both routes present in the policy table?
pub fn routes_present(routes: &[IpRouteEntry], policy: &HostPolicy) -> (bool, bool) {
    let subnet_route = routes.iter().any(|route| {
        route.dst.as_deref() == Some(policy.subnet.as_str())
            && route.dev.as_deref() == Some(policy.bridge.as_str())
    });
    let default_route = routes.iter().any(|route| {
        route.dst.as_deref() == Some("default")
            && route.dev.as_deref() == Some(policy.bridge.as_str())
            && route.gateway.as_deref() == Some(policy.gateway_ip.as_str())
    });
    (subnet_route, default_route)
}

/// Compare observed host state against the desired policy.
pub fn detect_drift(
    rules: &[IpRuleEntry],
    routes: &[IpRouteEntry],
    nft_table_exists: bool,
    policy: &HostPolicy,
) -> HostPolicyDrift {
    let (subnet_route, default_route) = routes_present(routes, policy);
    HostPolicyDrift {
        rule_missing: !rule_present(rules, policy),
        subnet_route_missing: !subnet_route,
        default_route_missing: !default_route,
        nft_table_missing: !nft_table_exists,
    }
}

fn split_prefix(prefix: &str) -> Option<(&str, u8)> {
    let (address, length) = prefix.split_once('/')?;
    Some((address, length.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HostPolicy {
        HostPolicy::new(
            1_700_000_000_000,
            "172.30.0.0/24".to_owned(),
            "br-vpn-egress".to_owned(),
            "172.30.0.2".to_owned(),
            200,
        )
    }

    fn installed_rules() -> Vec<IpRuleEntry> {
        vec![
            IpRuleEntry {
                priority: Some(0),
                ..Default::default()
            },
            IpRuleEntry {
                priority: Some(100),
                src: Some("172.30.0.0".to_owned()),
                srclen: Some(24),
                table: Some("200".to_owned()),
            },
        ]
    }

    fn installed_routes() -> Vec<IpRouteEntry> {
        vec![
            IpRouteEntry {
                dst: Some("172.30.0.0/24".to_owned()),
                dev: Some("br-vpn-egress".to_owned()),
                scope: Some("link".to_owned()),
                ..Default::default()
            },
            IpRouteEntry {
                dst: Some("default".to_owned()),
                dev: Some("br-vpn-egress".to_owned()),
                gateway: Some("172.30.0.2".to_owned()),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn fully_installed_host_state_reports_no_drift() {
        let drift = detect_drift(&installed_rules(), &installed_routes(), true, &policy());
        assert!(drift.is_clean());
        assert!(drift.missing().is_empty());
    }

    #[test]
    fn a_docker_restart_that_clears_host_state_is_detected_as_drift() {
        // The observed failure: bridge recreated, netfilter rebuilt, every
        // piece of the host policy gone while the gateway stayed healthy.
        let drift = detect_drift(&[], &[], false, &policy());
        assert!(!drift.is_clean());
        assert_eq!(
            drift.missing(),
            vec![
                "policy routing rule",
                "subnet route",
                "tunnel default route",
                "fail-closed nftables table",
            ]
        );
    }

    #[test]
    fn a_rule_for_a_different_table_does_not_satisfy_the_policy() {
        let rules = vec![IpRuleEntry {
            priority: Some(100),
            src: Some("172.30.0.0".to_owned()),
            srclen: Some(24),
            table: Some("201".to_owned()),
        }];
        assert!(!rule_present(&rules, &policy()));
    }

    #[test]
    fn a_rule_at_a_different_priority_does_not_satisfy_the_policy() {
        let rules = vec![IpRuleEntry {
            priority: Some(32766),
            src: Some("172.30.0.0".to_owned()),
            srclen: Some(24),
            table: Some("200".to_owned()),
        }];
        assert!(!rule_present(&rules, &policy()));
    }

    #[test]
    fn a_default_route_via_the_wrong_gateway_does_not_satisfy_the_policy() {
        let routes = vec![IpRouteEntry {
            dst: Some("default".to_owned()),
            dev: Some("br-vpn-egress".to_owned()),
            gateway: Some("172.30.0.9".to_owned()),
            ..Default::default()
        }];
        let (_, default_route) = routes_present(&routes, &policy());
        assert!(!default_route);
    }

    #[test]
    fn nft_table_is_fail_closed_for_traffic_leaving_any_other_interface() {
        let rendered = policy().render_nft();
        assert!(rendered.contains("table inet egressy_host"));
        assert!(rendered.contains(
            "ip saddr 172.30.0.0/24 oifname != \"br-vpn-egress\" counter reject with icmp type admin-prohibited"
        ));
    }

    #[test]
    fn ip_arguments_match_the_documented_host_setup() {
        let policy = policy();
        assert_eq!(
            policy.rule_add_args(),
            vec![
                "rule",
                "add",
                "priority",
                "100",
                "from",
                "172.30.0.0/24",
                "lookup",
                "200"
            ]
        );
        let routes = policy.route_replace_args();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].ends_with(&["scope".to_owned(), "link".to_owned()]));
        assert!(routes[1].contains(&"onlink".to_owned()));
    }

    #[test]
    fn ip_rule_json_from_iproute2_deserializes() {
        let entries: Vec<IpRuleEntry> = serde_json::from_str(
            r#"[{"priority":0,"src":"all","table":"local"},
                {"priority":100,"src":"172.30.0.0","srclen":24,"table":"200"},
                {"priority":32766,"src":"all","table":"main"}]"#,
        )
        .unwrap();
        assert!(rule_present(&entries, &policy()));
    }

    #[test]
    fn ip_route_json_from_iproute2_deserializes() {
        let entries: Vec<IpRouteEntry> = serde_json::from_str(
            r#"[{"dst":"172.30.0.0/24","dev":"br-vpn-egress","scope":"link"},
                {"dst":"default","gateway":"172.30.0.2","dev":"br-vpn-egress","flags":["onlink"]}]"#,
        )
        .unwrap();
        assert_eq!(routes_present(&entries, &policy()), (true, true));
    }
}
