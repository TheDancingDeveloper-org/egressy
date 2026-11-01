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
//!
//! The IPv6 kill switch is rendered whether or not IPv6 routing is on. With it
//! off, every IPv6 packet forwarded out of the enrolled bridge is rejected; with
//! it on, the same rule catches whatever the source rule did not capture, so a
//! lost rule or route rejects traffic instead of leaking it to the host uplink.

use serde::{Deserialize, Serialize};

/// nftables table owned by this policy, in the `inet` family.
pub const HOST_POLICY_TABLE: &str = "egressy_host";

/// Routing rule priority. Low enough to be consulted before the main table.
pub const RULE_PRIORITY: u32 = 100;

/// Wire schema version for the published policy document.
pub const SCHEMA_VERSION: u8 = 1;

/// Schema version of a policy that routes IPv6. An older agent refuses it loudly
/// rather than reconciling the IPv4 half and leaving client IPv6 unprotected.
pub const IPV6_SCHEMA_VERSION: u8 = 2;

/// Metric of the last-resort route that stops IPv6 lookups falling through the
/// policy table to the main table's default route.
pub const IPV6_UNREACHABLE_METRIC: u32 = u32::MAX;

/// Identifies the rendered kill switch. It carries the routed subnet, or
/// `disabled`, so a table left by an older release or configuration is replaced.
const IPV6_KILL_SWITCH_COMMENT: &str = "egressy-ipv6-kill-switch";

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<HostPolicyIpv6>,
}

/// The IPv6 half of the policy, present only when IPv6 routing is on.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostPolicyIpv6 {
    pub subnet: String,
    pub gateway_ip: String,
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
            ipv6: None,
        }
    }

    /// Route IPv6 for this subnet as well.
    pub fn with_ipv6(mut self, subnet: String, gateway_ip: String) -> Self {
        self.schema_version = IPV6_SCHEMA_VERSION;
        self.ipv6 = Some(HostPolicyIpv6 { subnet, gateway_ip });
        self
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

    /// `ip -6 rule add` arguments for the IPv6 source rule, when IPv6 is routed.
    pub fn ipv6_rule_add_args(&self) -> Option<Vec<String>> {
        let ipv6 = self.ipv6.as_ref()?;
        Some(vec![
            "-6".into(),
            "rule".into(),
            "add".into(),
            "priority".into(),
            self.rule_priority.to_string(),
            "from".into(),
            ipv6.subnet.clone(),
            "lookup".into(),
            self.route_table.to_string(),
        ])
    }

    /// `ip -6 route replace` argument sets, in the order they must be applied.
    /// Empty when IPv6 is not routed. The unreachable route comes first, so the
    /// table never relies on the main table while it is being filled.
    pub fn ipv6_route_replace_args(&self) -> Vec<Vec<String>> {
        let Some(ipv6) = self.ipv6.as_ref() else {
            return Vec::new();
        };
        let table = self.route_table.to_string();
        let route = |tail: &[&str]| {
            ["-6", "route", "replace", "table", table.as_str()]
                .iter()
                .chain(tail)
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>()
        };
        vec![
            route(&[
                "unreachable",
                "default",
                "metric",
                &IPV6_UNREACHABLE_METRIC.to_string(),
            ]),
            route(&[&ipv6.subnet, "dev", &self.bridge]),
            route(&[
                "default",
                "via",
                &ipv6.gateway_ip,
                "dev",
                &self.bridge,
                "onlink",
            ]),
        ]
    }

    /// The fail-closed nftables table. Enrolled source addresses leaving by any
    /// interface other than the enrolled bridge are rejected, not dropped, so
    /// clients fail fast rather than hanging.
    ///
    /// IPv6 is matched on the bridge rather than only on the source, so a
    /// link-local or otherwise unexpected source cannot pass, and unsolicited
    /// IPv6 from the host's side cannot reach an enrolled client either.
    pub fn render_nft(&self) -> String {
        let routed_source = self.ipv6.as_ref().map_or_else(String::new, |ipv6| {
            format!(
                "    ip6 saddr {subnet} oifname != \"{bridge}\" counter reject with icmpv6 type admin-prohibited\n",
                subnet = ipv6.subnet,
                bridge = self.bridge,
            )
        });
        format!(
            r#"table inet {table} {{
  chain forward {{
    type filter hook forward priority -5; policy accept;
    ip saddr {subnet} oifname != "{bridge}" counter reject with icmp type admin-prohibited
{routed_source}    meta nfproto ipv6 iifname "{bridge}" oifname != "{bridge}" counter reject with icmpv6 type admin-prohibited comment "{marker}"
    meta nfproto ipv6 iifname != "{bridge}" oifname "{bridge}" counter drop
  }}
}}
"#,
            table = HOST_POLICY_TABLE,
            subnet = self.subnet,
            bridge = self.bridge,
            marker = self.ipv6_kill_switch_marker(),
        )
    }

    fn ipv6_kill_switch_marker(&self) -> String {
        let scope = self
            .ipv6
            .as_ref()
            .map_or("disabled", |ipv6| ipv6.subnet.as_str());
        format!("{IPV6_KILL_SWITCH_COMMENT}:{scope}")
    }

    /// Does a listing of the installed table carry the kill switch this policy
    /// renders? The table's existence alone says nothing about its contents.
    pub fn nft_table_is_current(&self, listing: &str) -> bool {
        listing.contains(&format!("\"{}\"", self.ipv6_kill_switch_marker()))
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
    #[serde(default, rename = "type")]
    pub route_type: Option<String>,
}

/// What is missing from the host, if anything.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostPolicyDrift {
    pub rule_missing: bool,
    pub subnet_route_missing: bool,
    pub default_route_missing: bool,
    pub nft_table_missing: bool,
    pub nft_table_stale: bool,
    pub ipv6_rule_missing: bool,
    pub ipv6_routes_missing: bool,
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
        if self.nft_table_stale {
            missing.push("current IPv6 kill switch");
        }
        if self.ipv6_rule_missing {
            missing.push("IPv6 policy routing rule");
        }
        if self.ipv6_routes_missing {
            missing.push("IPv6 policy routes");
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
        ..Default::default()
    }
}

/// Add the IPv6 half of the comparison. A policy that does not route IPv6 has no
/// IPv6 rule or routes to require, only the kill switch.
pub fn detect_ipv6_drift(
    drift: &mut HostPolicyDrift,
    rules: &[IpRuleEntry],
    routes: &[IpRouteEntry],
    policy: &HostPolicy,
) {
    let Some(ipv6) = policy.ipv6.as_ref() else {
        return;
    };
    drift.ipv6_rule_missing = !ipv6_rule_present(rules, policy, ipv6);
    drift.ipv6_routes_missing = !ipv6_routes_present(routes, policy, ipv6);
}

fn ipv6_rule_present(rules: &[IpRuleEntry], policy: &HostPolicy, ipv6: &HostPolicyIpv6) -> bool {
    let Some((address, length)) = split_prefix(&ipv6.subnet) else {
        return false;
    };
    let table = policy.route_table.to_string();
    rules.iter().any(|rule| {
        rule.priority == Some(policy.rule_priority)
            && same_ipv6(rule.src.as_deref(), address)
            && rule.srclen == Some(length)
            && rule.table.as_deref() == Some(table.as_str())
    })
}

fn ipv6_routes_present(
    routes: &[IpRouteEntry],
    policy: &HostPolicy,
    ipv6: &HostPolicyIpv6,
) -> bool {
    let on_bridge = |route: &&IpRouteEntry| route.dev.as_deref() == Some(policy.bridge.as_str());
    let subnet = routes
        .iter()
        .filter(on_bridge)
        .any(|route| route.dst.as_deref() == Some(ipv6.subnet.as_str()));
    let default = routes.iter().filter(on_bridge).any(|route| {
        route.dst.as_deref() == Some("default")
            && route
                .gateway
                .as_deref()
                .is_some_and(|gateway| same_ipv6(Some(gateway), &ipv6.gateway_ip))
    });
    let unreachable = routes.iter().any(|route| {
        route.dst.as_deref() == Some("default")
            && route.route_type.as_deref() == Some("unreachable")
    });
    subnet && default && unreachable
}

fn same_ipv6(observed: Option<&str>, expected: &str) -> bool {
    let parse = |value: &str| value.parse::<std::net::Ipv6Addr>().ok();
    observed.and_then(parse).is_some() && observed.and_then(parse) == parse(expected)
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

    fn ipv6_policy() -> HostPolicy {
        policy().with_ipv6("fd30:172:30::/64".to_owned(), "fd30:172:30::2".to_owned())
    }

    fn installed_ipv6_rules() -> Vec<IpRuleEntry> {
        serde_json::from_str(
            r#"[{"priority":0,"src":"all","table":"local"},
                {"priority":100,"src":"fd30:172:30::","srclen":64,"table":"200"},
                {"priority":32766,"src":"all","table":"main"}]"#,
        )
        .unwrap()
    }

    fn installed_ipv6_routes() -> Vec<IpRouteEntry> {
        serde_json::from_str(
            r#"[{"dst":"fd30:172:30::/64","dev":"br-vpn-egress","metric":1024},
                {"dst":"default","gateway":"fd30:172:30::2","dev":"br-vpn-egress","metric":1024,"flags":["onlink"]},
                {"type":"unreachable","dst":"default","dev":"lo","metric":4294967295}]"#,
        )
        .unwrap()
    }

    #[test]
    fn a_policy_that_does_not_route_ipv6_still_renders_the_kill_switch() {
        let rendered = policy().render_nft();
        assert!(rendered.contains(
            "meta nfproto ipv6 iifname \"br-vpn-egress\" oifname != \"br-vpn-egress\" counter reject with icmpv6 type admin-prohibited"
        ));
        assert!(rendered.contains(
            "meta nfproto ipv6 iifname != \"br-vpn-egress\" oifname \"br-vpn-egress\" counter drop"
        ));
        assert!(rendered.contains("egressy-ipv6-kill-switch:disabled"));
        assert!(!rendered.contains("ip6 saddr"));
        assert!(policy().ipv6_rule_add_args().is_none());
        assert!(policy().ipv6_route_replace_args().is_empty());
    }

    #[test]
    fn a_policy_that_routes_ipv6_keeps_the_kill_switch_and_adds_the_source_rule() {
        let rendered = ipv6_policy().render_nft();
        assert!(rendered.contains(
            "ip6 saddr fd30:172:30::/64 oifname != \"br-vpn-egress\" counter reject with icmpv6 type admin-prohibited"
        ));
        assert!(rendered.contains("meta nfproto ipv6 iifname \"br-vpn-egress\""));
        assert!(rendered.contains("egressy-ipv6-kill-switch:fd30:172:30::/64"));
    }

    #[test]
    fn routing_ipv6_bumps_the_schema_so_an_older_agent_refuses_it() {
        assert_eq!(policy().schema_version, SCHEMA_VERSION);
        assert_eq!(ipv6_policy().schema_version, IPV6_SCHEMA_VERSION);
    }

    #[test]
    fn a_policy_without_ipv6_serializes_as_it_always_has() {
        let document = serde_json::to_value(policy()).unwrap();
        assert!(document.get("ipv6").is_none());
    }

    #[test]
    fn ipv6_arguments_install_the_unreachable_route_first() {
        let policy = ipv6_policy();
        assert_eq!(
            policy.ipv6_rule_add_args().unwrap(),
            vec![
                "-6",
                "rule",
                "add",
                "priority",
                "100",
                "from",
                "fd30:172:30::/64",
                "lookup",
                "200"
            ]
        );
        let routes = policy.ipv6_route_replace_args();
        assert_eq!(routes.len(), 3);
        assert!(routes[0].contains(&"unreachable".to_owned()));
        assert!(routes[0].contains(&"4294967295".to_owned()));
        assert!(routes[2].ends_with(&["onlink".to_owned()]));
    }

    #[test]
    fn installed_ipv6_state_reports_no_drift() {
        let mut drift = HostPolicyDrift::default();
        detect_ipv6_drift(
            &mut drift,
            &installed_ipv6_rules(),
            &installed_ipv6_routes(),
            &ipv6_policy(),
        );
        assert!(drift.is_clean());
    }

    #[test]
    fn missing_ipv6_rule_and_routes_are_drift() {
        let mut drift = HostPolicyDrift::default();
        detect_ipv6_drift(&mut drift, &[], &[], &ipv6_policy());
        assert_eq!(
            drift.missing(),
            vec!["IPv6 policy routing rule", "IPv6 policy routes"]
        );
    }

    #[test]
    fn each_missing_ipv6_route_is_drift() {
        for index in 0..3 {
            let mut routes = installed_ipv6_routes();
            routes.remove(index);
            let mut drift = HostPolicyDrift::default();
            detect_ipv6_drift(&mut drift, &installed_ipv6_rules(), &routes, &ipv6_policy());
            assert!(drift.ipv6_routes_missing, "route {index}");
        }
    }

    #[test]
    fn a_policy_without_ipv6_requires_no_ipv6_rule_or_routes() {
        let mut drift = HostPolicyDrift::default();
        detect_ipv6_drift(&mut drift, &[], &[], &policy());
        assert!(drift.is_clean());
    }

    #[test]
    fn a_table_without_the_current_kill_switch_is_not_current() {
        let installed_by_older_release = "table inet egressy_host { chain forward { } }";
        assert!(!policy().nft_table_is_current(installed_by_older_release));
        assert!(policy().nft_table_is_current(&policy().render_nft()));
        // Turning routing on or off has to replace the table.
        assert!(!ipv6_policy().nft_table_is_current(&policy().render_nft()));
        assert!(!policy().nft_table_is_current(&ipv6_policy().render_nft()));
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
