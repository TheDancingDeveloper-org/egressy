use std::net::{Ipv4Addr, Ipv6Addr};

use egressy::host_policy::HostPolicy;

use crate::config::Config;

/// The desired host-side policy for this configuration.
///
/// `generated_at_unix_ms` is supplied by the caller so the rendered script and
/// the published policy document stay byte-identical for the same config.
pub fn host_policy(config: &Config, generated_at_unix_ms: u64) -> HostPolicy {
    let network = &config.network;
    let policy = HostPolicy::new(
        generated_at_unix_ms,
        network.subnet.to_string(),
        network.host_bridge.clone(),
        network.gateway_ip.to_string(),
        network.route_table,
    );
    match network.ipv6_routing() {
        Some(ipv6) => policy.with_ipv6(ipv6.subnet.to_string(), ipv6.gateway_ip.to_string()),
        None => policy,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCounterRule {
    pub container_id: String,
    pub address: Ipv4Addr,
    pub ipv6_address: Option<Ipv6Addr>,
    pub download_packets: u64,
    pub downloaded_bytes: u64,
    pub upload_packets: u64,
    pub uploaded_bytes: u64,
}

pub fn render_host_setup(config: &Config) -> String {
    let policy = host_policy(config, 0);
    let rule = policy.rule_add_args().join(" ");
    let routes = policy
        .route_replace_args()
        .iter()
        .map(|args| format!("ip {}\n", args.join(" ")))
        .collect::<String>();
    let ipv6 = render_host_ipv6_setup(&policy);
    format!(
        r#"#!/bin/sh
set -eu

# Run on the Docker host after creating the vpn-egress network with the
# deterministic bridge name shown in config/docker-network.sh.
#
# This script is a bootstrap, not the owner of this state. The host-network
# agent reconciles the same policy continuously, so anything that clears it --
# a Docker daemon restart, for instance -- is repaired without rerunning this.
#
# Order matters, and mirrors the agent: the kill switch goes in first, before
# any forwarding is enabled, so a step that fails under `set -e` never leaves
# enrolled traffic forwarded without it. The empty `table` line makes the
# delete valid on a first run, so the whole replacement is one nft transaction
# with no window where the old table is gone and the new one is not yet loaded.
nft -f - <<'NFT'
table inet {nft_table}
delete table inet {nft_table}
{nft}NFT

sysctl -w net.ipv4.ip_forward=1 >/dev/null

{routes}ip rule del from {subnet} lookup {table} 2>/dev/null || true
ip {rule}
{ipv6}"#,
        subnet = policy.subnet,
        table = policy.route_table,
        rule = rule,
        routes = routes,
        ipv6 = ipv6,
        nft_table = egressy::host_policy::HOST_POLICY_TABLE,
        nft = policy.render_nft(),
    )
}

fn render_host_ipv6_setup(policy: &HostPolicy) -> String {
    let (Some(ipv6), Some(rule)) = (policy.ipv6.as_ref(), policy.ipv6_rule_add_args()) else {
        return String::new();
    };
    let routes = policy
        .ipv6_route_replace_args()
        .iter()
        .map(|args| format!("ip {}\n", args.join(" ")))
        .collect::<String>();
    format!(
        "\n# Enables IPv6 forwarding host-wide. An uplink that learns its default route from\n# router advertisements also needs accept_ra=2; see docs/NETWORKING.md.\nsysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null\n\n# Routes before the rule, `unreachable` first, so the rule never selects a\n# table that could fall through to the main default route.\n{routes}ip -6 rule del from {subnet} lookup {table} 2>/dev/null || true\nip {rule}\n",
        subnet = ipv6.subnet,
        table = policy.route_table,
        rule = rule.join(" "),
    )
}

pub fn render_gateway_firewall(
    config: &Config,
    port_forwards: &[(u16, Ipv4Addr, u16)],
    client_counters: &[ClientCounterRule],
) -> String {
    let network = &config.network;
    let tunnel = &config.wireguard.interface;
    let ipv6 = network.ipv6_routing();
    let dnat = port_forwards
        .iter()
        .map(|(tunnel_port, target, target_port)| format!(
            "    iifname \"{tunnel}\" tcp dport {tunnel_port} dnat ip to {target}:{target_port}\n    iifname \"{tunnel}\" udp dport {tunnel_port} dnat ip to {target}:{target_port}\n"
        ))
        .collect::<String>();
    let counter_objects = client_counters
        .iter()
        .flat_map(|client| {
            [
                format!(
                    "  counter {} {{ packets {} bytes {}; }}\n",
                    client_counter_name("down", &client.container_id),
                    client.download_packets,
                    client.downloaded_bytes
                ),
                format!(
                    "  counter {} {{ packets {} bytes {}; }}\n",
                    client_counter_name("up", &client.container_id),
                    client.upload_packets,
                    client.uploaded_bytes
                ),
            ]
        })
        .collect::<String>();
    // IPv6 is counted on the client's existing counters, so traffic totals cover
    // both families and survive a client gaining or losing an IPv6 address.
    let client_ipv6 = |client: &ClientCounterRule| ipv6.and(client.ipv6_address);
    let download_counters = client_counters
        .iter()
        .map(|client| {
            let name = client_counter_name("down", &client.container_id);
            let mut rules = format!(
                "    iifname \"{tunnel}\" ip daddr {} counter name {name}\n",
                client.address,
            );
            if let Some(address) = client_ipv6(client) {
                rules.push_str(&format!(
                    "    iifname \"{tunnel}\" ip6 daddr {address} counter name {name}\n"
                ));
            }
            rules
        })
        .collect::<String>();
    let upload_counters = client_counters
        .iter()
        .map(|client| {
            let name = client_counter_name("up", &client.container_id);
            let mut rules = format!(
                "    ip saddr {} oifname \"{tunnel}\" counter name {name}\n",
                client.address,
            );
            if let Some(address) = client_ipv6(client) {
                rules.push_str(&format!(
                    "    ip6 saddr {address} oifname \"{tunnel}\" counter name {name}\n"
                ));
            }
            rules
        })
        .collect::<String>();
    // There is deliberately no IPv6 equivalent of the unsolicited-inbound accept
    // or of DNAT: NAT-PMP maps IPv4 only, so inbound IPv6 is return traffic alone.
    let (ipv6_input, ipv6_forward, ipv6_postrouting) = ipv6.map_or_else(
        Default::default,
        |ipv6| {
            let subnet = ipv6.subnet;
            (
                format!(
                    "    iifname != \"{tunnel}\" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept\n"
                ),
                format!(
                    "    ip6 saddr {subnet} udp dport 53 reject with icmpv6 type admin-prohibited\n    ip6 saddr {subnet} tcp dport 53 reject with icmpv6 type admin-prohibited\n    ip6 saddr {subnet} oifname \"{tunnel}\" accept\n"
                ),
                format!("    ip6 saddr {subnet} oifname \"{tunnel}\" masquerade\n"),
            )
        },
    );
    // Enrolled traffic may only cross the gateway through the tunnel, and this
    // is checked before the established accept: a flow's conntrack entry
    // outlives the tunnel (DNAT'd flows are not masqueraded, so the kernel does
    // not drop them with the interface), and its next packet would otherwise be
    // routed out of the uplink once the tunnel's routes are gone.
    let ipv6_leak_guard = ipv6.map_or_else(String::new, |ipv6| {
        let subnet = ipv6.subnet;
        format!(
            "    ip6 saddr {subnet} ip6 daddr != {subnet} oifname != \"{tunnel}\" drop\n    ip6 daddr {subnet} ip6 saddr != {subnet} iifname != \"{tunnel}\" drop\n"
        )
    });
    let natpmp_input =
        if config.port_forwarding.backend == crate::config::PortForwardingBackend::NatPmp {
            format!(
                "    udp dport 5351 ip saddr {} accept\n",
                config.port_forwarding.gateway
            )
        } else {
            String::new()
        };
    format!(
        r#"table inet egressy {{
{counter_objects}
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    iifname "{tunnel}" meta nfproto ipv6 drop
{ipv6_input}    ip saddr {subnet} udp dport 53 accept
    ip saddr {subnet} tcp dport 53 accept
    tcp dport 8080 accept
{natpmp_input}
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
{download_counters}{upload_counters}
    ip saddr {subnet} ip daddr != {subnet} oifname != "{tunnel}" drop
    ip daddr {subnet} ip saddr != {subnet} iifname != "{tunnel}" drop
{ipv6_leak_guard}    ct state established,related accept
    ip saddr {subnet} udp dport 53 ip daddr != {gateway} reject with icmp type admin-prohibited
    ip saddr {subnet} tcp dport 53 ip daddr != {gateway} reject with icmp type admin-prohibited
    ip saddr {subnet} oifname "{tunnel}" accept
    iifname "{tunnel}" ip daddr {subnet} accept
{ipv6_forward}  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {subnet} oifname "{tunnel}" masquerade
{ipv6_postrouting}  }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
{dnat}  }}
}}
"#,
        subnet = network.subnet,
        tunnel = tunnel,
        natpmp_input = natpmp_input,
        gateway = network.gateway_ip,
        dnat = dnat,
        counter_objects = counter_objects,
        download_counters = download_counters,
        upload_counters = upload_counters,
        ipv6_input = ipv6_input,
        ipv6_forward = ipv6_forward,
        ipv6_leak_guard = ipv6_leak_guard,
        ipv6_postrouting = ipv6_postrouting,
    )
}

pub fn client_counter_name(direction: &str, container_id: &str) -> String {
    let safe_id = container_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(64)
        .collect::<String>();
    format!("client_{direction}_{safe_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_policy_is_fail_closed() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let script = render_host_setup(&config);
        assert!(script.contains("default via 172.30.0.2"));
        assert!(script.contains("oifname != \"br-vpn-egress\""));
    }

    #[test]
    fn forwarded_port_is_dnatd_for_both_protocols() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(
            &config,
            &[(45678, Ipv4Addr::new(172, 30, 0, 10), 6881)],
            &[],
        );
        assert!(rules.contains("tcp dport 45678 dnat ip to 172.30.0.10:6881"));
        assert!(rules.contains("udp dport 45678 dnat ip to 172.30.0.10:6881"));
    }

    #[test]
    fn unauthorized_plain_dns_is_rejected_for_both_transports() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(&config, &[], &[]);
        assert!(rules.contains("udp dport 53 ip daddr != 172.30.0.2 reject"));
        assert!(rules.contains("tcp dport 53 ip daddr != 172.30.0.2 reject"));
    }

    #[test]
    fn natpmp_input_exists_only_when_the_backend_is_enabled() {
        let disabled: Config = serde_yaml::from_str("{}").unwrap();
        assert!(!render_gateway_firewall(&disabled, &[], &[]).contains("udp dport 5351"));
        let enabled: Config =
            serde_yaml::from_str("port_forwarding:\n  backend: nat_pmp\n  gateway: 10.2.0.1\n")
                .unwrap();
        assert!(render_gateway_firewall(&enabled, &[], &[]).contains("udp dport 5351"));
    }

    #[test]
    fn renders_seeded_per_client_named_counters() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(
            &config,
            &[],
            &[ClientCounterRule {
                container_id: "abc123".to_owned(),
                address: "172.30.0.10".parse().unwrap(),
                ipv6_address: None,
                download_packets: 3,
                downloaded_bytes: 99,
                upload_packets: 4,
                uploaded_bytes: 101,
            }],
        );
        assert!(rules.contains("counter client_down_abc123 { packets 3 bytes 99; }"));
        assert!(rules.contains("counter client_up_abc123 { packets 4 bytes 101; }"));
        assert!(rules.contains("ip daddr 172.30.0.10 counter name client_down_abc123"));
        assert!(
            rules.contains("ip saddr 172.30.0.10 oifname \"wg0\" counter name client_up_abc123")
        );
    }

    #[test]
    fn enrolled_traffic_is_held_to_the_tunnel_before_the_established_accept() {
        let rules = render_gateway_firewall(&ipv6_config(), &[], &[]);
        let forward = &rules[rules.find("chain forward").unwrap()..];
        let established = forward.find("ct state established,related accept").unwrap();
        for guard in [
            "ip saddr 172.30.0.0/24 ip daddr != 172.30.0.0/24 oifname != \"wg0\" drop",
            "ip daddr 172.30.0.0/24 ip saddr != 172.30.0.0/24 iifname != \"wg0\" drop",
            "ip6 saddr fd30:172:30::/64 ip6 daddr != fd30:172:30::/64 oifname != \"wg0\" drop",
            "ip6 daddr fd30:172:30::/64 ip6 saddr != fd30:172:30::/64 iifname != \"wg0\" drop",
        ] {
            let at = forward
                .find(guard)
                .unwrap_or_else(|| panic!("missing {guard}"));
            assert!(
                at < established,
                "{guard} must precede the established accept"
            );
        }
    }

    fn ipv6_config() -> Config {
        serde_yaml::from_str("network:\n  ipv6:\n    enabled: true\n").unwrap()
    }

    #[test]
    fn with_ipv6_off_the_gateway_forwards_no_ipv6_and_ignores_it_on_the_tunnel() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(&config, &[], &[]);
        assert!(!rules.contains("ip6 "));
        assert!(!rules.contains("icmpv6"));
        assert!(rules.contains("type filter hook forward priority 0; policy drop;"));
        assert!(rules.contains("iifname \"wg0\" meta nfproto ipv6 drop"));
    }

    #[test]
    fn with_ipv6_on_enrolled_traffic_may_only_leave_by_the_tunnel() {
        let rules = render_gateway_firewall(&ipv6_config(), &[], &[]);
        assert!(rules.contains("ip6 saddr fd30:172:30::/64 oifname \"wg0\" accept"));
        assert!(rules.contains("ip6 saddr fd30:172:30::/64 oifname \"wg0\" masquerade"));
        // Reject x2, accept, masquerade, and the leak guard (a drop).
        assert_eq!(rules.matches("ip6 saddr fd30:172:30::/64").count(), 5);
        assert!(rules.contains("type filter hook forward priority 0; policy drop;"));
    }

    #[test]
    fn plain_ipv6_dns_is_rejected_for_both_transports() {
        let rules = render_gateway_firewall(&ipv6_config(), &[], &[]);
        let accept = rules.find("oifname \"wg0\" accept\n  }").unwrap();
        for transport in ["udp", "tcp"] {
            let reject = rules
                .find(&format!(
                    "ip6 saddr fd30:172:30::/64 {transport} dport 53 reject with icmpv6 type admin-prohibited"
                ))
                .unwrap();
            assert!(reject < accept);
        }
    }

    #[test]
    fn unsolicited_inbound_ipv6_has_no_forward_or_dnat_path() {
        let rules = render_gateway_firewall(
            &ipv6_config(),
            &[(45678, Ipv4Addr::new(172, 30, 0, 10), 6881)],
            &[],
        );
        // The only rule naming an IPv6 client destination is the leak guard's drop.
        assert!(rules
            .lines()
            .filter(|line| line.contains("ip6 daddr"))
            .all(|line| line.trim_end().ends_with("drop")));
        assert!(!rules.contains("dnat ip6"));
        assert!(rules.contains("iifname \"wg0\" meta nfproto ipv6 drop"));
    }

    #[test]
    fn neighbor_discovery_is_accepted_off_the_tunnel_only() {
        let rules = render_gateway_firewall(&ipv6_config(), &[], &[]);
        assert!(rules.contains(
            "iifname != \"wg0\" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept"
        ));
    }

    #[test]
    fn client_ipv6_counts_on_the_same_named_counters() {
        let rule = ClientCounterRule {
            container_id: "abc123".to_owned(),
            address: "172.30.0.10".parse().unwrap(),
            ipv6_address: Some("fd30:172:30::10".parse().unwrap()),
            download_packets: 0,
            downloaded_bytes: 0,
            upload_packets: 0,
            uploaded_bytes: 0,
        };
        let rules = render_gateway_firewall(&ipv6_config(), &[], std::slice::from_ref(&rule));
        assert!(rules
            .contains("iifname \"wg0\" ip6 daddr fd30:172:30::10 counter name client_down_abc123"));
        assert!(rules
            .contains("ip6 saddr fd30:172:30::10 oifname \"wg0\" counter name client_up_abc123"));
        let off: Config = serde_yaml::from_str("{}").unwrap();
        assert!(!render_gateway_firewall(&off, &[], &[rule]).contains("ip6 "));
    }

    #[test]
    fn host_setup_adds_ipv6_only_when_routed() {
        let off: Config = serde_yaml::from_str("{}").unwrap();
        let script = render_host_setup(&off);
        assert!(!script.contains("ip -6"));
        assert!(!script.contains("net.ipv6"));
        assert!(script.contains("egressy-ipv6-kill-switch:disabled"));
        let script = render_host_setup(&ipv6_config());
        assert!(script.contains("net.ipv6.conf.all.forwarding=1"));
        assert!(script.contains("ip -6 rule add priority 100 from fd30:172:30::/64 lookup 200"));
        assert!(script.contains(
            "ip -6 route replace table 200 default via fd30:172:30::2 dev br-vpn-egress onlink"
        ));
        assert!(
            script.contains("ip -6 route replace table 200 unreachable default metric 4294967295")
        );
    }

    #[test]
    fn host_setup_installs_the_kill_switch_before_any_forwarding_or_routing() {
        for config in [serde_yaml::from_str::<Config>("{}").unwrap(), ipv6_config()] {
            let script = render_host_setup(&config);
            let at = |needle: &str| {
                script
                    .find(needle)
                    .unwrap_or_else(|| panic!("missing {needle:?} in:\n{script}"))
            };
            // The table is replaced in one nft transaction, never by a separate
            // `nft delete table` that leaves a window without the kill switch.
            assert!(!script.contains("nft delete"));
            let batch = at("nft -f - <<'NFT'\ntable inet egressy_host\ndelete table inet egressy_host\ntable inet egressy_host {");
            let kill_switch = at("egressy-ipv6-kill-switch:");
            assert!(batch < kill_switch);
            assert!(kill_switch < at("sysctl -w net.ipv4.ip_forward=1"));
            assert!(kill_switch < at("ip route replace"));
            assert!(at("ip route replace") < at("ip rule add"));
        }
        let script = render_host_setup(&ipv6_config());
        let at = |needle: &str| script.find(needle).unwrap();
        assert!(at("NFT\n") < at("net.ipv6.conf.all.forwarding=1"));
        assert!(at("net.ipv6.conf.all.forwarding=1") < at("ip -6 route replace"));
        assert!(
            at("ip -6 route replace table 200 unreachable")
                < at("ip -6 route replace table 200 fd30")
        );
        assert!(at("ip -6 route replace table 200 default via") < at("ip -6 rule del"));
        assert!(at("ip -6 rule del") < at("ip -6 rule add"));
    }

    #[test]
    fn multiple_forwarded_ports_are_rendered_for_both_protocols() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(
            &config,
            &[
                (45678, Ipv4Addr::new(172, 30, 0, 10), 6881),
                (45679, Ipv4Addr::new(172, 30, 0, 11), 6882),
            ],
            &[],
        );
        for rule in [
            "tcp dport 45678 dnat ip to 172.30.0.10:6881",
            "udp dport 45678 dnat ip to 172.30.0.10:6881",
            "tcp dport 45679 dnat ip to 172.30.0.11:6882",
            "udp dport 45679 dnat ip to 172.30.0.11:6882",
        ] {
            assert!(rules.contains(rule));
        }
    }
}
