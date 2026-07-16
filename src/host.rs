use std::net::Ipv4Addr;

use crate::config::Config;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCounterRule {
    pub container_id: String,
    pub address: Ipv4Addr,
    pub download_packets: u64,
    pub downloaded_bytes: u64,
    pub upload_packets: u64,
    pub uploaded_bytes: u64,
}

pub fn render_host_setup(config: &Config) -> String {
    let network = &config.network;
    format!(
        r#"#!/bin/sh
set -eu

# Run on the Docker host after creating the vpn-egress network with the
# deterministic bridge name shown in config/docker-network.sh.
sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip rule del from {subnet} lookup {table} 2>/dev/null || true
ip rule add priority 100 from {subnet} lookup {table}
ip route replace table {table} {subnet} dev {bridge} scope link
ip route replace table {table} default via {gateway} dev {bridge} onlink

nft delete table inet egressy_host 2>/dev/null || true
nft -f - <<'NFT'
table inet egressy_host {{
  chain forward {{
    type filter hook forward priority -5; policy accept;
    ip saddr {subnet} oifname != "{bridge}" counter reject with icmp type admin-prohibited
  }}
}}
NFT
"#,
        subnet = network.subnet,
        table = network.route_table,
        bridge = network.host_bridge,
        gateway = network.gateway_ip,
    )
}

pub fn render_gateway_firewall(
    config: &Config,
    port_forward: Option<(u16, Ipv4Addr, u16)>,
    client_counters: &[ClientCounterRule],
) -> String {
    let network = &config.network;
    let tunnel = &config.wireguard.interface;
    let dnat = port_forward.map_or_else(String::new, |(public_port, target, target_port)| {
        format!(
            "    iifname \"{tunnel}\" tcp dport {public_port} dnat ip to {target}:{target_port}\n    iifname \"{tunnel}\" udp dport {public_port} dnat ip to {target}:{target_port}\n"
        )
    });
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
    let download_counters = client_counters
        .iter()
        .map(|client| {
            format!(
                "    iifname \"{tunnel}\" ip daddr {} counter name {}\n",
                client.address,
                client_counter_name("down", &client.container_id)
            )
        })
        .collect::<String>();
    let upload_counters = client_counters
        .iter()
        .map(|client| {
            format!(
                "    ip saddr {} oifname \"{tunnel}\" counter name {}\n",
                client.address,
                client_counter_name("up", &client.container_id)
            )
        })
        .collect::<String>();
    format!(
        r#"table inet egressy {{
{counter_objects}
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip saddr {subnet} udp dport 53 accept
    ip saddr {subnet} tcp dport 53 accept
    tcp dport 8080 accept
    udp dport 5351 ip saddr {natpmp_gateway} accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
{download_counters}{upload_counters}
    ct state established,related accept
    ip saddr {subnet} udp dport 53 ip daddr != {gateway} reject with icmp type admin-prohibited
    ip saddr {subnet} tcp dport 53 ip daddr != {gateway} reject with icmp type admin-prohibited
    ip saddr {subnet} oifname "{tunnel}" accept
    iifname "{tunnel}" ip daddr {subnet} accept
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {subnet} oifname "{tunnel}" masquerade
  }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
{dnat}  }}
}}
"#,
        subnet = network.subnet,
        tunnel = tunnel,
        natpmp_gateway = config.proton.natpmp_gateway,
        gateway = network.gateway_ip,
        dnat = dnat,
        counter_objects = counter_objects,
        download_counters = download_counters,
        upload_counters = upload_counters,
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
            Some((45678, Ipv4Addr::new(172, 30, 0, 10), 6881)),
            &[],
        );
        assert!(rules.contains("tcp dport 45678 dnat ip to 172.30.0.10:6881"));
        assert!(rules.contains("udp dport 45678 dnat ip to 172.30.0.10:6881"));
    }

    #[test]
    fn unauthorized_plain_dns_is_rejected_for_both_transports() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(&config, None, &[]);
        assert!(rules.contains("udp dport 53 ip daddr != 172.30.0.2 reject"));
        assert!(rules.contains("tcp dport 53 ip daddr != 172.30.0.2 reject"));
    }

    #[test]
    fn renders_seeded_per_client_named_counters() {
        let config: Config = serde_yaml::from_str("{}").unwrap();
        let rules = render_gateway_firewall(
            &config,
            None,
            &[ClientCounterRule {
                container_id: "abc123".to_owned(),
                address: "172.30.0.10".parse().unwrap(),
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
}
