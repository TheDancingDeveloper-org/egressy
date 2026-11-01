#!/bin/sh
# IPv6 routing and kill-switch test. Everything lives in throwaway namespaces.
#
#   client, peer -- host (br-vpn-egress) -- gateway -- wg0 -- provider
#                       |                     |
#                       +------- isp --------+
#
# The target address exists at both the provider and the ISP. Reaching it at the
# provider means the tunnel was used; a packet counted at the ISP is a leak.
set -eu

if [ "${EGRESSY_RUN_NETNS_TESTS:-}" != "1" ]; then
  echo "skip: set EGRESSY_RUN_NETNS_TESTS=1 to run the isolated namespace test"
  exit 0
fi
if [ "$(id -u)" != "0" ]; then
  echo "error: the opt-in namespace test requires root" >&2
  exit 1
fi
for command in ip nsenter wg nft ping nc python3; do
  command -v "$command" >/dev/null || { echo "error: missing $command" >&2; exit 1; }
done

bin=${EGRESSY_BIN_DIR:-target/debug}
[ -x "$bin/egressy" ] && [ -x "$bin/egressy-isolation-agent" ] || {
  echo "error: build the binaries first (looked in $bin)" >&2
  exit 1
}

work=$(mktemp -d)
namespaces="egressy6-client egressy6-peer egressy6-host egressy6-gateway egressy6-provider egressy6-isp"
agent=""
server=""
cleanup() {
  [ -z "$agent" ] || kill "$agent" 2>/dev/null || true
  [ -z "$server" ] || kill "$server" 2>/dev/null || true
  for namespace in $namespaces; do
    ip netns del "$namespace" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
cleanup_only_namespaces() {
  for namespace in $namespaces; do
    ip netns del "$namespace" 2>/dev/null || true
  done
}
# nsenter rather than "ip netns exec" or "ip -n", which remount /sys and fail inside
# a container.
ns() {
  ns_path=/run/netns/$1
  shift
  nsenter --net="$ns_path" "$@"
}
cleanup_only_namespaces
for namespace in $namespaces; do
  ip netns add "$namespace"
  ns "$namespace" ip link set lo up
done

in_client() { ns egressy6-client "$@"; }
in_peer() { ns egressy6-peer "$@"; }
in_host() { ns egressy6-host "$@"; }
in_gateway() { ns egressy6-gateway "$@"; }
in_provider() { ns egressy6-provider "$@"; }
in_isp() { ns egressy6-isp "$@"; }

subnet=fd30:172:30::/64
target=2001:db8:f::1
tunnel_address=2001:db8:e::2

fail() {
  echo "FAIL: $*" >&2
  exit 1
}
ok() { echo "ok: $*"; }

# Bridge and enrolled namespaces.
in_host ip link add br-vpn-egress type bridge mcast_snooping 0
in_host ip addr add 172.30.0.1/24 dev br-vpn-egress
in_host ip addr add fd30:172:30::1/64 dev br-vpn-egress nodad
in_host ip link set br-vpn-egress up
in_host sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
attach() { # namespace, interface, IPv4, IPv6
  ns egressy6-host ip link add "$2-br" type veth peer name "$2"
  ns egressy6-host ip link set "$2" netns "$1"
  ns egressy6-host ip link set "$2-br" master br-vpn-egress up
  ns "$1" ip addr add "$3/24" dev "$2"
  ns "$1" ip addr add "$4/64" dev "$2" nodad
  ns "$1" ip link set "$2" up
}
attach egressy6-client c0 172.30.0.10 fd30:172:30::10
attach egressy6-peer p0 172.30.0.11 fd30:172:30::11
attach egressy6-gateway g0 172.30.0.2 fd30:172:30::2
for namespace in in_client in_peer; do
  # A redirect would send later packets straight to the gateway, and hide what
  # the host does with them.
  $namespace sysctl -q -w net.ipv6.conf.all.accept_redirects=0
  $namespace sysctl -q -w net.ipv6.conf.default.accept_redirects=0
done
in_client sysctl -q -w net.ipv6.conf.c0.accept_redirects=0
in_peer sysctl -q -w net.ipv6.conf.p0.accept_redirects=0
for namespace in egressy6-client egressy6-peer; do
  ns "$namespace" ip route add default via 172.30.0.1
  ns "$namespace" ip -6 route add default via fd30:172:30::1
done

# The ISP gives the host and the gateway an ordinary IPv6 default route.
uplink() { # namespace, interface, network
  ns "$1" ip link add "$2" type veth peer name "$2-isp"
  ns "$1" ip link set "$2-isp" netns egressy6-isp
  ns "$1" ip addr add "2001:db8:$3::2/64" dev "$2" nodad
  ns egressy6-isp ip addr add "2001:db8:$3::1/64" dev "$2-isp" nodad
  ns "$1" ip link set "$2" up
  ns egressy6-isp ip link set "$2-isp" up
  ns "$1" ip -6 route add default via "2001:db8:$3::1"
}
uplink egressy6-host h-up a
uplink egressy6-gateway g-up b
in_isp ip addr add "$target/128" dev lo
in_isp nft -f - <<NFT
table inet leak {
  counter leaked { }
  chain prerouting {
    type filter hook prerouting priority -300; policy accept;
    ip6 daddr $target counter name leaked
  }
}
NFT

# The provider, reached on its own link so the only route to it is the endpoint.
ns egressy6-gateway ip link add g-wan type veth peer name provider0
ns egressy6-gateway ip link set provider0 netns egressy6-provider
ns egressy6-gateway ip addr add 192.0.2.2/24 dev g-wan
ns egressy6-provider ip addr add 192.0.2.1/24 dev provider0
ns egressy6-gateway ip link set g-wan up
ns egressy6-provider ip link set provider0 up
in_gateway sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
provider_private=$(wg genkey)
provider_public=$(printf '%s' "$provider_private" | wg pubkey)
gateway_private=$(wg genkey)
gateway_public=$(printf '%s' "$gateway_private" | wg pubkey)
ns egressy6-provider ip link add wg-provider type wireguard
ns egressy6-gateway ip link add wg0 type wireguard
printf '%s' "$provider_private" > "$work/provider.key"
printf '%s' "$gateway_private" > "$work/gateway.key"
in_provider wg set wg-provider private-key "$work/provider.key" listen-port 51820 \
  peer "$gateway_public" allowed-ips 10.200.0.2/32,$tunnel_address/128
in_gateway wg set wg0 private-key "$work/gateway.key" \
  peer "$provider_public" endpoint 192.0.2.1:51820 allowed-ips 0.0.0.0/0,::/0
ns egressy6-provider ip addr add 10.200.0.1/24 dev wg-provider
ns egressy6-provider ip addr add 2001:db8:e::1/64 dev wg-provider nodad
ns egressy6-provider ip addr add "$target/128" dev lo
ns egressy6-provider ip link set wg-provider up
ns egressy6-provider ip route add 172.30.0.0/24 dev wg-provider
ns egressy6-provider ip -6 route add "$tunnel_address/128" dev wg-provider
ns egressy6-provider ip -6 route add "$subnet" dev wg-provider
in_provider nft -f - <<NFT
table inet seen {
  counter from_tunnel { }
  counter unmasqueraded { }
  counter dns { }
  chain input {
    type filter hook input priority -300; policy accept;
    ip6 saddr $tunnel_address ip6 daddr $target counter name from_tunnel
    ip6 saddr $subnet counter name unmasqueraded
    ip6 daddr $target udp dport 53 counter name dns
  }
}
NFT

tunnel_up() {
  ns egressy6-gateway ip link set wg0 up
  ns egressy6-gateway ip addr replace 10.200.0.2/32 dev wg0
  ns egressy6-gateway ip addr replace "$tunnel_address/128" dev wg0 nodad
  ns egressy6-gateway ip route replace 10.200.0.0/24 dev wg0
  ns egressy6-gateway ip -6 route replace 2001:db8:e::/64 dev wg0
  ns egressy6-gateway ip route replace table 200 default dev wg0
  ns egressy6-gateway ip -6 route replace table 200 default dev wg0
}

# The gateway side uses the firewall the daemon renders, and the rule and route
# order of runtime::configure_gateway_ipv6_routes.
write_config() { # enabled
  cat > "$work/config.yaml" <<YAML
network:
  ipv6:
    enabled: $1
YAML
}
render_gateway_firewall() {
  write_config "$1"
  "$bin/egressy" --config "$work/config.yaml" render-gateway-firewall > "$work/firewall.nft"
  in_gateway nft delete table inet egressy 2>/dev/null || true
  in_gateway nft -f "$work/firewall.nft"
}
render_gateway_firewall true
ns egressy6-gateway ip -6 route replace table 200 unreachable default metric 4294967295
ns egressy6-gateway ip rule add priority 90 from 172.30.0.2 lookup main
ns egressy6-gateway ip rule add priority 100 from 172.30.0.0/24 lookup 200
ns egressy6-gateway ip -6 rule add priority 90 from fd30:172:30::2 lookup main
ns egressy6-gateway ip -6 rule add priority 100 from "$subnet" lookup 200
tunnel_up

# The host side is installed by the real agent from a published policy.
mkdir -p "$work/web/api/v2"
publish_host_policy() { # enabled
  if [ "$1" = true ]; then
    cat > "$work/web/api/v2/host-policy" <<JSON
{"schema_version":2,"generated_at_unix_ms":0,"subnet":"172.30.0.0/24","bridge":"br-vpn-egress","gateway_ip":"172.30.0.2","route_table":200,"rule_priority":100,"ipv6":{"subnet":"$subnet","gateway_ip":"fd30:172:30::2"}}
JSON
  else
    cat > "$work/web/api/v2/host-policy" <<JSON
{"schema_version":1,"generated_at_unix_ms":0,"subnet":"172.30.0.0/24","bridge":"br-vpn-egress","gateway_ip":"172.30.0.2","route_table":200,"rule_priority":100}
JSON
  fi
}
publish_isolation_policy() {
  cat > "$work/web/api/v2/isolation-policy" <<JSON
{"schema_version":1,"generated_at_unix_ms":$(date +%s)000,"network":"vpn-egress","bridge":"br-vpn-egress","subnet":"172.30.0.0/24","eligible_for_enforcement":true,"reason_code":"isolation.policy_complete","safe_message":"test","issues":[],"ipv6_subnet":"$subnet","participants":[
{"container_id":"client","name":"client","isolation_id":"client","ipv4_address":"172.30.0.10","allowances":[]},
{"container_id":"peer","name":"peer","isolation_id":"peer","ipv4_address":"172.30.0.11","allowances":[]}]}
JSON
}
publish_host_policy true
publish_isolation_policy
in_host python3 -m http.server --bind 127.0.0.1 --directory "$work/web" 8080 >/dev/null 2>&1 &
server=$!
start_agent() {
  in_host "$bin/egressy-isolation-agent" --mode enforce --interval-seconds 1 --stale-seconds 3600 \
    >"$work/agent.log" 2>&1 &
  agent=$!
}
stop_agent() {
  kill "$agent" 2>/dev/null || true
  wait "$agent" 2>/dev/null || true
  agent=""
}
wait_for() { # description, command...
  description=$1
  shift
  attempt=0
  until "$@" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 40 ]; then
      cat "$work/agent.log" >&2 || true
      fail "timed out waiting for $description"
    fi
    sleep 0.5
  done
}
host_state_installed() {
  in_host ip -6 rule show | grep -q "from $subnet lookup 200" \
    && in_host ip -6 route show table 200 | grep -q "default via fd30:172:30::2" \
    && in_host ip -6 route show table 200 | grep -q "unreachable default" \
    && in_host nft list table inet egressy_host | grep -q "egressy-ipv6-kill-switch:$subnet"
}
sleep 1
start_agent
wait_for "the agent to install the host policy" host_state_installed
wait_for "bridge isolation" in_host nft list table bridge egressy_isolation
ok "agent installed the IPv6 rule, routes and kill switch"

counter() { # namespace function, table, name
  $1 nft -j list counter inet "$2" "$3" | python3 -c '
import json, sys
for item in json.load(sys.stdin)["nftables"]:
    if "counter" in item:
        print(item["counter"]["packets"])'
}
leaked() { counter in_isp leak leaked; }
assert_no_leak() { # description
  [ "$(leaked)" = "0" ] || fail "$1: enrolled IPv6 reached the host or gateway uplink"
}
can_reach() { in_client ping -6 -c 1 -W 1 "$1" >/dev/null 2>&1; }
cannot_reach() { # address, description
  if can_reach "$1"; then
    fail "$2: $1 was reachable"
  fi
  assert_no_leak "$2"
  ok "$2"
}

# Client egress and return.
wait_for "the tunnel path" can_reach "$target"
assert_no_leak "normal egress"
[ "$(counter in_provider seen from_tunnel)" -gt 0 ] || fail "the provider did not see the tunnel address"
[ "$(counter in_provider seen unmasqueraded)" = "0" ] || fail "the provider saw an enrolled source address"
ok "client IPv6 leaves through wg0, masqueraded to the tunnel address"
in_client ping -c 1 -W 2 10.200.0.1 >/dev/null || fail "IPv4 stopped working"
ok "IPv4 still routes through the tunnel"

# Plain DNS over IPv6 has to use the gateway's IPv4 forwarder.
printf query | in_client nc -6 -u -w 1 "$target" 53 >/dev/null 2>&1 || true
[ "$(counter in_provider seen dns)" = "0" ] || fail "plain IPv6 DNS left the gateway"
assert_no_leak "plain IPv6 DNS"
ok "plain IPv6 DNS is rejected"

# Inbound over the tunnel.
if in_provider ping -6 -c 1 -W 1 fd30:172:30::10 >/dev/null 2>&1; then
  fail "unsolicited inbound IPv6 reached a client"
fi
if in_provider ping -6 -c 1 -W 1 "$tunnel_address" >/dev/null 2>&1; then
  fail "unsolicited inbound IPv6 reached the gateway"
fi
ok "unsolicited inbound IPv6 is dropped"

# Lateral traffic on the shared bridge.
peer_link_local=$(ns egressy6-peer ip -6 -o addr show dev p0 scope link | awk '{print $4}' | cut -d/ -f1)
if in_client ping -6 -c 1 -W 1 fd30:172:30::11 >/dev/null 2>&1; then
  fail "bridge isolation allowed peer IPv6"
fi
if [ -n "$peer_link_local" ] && in_client ping -6 -c 1 -W 1 -I c0 "$peer_link_local" >/dev/null 2>&1; then
  fail "bridge isolation allowed peer link-local IPv6"
fi
ok "bridge isolation drops peer IPv6, including link-local"
can_reach "$target" || fail "bridge isolation broke the tunnel path"

# Tunnel loss, with and without the gateway firewall.
ns egressy6-gateway ip link set wg0 down
cannot_reach "$target" "tunnel loss blocks client IPv6"
in_gateway nft delete table inet egressy
cannot_reach "$target" "tunnel loss blocks client IPv6 on routing alone, with no gateway firewall"
render_gateway_firewall true
tunnel_up
wait_for "recovery after tunnel loss" can_reach "$target"
ok "recovery restores client IPv6"

# Gateway loss.
ns egressy6-gateway ip link set g0 down
cannot_reach "$target" "gateway loss blocks client IPv6"
ns egressy6-gateway ip link set g0 up
ns egressy6-gateway ip addr replace fd30:172:30::2/64 dev g0 nodad
ns egressy6-gateway ip route replace 172.30.0.0/24 dev g0
wait_for "recovery after gateway loss" can_reach "$target"
ok "recovery after gateway loss"

# Host state lost. The agent is stopped so the kill switch is the only protection.
stop_agent
in_host ip -6 rule del priority 100 from "$subnet" lookup 200
cannot_reach "$target" "the host rejects enrolled IPv6 when its source rule is lost"
# A source outside the enrolled subnet misses the source rule and the
# source-matched reject. Only the bridge-wide kill switch can stop it.
ns egressy6-client ip addr add fd99::10/128 dev c0 nodad
if in_client ping -6 -c 1 -W 1 -I fd99::10 "$target" >/dev/null 2>&1; then
  fail "IPv6 from outside the enrolled subnet was forwarded"
fi
assert_no_leak "IPv6 from outside the enrolled subnet"
ns egressy6-client ip addr del fd99::10/128 dev c0
[ "$(in_host nft -j list table inet egressy_host | python3 -c '
import json, sys
for item in json.load(sys.stdin)["nftables"]:
    rule = item.get("rule")
    if rule and "egressy-ipv6-kill-switch" in rule.get("comment", ""):
        for part in rule["expr"]:
            if "counter" in part:
                print(part["counter"]["packets"])')" -gt 0 ] || fail "the kill switch did not count the rejected packet"
ok "the kill switch rejects IPv6 from any source on the bridge"

# Reconciliation after everything is cleared, as a Docker daemon restart would.
in_host nft delete table inet egressy_host
in_host ip -6 route flush table 200
start_agent
wait_for "the agent to restore the host policy" host_state_installed
wait_for "client IPv6 after reconciliation" can_reach "$target"
ok "the agent restores cleared host state"

# A table from an older release has no kill switch and has to be replaced.
stop_agent
in_host nft delete table inet egressy_host
in_host nft -f - <<'NFT'
table inet egressy_host {
  chain forward {
    type filter hook forward priority -5; policy accept;
    ip saddr 172.30.0.0/24 oifname != "br-vpn-egress" counter reject with icmp type admin-prohibited
  }
}
NFT
start_agent
wait_for "the agent to replace the older table" host_state_installed
ok "the agent replaces a table without the current kill switch"

# Routing switched off. The IPv6 rule and routes are left behind on purpose.
publish_host_policy false
render_gateway_firewall false
kill_switch_disabled() {
  in_host nft list table inet egressy_host | grep -q "egressy-ipv6-kill-switch:disabled"
}
wait_for "the agent to install the disabled-mode table" kill_switch_disabled
stop_agent
before=$(counter in_provider seen from_tunnel)
cannot_reach "$target" "with routing off, the gateway drops client IPv6"
[ "$(counter in_provider seen from_tunnel)" = "$before" ] || fail "IPv6 used the tunnel with routing off"
in_host ip -6 rule del priority 100 from "$subnet" lookup 200
cannot_reach "$target" "with routing off, the host rejects client IPv6"
in_client ping -c 1 -W 2 10.200.0.1 >/dev/null || fail "IPv4 stopped working with IPv6 off"
ok "IPv4 is unaffected with IPv6 routing off"

# Control: without the kill switch this path does leak, so the checks above can fail.
in_host nft delete table inet egressy_host
in_client ping -6 -c 1 -W 1 "$target" >/dev/null 2>&1 || true
[ "$(leaked)" -gt 0 ] || fail "control: the leak detector saw nothing with the kill switch removed"
ok "control: removing the kill switch does leak, so the detector works"

echo "ok: IPv6 routing and fail-closed behavior verified in isolated namespaces"
