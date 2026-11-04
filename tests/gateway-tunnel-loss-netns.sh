#!/bin/sh
# After wg0 disappears, enrolled traffic must not leave by the gateway's uplink:
# not through the policy table (its IPv4 unreachable default) and not through
# the forward chain (the oif guard ahead of the established accept), each on
# its own. Opt-in and root-only, like the other namespace tests.
#
#   EGRESSY_RUN_NETNS_TESTS=1 EGRESSY_BIN=target/debug/egressy sh tests/gateway-tunnel-loss-netns.sh
set -eu

if [ "${EGRESSY_RUN_NETNS_TESTS:-}" != "1" ]; then
  echo "skip: set EGRESSY_RUN_NETNS_TESTS=1 to run the isolated namespace test"
  exit 0
fi
if [ "$(id -u)" != "0" ]; then
  echo "error: the opt-in namespace test requires root" >&2
  exit 1
fi
for command in ip nft ping; do
  command -v "$command" >/dev/null || { echo "error: missing $command" >&2; exit 1; }
done
egressy=${EGRESSY_BIN:-target/debug/egressy}
[ -x "$egressy" ] || { echo "error: build egressy first ($egressy)" >&2; exit 1; }

client=egressy-loss-client
gateway=egressy-loss-gateway
uplink=egressy-loss-uplink
cleanup() {
  for ns in "$client" "$gateway" "$uplink"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM
cleanup
for ns in "$client" "$gateway" "$uplink"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

ip link add client0 type veth peer name gateway0
ip link set client0 netns "$client"
ip link set gateway0 netns "$gateway"
ip -n "$client" addr add 172.30.0.10/24 dev client0
ip -n "$gateway" addr add 172.30.0.2/24 dev gateway0
ip -n "$client" link set client0 up
ip -n "$gateway" link set gateway0 up
ip -n "$client" route add default via 172.30.0.2

ip link add uplink0 type veth peer name wan0
ip link set uplink0 netns "$gateway"
ip link set wan0 netns "$uplink"
ip -n "$gateway" addr add 192.0.2.2/24 dev uplink0
ip -n "$uplink" addr add 192.0.2.1/24 dev wan0
ip -n "$gateway" link set uplink0 up
ip -n "$uplink" link set wan0 up
ip -n "$gateway" route add default via 192.0.2.1
ip -n "$uplink" route add 172.30.0.0/24 via 192.0.2.2
ip netns exec "$gateway" sysctl -q -w net.ipv4.ip_forward=1

# A stand-in tunnel interface; deleting it is the event under test.
ip -n "$gateway" link add wg0 type dummy
ip -n "$gateway" addr add 10.2.0.2/32 dev wg0
ip -n "$gateway" link set wg0 up

# Gateway routing as runtime::configure_gateway_routes installs it.
ip -n "$gateway" rule add priority 90 from 172.30.0.2 lookup main
ip -n "$gateway" rule add priority 100 from 172.30.0.0/24 lookup 200
ip -n "$gateway" route replace table 200 unreachable default metric 4294967295
ip -n "$gateway" route replace table 200 default dev wg0

work=$(mktemp -d)
trap 'cleanup; rm -rf "$work"' EXIT INT TERM
printf '{}\n' > "$work/config.yaml"
EGRESSY_CONFIG="$work/config.yaml" "$egressy" render-gateway-firewall > "$work/gateway.nft"
ip netns exec "$gateway" nft -f "$work/gateway.nft"

# Count anything from the enrolled subnet that reaches the uplink side.
ip netns exec "$uplink" nft -f - <<'NFT'
table inet probe {
  counter leaked {}
  chain input { type filter hook input priority 0; policy accept;
    ip saddr 172.30.0.0/24 counter name leaked
  }
}
NFT
leaked() {
  ip netns exec "$uplink" nft -j list counter inet probe leaked | grep -o '"packets": *[0-9]*' | grep -o '[0-9]*$'
}

ip -n "$gateway" link del wg0

ip netns exec "$client" ping -c 2 -W 1 192.0.2.1 >/dev/null 2>&1 || true
[ "$(leaked)" = "0" ] || { echo "FAIL: enrolled traffic left by the uplink with the full policy" >&2; exit 1; }

# The forward-chain guard alone: remove the unreachable default as well.
ip -n "$gateway" route del table 200 unreachable default metric 4294967295
ip netns exec "$client" ping -c 2 -W 1 192.0.2.1 >/dev/null 2>&1 || true
[ "$(leaked)" = "0" ] || { echo "FAIL: the forward chain let enrolled traffic out of the uplink" >&2; exit 1; }

# The unreachable default alone: restore it and drop the guard rules.
ip -n "$gateway" route replace table 200 unreachable default metric 4294967295
ip netns exec "$gateway" nft -a list chain inet egressy forward \
  | awk '/oifname != "wg0" drop|iifname != "wg0" drop/ { print $NF }' \
  | while read -r handle; do ip netns exec "$gateway" nft delete rule inet egressy forward handle "$handle"; done
ip netns exec "$client" ping -c 2 -W 1 192.0.2.1 >/dev/null 2>&1 || true
[ "$(leaked)" = "0" ] || { echo "FAIL: the policy table fell through to the uplink" >&2; exit 1; }

echo "ok: no enrolled traffic left by the uplink after the tunnel was deleted"
