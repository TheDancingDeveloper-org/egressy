#!/bin/sh
set -eu

if [ "${EGRESSY_RUN_NETNS_TESTS:-}" != "1" ]; then
  echo "skip: set EGRESSY_RUN_NETNS_TESTS=1 to run the isolated namespace test"
  exit 0
fi
if [ "$(id -u)" != "0" ]; then
  echo "error: the opt-in namespace test requires root" >&2
  exit 1
fi
for command in ip wg nft ping nc; do
  command -v "$command" >/dev/null || { echo "error: missing $command" >&2; exit 1; }
done

client=egressy-test-client
gateway=egressy-test-gateway
provider=egressy-test-provider
cleanup() {
  ip netns del "$client" 2>/dev/null || true
  ip netns del "$gateway" 2>/dev/null || true
  ip netns del "$provider" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cleanup
ip netns add "$client"
ip netns add "$gateway"
ip netns add "$provider"

ip link add client0 type veth peer name gateway0
ip link set client0 netns "$client"
ip link set gateway0 netns "$gateway"
ip -n "$client" addr add 172.30.0.10/24 dev client0
ip -n "$gateway" addr add 172.30.0.2/24 dev gateway0
ip -n "$client" link set lo up
ip -n "$client" link set client0 up
ip -n "$gateway" link set lo up
ip -n "$gateway" link set gateway0 up
ip -n "$client" route add default via 172.30.0.2

ip link add uplink0 type veth peer name provider0
ip link set uplink0 netns "$gateway"
ip link set provider0 netns "$provider"
ip -n "$gateway" addr add 192.0.2.2/24 dev uplink0
ip -n "$provider" addr add 192.0.2.1/24 dev provider0
ip -n "$gateway" link set uplink0 up
ip -n "$provider" link set lo up
ip -n "$provider" link set provider0 up
ip netns exec "$gateway" sysctl -q -w net.ipv4.ip_forward=1

provider_private=$(ip netns exec "$provider" wg genkey)
provider_public=$(printf '%s' "$provider_private" | ip netns exec "$provider" wg pubkey)
gateway_private=$(ip netns exec "$gateway" wg genkey)
gateway_public=$(printf '%s' "$gateway_private" | ip netns exec "$gateway" wg pubkey)
ip -n "$provider" link add wg-provider type wireguard
ip -n "$gateway" link add wg0 type wireguard
printf '%s' "$provider_private" | ip netns exec "$provider" wg set wg-provider private-key /dev/stdin listen-port 51820 peer "$gateway_public" allowed-ips 10.200.0.2/32,172.30.0.0/24
printf '%s' "$gateway_private" | ip netns exec "$gateway" wg set wg0 private-key /dev/stdin peer "$provider_public" endpoint 192.0.2.1:51820 allowed-ips 0.0.0.0/0
ip -n "$provider" addr add 10.200.0.1/24 dev wg-provider
ip -n "$gateway" addr add 10.200.0.2/24 dev wg0
ip -n "$provider" link set wg-provider up
ip -n "$gateway" link set wg0 up
ip -n "$provider" route add 172.30.0.0/24 dev wg-provider
ip -n "$gateway" rule add priority 90 from 172.30.0.2 lookup main
ip -n "$gateway" rule add priority 100 from 172.30.0.0/24 lookup 200
ip -n "$gateway" route add table 200 default dev wg0
ip netns exec "$gateway" nft -f - <<'EOF'
table inet egressy_test {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ip saddr 172.30.0.0/24 oifname "wg0" accept
    iifname "wg0" ip daddr 172.30.0.0/24 accept
  }
}
EOF

ip netns exec "$client" ping -c 1 -W 2 10.200.0.1 >/dev/null
# A bounded UDP request/response over the same protected path exercises the
# transport used by profile-derived DNS without requiring a DNS daemon fixture.
ip netns exec "$provider" sh -c 'printf dns-ok | nc -u -l -p 5353 -w 3' >/tmp/egressy-netns-dns-response &
dns_server=$!
printf query | ip netns exec "$client" nc -u -w 2 10.200.0.1 5353 | grep -q dns-ok
wait "$dns_server"
ip -n "$gateway" link set wg0 down
if ip netns exec "$client" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
  echo "error: enrolled traffic fell back to the ordinary uplink" >&2
  exit 1
fi
echo "ok: tunnel egress and fail-closed tunnel loss verified in isolated namespaces"
