#!/bin/sh
# IPv6 end-to-end test with real Docker networks and the real daemon, inside a
# disposable Docker-in-Docker sandbox with its own network stack. The host's
# routes, firewall, containers and Docker networks are not changed.
#
# The provider is a local WireGuard peer. The target address exists only beyond
# it, and the sandbox host has an IPv6 default route to a dummy "uplink" where
# any packet for the target is counted as a leak.
#
# Requires the image: docker build -t egressy:test .
set -u

if [ "${EGRESSY_RUN_DOCKER_TESTS:-}" != "1" ]; then
  echo "skip: set EGRESSY_RUN_DOCKER_TESTS=1 to run the Docker end-to-end test"
  exit 0
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sandbox=egressy-ipv6-e2e-$$
docker image inspect egressy:test >/dev/null || {
  echo "error: build egressy:test first" >&2
  exit 1
}
cleanup() {
  docker rm -f -v "$sandbox" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run -d --privileged --name "$sandbox" -e DOCKER_TLS_CERTDIR= docker:28-dind >/dev/null
attempt=0
until docker exec "$sandbox" docker info >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || { echo "error: the sandbox daemon did not start" >&2; exit 1; }
  sleep 2
done
docker save egressy:test | docker exec -i "$sandbox" docker load >/dev/null
docker exec "$sandbox" mkdir -p /work/config
for file in compose.yaml compose.ipv6.yaml config/config.example.yaml \
  config/docker-api-proxy.cfg config/docker-network.sh; do
  docker cp "$repo_root/$file" "$sandbox:/work/$file" >/dev/null
done

docker exec -i "$sandbox" sh -s <<'SANDBOX'
cd /work
failures=0
pass() { echo "ok: $*"; }
bad() { echo "FAIL: $*"; failures=$((failures + 1)); }

apk add --no-cache -q nftables iproute2 wireguard-tools-wg curl jq >/dev/null
umask 077
mkdir -p secrets provider
wg genkey > secrets/provider.key
wg pubkey < secrets/provider.key > secrets/provider.pub
wg genkey > secrets/gateway.key
wg pubkey < secrets/gateway.key > secrets/gateway.pub
cat > secrets/wg0.conf <<CONF
[Interface]
PrivateKey = $(cat secrets/gateway.key)
Address = 10.2.0.2/32, 2001:db8:e::2/128
DNS = 10.2.0.1

[Peer]
PublicKey = $(cat secrets/provider.pub)
Endpoint = 10.99.0.9:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CONF
umask 022
chmod 644 secrets/provider.key secrets/gateway.pub

cat > provider/Dockerfile <<'DOCKERFILE'
FROM alpine:3.22
RUN apk add --no-cache wireguard-tools-wg iproute2 nftables dnsmasq socat
COPY start.sh /start.sh
ENTRYPOINT ["sh", "/start.sh"]
DOCKERFILE
cat > provider/start.sh <<'START'
set -eu
ip link add wg-provider type wireguard
wg set wg-provider private-key /secrets/provider.key listen-port 51820 \
  peer "$(cat /secrets/gateway.pub)" allowed-ips 10.2.0.2/32,2001:db8:e::2/128
ip addr add 10.2.0.1/24 dev wg-provider
ip addr add 2001:db8:e::1/64 dev wg-provider nodad
ip addr add 2001:db8:f::1/128 dev lo
ip link set wg-provider up
# Advertise a full-size MSS, as an ordinary server does, so that TCP depends on
# the path MTU rather than on the tunnel's own limit.
ip -6 route add 2001:db8:e::2/128 dev wg-provider advmss 1440
nft -f - <<'NFT'
table inet seen {
  counter from_tunnel { }
  counter unmasqueraded { }
  chain input {
    type filter hook input priority -300; policy accept;
    ip6 saddr 2001:db8:e::2 ip6 daddr 2001:db8:f::1 counter name from_tunnel
    ip6 saddr fd30:172:30::/64 counter name unmasqueraded
  }
}
NFT
printf 'HTTP/1.0 200 OK\r\n\r\n' > /tmp/head
cat > /serve.sh <<'SERVE'
cat /tmp/head
head -c 5000000 /dev/zero
SERVE
socat TCP6-LISTEN:8000,fork,reuseaddr SYSTEM:"sh /serve.sh" &
socat -u TCP6-LISTEN:8001,fork,reuseaddr OPEN:/dev/null &
exec dnsmasq --keep-in-foreground --no-resolv --no-hosts --listen-address=10.2.0.1 \
  --bind-interfaces --address=/target.test/2001:db8:f::1 --address=/target.test/10.2.0.1
START
cat > override.yaml <<'YAML'
services:
  docker-api-proxy:
    image: haproxy:3.2-alpine
  egressy:
    image: egressy:test
  egressy-probe:
    image: egressy:test
  egressy-isolation-agent:
    image: egressy:test
  provider:
    image: egressy-test-provider
    container_name: provider
    cap_add: [NET_ADMIN]
    networks:
      uplink:
        ipv4_address: 10.99.0.9
    volumes:
      - /work/secrets:/secrets:ro
  client:
    image: alpine:3.22
    container_name: client
    command: ["sleep", "infinity"]
    labels:
      egressy.enabled: "true"
      egressy.usage-id: "test/client"
      egressy.isolation-id: client
    dns: [172.30.0.2]
    networks:
      vpn-egress: {}
networks:
  uplink:
    ipam:
      config:
        - subnet: 10.99.0.0/24
YAML
sed -e 's/^    enabled: false$/    enabled: true/' config/config.example.yaml > config/config.yaml
ip link add isp0 type dummy
ip link set isp0 up
ip -6 route add default dev isp0
nft -f - <<'NFT'
table inet leak {
  counter leaked { }
  chain postrouting {
    type filter hook postrouting priority 300; policy accept;
    oifname "isp0" ip6 daddr 2001:db8:f::1 counter name leaked
  }
}
NFT
EGRESSY_IPV6=1 sh config/docker-network.sh >/dev/null
cat > .env <<ENV
DOCKER_SOCKET_GID=$(stat -c %g /var/run/docker.sock)
EGRESSY_WIREGUARD_CONFIG=/work/secrets/wg0.conf
ENV
docker build -q -t egressy-test-provider provider >/dev/null
docker pull -q alpine:3.22 >/dev/null
docker pull -q haproxy:3.2-alpine >/dev/null
compose="docker compose -p egressy-e2e -f compose.yaml -f compose.ipv6.yaml -f override.yaml"
# Policy before client traffic: the agent cannot protect a client that starts
# first, as docs/NETWORKING.md explains.
$compose up -d --no-build docker-api-proxy egressy egressy-probe provider egressy-isolation-agent \
  >/dev/null 2>&1 || bad "the stack did not start"
attempt=0
until ip -6 rule | grep -q "lookup 200" && nft list table inet egressy_host 2>/dev/null | grep -q kill-switch; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 60 ] || { bad "the agent did not install the host policy"; break; }
  sleep 1
done
$compose up -d --no-build client >/dev/null 2>&1 || bad "the client did not start"

target=2001:db8:f::1
number() { awk '/packets/{print $2}'; }
leaked() { nft list counter inet leak leaked | number; }
seen() { docker exec provider nft list counter inet seen "$1" | number; }
can_reach() { docker exec client ping -6 -c 1 -W 2 "$target" >/dev/null 2>&1; }
blocked() {
  if can_reach; then
    bad "$1: the target was reachable"
  elif [ "$(leaked)" != "0" ]; then
    bad "$1: $(leaked) packets reached the uplink"
  else
    pass "$1"
  fi
}
wait_reachable() {
  attempt=0
  until can_reach; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 30 ] || return 1
    sleep 2
  done
}
client_status() {
  curl -s http://127.0.0.1:8080/api/v2/status \
    | jq -c '.clients | to_entries | map(select(.value.name == "client")) | .[0].value'
}

wait_reachable || bad "the client never reached the target"
[ "$(leaked)" = "0" ] && pass "client IPv6 reaches the target through the real daemon's routes" \
  || bad "normal egress leaked"
{ [ "$(seen from_tunnel)" -gt 0 ] && [ "$(seen unmasqueraded)" = "0" ]; } \
  && pass "the provider sees only the masqueraded tunnel address" || bad "masquerade"
docker exec client ping -c 1 -W 2 10.2.0.1 >/dev/null && pass "IPv4 still routes through the tunnel" \
  || bad "IPv4"
docker exec client nslookup -type=AAAA target.test 2>&1 | grep -q "$target" \
  && pass "the gateway's DNS forwarder returns AAAA answers" || bad "AAAA"
received=$(docker exec client sh -c "wget -q -T 15 -O - 'http://[$target]:8000/' | wc -c")
[ "$received" = "5000000" ] && pass "TCP download of 5 MB over IPv6" || bad "TCP download got $received bytes"
docker exec client sh -c "head -c 5000000 /dev/zero | nc -w 20 $target 8001" \
  && pass "TCP upload of 5 MB over IPv6" || bad "TCP upload"
docker exec client ping -6 -c 1 -W 2 -s 1400 "$target" >/dev/null \
  && pass "an IPv6 packet larger than the tunnel MTU gets through, fragmented" \
  || bad "oversized IPv6 packet"
attempt=0
until [ "$(client_status | jq .compliant)" = "true" ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || break
  sleep 1
done
[ "$(curl -s http://127.0.0.1:8080/api/v2/status | jq .topology.client_ipv6_supported)" = "true" ] \
  && [ "$(client_status | jq .compliant)" = "true" ] \
  && pass "the API reports IPv6 supported and the client compliant" || bad "API status with IPv6 on"

docker exec egressy ip link set wg0 down
blocked "tunnel loss blocks client IPv6"
docker restart egressy >/dev/null
wait_reachable && pass "client IPv6 returns after a gateway restart" || bad "recovery after tunnel loss"

docker stop egressy >/dev/null
blocked "gateway loss blocks client IPv6"
docker start egressy >/dev/null
wait_reachable && pass "client IPv6 returns when the gateway starts" || bad "recovery after gateway loss"

docker stop egressy-isolation-agent >/dev/null
ip -6 rule del priority 100 from fd30:172:30::/64 lookup 200
blocked "the host rejects client IPv6 when its source rule is lost"
ip -6 route flush table 200
nft delete table inet egressy_host
docker start egressy-isolation-agent >/dev/null
attempt=0
until ip -6 rule | grep -q "lookup 200" && nft list table inet egressy_host 2>/dev/null | grep -q kill-switch; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 20 ] || break
  sleep 1
done
wait_reachable && pass "the agent restores cleared host state" || bad "agent restore"

cp secrets/wg0.conf secrets/wg0.full
sed -i 's|, ::/0||' secrets/wg0.conf
docker restart egressy >/dev/null
sleep 12
docker logs --since 15s egressy 2>&1 | grep -q "no IPv6 address or ::/0" \
  && pass "a profile without ::/0 logs a warning" || bad "missing profile warning"
blocked "a profile without ::/0 leaves client IPv6 unreachable"
docker exec client ping -c 1 -W 2 10.2.0.1 >/dev/null \
  && pass "IPv4 is unaffected by a profile without ::/0" || bad "IPv4 with no IPv6 in the profile"
cp secrets/wg0.full secrets/wg0.conf

# Routing off, on a Docker network that still has IPv6 enabled.
before=$(seen from_tunnel)
sed -i 's/^    enabled: true$/    enabled: false/' config/config.yaml
docker compose -p egressy-e2e -f compose.yaml -f override.yaml up -d --no-build --force-recreate \
  egressy egressy-isolation-agent >/dev/null 2>&1
attempt=0
until nft list table inet egressy_host 2>/dev/null | grep -q kill-switch:disabled; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || { bad "the agent did not replace the host table"; break; }
  sleep 1
done
sleep 5
[ "$(curl -s http://127.0.0.1:8080/api/v2/host-policy | jq .schema_version)" = "1" ] \
  && pass "the published policy returns to schema 1 with routing off" || bad "schema with routing off"
blocked "with routing off, client IPv6 is blocked with the old host rule still present"
ip -6 rule del priority 100 from fd30:172:30::/64 lookup 200 2>/dev/null
blocked "with routing off, client IPv6 is blocked with the host rule removed"
[ "$(seen from_tunnel)" = "$before" ] && pass "no IPv6 used the tunnel with routing off" || bad "IPv6 used the tunnel"
docker exec client ping -c 1 -W 2 10.2.0.1 >/dev/null && pass "IPv4 still routes with IPv6 routing off" \
  || bad "IPv4 with routing off"

# Control: without the kill switch the same packet reaches the uplink.
nft delete table inet egressy_host
docker exec client ping -6 -c 1 -W 1 "$target" >/dev/null 2>&1
[ "$(leaked)" -gt 0 ] && pass "control: removing the kill switch does leak, so the detector works" \
  || bad "control: the detector saw nothing"

echo "failures: $failures"
exit "$failures"
SANDBOX
status=$?
[ "$status" = "0" ] && echo "ok: IPv6 verified with real Docker networks and the real daemon"
exit "$status"
