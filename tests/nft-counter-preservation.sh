#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rules=$(mktemp)
container=egressy-nft-syntax-test-$$

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -f "$rules"
}
trap cleanup EXIT INT TERM

(cd "$repo_root" && cargo run --quiet -- \
    --config config/config.example.yaml render-gateway-firewall) > "$rules"

# The Docker daemon may not see this development container's filesystem, so
# copy the rendered rules into a stopped disposable container.
docker create --name "$container" --cap-add NET_ADMIN alpine:3.22 \
    sh -c 'apk add --no-cache nftables >/dev/null && nft -c -f /tmp/egressy-gateway.nft' \
    >/dev/null
docker cp "$rules" "$container:/tmp/egressy-gateway.nft"
docker start -a "$container" >/dev/null
docker rm "$container" >/dev/null

# Exercise the exact seeded named-counter behavior used by reconciliation.
docker run --rm --cap-add NET_ADMIN alpine:3.22 sh -eu -c '
apk add --no-cache nftables >/dev/null
nft -f - <<"NFT"
table inet egressy {
 counter client_up_test { packets 3 bytes 99; }
 chain forward {
  type filter hook forward priority 0; policy drop;
  ip saddr 172.30.0.10 oifname "wg0" counter name client_up_test
 }
}
NFT
raw=$(nft -j list counters table inet egressy)
packets=$(printf "%s" "$raw" | sed -n "s/.*\"packets\": \([0-9]*\).*/\1/p")
bytes=$(printf "%s" "$raw" | sed -n "s/.*\"bytes\": \([0-9]*\).*/\1/p")
[ "$packets" = 3 ] && [ "$bytes" = 99 ]
nft -f - <<NFT
delete table inet egressy
table inet egressy {
 counter client_up_test { packets $packets bytes $bytes; }
 chain forward {
  type filter hook forward priority 0; policy drop;
  ip saddr 172.30.0.10 oifname "wg0" counter name client_up_test
 }
}
NFT
nft -j list counters table inet egressy |
    grep -q "\"packets\": 3, \"bytes\": 99"
'

echo 'Rendered nftables syntax and seeded counter replacement passed'
