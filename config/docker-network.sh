#!/bin/sh
set -eu

# --ip-range keeps Docker's dynamic pool away from the low addresses, and
# --aux-address reserves the gateway's own address outright. Without both, IPAM
# is free to hand 172.30.0.2 to whichever container starts first after a daemon
# restart, and the gateway then cannot start at all: it fails container creation
# with "Address already in use" and stays down, because that failure does not
# trigger the restart policy.
#
# Statically pinned clients belong below the dynamic range; leave 172.30.0.2
# to the gateway.
#
# Set EGRESSY_IPV6=1 to create the network with the addresses network.ipv6 uses
# by default. IPv6 cannot be added to an existing network: recreate it instead,
# and pair it with compose.ipv6.yaml.
set --
if [ "${EGRESSY_IPV6:-}" = "1" ]; then
  set -- --ipv6 \
    --subnet fd30:172:30::/64 \
    --gateway fd30:172:30::1 \
    --ip-range fd30:172:30:0:8000::/65 \
    --aux-address egressy-gateway-ipv6=fd30:172:30::2
fi
docker network inspect vpn-egress >/dev/null 2>&1 || docker network create \
  --driver bridge \
  --subnet 172.30.0.0/24 \
  --gateway 172.30.0.1 \
  --ip-range 172.30.0.128/25 \
  --aux-address egressy-gateway=172.30.0.2 \
  --opt com.docker.network.bridge.name=br-vpn-egress \
  "$@" \
  vpn-egress

