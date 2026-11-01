#!/bin/sh
set -eu

# --ip-range keeps Docker's dynamic pool away from the low addresses. Without it,
# IPAM is free to hand 172.30.0.2 to whichever container starts first after a
# daemon restart, and the gateway then cannot start at all: it fails container
# creation with "Address already in use" and stays down, because that failure
# does not trigger the restart policy. Do not also declare the gateway's address
# with --aux-address: Docker then refuses the gateway's own static assignment
# with the same error.
#
# Statically pinned clients belong below the dynamic range; leave 172.30.0.2
# to the gateway.
#
# Set EGRESSY_IPV6=1 to create the network with the addresses network.ipv6 uses
# by default. IPv6 cannot be added to an existing network: recreate it instead,
# and pair it with compose.ipv6.yaml.
#
# The MTU matches WireGuard's default. IPv6 routers do not fragment, and a client
# fragmenting to a smaller path MTU can be reassembled by the host's connection
# tracking and resent whole, so oversized UDP and ICMP would never arrive.
set --
if [ "${EGRESSY_IPV6:-}" = "1" ]; then
  set -- --ipv6 \
    --subnet fd30:172:30::/64 \
    --gateway fd30:172:30::1 \
    --ip-range fd30:172:30:0:8000::/65 \
    --opt com.docker.network.driver.mtu=1420
fi
docker network inspect vpn-egress >/dev/null 2>&1 || docker network create \
  --driver bridge \
  --subnet 172.30.0.0/24 \
  --gateway 172.30.0.1 \
  --ip-range 172.30.0.128/25 \
  --opt com.docker.network.bridge.name=br-vpn-egress \
  "$@" \
  vpn-egress

