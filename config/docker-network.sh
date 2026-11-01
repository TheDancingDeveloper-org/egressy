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
docker network inspect vpn-egress >/dev/null 2>&1 || docker network create \
  --driver bridge \
  --subnet 172.30.0.0/24 \
  --gateway 172.30.0.1 \
  --ip-range 172.30.0.128/25 \
  --aux-address egressy-gateway=172.30.0.2 \
  --opt com.docker.network.bridge.name=br-vpn-egress \
  vpn-egress

