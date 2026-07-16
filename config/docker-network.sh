#!/bin/sh
set -eu

docker network inspect vpn-egress >/dev/null 2>&1 || docker network create \
  --driver bridge \
  --subnet 172.30.0.0/24 \
  --gateway 172.30.0.1 \
  --opt com.docker.network.bridge.name=br-vpn-egress \
  vpn-egress

