#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
container=egressy-docker-proxy-test-$$

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

socket_gid=$(stat -c '%g' /var/run/docker.sock)
docker create \
    --name "$container" \
    --group-add "$socket_gid" \
    --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly \
    haproxy:3.2-alpine >/dev/null
docker cp "$repo_root/config/docker-api-proxy.cfg" \
    "$container:/usr/local/etc/haproxy/haproxy.cfg"
docker start "$container" >/dev/null

request_status() {
    method=$1
    path=$2
    docker exec -e METHOD="$method" -e PATH_INFO="$path" "$container" sh -c '
        printf "%s %s HTTP/1.0\r\nHost: docker\r\nContent-Length: 0\r\n\r\n" \
            "$METHOD" "$PATH_INFO" |
            nc -w 5 127.0.0.1 2375 |
            awk "NR == 1 { print \$2; exit }"
    '
}

attempt=0
until [ "$(request_status GET '/containers/json?all=true')" = 200 ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 20 ] || {
        docker logs "$container" >&2
        exit 1
    }
    sleep 0.1
done

expect_status() {
    expected=$1
    method=$2
    path=$3
    actual=$(request_status "$method" "$path")
    if [ "$actual" != "$expected" ]; then
        echo "$method $path returned $actual, expected $expected" >&2
        exit 1
    fi
}

# Required read operations, with and without Docker's API-version prefix.
expect_status 200 GET '/containers/json?all=true'
expect_status 200 GET '/v1.41/containers/json?all=true'
expect_status 200 GET '/networks/bridge'
expect_status 200 GET '/v1.41/networks/bridge'

# Representative lifecycle, mutation, data-exposure, and unrelated reads.
expect_status 403 POST '/containers/does-not-exist/start'
expect_status 403 POST '/containers/does-not-exist/stop'
expect_status 403 POST '/containers/does-not-exist/restart'
expect_status 403 POST '/containers/does-not-exist/attach'
expect_status 403 POST '/containers/does-not-exist/exec'
expect_status 403 GET '/containers/does-not-exist/json'
expect_status 403 GET '/containers/does-not-exist/logs'
expect_status 403 POST '/networks/create'
expect_status 403 DELETE '/networks/does-not-exist'
expect_status 403 GET '/events'
expect_status 403 GET '/images/json'
expect_status 403 GET '/volumes'
expect_status 403 GET '/secrets'
expect_status 403 GET '/_ping'

echo 'Docker proxy exact allow-list passed'
