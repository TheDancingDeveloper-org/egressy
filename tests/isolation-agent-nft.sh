#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
container=egressy-isolation-nft-test-$$

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker create \
    --name "$container" \
    --cap-add NET_ADMIN \
    --entrypoint sh \
    egressy:test -eu -c '
cat > /tmp/policy-server.sh <<"SERVER"
#!/bin/sh
length=$(wc -c < /tmp/isolation-policy.json | tr -d " ")
printf "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n" "$length"
cat /tmp/isolation-policy.json
SERVER
chmod +x /tmp/policy-server.sh
busybox nc -lk -s 127.0.0.1 -p 8080 -e /tmp/policy-server.sh &
server_pid=$!
/usr/local/bin/egressy-isolation-agent \
    --mode audit \
    --interval-seconds 1 \
    --stale-seconds 18446744073709551 &
agent_pid=$!

attempt=0
until nft list table bridge egressy_isolation >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || exit 1
    sleep 0.1
done
nft list table bridge egressy_isolation > /tmp/table.txt
grep -q "tcp dport 8083 accept" /tmp/table.txt
grep -q "isop_sourcecontainer_destinationcontainer" /tmp/table.txt
grep -q "counter name .* accept" /tmp/table.txt

kill -INT "$agent_pid"
wait "$agent_pid"
/usr/local/bin/egressy-isolation-agent \
    --mode disabled \
    --interval-seconds 1 \
    --stale-seconds 1 &
disabled_pid=$!
attempt=0
while nft list table bridge egressy_isolation >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || exit 1
    sleep 0.1
done
kill -INT "$disabled_pid"
wait "$disabled_pid"
kill "$server_pid"
' >/dev/null
docker cp "$repo_root/tests/fixtures/isolation-policy.json" \
    "$container:/tmp/isolation-policy.json"
docker start -a "$container"
exit_code=$(docker inspect -f "{{.State.ExitCode}}" "$container")
[ "$exit_code" = 0 ]

echo 'Isolation agent audit apply and disabled rollback passed'
