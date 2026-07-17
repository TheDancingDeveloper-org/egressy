#!/bin/sh
# Release-build probe smoke test. Loopback-only and safe for developer hosts.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
probe=${EGRESSY_PROBE_BIN:-$repo_root/target/release/egressy-probe}
[ -x "$probe" ] || { echo "probe binary not found: $probe" >&2; exit 1; }
tmpdir=$(mktemp -d)
pid=
cleanup() {
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
    rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
umask 077
printf '%s' 'probe-test-token' >"$tmpdir/token"
EGRESSY_PROBE_LISTEN="127.0.0.1:$port" \
EGRESSY_PROBE_DNS=127.0.0.1:9 \
EGRESSY_PROBE_IDENTITY_ENABLED=false \
EGRESSY_PROBE_TOKEN='probe-test-token' \
    "$probe" >"$tmpdir/probe.log" 2>&1 &
pid=$!

attempt=0
until curl -fsS "http://127.0.0.1:$port/livez" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || { cat "$tmpdir/probe.log" >&2; exit 1; }
    sleep 0.1
done

status_code=$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/status")
[ "$status_code" = 401 ] || { echo "expected 401, got $status_code" >&2; exit 1; }
curl -fsS -H 'Authorization: Bearer probe-test-token' "http://127.0.0.1:$port/status" >"$tmpdir/status.json"
python3 - "$tmpdir/status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
required = {"observed_at_unix_ms", "udp_dns_ok", "tcp_dns_ok", "https_egress_ok", "vpn_identity_ok", "reason_code", "safe_message"}
missing = required.difference(status)
if missing:
    raise SystemExit(f"probe status missing fields: {sorted(missing)}")
if not isinstance(status["udp_dns_ok"], bool) or not isinstance(status["tcp_dns_ok"], bool):
    raise SystemExit("probe DNS results must be booleans")
PY

if [ -n "${EGRESSY_PROBE_URL:-}" ]; then
    live_status="$tmpdir/live-status.json"
    if [ -n "${EGRESSY_PROBE_TOKEN:-}" ]; then
        curl -fsS -H "Authorization: Bearer $EGRESSY_PROBE_TOKEN" "$EGRESSY_PROBE_URL" >"$live_status"
    else
        curl -fsS "$EGRESSY_PROBE_URL" >"$live_status"
    fi
    python3 - "$live_status" <<'PY'
import json, sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
for field in ("observed_at_unix_ms", "reason_code", "safe_message"):
    if field not in status:
        raise SystemExit(f"live probe status missing field: {field}")
PY
fi
echo "release probe network smoke test passed"
