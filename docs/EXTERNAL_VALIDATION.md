# Egressy external validation

Egressy includes an optional internet-path check for development, release
qualification, and operator canaries. It answers two questions that the
gateway cannot prove locally:

- did the request arrive from a public address consistent with the current
  tunnel claim;
- can an independent host connect to the active forwarded TCP port.

The result is advisory. It never changes `/healthz`, protection, readiness, or
WireGuard recovery.

## Components

`egressy-probe` sends a bounded authenticated HTTPS request from the enrolled
path. `external-probe/external_probe_service.py` is a dependency-free reference
service. The gateway ingests only safe summarized state from its local
companion.

**The probe must itself be enrolled**, with the `egressy.enabled` label — not
merely pointed at the gateway's resolver. An unenrolled probe leaves by the
host's default route, so the address the endpoint observes is never the address
the gateway claims, and every result is a permanent `claimed_ip_mismatch`. That
is not a harmless false positive: it is byte-identical to the report produced by
a genuine client-egress leak, so the check cannot distinguish a healthy tunnel
from a broken one.

The probe now detects this itself. When its own public address — taken from the
identity endpoint — differs from the gateway's claimed address, a mismatch is
reported as `external_probe.probe_not_enrolled` instead, which describes the
probe's own path and makes clear that client egress was not validated.

The feature is disabled by default in YAML, environment defaults, and examples.

## Request safety

Each request has an instance identifier, unique request ID, timestamp, and
optional active-lease claims. The client sends `claimed_public_ip` and
`forwarded_port` only when it has a fresh active forwarding lease. It never logs
those values.

The endpoint must:

- use HTTPS;
- use a DNS hostname rather than a raw address;
- not use a tailnet hostname;
- resolve only to public unicast addresses accepted by the client;
- be revalidated each interval without unsafe redirects.

## Service behavior

The reference service validates bearer authentication, body size, schema,
timestamp freshness, replay, and rate limits. It derives the source from the
direct peer unless that peer belongs to an explicitly trusted proxy CIDR. The
optional TCP test connects only to that verified source.

Responses contain booleans and a stable reason code, never the raw observed
address, token, request ID, or reflected body. Healthy requires both the
explicit `external_probe.healthy` reason code and internally consistent
booleans. Other or incomplete results map to degraded or unavailable.

## Development test

Run the service unit suite:

```sh
python3 -m unittest external-probe/test_external_probe_service.py
```

For a full-path test, use a disposable public host independent from the Docker
gateway. Terminate HTTPS directly or at a reverse proxy that preserves the
caller address. Use a dedicated test token, expose only the HTTPS endpoint,
enable the companion variables for one test window, and remove the service and
token afterward if continuous validation is not required.

The service must not sit behind a CDN or generic forward proxy because the
observed source would be the intermediary. It must not be reachable only over a
private overlay because that bypasses the public VPN path being measured.

## Configuration split

The daemon's `external_probe` YAML section gates ingestion and staleness. The
companion performs the request and uses `EGRESSY_EXTERNAL_PROBE_*` variables:

- `ENABLED`
- `INSTANCE_ID`
- `URL`
- `INTERVAL_SECONDS`
- `TIMEOUT_SECONDS`
- `TOKEN_PATH`
- `STATE_URL`

Use identical instance, timeout, and token settings across components. Keep the
token in protected mounted files, not tracked YAML or Compose.
The default external request interval is 10 seconds with a 5-second timeout.
The daemon polls the companion every 10 seconds. When NAT-PMP is enabled, their
combined worst-case propagation time must remain shorter than the lease refresh
interval so every renewal has an opportunity to receive correlated evidence.

## Limitations

A successful result is a point-in-time observation. It does not prove all
protocols, every client, future lease continuity, provider identity, DNS
correctness, or fail-closed behavior. Continue to test local rules, tunnel loss,
gateway loss, and actual client egress independently.
