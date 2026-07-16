# Egressy API and dashboard contract

Egressy exposes operational state through versioned JSON endpoints, health
checks, metrics, server-sent events, and its embedded dashboard.

## Compatibility endpoints

`GET /api/v1/status` retains the original `AppState` fields and meanings:
`tunnel`, `traffic`, `port_forward`, `clients`, and `last_error`. Client objects
now add running state, discovered networks, IPv6 diagnostics, forwarding label
validity, and a `route_intent` object. The additive route-intent field remains
advisory and does not change v1 compliance semantics. Consumers must continue
to ignore unknown fields.

`GET /healthz` remains the Docker compatibility health check. It returns
`200 ok` only when the latest non-zero WireGuard handshake is younger than 180
seconds, and otherwise returns `503 tunnel down`. Docker discovery, forwarding,
DNS, and client-path probe results do not change this legacy semantic.

## Canonical v2 state

`GET /api/v2/status` returns the immutable snapshot used by the dashboard and
recovery framework. Its main fields are:

- `protection`: `enforced`, `unknown`, or `violated`;
- `availability`: `starting`, `healthy`, `degraded`, `unavailable`, or
  `recovering`;
- `checks`: subsystem observations with status, impact, timestamps, stable
  reason code, safe message, failure count, and next-attempt time;
- `transitions`: the newest 200 in-memory status transitions;
- `port_forward`: requested target, lease timing, TCP/UDP agreement, installed
  DNAT state, verification state, and change sequence;
- `recovery`: active attempt, reason, and next-attempt time;
- `topology`: configured network, subnet, gateway, bridge, table, IPv6 support,
  route-verification limitation, and client-isolation posture;
- `clients`: v1-compatible discovery details plus lifecycle, topology, and
  typed Docker route-intent and per-client traffic data;
- `traffic`: aggregate WireGuard byte rates, totals, and sample time;
- `last_client_path_success_at_unix_ms`: last complete successful probe.
- `external_probe`: advisory public-path validation state reported by the
  enrolled `egressy-probe` companion after calling the external HTTPS probe.
- `isolation_policy`: the safe desired bridge-participant policy, eligibility,
  reason, issues, identities, addresses, and resolved service allowances.

Protection and availability are deliberately independent. For example,
`protection=enforced` with `availability=unavailable` means enrolled traffic is
failing closed rather than leaking through the Docker host.

Stable reason codes are machine-facing. Safe messages may improve over time.
The snapshot's 200-entry transition ring is diagnostic and resets on process
restart. Safe canonical transitions are also persisted separately in the
bounded SQLite history API; neither surface is a security audit log.

App-owned historical usage/events are available through the bounded endpoints
below. `vpn_server` reports safe configured and runtime WireGuard endpoint
metadata, handshake-derived active state, explicitly labelled inference, and
advisory endpoint latency.

Each client's `route_intent` contains `status` (`verified`, `mismatch`, or
`unknown`), Docker's selected IPv4/IPv6 network names when determinable, the
egress endpoint priority, all observed endpoint priorities, and a safe reason.
`verified` means Docker declares `vpn-egress` as its IPv4 default; `mismatch`
means Docker declares another eligible network; `unknown` means the API fields
are insufficient. None proves the effective route inside the container.
A known `mismatch` makes the client non-compliant and ineligible for port
forwarding. `unknown` remains compatible because absence of Docker metadata is
not evidence of an alternate runtime route.

Each client also contains `traffic` packet/byte totals and up to 120 changed
samples. Totals come from named nftables counters on the gateway path. They are
preserved across coordinator-owned firewall reconciliation, reset when a
container is removed or changes address, and do not transfer when an address
is reused by a different container. Process restart resets this current-state
sample ring. Transactional SQLite baselines prevent already committed usage
from being counted again after restart.

The history API aggregates persisted deltas by stable workload identity rather
than treating an ephemeral container ID as a permanent series key. Each client
exposes `usage_id` and `usage_id_source` (`explicit_label`, `compose_service`,
or `container_lifetime`). `/metrics` remains a current-process exposition and
is not the durable history API.

## Persistent history

`GET /api/v2/history/usage` returns time-bucketed per-workload byte/packet
deltas from app-owned SQLite. Query parameters are `from_unix_ms`,
`to_unix_ms`, `bucket_seconds`, optional `usage_id`, and `limit`. Ranges are
positive and bounded to 366 days, bucket sizes must be a multiple of the
configured storage bucket, and result cardinality is bounded.

`GET /api/v2/history/events` returns newest-first safe canonical transitions
and forwarded-port lifecycle observations. `before_id` provides cursor
pagination; `from_unix_ms`, `to_unix_ms`, and `limit` are bounded.

Both endpoints return `503 {"error":"history_unavailable"}` while SQLite is
unavailable. Current-state APIs, routing, health, and recovery continue. An
invalid query returns `400` rather than causing an unbounded database scan.

`GET /api/v2/history/vpn-server` returns time-bucketed endpoint active-sample
counts and measured RTT min/average/max. A missing RTT remains null; it is never
rendered as zero. The measurement is low-rate underlay ICMP to the runtime peer
endpoint, not application latency through the VPN, and it never affects
`/healthz`, `/readyz`, recovery, or protection.

## Shared-bridge policy

`GET /api/v2/isolation-policy` returns the same `isolation_policy` object as
the canonical snapshot for the loopback-only host agent. It contains no Docker
labels beyond the validated isolation identity and resolved allowance contract,
no environment values, and no credentials. Every running IPv4 participant on
`vpn-egress` must have a unique valid identity before
`eligible_for_enforcement=true`.

This endpoint describes desired policy, not proof that host nftables has
applied it. The isolation agent's configured mode and live
`bridge egressy_isolation` table remain authoritative; API consumers must not
infer enforcement solely from policy eligibility.

## Events and generated contract

`GET /api/v2/events` is a server-sent event stream. Events have type
`transition`; their SSE `id` is the monotonically increasing sequence number.
Clients must refresh `/api/v2/status` after reconnecting because transition
history is bounded and in memory.

`GET /api/v2/openapi.json` serves the checked-in OpenAPI document from
`openapi/v2.json`. `npm run generate:types` in `ui/` regenerates
`ui/src/generated.ts`. CI fails when either generated TypeScript or the embedded
single-file dashboard differs from a clean build.

`GET /metrics` exposes `egressy_client_traffic_bytes_total` and
`egressy_client_traffic_packets_total`, labelled only by current container ID
and direction. Only currently enrolled clients produce series, bounding live
cardinality to twice the inventory size. Container-controlled label values are
escaped.

## Liveness and readiness

- `GET /livez` proves the HTTP process and essential server are responsive.
- `GET /readyz` returns `200 ready` when the canonical snapshot is past startup
  and no critical check has failed. It returns `503 data_plane_not_ready`
  otherwise.
- `/healthz` is retained separately until existing Docker and deployment
  consumers migrate.

## Forwarding semantics

The v2 lifecycle distinguishes disabled, waiting, requested, leased, installed,
verified, ambiguous, lost, failed, and unavailable states. `dnat_installed=true`
is published only after the complete owned nftables ruleset was reconciled.
Tunnel, target, lease, or mapping failure removes DNAT before inactive state is
published. A reconciliation failure therefore remains an enforcement error
rather than being misreported as ordinary inactivity.

`installed` is not proof of public reachability. When the optional external
probe returns fresh evidence for the exact active port and NAT-PMP lease
acquisition, a reachable result produces `verified` and
`externally_verified=true`; an explicit TCP failure produces
`verification_failed` and `externally_verified=false`. Stale, unavailable,
contradictory, or mismatched evidence leaves DNAT installed but returns the
lifecycle to `installed` with unknown verification. Every successful lease
renewal invalidates evidence collected for the previous lease, even when the
provider keeps the same port. Verification is Optional/Advisory and does not
change `/healthz`, `/readyz`, protection, recovery, or DNAT installation.

The external-probe subsection includes only safe correlation metadata: the
claimed forwarded port, lease-acquisition timestamp, and request-start
timestamp. It never contains the observed or claimed raw public address.
Port changes are observable through the snapshot change sequence and
transition stream; `egressy` never executes a command inside an application
container.

The probe result endpoint is reachable only on the enrolled network. Operators
may additionally set `probe.token_path` and the companion's
`EGRESSY_PROBE_TOKEN` to require a bearer token; the token is never included in
canonical state or logs.

When `external_probe.enabled=true`, the same companion also publishes a safe
`external_probe` subsection. The companion is the HTTP client for the external
check because it originates on the enrolled path; the main `egressy` process
does not make that call directly. The reference implementation is the small
Python HTTPS API under `external-probe/`. It is primarily a development and
release-validation tool. Its response is advisory only and does not change
`/healthz` semantics or trigger tunnel recovery by itself.

## Dashboard

`GET /` serves the React/TypeScript dashboard embedded in the Rust binary as a
single deterministic HTML asset. It provides overview, data-path, clients,
forwarding, and diagnostics sections; uses both text and color; exposes
observation times; and enters an explicit stale/API-disconnected state. React
text rendering escapes container-controlled values.

The operational views are read-only, but the notifications view writes its own
narrow settings contract. `GET` and `PUT /api/v2/settings/notifications` read
and update GUI-managed Omnihook settings, and
`POST /api/v2/settings/notifications/test` sends a test notification. The read
contract returns only booleans and a scheme/hostname destination mask; webhook
paths, Telegram chat IDs, and HMAC secrets are write-only. Blank secret fields
retain their saved values.

The dashboard and settings API are unauthenticated. Restrict them to localhost
or a trusted management network, or put an authenticated reverse proxy in
front of them.

## Secret boundary

No API or event may include WireGuard keys or profiles, Docker environment
variables, provider credentials or account identifiers, secret-manager values,
or generated passwords. The client-path probe reports a
boolean identity match and never publishes the observed public address. Its
tokenless identity provider is queried independently of the 30-second DNS
checks; the latest safe HTTPS and identity booleans remain cached between the
default five-minute observations.
