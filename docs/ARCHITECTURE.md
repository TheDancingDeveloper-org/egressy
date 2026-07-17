# Egressy architecture

## Scope

Egressy is a single-host, single-tunnel IPv4 router for Docker workloads. A
client keeps its own network namespace and joins an external bridge. Linux
policy routing sends packets sourced from that bridge to the gateway container,
which applies fail-closed policy and forwards them through WireGuard.

The system deliberately does not mutate client containers, provide an
application proxy, select provider servers, manage provider credentials, or
claim IPv6 client protection.

## Components

### Gateway daemon

The `egressy` binary owns configuration validation, startup ordering,
WireGuard lifecycle, nftables reconciliation, source-policy routes, DNS,
NAT-PMP, Docker observation, state publication, history, and the HTTP server.
One enforcement coordinator serializes gateway firewall changes so tunnel
recovery and forwarding updates cannot independently replace its table.

### Host policy

`egressy render-host-setup` produces an idempotent script for the Docker host.
It adds a source rule for the enrolled subnet and a policy-table route through
the gateway. A host nftables forward rule rejects enrolled traffic that did not
enter from or leave toward the expected bridge path. This layer prevents an
ordinary Docker masquerade route from becoming an escape when the gateway is
unavailable.

### Restricted Docker API proxy

The daemon observes containers and its configured network through a dedicated
internal network. HAProxy is the only Docker-socket consumer and permits only
container listing and named network inspection. The `egressy` daemon has no
socket mount and does not use the Docker API to change runtime state.

### Companion probe

`egressy-probe` is an unprivileged container attached only to the enrolled
network. It tests UDP DNS, TCP DNS, HTTPS egress, and expected provider identity
from the same routed path as a client. It posts safe summarized results to the
gateway. An optional external check can validate observed public-source and
forwarded-port reachability; that result is advisory.

### Isolation agent

`egressy-isolation-agent` is a separate host-networked binary that can audit or
enforce Layer-3/4 communication policy on the shared bridge. It consumes a
complete policy snapshot from Egressy. The feature is disabled by default
because incomplete inventory can interrupt workload dependencies and because
it is not a Layer-2 anti-spoofing or hostile multi-tenant boundary.

### Dashboard and API

Axum serves the versioned JSON API, Server-Sent Events, health endpoints,
metrics, OpenAPI document, and a single-file React application embedded in the
Rust binary. Canonical state separates leak protection from service
availability. SQLite retains bounded traffic and event history; optional OTLP
export mirrors safe telemetry without becoming a data-plane dependency.

## Startup order

1. Parse and strictly validate YAML and environment overrides.
2. Initialize local telemetry and optional OTLP export.
3. Validate the WireGuard source and create a protected normalized copy.
4. Install the fail-closed gateway nftables table.
5. Bring up WireGuard with `Table = off`.
6. Install the gateway's priority-90 and priority-100 rules and table-200
   routes.
7. Start DNS, Docker observation, probes, traffic sampling, recovery,
   forwarding, persistence, and HTTP tasks.

The firewall precedes the tunnel so startup cannot briefly forward enrolled
traffic through the management uplink.

## State model

Canonical v2 state publishes:

- `protection`: whether fail-closed enforcement is observed;
- `availability`: whether the routed service is usable;
- typed checks with critical, optional, or advisory impact;
- bounded transitions with stable reason codes and safe messages;
- current clients, route intent, traffic counters, and forwarding state;
- recovery, external validation, VPN endpoint, and isolation information.

Advisory evidence never relaxes protection or initiates tunnel recovery.
Compatibility v1 state remains available for existing consumers.

## Failure behavior

- Tunnel loss: gateway and host rejects remain; recovery retries with bounded
  backoff.
- Gateway loss: host policy prevents the enrolled bridge from using Docker's
  ordinary egress.
- Docker API loss: discovery becomes stale, but existing routing and firewall
  ownership continue.
- Probe or external-validator loss: diagnostics degrade without weakening
  enforcement.
- History or OTLP loss: current state and data plane remain operational.
- Forward target loss or ambiguity: DNAT is removed and forwarding becomes
  unavailable.

## Extension boundaries

Provider-specific examples are isolated from the provider-neutral WireGuard,
DNS, identity-validation, and optional NAT-PMP capabilities. Supporting another provider
requires an explicit capability model for DNS and port allocation; it must not
weaken the fail-closed routing layers.
