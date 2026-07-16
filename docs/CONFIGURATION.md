# Egressy configuration reference

Egressy's `egressy` daemon reads strict YAML from `/etc/egressy/config.yaml` by
default. Change the path with `--config` or `EGRESSY_CONFIG`. Unknown fields
are rejected.
Start from `config/config.example.yaml` and run `egressy check` before startup.

## Top-level settings

### HTTP and Docker

| Field | Default | Meaning |
|---|---|---|
| `listen` | `0.0.0.0:8080` | Dashboard and API listener. |
| `docker_socket` | restricted proxy URL | Docker API endpoint used for read-only observation. |

Use the bundled HAProxy configuration. Pointing directly at a socket broadens
the security boundary even when the mount is marked read-only.

### `network`

| Field | Example | Meaning |
|---|---|---|
| `name` | `vpn-egress` | External Docker network. |
| `subnet` | `172.30.0.0/24` | Enrolled IPv4 source range. |
| `gateway_ip` | `172.30.0.2` | Egressy address on that network. |
| `host_bridge` | `br-vpn-egress` | Stable host bridge interface name. |
| `route_table` | `200` | Dedicated Linux policy table. |

These values must match the Docker network and installed host policy.

### `wireguard`

| Field | Meaning |
|---|---|
| `interface` | Managed interface name, normally `wg0`. |
| `config_path` | Protected raw profile path. |
| `config_base64_path` | Optional protected base64 profile path. |
| `manage` | Whether Egressy starts and stops the interface. |

The normal managed mode rewrites a tmpfs copy with `Table = off`. Do not add
PostUp/PostDown commands that compete with Egressy firewall ownership.

### `proton`

`port_forwarding` enables NAT-PMP. `natpmp_gateway` is the provider gateway,
`refresh_seconds` is the renewal interval, and `lifetime_seconds` is the
requested lease. Refresh must be shorter than lifetime. Defaults are tuned for
Proton's 60-second lease.

### `dns`

`enabled`, `listen`, and `upstream` control the bounded UDP/TCP forwarder.
`timeout_ms` limits an upstream attempt and `max_concurrent_queries` bounds
load. Enrolled clients should use only the gateway listener; firewall policy
rejects other plain DNS destinations.

### `probe`

The internal companion URL is polled at `interval_seconds`. `token_path` may
protect the local status exchange. `expected_identity` is matched against the
safe provider organization returned by the companion's identity endpoint.

The companion itself is configured with `EGRESSY_PROBE_*` variables in
Compose, including DNS address, identity URL, expected identity, token, and
optional external validation settings.

### `external_probe`

This daemon section gates ingestion and staleness reporting. It is disabled by
default. The companion performs outbound validation using its
`EGRESSY_EXTERNAL_PROBE_*` environment variables. Keep the settings aligned.
The endpoint must use HTTPS, a DNS hostname, and a public non-tailnet address.

### `persistence`

`enabled` controls SQLite history. `path` selects the database,
`retention_days` bounds age, `bucket_seconds` controls aggregation resolution,
and `writer_capacity` bounds the asynchronous queue. Database failure degrades
history only; it does not relax routing protection.

### `otel`

OTLP/HTTP protobuf export is disabled by default. Configure it in YAML or with:

- `EGRESSY_OTEL_ENABLED`
- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/protobuf` only)
- `OTEL_EXPORTER_OTLP_TIMEOUT`
- `OTEL_SERVICE_NAME`
- `EGRESSY_OTEL_HEADERS_PATH`
- `EGRESSY_OTEL_INSECURE`

HTTPS is required unless the explicit insecure flag is set. Store headers in a
protected file, never inline in tracked Compose.

### `vpn_server`, `recovery`, and `reconcile`

`vpn_server` controls optional endpoint-latency observation. `recovery` sets
failure and success hysteresis plus maximum backoff. `reconcile.interval_seconds`
sets the enforcement loop. `apply_gateway_firewall` must remain `true`; false
is rejected because managed routing without a fail-closed owner is unsafe.

## Client labels

| Label | Purpose |
|---|---|
| `egressy.enabled=true` | Requests enrollment and monitoring. |
| `egressy.usage-id` | Stable history identity across container recreation. |
| `egressy.port-forward=true` | Selects the sole forwarding target. |
| `egressy.target-port` | TCP/UDP destination port inside that client. |
| `egressy.isolation-id` | Stable shared-bridge policy identity. |
| `egressy.isolation-allow` | Comma-separated destination and port allowances. |

A label without a valid network address or with a declared alternate default
route is non-compliant. Labels never alter container networking.

## Commands

```text
egressy [--config PATH] run
egressy [--config PATH] check
egressy [--config PATH] render-host-setup
egressy [--config PATH] render-gateway-firewall
```

The two render commands write policy to standard output and do not apply it.
