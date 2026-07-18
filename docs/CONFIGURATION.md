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
| `source` | Explicitly selects `mounted` or `gui_managed`. |
| `config_path` | Protected raw profile path. |
| `config_base64_path` | Optional protected base64 profile path. |
| `manage` | Whether Egressy starts and stops the interface. |
| `profile_database_path` | GUI-managed encrypted revision database. |
| `storage_key_path` | Protected external 32-byte base64 AEAD key. |
| `admin_token_path` | Protected bearer token for profile mutation. |
| `trusted_origins` | Reviewed reverse-proxy browser origins. |

The normal managed mode rewrites a tmpfs copy with `Table = off`. Do not add
PostUp/PostDown commands that compete with Egressy firewall ownership.

### `port_forwarding`

`port_forwarding.backend` is `disabled` by default. `nat_pmp` enables the
optional backend. `gateway` is the provider service address,
`refresh_seconds` is the renewal interval, and `lifetime_seconds` is the
requested lease. Refresh must be shorter than lifetime. Defaults are tuned for
the configured NAT-PMP lease. `max_leases` bounds concurrent leases from 1 to
5. `primary_usage_id` projects one designated lease into the backward-compatible
singular API field; when unset, a sole lease is selected automatically.

### `dns`

`enabled`, `listen`, and `upstream.source` control the bounded UDP/TCP forwarder.
Use `profile` to derive IPv4 DNS from the profile or `explicit` with
`upstream.addresses` for reviewed overrides.
`timeout_ms` limits each upstream attempt and `max_concurrent_queries` bounds
load. `udp_attempts` retries transient UDP loss before falling back to TCP to
the same in-tunnel resolver. `failure_threshold` and `success_threshold`
provide global check hysteresis while individual failures remain logged.
Enrolled clients should use only the gateway listener; firewall policy rejects
other plain DNS destinations.

### `probe` and `validation.identity`

The internal companion URL is polled at `interval_seconds`. `token_path` may
protect the local status exchange. Optional identity validation uses bounded
`plain_text_contains`, allowlisted `json_string_contains`, or allowlisted
`json_boolean` matchers and remains advisory.

The companion itself is configured with `EGRESSY_PROBE_*` variables in
Compose, including DNS address, identity URL, expected identity, token, and
optional external validation settings.

### `external_probe`

This daemon section gates ingestion and staleness reporting. It is disabled by
default. The companion performs outbound validation using its
`EGRESSY_EXTERNAL_PROBE_*` environment variables. Keep the settings aligned.
The endpoint must use HTTPS, a DNS hostname, and a public non-tailnet address.
The default external interval is 10 seconds with a 5-second timeout, while the
daemon polls the companion every 10 seconds. With NAT-PMP enabled, their
combined worst-case propagation time must remain shorter than the lease refresh
interval so every renewal can receive correlated evidence.

### `persistence`

`enabled` controls SQLite history. `path` selects the database,
`retention_days` bounds age, `bucket_seconds` controls aggregation resolution,
and `writer_capacity` bounds the asynchronous queue. Database failure degrades
history only; it does not relax routing protection.
Per-workload bandwidth history is stored in the same SQLite buckets and follows
the configured retention and bucket lifecycle.

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
| `egressy.port-forward=true` | Requests an independent forwarding lease. |
| `egressy.target-port` | Unique NAT-PMP lease key and TCP/UDP destination port inside that client. |
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
