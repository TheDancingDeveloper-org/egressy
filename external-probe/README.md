# Egressy external validation service

This directory contains a small reference service for validating an Egressy
gateway from outside its VPN path. It is primarily a development and release
validation tool. Running it continuously is optional, disabled by default, and
never changes protection, readiness, or recovery decisions.

The service exposes:

- `POST /api/v1/check`
- `GET /livez`

It verifies bearer authentication, request freshness, replay protection,
public caller classification, an optional claimed-address match, and optional
TCP reachability to the caller's active forwarded port. It does not perform
DNS or provider-identity checks and never returns observed public addresses or
reflected request data.

## Local validation

```sh
cd external-probe
python3 -m unittest test_external_probe_service.py
```

For a local process:

```sh
export EXTERNAL_PROBE_TOKEN=replace-with-a-development-token
export EXTERNAL_PROBE_LISTEN_PORT=8443
python3 external_probe_service.py
```

The service also has a minimal container image:

```sh
docker build -t egressy-external-probe:dev external-probe
```

## Configuration

- `EXTERNAL_PROBE_TOKEN` or `EXTERNAL_PROBE_TOKEN_FILE` is required.
- `EXTERNAL_PROBE_LISTEN_HOST` defaults to `0.0.0.0`.
- `EXTERNAL_PROBE_LISTEN_PORT` defaults to `443`.
- `EXTERNAL_PROBE_TLS_CERT` and `EXTERNAL_PROBE_TLS_KEY` are optional together.
- `EXTERNAL_PROBE_FRESHNESS_SECONDS` defaults to `60`.
- `EXTERNAL_PROBE_CONNECT_TIMEOUT_SECONDS` defaults to `5`.
- `EXTERNAL_PROBE_RATE_LIMIT_REQUESTS` defaults to `30`.
- `EXTERNAL_PROBE_RATE_LIMIT_WINDOW_SECONDS` defaults to `60`.
- `EXTERNAL_PROBE_BODY_LIMIT_BYTES` defaults to `4096`.
- `EXTERNAL_PROBE_TRUSTED_PROXY_CIDRS` defaults to loopback only.

For an internet-path integration test, place the service behind HTTPS on a
host that is independent of the gateway. If a reverse proxy terminates TLS,
bind the Python listener to a private interface, preserve the direct caller
address, and trust only the proxy's exact address. Never trust an entire
container or private network merely for convenience.

The public hostname must resolve directly to the validation host. A CDN or
forward proxy changes the observed source and makes the address-match result
meaningless. Expose only the HTTPS endpoint, store the shared token outside
the repository, and rotate any token that reaches logs or source control.

See [external validation](../docs/EXTERNAL_VALIDATION.md) for the protocol and
safe production-style test procedure.
