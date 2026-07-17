# Egressy

Egressy is a transparent Layer-3 VPN gateway for Docker. Containers in
independent Compose projects opt into a shared external bridge while retaining
their own network namespaces, port spaces, and service discovery. Their IPv4
traffic is policy-routed through a standalone Rust gateway and a conventional WireGuard VPN over
WireGuard—no HTTP or SOCKS proxy configuration required.

The project, crate, daemon, CLI, images, services, labels, environment
variables, metrics, firewall objects, and runtime paths all use the `egressy`
name.

> [!IMPORTANT]
> Egressy changes Linux routing and firewall policy. Use a disposable host or
> console-accessible test machine first. The current release supports one Linux
> Docker Engine host, one WireGuard tunnel, and IPv4-enrolled clients.

## Why Egressy

Many container VPN patterns place applications in the VPN container's network
namespace. That is simple for one stack, but it couples restarts, shares port
space, and becomes awkward across projects. Egressy uses a real router instead:

```text
application container
  -> Docker vpn-egress bridge
  -> host source-policy routing
  -> Egressy gateway
  -> fail-closed nftables policy
  -> WireGuard wg0
  -> WireGuard provider
```

Applications can use TCP, UDP, and ICMP through the tunnel while management
networks remain separate. See [networking](docs/NETWORKING.md) for the packet
paths and failure behavior.

## Features

- Transparent IPv4 routing for containers across Compose projects.
- Fail-closed host and gateway nftables policy.
- Router-owned WireGuard policy routes that preserve management traffic.
- Restricted, read-only Docker discovery and label-aware enrollment.
- UDP/TCP DNS forwarding to the tunnel resolver with leak rejection.
- Optional NAT-PMP with matching TCP/UDP allocation and dynamic DNAT to
  one compliant target.
- Bounded tunnel recovery with backoff and firewall preservation.
- Enrolled-path DNS, HTTPS, and provider-identity validation companion.
- Optional advisory internet-path validator for development and release tests.
- Versioned JSON API, OpenAPI contract, Prometheus metrics, SQLite history,
  optional OTLP export, and an embedded React dashboard.
- Optional notifications and audited shared-bridge isolation policy.
- `linux/amd64` and `linux/arm64` container builds.

## Requirements

- A Linux host with Docker Engine and Compose 2.33.1 or later.
- Root access for initial host routing setup.
- `/dev/net/tun`, `NET_ADMIN`, nftables, and policy-routing support.
- A supported IPv4 full-tunnel WireGuard profile. NAT-PMP is configured
  separately if the provider supports it.
- A dedicated, unused IPv4 subnet. Examples use `172.30.0.0/24`.

Rootless Docker, Docker Desktop, Kubernetes, IPv6 client enrollment, multiple
tunnels, and hostile multi-tenant isolation are not currently supported.

## Quick start

### 1. Clone and configure

```sh
git clone https://github.com/AusAgentSmith-org/egressy.git
cd egressy
cp config/config.example.yaml config/config.yaml
```

Review `config/config.yaml`. The network values must match the host bridge and
Compose definitions. Do not place a WireGuard profile in the repository.

### 2. Create the external bridge

The included helper creates the example network idempotently:

```sh
sudo ./config/docker-network.sh
```

Confirm that the subnet does not overlap LAN, VPN, container, or routed
networks before running it.

### 3. Validate and install host policy

Build the image, validate configuration, and inspect the generated host script:

```sh
docker build -t egressy:local -t ghcr.io/ausagentsmith-org/egressy:0.1.0 .
docker run --rm \
  -v "$PWD/config/config.yaml:/etc/egressy/config.yaml:ro" \
  egressy:local check

docker run --rm \
  -v "$PWD/config/config.yaml:/etc/egressy/config.yaml:ro" \
  egressy:local render-host-setup > /tmp/egressy-host-setup.sh
less /tmp/egressy-host-setup.sh
sudo sh /tmp/egressy-host-setup.sh
rm /tmp/egressy-host-setup.sh
```

The rendered script is idempotent, but it changes host routing and nftables.
Review it every time network values change.

### 4. Start the gateway

Store the provider profile outside the checkout with mode `0600`, then start
the example stack:

```sh
chmod 600 /protected/path/wg0.conf
EGRESSY_WIREGUARD_CONFIG=/protected/path/wg0.conf docker compose up -d --build
```

The dashboard binds to `http://127.0.0.1:8080` by default. Check:

```sh
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/api/v2/status
```

### 5. Enroll a client

Start from [config/client.compose.yaml](config/client.compose.yaml). The
important parts are:

```yaml
services:
  app:
    image: your-image
    labels:
      egressy.enabled: "true"
      egressy.usage-id: "example/app"
    networks:
      app:
        gw_priority: 0
      vpn-egress:
        gw_priority: 100
    dns:
      - 172.30.0.2

networks:
  app: {}
  vpn-egress:
    external: true
```

Recreate the client after changing networks or gateway priorities. Labels do
not change a running container's route. Verify from inside the client that its
default route and public exit are correct before enrolling real workloads.

## Port forwarding

A configured tunnel supplies at most one forwarded port. Exactly one enrolled client may
request it:

```yaml
labels:
  egressy.enabled: "true"
  egressy.port-forward: "true"
  egressy.target-port: "6881"
```

The `egressy` daemon requests matching TCP and UDP mappings, refreshes them
before expiry, and installs DNAT only while one unique compliant target exists.
A reported mapping is not proof of internet reachability; use the optional
external validator for that advisory check.

## Images and supported architectures

The Dockerfile builds all three Rust binaries. The included GitHub workflow
publishes multi-platform `linux/amd64` and `linux/arm64` images to GHCR. The
generic Woodpecker pipeline supports the same platforms when its registry
variables and secrets are configured. See [installation](docs/INSTALLATION.md)
for image tags, source builds, upgrades, and rollback.

## Dashboard demo

The GitHub Pages workflow publishes the real React dashboard with an in-browser
mock API. Demo mode never contacts a gateway and disables persistent settings
changes. Enable Pages with GitHub Actions as its source after publishing the
repository; the workflow reports the resulting URL.

## Security notes

- The dashboard has no built-in authentication. Keep it on localhost or a
  trusted management network behind your own access control.
- The `egressy` daemon does not mount the Docker socket. A restricted proxy
  exposes only the exact read operations needed for discovery.
- The profile is copied to protected tmpfs and normalized to `Table = off`
  before `wg-quick` runs.
- IPv6 client leak protection is not implemented. Do not attach enrolled
  workloads to an independent IPv6 egress path.
- Docker route-intent metadata is useful evidence, not proof of the effective
  route inside a container.

Read [security](docs/SECURITY.md) before exposing the dashboard, enabling
bridge isolation, or running an internet-facing validator.

## Documentation

- [Installation and upgrades](docs/INSTALLATION.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Networking and packet flow](docs/NETWORKING.md)
- [Operations](docs/OPERATIONS.md)
- [API and dashboard](docs/API.md)
- [External validation](docs/EXTERNAL_VALIDATION.md)
- [Security](docs/SECURITY.md)
- [Testing and contributing](docs/TESTING.md)

## Project status

Egressy is an early release intended for operators comfortable reviewing Linux
routing, nftables, and Docker networking. Back up configuration, pin immutable
image tags, and validate fail-closed behavior on your own kernel and Docker
version before relying on it.

## License

AGPL-3.0-only.
