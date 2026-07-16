# Egressy contributor guide

This guide applies to automated and human contributors working in this
repository.

## Product invariants

Egressy is a Linux-only transparent Layer-3 Docker VPN gateway. It routes
independently networked containers through WireGuard; it is not an HTTP or
SOCKS proxy and must not be converted to a shared-network-namespace model.

The product and project are named **Egressy**. Use `egressy` for the daemon,
CLI, crate, container service, labels, environment variables, metrics, and
filesystem or firewall identifiers.

1. Enrolled IPv4 traffic exits through `wg0` or fails closed. It must never
   fall back to Docker's normal host NAT path.
2. Install the gateway nftables policy before bringing up WireGuard.
3. Keep WireGuard `Table = off`; the `egressy` daemon owns source-policy routing.
4. Preserve the priority-90 management exception and priority-100 enrolled
   subnet rule described in `docs/NETWORKING.md`.
5. Host and gateway subnet, gateway address, bridge name, and policy table
   must match.
6. Docker discovery is read-only. Do not start, stop, attach, restart, or
   reconfigure application containers.
7. Labels describe desired policy and monitoring intent; they do not prove or
   change a running container's effective route.
8. A tunnel supplies one forwarded port. At most one compliant container may
   opt into forwarding.
9. Never log, return, commit, or bake credentials, WireGuard private keys, or
   complete WireGuard profiles into an image.
10. Keep decoded WireGuard profiles on tmpfs with mode `0600`.
11. Client enrollment is IPv4-only. Do not claim IPv6 leak protection.

## Source map

- `src/runtime.rs`: lifecycle, routing, reconciliation, traffic, and NAT-PMP.
- `src/host.rs`: rendered host and gateway nftables/routing policy.
- `src/docker.rs`: read-only Docker discovery.
- `src/natpmp.rs`: RFC 6886 mapping logic.
- `src/dns.rs`: bounded UDP/TCP DNS forwarding.
- `src/domain.rs`, `src/control.rs`: canonical state and transitions.
- `src/enforcement.rs`: serialized nftables ownership.
- `src/state.rs`, `src/web.rs`: compatibility API and dashboard server.
- `src/bin/egressy-probe.rs`: enrolled-path and optional external validation.
- `external-probe/`: reference public validation service.
- `ui/`: the React dashboard embedded in the application and used by the
  static demo.

## Change rules

- For routing or firewall changes, test rendered rules and trace client
  egress, return, gateway-originated, and inbound-forward traffic. Check
  startup, tunnel loss, gateway loss, and target removal.
- Never infer compliance from a label alone. A labelled container without a
  valid egress-network address is non-compliant.
- Preserve NAT-PMP byte-order and response tests, bounded retries, matching
  TCP/UDP ports, early refresh, and immediate DNAT removal when no unique
  compliant target exists.
- Treat `src/state.rs` and `openapi/v2.json` as external contracts. Test
  serialization and handlers when semantics change. Escape all
  container-controlled HTML strings.
- `/healthz` represents tunnel health. Advisory checks must not affect
  protection, readiness, or recovery.
- The external validation feature stays disabled by default and advisory. The
  Rust client and Python service duplicate their request shape, reason codes,
  and IP classification; update and test both sides together.
- Never let the external service connect to an arbitrary requested address.
  Its reachability test may target only the verified caller source.
- Do not mutate host routing or firewall state in ordinary local tests.

## Required validation

Before a Rust commit:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

When relevant, also run:

```sh
python3 -m unittest external-probe/test_external_probe_service.py
(cd ui && npm ci && npm test && npm run build && npm run test:e2e)
docker compose config
docker build .
```

Do not commit credentials or add AI co-author metadata.
