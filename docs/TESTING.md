# Testing and contributing to Egressy

These checks validate Egressy without mutating ordinary host routing or
firewall state.

## Safe local checks

The standard suite does not require applying host policy:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
python3 -m unittest external-probe/test_external_probe_service.py
```

Dashboard checks:

```sh
cd ui
npm ci
npm test
npm run build
npm run test:e2e
git diff --exit-code -- src/generated.ts dist/index.html
```

The production UI is generated into `ui/dist/index.html` and embedded by Rust.
Update `openapi/v2.json` and regenerate `ui/src/generated.ts` when the API
contract changes.

## Packaging checks

Provide placeholder paths and values as needed, then run:

```sh
docker compose config
docker build --pull -t egressy:test .
docker build -t egressy-external-probe:test external-probe
```

For multi-platform validation with Buildx:

```sh
docker buildx build --platform linux/amd64,linux/arm64 --output=type=oci,dest=/tmp/egressy.oci .
rm /tmp/egressy.oci
```

If the builder cannot execute foreign-architecture `RUN` steps, install QEMU
binfmt support or use native builders. CI publishes both architectures.

## Rendered-policy tests

Routing and firewall changes require unit tests for exact rules and
calculations. Trace:

- normal client egress and return traffic;
- gateway-originated DNS and dashboard replies;
- inbound forwarded-port traffic;
- startup before WireGuard;
- tunnel loss and recovery;
- gateway loss;
- forwarding target stop, removal, ambiguity, address change, and reuse.

Shell integration tests under `tests/` exercise nftables behavior. They require
Linux privileges and must run only in a disposable namespace or host:

```sh
sudo tests/nft-counter-preservation.sh
sudo tests/isolation-agent-nft.sh
tests/docker-proxy-acl.sh
```

Read each script before running it. Do not mutate a workstation or production
host's routing/firewall state as an ordinary test step.

## Live gateway acceptance

Use a disposable enrolled container and verify:

1. host and gateway rules exist before client traffic;
2. the WireGuard handshake is recent;
3. UDP and TCP DNS pass through the gateway;
4. HTTPS and the expected provider identity pass from the companion;
5. the client's public exit is the tunnel, not the host;
6. tunnel loss blocks client traffic;
7. gateway loss blocks client traffic;
8. recovery restores service without removing the kill switch;
9. a forwarding lease installs matching TCP/UDP state for one target;
10. target removal immediately removes DNAT;
11. API, dashboard, metrics, history, and events remain safe and bounded.

An external validation result is optional and advisory. A successful container
start, Compose run, image publish, dashboard load, or handshake alone is not
acceptance evidence.

## Secret scan

Before publication or release, inspect tracked files and the commits being
published for private keys, complete profiles, bearer tokens, webhook URLs,
internal hostnames, personal identifiers, and private infrastructure details.
Useful tools include `gitleaks`, `trufflehog`, and targeted `git grep` searches.
Never put a real key in a test fixture or command line.

## Pull requests

- Keep behavior compatible unless the change explicitly announces a break.
- Add unit and boundary tests for changed logic.
- Update public documentation and OpenAPI with behavior changes.
- Preserve disabled-by-default and advisory semantics for external validation.
- Preserve the v1 status contract unless a versioned migration is supplied.
- Do not include generated credentials, local operator notes, or AI contributor
  metadata.
