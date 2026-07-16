# Operating Egressy

## Routine health check

Start with application state:

```sh
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/v2/status
docker compose ps
```

`/livez` confirms the HTTP process. `/readyz` reports canonical readiness.
`/healthz` retains the v1 tunnel-health meaning. Inspect `protection` and
`availability` separately in v2 state; a usable tunnel is not the same claim as
verified fail-closed enforcement.

Then inspect the actual data plane:

```sh
ip rule show
ip route show table 200
sudo nft list table inet egressy_host
docker exec egressy ip rule show
docker exec egressy ip route show table 200
docker exec egressy nft list table inet egressy
docker exec egressy wg show wg0 latest-handshakes
```

Do not paste `wg showconf`, `wg-quick strip`, environment dumps, Docker inspect
output, or complete profiles into issues or logs.

## Enroll a workload

1. Confirm its image supports the expected DNS and application behavior.
2. Add the external egress network and keep any management network.
3. Make `vpn-egress` the declared IPv4 default with Compose `gw_priority`.
4. Set DNS to the Egressy gateway.
5. Add `egressy.enabled=true` and a stable `egressy.usage-id`.
6. Add forwarding labels only if this is the sole intended target.
7. Recreate the container.
8. Confirm it appears compliant in `/api/v2/status`.
9. Enter the container and verify its effective default route.
10. Resolve a name and confirm its public exit through the tunnel.
11. Test local management access independently, if applicable.

Docker metadata can report route intent but cannot prove the route inside the
container. Always perform the in-container check.

To unenroll, remove labels and the external network, restore the intended DNS
and default route, recreate the container, and confirm its old address no
longer appears in firewall counters or forwarding state.

## Port-forward operations

The dashboard and v2 API expose the requested target, external port, lease
times, phase, installed-DNAT state, and optional external verification. Treat
`dnat_installed=true` as kernel policy evidence, not internet reachability.

If forwarding becomes unavailable:

- confirm exactly one running compliant target has valid labels;
- confirm its target port is listening on the enrolled address;
- inspect the NAT-PMP reason code without printing secrets;
- check the provider profile was generated with forwarding enabled;
- verify matching TCP and UDP leases;
- use the external validator only after local routing and listener checks pass.

Removing, stopping, or making the target non-compliant must remove DNAT. If it
does not, stop the gateway and collect safe rule output for a bug report.

## Backups

Back up the operator-owned YAML, orchestration definitions, and the SQLite data
volume. Never put the WireGuard profile or notification credentials in an
unencrypted repository backup. Use a SQLite-safe online backup or stop Egressy
before copying the database and preserve restrictive file permissions.

Restore configuration and data before starting the service, validate YAML,
then verify routes, rules, handshake, client egress, and history queries.

## Secret rotation

For the WireGuard profile:

1. generate a new provider profile;
2. store it in a new protected file;
3. run configuration validation;
4. recreate the gateway;
5. verify firewall ownership before handshake and client egress;
6. remove the old profile securely after rollback confidence is sufficient.

Rotate external-validator, probe, notification, and OTLP credentials at both
ends. If any secret appears in chat, logs, shell history, or Git, rotate it
even if access was brief.

## Troubleshooting

### Gateway restarts during WireGuard startup

Check that the mounted profile is readable, a regular file, and protected. The
runtime copy must be on `/run/egressy` tmpfs. Confirm the profile does not rely
on unsupported hooks or tools. Redact all key material from logs.

### Client has no DNS

Confirm the client nameserver is the gateway, the gateway listens on port 53,
priority-90 management replies use `main`, and the provider resolver is
reachable through `wg0`. Both UDP and TCP DNS should pass the companion probe.

### Client uses the host's ordinary public exit

Treat this as a critical failure. Stop the client. Check the effective default
route, host source rule, table-200 route, host reject table, gateway priority
rules, gateway table-200 default, and `wg0`. Do not resume until tunnel loss and
gateway loss both fail closed in a disposable client test.

### Dashboard loads but health fails

The management listener intentionally remains reachable when the tunnel is
unhealthy. Inspect the failed critical check and safe reason code. Do not infer
data-plane health from an HTTP 200 on the dashboard.

### Docker discovery is stale

Check the internal `docker-control` network, HAProxy health and ACLs, socket
group ID, and only the two allowed read endpoints. Do not “fix” discovery by
giving Egressy unrestricted socket access.

### History is unavailable

Current routing can remain operational when SQLite fails. Check volume
ownership, free space, database integrity, and the `history.persistence`
advisory check. Restore from backup if needed.

### Isolation policy blocks a dependency

Change the agent to `audit`, inspect the complete participant and allowance
inventory, update labels, recreate affected clients if networking changed, and
observe counters before returning to `enforce`. Disabling isolation does not
change the core gateway kill switch.

## Incident evidence

Useful safe evidence includes image digest, application version, kernel and
Docker versions, redacted config with addresses generalized, `ip rule`, the
dedicated route table, relevant nftables tables, health JSON, and bounded logs.
Never include keys, profiles, bearer tokens, webhook URLs, provider account
identifiers, environment dumps, or observed public IPs from the external
validator.
