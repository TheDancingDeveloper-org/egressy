# Installing and upgrading Egressy

## Choose an image source

The supplied Dockerfile builds the Egressy image for `linux/amd64` and
`linux/arm64`. It contains the `egressy`, `egressy-probe`, and
`egressy-isolation-agent` binaries. After GitHub publication, the release
workflow publishes:

```text
ghcr.io/<owner>/<repository>:latest
ghcr.io/<owner>/<repository>:<commit-sha>
```

Use an immutable commit tag for real installations. `latest` is useful for
evaluation, not controlled rollouts.

To build locally:

```sh
docker build --pull -t egressy:local .
```

To compile without Docker, install Rust 1.97, a C compiler, OpenSSL development
files, nftables, iproute2, WireGuard tools, and openresolv, then run:

```sh
cargo build --locked --release --bins
```

The daemon is Linux-only; compile success on another OS does not make routing
operations supported there.

## Prepare networking

Pick an unused private IPv4 subnet. The examples use:

| Setting | Example |
|---|---|
| External Docker network | `vpn-egress` |
| Client subnet | `172.30.0.0/24` |
| Docker bridge gateway | `172.30.0.1` |
| Egressy gateway address | `172.30.0.2` |
| Host bridge | `br-vpn-egress` |
| Policy table | `200` |

Search the host's routes and Docker networks for overlap before creating it:

```sh
ip -4 route
docker network ls
docker network inspect $(docker network ls -q)
```

Edit `config/docker-network.sh` and `config/config.yaml` together if you change
the example values. Run the network helper once with root privileges.

## Supply WireGuard safely

Generate a conventional IPv4 full-tunnel WireGuard profile. Store it outside the checkout,
owned by the operator, with mode `0600`. The Compose example mounts it
read-only. Egressy validates it, writes a normalized `Table = off` copy to
`/run/egressy` tmpfs, and gives only that copy to `wg-quick`.

An orchestrator may instead mount a base64-encoded profile into
`wireguard.config_base64_path`. Base64 is transport encoding, not encryption;
protect it exactly like the raw profile.

## Install host policy

Run `check` and review `render-host-setup` as shown in the README. The output
must be installed on every boot before enrolled workloads can safely send
traffic. Integrate the reviewed script with the host's native service manager
or immutable host configuration. Do not run it from an unpinned remote URL.

After installation, verify:

```sh
ip rule show
ip route show table 200
sudo nft list table inet egressy_host
```

## Start and verify

Set `DOCKER_SOCKET_GID` to the numeric group owning the Docker socket and
`EGRESSY_WIREGUARD_CONFIG` to the protected profile path if Compose cannot infer
them in your environment:

```sh
export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
export EGRESSY_WIREGUARD_CONFIG=/protected/path/wg0.conf
docker compose up -d --build
docker compose ps
docker compose logs --no-log-prefix egressy
```

Do not paste unredacted logs if they could contain provider configuration.
Validate the host and gateway rules, recent handshake, probe state, and actual
client public exit. A successful Compose command alone is insufficient.

## Upgrades

1. Read release notes and compare configuration examples.
2. Pull or build an immutable new image.
3. Run `egressy check` with the current configuration.
4. Render and review host policy if network behavior changed.
5. Back up `/var/lib/egressy/egressy.sqlite3` while the service is stopped or
   with a SQLite-safe backup method.
6. Recreate the gateway and probe.
7. Repeat firewall, route, handshake, DNS, HTTPS, and client-exit checks.

## Rollback

Re-pin the previous immutable image and recreate the services. Avoid deleting
the external bridge: every enrolled client depends on its stable subnet and
addressing. If routing correctness is uncertain, stop enrolled workloads first,
then stop the gateway; the host fail-closed policy should remain installed
until clients are safely unenrolled.

## Uninstall

1. Remove `vpn-egress` from every client and recreate those containers.
2. Stop the gateway stack.
3. Remove only the host rules and table created for Egressy, using a reviewed
   inverse of the rendered host script.
4. Confirm no `ip rule` or nftables references remain.
5. Remove the external Docker network only after `docker network inspect`
   shows no attached endpoints.
6. Remove the data volume and protected profile only if their retention is no
   longer required.
