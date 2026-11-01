# Egressy networking and packet flow

This document describes the default example values. If you change them, update
the Docker network, YAML, Compose addresses, host policy, and verification
commands together.

| Component | Example |
|---|---|
| Enrolled network | `vpn-egress` |
| Subnet | `172.30.0.0/24` |
| Docker bridge gateway | `172.30.0.1` |
| Egressy address | `172.30.0.2` |
| Probe address | `172.30.0.5` |
| Host bridge | `br-vpn-egress` |
| Policy table | `200` |
| WireGuard interface | `wg0` |

## Client egress

1. Compose selects `vpn-egress` as the client's IPv4 default route.
2. The packet enters `br-vpn-egress` with a source in `172.30.0.0/24`.
3. A host source rule selects table 200.
4. Table 200 routes through `172.30.0.2` on the same bridge.
5. The gateway's priority-100 source rule selects its table 200.
6. Gateway table 200 defaults through `wg0`.
7. Gateway nftables permits the enrolled-subnet-to-tunnel path and
   masquerades it on `wg0`.

Both policy-routing hops are required. The client is directly connected to the
host bridge, so attaching the gateway container alone does not make it the
router.

## Return traffic

WireGuard decapsulates the response into `wg0`. Connection tracking reverses
the tunnel masquerade, the gateway routes the enrolled destination to
`vpn-egress`, and the host bridge delivers it to the client's veth. Established
and related state is accepted; unsolicited forwarding is rejected unless a
current DNAT rule explicitly permits it.

## Gateway-originated traffic

The gateway has a normal Docker uplink for management tasks and an enrolled
network address for DNS and dashboard replies. Policy order matters:

```text
priority 90: from 172.30.0.2 lookup main
priority 100: from 172.30.0.0/24 lookup 200
```

The priority-90 exception keeps replies sourced from the gateway address on the
connected/main path. Without it, DNS and dashboard replies can be sent into
`wg0`. Other enrolled-subnet sources use the tunnel table. Traffic sourced from
the uplink address continues to use `main`.

WireGuard remains `Table = off`; automatic `wg-quick` routes must not replace
the gateway's management default route.

## DNS

Clients send UDP or TCP DNS to `172.30.0.2:53`. Egressy forwards to the provider
resolver through the tunnel, bounds concurrency and timeouts, and retries a
truncated UDP answer over TCP. Gateway firewall policy rejects enrolled plain
DNS sent to other destinations. Encrypted DNS inside arbitrary HTTPS traffic is
not intercepted.

### Local zones

With `dns.local_zones.enabled`, single-label names matching a running container
on the enrolled bridge are answered from Docker discovery rather than forwarded.
Without it, enrolled clients can resolve public names only, which makes Egressy
unusable for any stack whose containers address each other by service name.

Three properties make this safe:

- **Single-label only.** A container named `api` cannot shadow
  `api.example.com`; anything with a dot is forwarded untouched.
- **Bridge addresses only.** Answers come from discovery and are always
  addresses on the enrolled bridge, so this cannot point a client elsewhere.
- **Nothing leaks.** A name we own is never forwarded. `AAAA` and other types
  for a known name are answered `NOERROR` with no records rather than sent
  upstream, so the provider resolver never learns internal names exist.

Answers are served before admission control, since they need no upstream
capacity, and carry a short TTL because they track container lifecycle.

## Fail-closed layers

### Host

The host policy permits the intended bridge-to-gateway path and rejects
enrolled traffic that would otherwise use Docker's normal uplink/NAT. If the
gateway container disappears, the source rule and reject policy prevent silent
fallback.

That protection only holds while the host policy is actually installed, and it
is ordinary host state that anything rebuilding netfilter — a Docker daemon
restart, for instance — will remove. `render-host-setup` installs it, but a
one-shot cannot maintain it: after the state is cleared, enrolled traffic misses
the source rule, falls through to the main routing table and leaves by the
host's default route, with nothing rejecting it.

The host-network agent therefore **owns** this policy rather than assuming it.
It reads the desired policy from `GET /api/v2/host-policy`, compares it against
`ip rule`, the policy routing table and the `inet egressy_host` table on every
interval, and reinstalls whatever is absent. Drift is logged at warn level
naming exactly which parts were missing. Set `EGRESSY_MANAGE_HOST_POLICY=false`
to opt out and manage the state yourself.

That endpoint is on the same gateway API as the isolation policy, so
`EGRESSY_HOST_POLICY_URL` defaults to `EGRESSY_ISOLATION_POLICY_URL` with the
host-policy path: publish the API on a different port and overriding the
isolation URL alone is enough. Set it explicitly only if the two genuinely
differ.

If the agent cannot reach that endpoint it warns on each interval and, after a
sustained run of failures, escalates to an error naming the URL. Take that
seriously — it means nothing is maintaining the fail-closed state, and it is not
otherwise visible: bridge isolation keeps working and the gateway keeps
reporting a healthy tunnel while enrolled traffic is one netfilter rebuild away
from leaving on the host's default route.

### Gateway

The gateway table is installed before WireGuard starts. Its forward chain
permits enrolled traffic only toward `wg0`, return state from `wg0`, DNS and
management input, and active forwarding state. Other enrolled forwarding is
rejected. If `wg0` disappears or table 200 lacks a route, traffic remains
blocked while recovery runs.

Never disable gateway firewall reconciliation while Egressy manages the tunnel;
configuration validation rejects that combination.

## NAT-PMP and inbound forwarding

Egressy requests equal TCP and UDP external ports from the provider NAT-PMP
gateway. A mapping is accepted only when the response version, operation,
result, internal port, external port, epoch, and lease are valid and both
protocols agree.

For one unique compliant target, nftables installs DNAT from `wg0` to the
target address and port and permits the corresponding forward/return state.
Target loss, ambiguity, invalid labels, route-intent mismatch, tunnel recovery,
or lease loss removes DNAT. Provider lease refresh occurs before expiry.

The optional external validator tests TCP reachability only. UDP reachability
and application-level correctness need separate tests.

## Management access to enrolled applications

An application's management network must not become its preferred default
route. If a local UI must remain reachable, use a narrowly scoped proxy or
published helper attached to both the management and enrolled networks. The
application itself should retain the enrolled default route. Review any such
proxy carefully: it is an intentional management path, not a general egress
path.

## Shared-bridge isolation

Docker bridge peers can communicate directly without entering the gateway
namespace. The optional isolation agent applies host bridge-family policy from
a complete inventory and explicit allowances. It is disabled by default and
does not provide hostile Layer-2 tenant isolation.

## IPv6

IPv6 routing is opt-in through `network.ipv6`, and it is off by default. In both
modes, the host and gateway policies reject enrolled IPv6 that would leave any
other way than through the tunnel.

| | `network.ipv6` off | `network.ipv6` on |
|---|---|---|
| Enrolled IPv6 egress | Rejected on the host; dropped on the gateway | Through `wg0`, masqueraded to the profile's IPv6 address |
| Tunnel or route loss | Rejected | Unreachable or rejected |
| Host policy schema | 1 | 2 |

### Enabling

1. Use a profile with an IPv6 `Address` and `::/0` in `AllowedIPs`. Otherwise
   Egressy logs a warning and enrolled IPv6 stays unreachable.
2. Recreate the Docker network with `EGRESSY_IPV6=1 config/docker-network.sh`.
   Docker cannot add IPv6 to an existing network, so enrolled containers must be
   recreated as well.
3. Set `network.ipv6.enabled: true`, and start with
   `docker compose -f compose.yaml -f compose.ipv6.yaml up -d`.
4. Upgrade the host agent at the same time. An older agent refuses schema 2
   rather than leaving client IPv6 without host policy, and it logs that failure.
5. If the host is not using the agent, rerun `render-host-setup`.

The script enables `net.ipv6.conf.all.forwarding` on the host, as Docker itself
does for IPv6 networks. A host uplink that learns its default route from router
advertisements needs `accept_ra=2` on that interface, or it loses that route.

### Packet path

The path mirrors IPv4: a client's default route points at the Docker bridge, the
host's priority-100 source rule selects table 200, and table 200 routes through
the gateway's `fd30:172:30::2` address. On the gateway, priority 90 keeps the
gateway's own address on `main`, priority 100 selects table 200, and table 200
defaults to `wg0`. The tunnel provides one address, so the gateway masquerades
enrolled IPv6 to it, and clients can use a private `fd00::/8` subnet.

### Fail-closed layers

- **Host kill switch.** Every IPv6 packet forwarded from the enrolled bridge to
  another interface is rejected, whatever its source, and IPv6 forwarded toward
  the bridge from another interface is dropped. The rule is rendered in both
  modes, and the agent replaces a table that lacks the current rule.
- **Gateway firewall.** The forward chain's drop policy permits enrolled IPv6 only
  toward `wg0` and return state from it. Plain IPv6 DNS is rejected, and new IPv6
  arriving on `wg0` is dropped.
- **Unreachable routes.** Table 200 on the host and gateway ends with an
  `unreachable` default, so a lookup that loses its tunnel or gateway route does
  not fall through to the main table, even if a firewall table was removed.
- **Compliance.** A client whose IPv6 address is off the configured subnet, or
  whose declared IPv6 default is another network, is reported as non-compliant.
  Docker metadata does not attest the route inside the container.

### Limits

- **Inbound.** NAT-PMP maps IPv4 only, so forwarded ports stay IPv4 and unsolicited
  inbound IPv6 is dropped. Publishing a client's port over IPv6 through Docker
  does not work, because the host kill switch blocks it.
- **DNS.** Clients keep using the gateway's IPv4 address as their resolver. That
  transport returns `AAAA` answers from the provider resolver, and upstream IPv6
  resolvers remain unused.
- **Bridge isolation.** `IsolationPolicy.ipv6_subnet` extends audit and enforce
  modes to IPv6 peer traffic. Allowances remain IPv4, so peer-to-peer IPv6 is not
  allowed in enforce mode.
- **Startup.** The kill switch exists only once the host policy is installed. A
  client that sends IPv6 before that, such as one that starts ahead of the agent
  after a reboot, can leave by the host's IPv6 default route. IPv4 has the same
  window. On a host with an IPv6 uplink, install the host policy at boot, before
  Docker starts, by running the `render-host-setup` output or an equivalent.
- **MTU.** `config/docker-network.sh` sets the network's MTU to 1420, WireGuard's
  default. With a larger bridge MTU, TCP still adapts through Packet Too Big, but
  oversized UDP and ICMP can be lost. A profile with a lower `MTU` needs the same
  value on the network.
- **External validation.** The probe still validates IPv4 only. Verify IPv6 by hand
  with the commands below.

### Rollback

Set `network.ipv6.enabled: false` and drop the overlay. The agent replaces the
host table, so enrolled IPv6 is rejected right away. The IPv6 rule and routes it
leaves behind are inert, and you can remove them with
`ip -6 rule del priority 100 from fd30:172:30::/64 lookup 200` and
`ip -6 route flush table 200`.

## Verification

Use a disposable client and inspect all layers:

```sh
ip rule show
ip route show table 200
sudo nft list table inet egressy_host

docker exec egressy ip rule show
docker exec egressy ip route show table 200
docker exec egressy nft list table inet egressy
docker exec egressy wg show wg0 latest-handshakes

docker exec disposable-client ip -4 route
docker exec disposable-client getent hosts example.com
docker exec disposable-client wget -qO- https://ifconfig.co/ip

# With network.ipv6 enabled:
ip -6 rule show
ip -6 route show table 200
docker exec egressy ip -6 rule show
docker exec egressy ip -6 route show table 200
docker exec disposable-client ip -6 route
docker exec disposable-client wget -6 -qO- https://ifconfig.co/ip
```

Confirm the client exit differs from the host's ordinary exit without placing
either raw address in public logs. Then test tunnel loss and gateway loss; the
client must lose egress rather than fall back.
