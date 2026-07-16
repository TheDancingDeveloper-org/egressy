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

## Fail-closed layers

### Host

The host policy permits the intended bridge-to-gateway path and rejects
enrolled traffic that would otherwise use Docker's normal uplink/NAT. If the
gateway container disappears, the source rule and reject policy prevent silent
fallback.

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

The host client-source rule, bridge enrollment, and leak protections are IPv4
only. A WireGuard profile containing IPv6 does not extend these controls to
clients. Do not give enrolled clients a separate IPv6 default route.

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
```

Confirm the client exit differs from the host's ordinary exit without placing
either raw address in public logs. Then test tunnel loss and gateway loss; the
client must lose egress rather than fall back.
