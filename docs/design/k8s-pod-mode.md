# Design: Kubernetes pod mode

Status: **superseded** by Kubernetes pod discovery on the existing bridge
(`docs/KUBERNETES.md`, WI-3228). Kept for its test ideas. Was: **proposal, not implemented.** Work item WI-2964. Nothing here changes
the running Docker gateway (`personal-egressd`), and nothing here may be
deployed until the open questions at the end are answered.

## Why

The *arr download clients (qbittorrent, rusttorrent, sonarr, radarr, prowlarr),
and later crw and searxng, are due to move from Node B to the k3s cluster. Today
their kill switch is host state on Node B:

- the `vpn-egress` bridge;
- policy table 200;
- the gateway's `inet egressy` table;
- the host agent's `inet egressy_host` table.

None of that exists on a k3s node. The Phase 0 inventory (§3) concludes egressy
needs a pod-netns design, and this document specifies it.

## Scope and the shared-netns invariant

`AGENTS.md` says egressy is a transparent L3 gateway and "must not be converted
to a shared-network-namespace model". Pod mode is a **second, additive mode**:

- it is selected by `mode: pod` in the config (default `gateway`);
- the Docker gateway mode keeps every existing invariant and code path;
- pod mode has its own invariants, listed below. Neither mode's guarantees are
  weakened to suit the other.

Amending `AGENTS.md` this way is an operator decision (open question 1). It must
be agreed before any code lands.

In pod mode egressy is not a router. There is no forwarding, no masquerade, no
second policy-routing hop and no Docker discovery. Each pod's network namespace
is the "enrolled network". Every container in the pod is enrolled because it
shares that namespace.

### Pod-mode invariants

1. The nftables kill switch is in place in the pod netns **before** any
   container except the init container runs. The init container never removes
   it, and nothing else does either: a sidecar restart rebuilds the routes and
   the tunnel only. This is the PR #40/#41 lesson ("install the kill switch
   before forwarding") applied to the pod.
2. Non-local traffic leaves the pod only by `wg0`, apart from the explicit,
   enumerated exceptions below. Anything else is dropped, whatever the routing
   table says.
3. All IPv6 is dropped in the pod (no IPv6 tunnel routing in v1). This is a
   real, testable leak guarantee for pod mode, unlike the gateway mode's
   IPv4-only claim.
4. DNS from app containers goes only to the in-pod resolver (`127.0.0.1:53`).
   Its upstream is the provider resolver through `wg0`, or CoreDNS for
   `*.cluster.local` names only.
5. WireGuard keeps `Table = off`. Egressy owns the routes.
6. No credentials are logged. The profile is mounted from a Secret, read once,
   and rendered to a `0600` tmpfs file.

## 1. Pod topology

```text
Pod "arr-dl"  (ns media, PSA privileged, pinned to one node)
 │  shared pod netns: eth0 (flannel, 10.42.x.y), lo, wg0
 │
 ├─ initContainer  egressy-init        egressy pod-init
 │     caps NET_ADMIN; runs to completion
 │     - nft -f: table inet egressy_pod (kill switch, below)
 │     - sysctl check: src_valid_mark=1 (pod sysctl), disable_ipv6=1
 │     - fwmark rules for inbound replies (§3)
 │     - exits 0 only after reading the table back and checking it
 │
 ├─ initContainer  egressy  (restartPolicy: Always = native sidecar)
 │     egressy pod-run; caps NET_ADMIN, NET_RAW
 │     - wg-quick up wg0 (Table = off) from the Secret profile
 │     - ip route replace default dev wg0 table 200; rule priority 100
 │     - in-pod DNS on 127.0.0.1:53 (existing dns.rs forwarder)
 │     - NAT-PMP lease → writes /run/egressy/forwarded-port (emptyDir)
 │     - startupProbe /readyz: wg0 handshake < 180 s
 │     - livenessProbe /livez: process + table present (NOT tunnel health)
 │     - dashboard/API on :8080 (pod IP, cluster-internal)
 │
 ├─ qbittorrent, rusttorrent, sonarr, radarr, prowlarr  (no added caps)
 └─ port-sync  (reads /run/egressy/forwarded-port, sets the client's port on localhost)
```

**Why the init container installs the switch, not the sidecar.** Kubernetes runs
init containers in order and starts app containers only after every regular
init container has exited 0. A native sidecar (an init container with
`restartPolicy: Always`) also starts before the app containers, but its
"started" gate is only its startupProbe. If the sidecar installed the switch, a
crash between process start and `nft -f` could pass a weak probe. A separate
run-to-completion init container makes the order structural:

1. `egressy-init` applies the table, verifies it and exits 0.
2. Only then is the `egressy` sidecar started, and its startupProbe gates the
   app containers on a live tunnel.

### Kill-switch table (`inet egressy_pod`)

The table is rendered by `egressy render-pod-firewall`, which is unit-testable
in the same way as `render_gateway_firewall`. Placeholders below are config
values.

```nft
table inet egressy_pod {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    meta nfproto ipv6 drop                       # invariant 3
    oifname "wg0" accept                         # everything tunnelled
    # WireGuard transport to the provider endpoint only, marked by wg (fwmark)
    oifname "eth0" ip daddr {endpoint} udp dport {endpoint_port} meta mark {wg_fwmark} accept
    # CoreDNS, for *.cluster.local forwarding by the in-pod resolver only
    oifname "eth0" ip daddr {cluster_dns} meta skuid 0 udp dport 53 accept
    oifname "eth0" ip daddr {cluster_dns} meta skuid 0 tcp dport 53 accept
    # replies to inbound connections (Service / probes), see §3
    oifname "eth0" ct state established,related ct direction reply accept
    # optional, explicit: NFS to the media server, if mounts are not node-level
    {extra_allow}
    counter reject with icmpx type admin-prohibited
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    meta nfproto ipv6 drop
    ct state established,related accept
    iifname "eth0" tcp dport { {inbound_ports} } ct mark set {inbound_mark} accept
    iifname "wg0" udp sport 5351 ip saddr {natpmp_gw} accept
    iifname "wg0" {forwarded_port_rules}        # DNAT-free: the client listens on the port
  }
}
```

Notes:

- No `forward` chain is needed because nothing forwards. `ip_forward` stays `0`
  in the pod, a stronger setting than the gateway mode needs.
- The CoreDNS exception is tied to `skuid 0` (the egressy sidecar's UID). App
  containers run as non-root UIDs, so they cannot use it as a DNS side channel.
  This needs app images to run non-root (open question 6). Without that, the
  rule falls back to allowing only `cluster.local` queries, filtered by the
  in-pod resolver rather than by nftables.
- Pod-to-pod traffic inside the cluster (sonarr → indexarr, prowlarr → indexarr)
  goes out by `eth0`, so it needs an explicit `{extra_allow}` entry per
  destination Service CIDR address and port. The default is none. The inventory
  draft's blanket "cluster CIDR 10.42/16, 10.43/16" allow is rejected: it would
  let any app reach any in-cluster proxy and leave by the node.
- The WireGuard endpoint is checked by IP and port, plus the fwmark that
  `wg-quick` sets on its own transport socket. An app process sending UDP to the
  endpoint IP from an unmarked socket is dropped. Hostname endpoints are
  resolved by `pod-init` through CoreDNS before the table is installed, and the
  table is regenerated on profile change (§4).

### Tunnel loss (fail closed)

The table does not depend on `wg0` existing:

- If `wg0` goes down or is deleted, the default route in table 200 is gone.
  Packets then hit main's default route via `eth0` and the output chain drops
  them.
- To make this explicit, `pod-init` also installs `unreachable default table 200
  metric 4294967295`, so a missing tunnel route fails at routing ("network
  unreachable" to the app) rather than only at the filter. This mirrors the
  IPv6 work's unreachable defaults.
- The sidecar's existing recovery state machine (`recovery.rs`) re-handshakes and
  re-creates `wg0`. `/readyz` goes false, so the pod drops out of Service
  endpoints if that is wanted. `/livez` stays true, because a liveness restart
  cannot fix a provider outage and restart storms are noise.

### Sidecar restart

When kubelet restarts the native sidecar, which is allowed while app containers
keep running:

- The netns, and with it `inet egressy_pod`, survives. The netns belongs to the
  pause container, not to the sidecar.
- `wg0` also survives the process exit, because it is a kernel interface. On
  start, `pod-run` takes ownership: it runs `wg syncconf` if the interface
  exists, otherwise `wg-quick up`.
- Between exit and recovery, traffic either still flows through the existing
  `wg0` or hits the unreachable default and the output drop. It never leaks.
- `pod-run` **verifies** `inet egressy_pod` on start and every reconcile
  interval: it lists the table and compares it with the render. If the table is
  missing or different, the sidecar does not reinstall it from a running pod.
  It flags `kill_switch_missing`, goes not-ready and exits non-zero.

That last behaviour is a deliberate choice. The table changes only through init.
A missing table means something outside egressy changed the netns, so the safe
response is to recreate the pod. This needs a `kubectl delete pod` from an
operator or a small controller (open question 4). Kubernetes does not re-run
init containers when a sidecar restarts.

The alternative is for the sidecar to reinstall the table, which is what the host
agent does today. The trade-offs are listed in open question 4.

## 2. Requirements

### Capabilities

| Container | Caps | Why |
|---|---|---|
| egressy-init | `NET_ADMIN` | nft, ip rule/route, sysctl writes the runtime allows |
| egressy (sidecar) | `NET_ADMIN`, `NET_RAW` | `NET_ADMIN` for `wg` and `ip link`. NAT-PMP is plain UDP, so it does not need `NET_RAW`. ICMP health probes do, so drop `NET_RAW` if the probes use UDP or TCP only |
| apps | none added; `drop: [ALL]` where the image allows | — |

Neither container needs `privileged: true` or `hostNetwork`, and nothing needs
`pid: host` or `nsenter`. That removes the riskiest part of `personal-egressd`.

### Kernel WireGuard versus `/dev/net/tun`

Kernel 7.0 ships WireGuard as a module (on these nodes it is loadable, not built in). The image
already ships `wireguard-tools`, and `wg-quick` uses the kernel module when it is
present. **Prefer the kernel module and don't mount `/dev/net/tun`.** A tun
device needs a hostPath or a device plugin, and it widens the AppArmor profile.

**Node check (oversight, 2026-11-02).** Both nodes, winrarhost1 (192.168.1.216)
and winrarhosttrig (192.168.1.160), gave the same results:

- kernel `7.0.0-42-generic`;
- `wireguard` is a loadable module (modinfo version 1.0.0), **not built in, and
  not loaded** (`lsmod` shows 0);
- `/dev/net/tun` is present;
- `nft` is at `/usr/sbin/nft`.

The kernel can autoload the module the first time a pod with NET_ADMIN creates a
`wireguard` link, through the `rtnl-link-wireguard` alias. Pod mode should not
rely on that: whether the autoload works depends on kernel and AppArmor policy,
and a failure would only appear at the first pod start. **The `k8s_node` role
loads it at boot** by writing `wireguard` to
`/etc/modules-load.d/wireguard.conf`, plus a `modprobe wireguard` task. Pods
cannot run `modprobe` themselves. `pod-run` fails with a clear
`wireguard_module_unavailable` error if `ip link add type wireguard` returns
`EOPNOTSUPP`.

`/dev/net/tun` is present, so a wireguard-go fallback is possible, but it is not
planned. It would need a hostPath device mount and a wider AppArmor profile.

To re-check, run on each node:

```sh
uname -r; modinfo -F version wireguard; lsmod | grep -cw wireguard
sudo ip netns add wgt && sudo ip -n wgt link add wg-test type wireguard \
  && echo OK; sudo ip netns del wgt
```

### Sysctls

| Sysctl | Value | Scope | k8s class |
|---|---|---|---|
| `net.ipv4.conf.all.src_valid_mark` | 1 | per netns | unsafe (needs allowlist) |
| `net.ipv6.conf.all.disable_ipv6` | 1 | per netns | unsafe |
| `net.ipv4.ip_forward` | **0 (default; not set)** | per netns | — |

`ip_forward` is **not** needed in pod mode, because nothing is routed between
interfaces. Leaving it out removes it from the allowlist, unlike the inventory
draft.

`src_valid_mark` is needed so that `wg-quick`'s fwmark-based reverse-path
behaviour works. With `Table = off` and our own rules it is still set, for
consistency with the provider profiles.

**k3s allowlist.** The `k8s_node` role adds the following to
`/etc/rancher/k3s/config.yaml` on both nodes, then restarts k3s (a rolling
restart, one node at a time):

```yaml
kubelet-arg:
  - "allowed-unsafe-sysctls=net.ipv4.conf.all.src_valid_mark,net.ipv6.conf.all.disable_ipv6"
```

The pod then sets them in `securityContext.sysctls`. A pod that sets a sysctl the
kubelet does not allow is rejected with `SysctlForbidden`. This is the safe
failure: the pod does not run.

As a fallback that needs no kubelet change, `egressy-init` can write the
per-netns sysctls itself through `/proc/sys`, which works with NET_ADMIN.
containerd mounts `/proc/sys` read-only unless the container is privileged,
though, so this probably does not work under the default runtime. The allowlist
is the recommended path.

### Pod Security and AppArmor

- **Pod Security:** the namespace needs the PSA `privileged` level. `baseline`
  forbids the unsafe sysctls and `NET_ADMIN`. Keep the download pod in its own
  namespace (`media-vpn`), so the privileged label does not spread to the
  rest of `media`.
- **AppArmor:** the ops `k8s_node` role pins containers to a containerd AppArmor
  profile.
  - The stock `cri-containerd.apparmor.d` profile allows `network` and
    `capability net_admin`, but denies writes to most of `/proc/sys`. That is
    another reason to prefer kubelet sysctls over in-container writes.
  - If the role's profile is stricter, it must allow `network netlink raw`
    (nft, ip, wg) and `capability net_admin, net_raw` for the two egressy
    containers.
  - Set `appArmorProfile: { type: Localhost, localhostProfile: egressy-pod }`
    on those two containers only, and leave apps on the default profile.
  - Check the role's profile text in ops `ops-k3s-apparmor` before choosing
    (open question 3).
- **seccomp:** `RuntimeDefault` allows the required netlink syscalls, so no
  change is needed.

## 3. Inbound access to app UIs

The apps (qbittorrent:8083, sonarr:8989, radarr:7878, prowlarr:9696) must answer
on the pod IP for a ClusterIP Service, Ingress (Traefik) and kubelet probes, and
their replies must leave by `eth0`, not `wg0`.

### Problem

With egressy's default route in table 200 via `wg0`, a reply to a packet from
`10.42.0.0/16`, or from a node IP for probes, would be routed into the tunnel.
There it gets dropped, or worse, sent to the provider.

### Recommended: connmark-based policy routing

1. Inbound connections on `eth0` to a declared UI port are marked on input
   (`ct mark set 0x1`, see the table above).
2. On output, replies restore the mark: `meta mark set ct mark`, in a
   `type route hook output` chain so that a reroute happens.
3. Rule priority 90: `fwmark 0x1 lookup main`. Main has the flannel `eth0`
   routes, so replies go back through `eth0`. This is the pod analogue of the
   gateway's priority-90 management exception.
4. The output filter accepts `ct direction reply` on `eth0` only. An app cannot
   open a *new* connection out of `eth0` by setting a mark, because apps have no
   `NET_ADMIN` and so cannot set `SO_MARK`. The filter also keys on conntrack
   direction, not on the mark alone.

Rule order in the pod:

```text
priority 90:  fwmark 0x1 lookup main         # replies to inbound UI/probes
priority 100: from all lookup 200            # everything else → wg0 / unreachable
```

kubelet HTTP probes come from the node IP into `eth0` and are covered by the same
mark.

### Alternative: separate un-tunnelled front pod (the crw-front pattern)

In this pattern a second, ordinary pod runs nginx, Service → front → the
download pod's UI ports. The download pod's input then accepts only the front
pod's IP, or a NetworkPolicy label. Its replies still need the connmark
exception, because they still leave by `eth0`, so this does not remove item 3
above. It only narrows who can connect.

It earns its keep as defence in depth when apps cannot run non-root. Recommended
for v2, not v1.

### Lateral isolation

The host isolation agent's job, stopping enrolled peers reaching each other, is
taken over by NetworkPolicy, which k3s enforces through its kube-router policy
controller. Default deny ingress to `media-vpn`, then allow from Traefik and the
front pod.

## 4. Secrets

- **One WireGuard key per pod.** Each pod is its own peer, because two pods
  using the same key break each other's handshakes.
  - Plan for `arr-dl` plus one spare.
  - Crw/searxng get a second pod only if they move, which uses the spare.
- **Infisical naming,** following the existing `HOMELAB_EGRESSY_WIREGUARD_CONFIG_B64`:
  - `HOMELAB_EGRESSY_POD_<POD>_WG_CONFIG_B64`, for example
    `HOMELAB_EGRESSY_POD_ARR_DL_WG_CONFIG_B64`;
  - one complete provider profile per pod, NAT-PMP enabled for `arr-dl`.
  - The existing Docker gateway key is **not** reused while `personal-egressd`
    runs.
- **ExternalSecret** (External Secrets Operator, Infisical provider) per pod:

  ```yaml
  apiVersion: external-secrets.io/v1
  kind: ExternalSecret
  metadata: { name: egressy-arr-dl-wg, namespace: media-vpn }
  spec:
    refreshInterval: 1h
    secretStoreRef: { kind: ClusterSecretStore, name: infisical-apps }
    target: { name: egressy-arr-dl-wg, creationPolicy: Owner }
    data:
      - secretKey: wg0.conf.b64
        remoteRef: { key: HOMELAB_EGRESSY_POD_ARR_DL_WG_CONFIG_B64 }
  ```

- **Mounting:**
  - mounted read-only, `defaultMode: 0400`, into `egressy-init` (to resolve the
    endpoint) and `egressy`;
  - decoded to an `emptyDir: { medium: Memory }` at `0600`, which keeps invariant
    10;
  - never mounted into app containers.
- **Rotation:**
  - ESO updates the Secret, and the projected volume updates in place.
  - `pod-run` watches the file and applies the change with the existing
    `profile_manager` diff/syncconf logic.
  - If the endpoint changed, the kill-switch table no longer allows the new
    endpoint, so the tunnel cannot come up. `pod-run` reports
    `endpoint_not_allowed` and stays fail-closed. Recreating the pod re-runs init
    with the new endpoint. This is safe and simple, and a rollout restart is
    acceptable for a rare event.

## 5. Tests that prove fail-closed

These are added to `docs/TESTING.md` under a "pod mode" section. Unit tests come
in step 1 below, the kind/k3d test is CI-only in the merge queue, and the live
checks are manual.

**Unit (no network):**

- `render_pod_firewall` snapshot tests: output policy drop, the IPv6 drop
  present, no blanket CIDR allow, and the endpoint rule carries the fwmark.
- Every `extra_allow` entry is a host/port, never a bare CIDR wider than /32
  unless explicitly flagged.

**Integration (privileged CI runner, throwaway netns, no k8s needed):**

- Build a netns with a veth standing in for `eth0` and a mock WG peer in a second
  netns, then run `pod-init` and `pod-run` against it. This mirrors the existing
  `tests/` approach without touching host state.

**Cluster (k3d in the merge queue, or a manual run on the real nodes):**

1. **Tunnel kill.**
   - In a test pod with an `ifconfig.co`-style client container, delete the
     tunnel: `kubectl exec -c egressy -- ip link del wg0`.
   - At the same time, on the node, capture the pod's host-side veth:
     `tcpdump -ni <veth> 'not (udp port {endpoint_port} and host {endpoint})' and not arp`.
   - From the client, run `curl -m5 https://1.1.1.1` and `curl -m5 http://<LAN ip>`.
   - **Assert:** both fail, and tcpdump saw no packet from the pod IP other than
     replies to inbound connections. Repeat with the sidecar killed
     (`kill 1` in the sidecar) instead of the link.
2. **Init ordering.** Make `egressy-init` fail (bad config). Assert that the app
   containers never reach `Running` and that `kubectl get pod` shows
   `Init:Error`.
3. **DNS leak.**
   - `dig @1.1.1.1 example.com` and `dig @<CoreDNS IP> example.com` from an app
     container (non-root) must fail.
   - `dig @127.0.0.1 example.com` must succeed.
   - On the node, capture the veth for port 53 to non-CoreDNS addresses; assert
     zero packets.
   - Run a DNS leak test (a resolver-echo name) and assert it reports only the
     provider's resolver.
4. **IPv6 leak.**
   - Assert `ip -6 addr` in the app container shows no global address, and
     `curl -6 -m5 https://ipv6.icanhazip.com` fails.
   - On the node, `tcpdump -ni <veth> ip6` sees nothing except
     link-local ND, if disable_ipv6 is unavailable.
5. **Inbound.**
   - `curl` the qbittorrent UI through its Service from another pod, and assert
     200.
   - On the node, assert that the reply left by the veth and the tunnel counters
     did not move.
6. **Sidecar restart with the table removed.** Run `nft delete table inet
   egressy_pod` from a debug container with NET_ADMIN. Assert that the sidecar
   goes not-ready and exits, and that no traffic flows meanwhile, because routing
   still points at `wg0`.
7. **Exit identity.** The existing `egressy-probe` runs as a container in the pod
   and asserts the exit ASN.

## 6. Implementation plan

The code changes in egressy are all behind `mode: pod`. In gateway mode they are
inert. Each step is one graft land.

| # | Change | Size |
|---|---|---|
| 1 | `config.rs`: `mode: gateway \| pod`; `pod:` block (`ui_ports`, `cluster_dns`, `extra_allow`, `inbound_mark`); validation (pod mode forbids docker/isolation/host-policy settings, requires `Table = off` profiles). `host.rs`/new `pod.rs`: `render_pod_firewall`, `render_pod_routes`; `egressy render-pod-firewall` subcommand. Snapshot tests. | M (≈400 lines + tests) |
| 2 | `egressy pod-init` subcommand: resolve endpoint, apply table + rules + unreachable default atomically (`nft -f` one transaction), read back and compare, exit 0. Reuses `enforcement.rs`. | S–M |
| 3 | `egressy pod-run`: runtime path that skips Docker discovery, host policy, isolation and forwarding; keeps profile_manager, recovery, DNS on 127.0.0.1, NAT-PMP writing the forwarded port to a file instead of DNAT; kill-switch verification loop; `/readyz` vs `/livez` split. | L (runtime.rs is the largest file; mostly gating existing tasks) |
| 4 | NAT-PMP without DNAT: input-chain accept for the leased port on `wg0` (the app listens on the internal port = external port; port-sync sets it). | S |
| 5 | Netns integration tests (privileged CI job, merge queue only). | M |
| 6 | Docs: `ARCHITECTURE.md`, `NETWORKING.md` pod section, `AGENTS.md` invariants (after Q1), example manifests under `deploy/k8s/` (kustomize: init, sidecar, ExternalSecret, NetworkPolicy, Service). | S–M |
| 7 | k3d merge-queue test running §5 tests 1–5. | M |

The cluster work below happens in ops, not in egressy. It is listed so the
ordering is clear.

- `k8s_node` role: load the WireGuard module at boot (`modules-load.d`; it is available but not loaded on both nodes), and the kubelet
  unsafe-sysctl allowlist (step A, before step 7 can run on the real cluster).
- AppArmor profile for the egressy containers, if needed (step B).
- Infisical key `HOMELAB_EGRESSY_POD_ARR_DL_WG_CONFIG_B64`, generated as a new
  provider device (step C).
- `media-vpn` namespace, ESO store, and the `arr-dl` manifests (step D, after
  egressy steps 1–4 ship in an image).

**Order:** Q1 answered → 1 → 2 → A → 3 → 4 → 5 → C → D (a canary
pod with only the probe and a test client, running §5 by hand) → 6 → 7 →
cut over qbittorrent, then the rest. `personal-egressd` keeps running until the
last Docker client is gone, and is retired separately.

**Overall size:** about 2–3 worker-weeks of egressy changes, plus 2–3 days of
ops/cluster work.

## Open questions for the operator

1. **The invariant.** Is pod mode an acceptable second mode, amending the
   `AGENTS.md` "must not be converted to a shared-network-namespace model" rule
   to apply to gateway mode only? Or should it be a separate binary or repo?
2. **Pod grouping.** Choose between:
   - one `arr-dl` pod holding qbittorrent, rusttorrent, sonarr, radarr and
     prowlarr: one key, all on one node, restarted together;
   - download clients only, with the *arrs split out: two or more keys.
3. **AppArmor profile.** Does the `k8s_node` role's containerd profile allow
   netlink and `net_admin`, or does it need an `egressy-pod` Localhost profile?
4. **Missing kill switch at runtime.** Choose between:
   - the sidecar exits and the pod is recreated (recommended, strict);
   - the sidecar reinstalls the table itself (self-healing, as the host agent
     does today).
5. **Provider device budget.** Does ProtonVPN have room for one or two more
   WireGuard devices while the Docker gateway still runs?
6. **Non-root apps.** Can the linuxserver images run with a fixed non-root UID?
   The CoreDNS exception relies on `skuid 0` being egressy alone.
7. **NFS and the inventory's 192.168.1.75:2049 allowance.** If the download
   volumes are NFS PVs mounted by kubelet, mount traffic is node-level and needs
   no pod exception. Confirm that no in-pod NFS client is planned.
8. **Retiring gluetun and the duplicate speedtest** before the move (inventory
   §3 finding). This avoids designing for a second VPN.
