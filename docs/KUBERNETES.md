# Kubernetes pod discovery

Egressy can enroll Kubernetes pods next to Docker containers. The gateway
stays a Docker container; pods join its existing bridge (`br-vpn-egress`)
through a Multus network attachment, and Egressy discovers them read-only from
the Kubernetes API. An annotated pod is treated exactly like a labelled
container: the same compliance rules, isolation policy, and NAT-PMP leases.

The feature is off by default (`kubernetes.enabled: false`). Nothing in this
mode changes the gateway invariants in `AGENTS.md`: enrolled traffic still
leaves through `wg0` or fails closed, and Egressy never writes to the cluster.

## How a pod is enrolled

1. The pod lists the attachment in `k8s.v1.cni.cncf.io/networks`, for example
   `personal-arr/vpn-egress`. Multus attaches a second interface to
   `br-vpn-egress` and writes the address and MAC into the pod's
   `k8s.v1.cni.cncf.io/network-status` annotation.
2. The pod carries the Egressy annotations, which mirror the container labels:

   | Annotation | Purpose |
   |---|---|
   | `egressy.enabled: "true"` | Requests enrollment and monitoring. |
   | `egressy.usage-id` | Stable history and lease identity. Without it the pod's `namespace/name` is used, which changes when a Deployment replaces the pod. |
   | `egressy.port-forward: "true"` | Requests a forwarding lease. |
   | `egressy.target-port` | Unique lease key and destination port inside the pod. |
   | `egressy.isolation-id` | Shared-bridge policy identity. |
   | `egressy.isolation-allow` | Comma-separated `identity:port/proto` allowances. Honoured only where the destination accepts this pod (below). |
   | `egressy.isolation-accept` | Comma-separated isolation identities whose pod allowances may open this pod. |

3. On every reconcile, Egressy lists the pods on `kubernetes.node_name`, reads
   the configured attachment's entry from `network-status`, and merges the
   result with Docker discovery. Target-port, usage-ID and lease-cap rules are
   applied across both sources together, so a pod and a container cannot hold
   the same target port.

A pod is compliant only when it is `Running`, not terminating, and its
attachment has exactly one IPv4 address inside `kubernetes.address_range` and
a valid unicast MAC. A missing or malformed annotation, an address outside the
range, or an invalid `egressy.target-port` makes it non-compliant, exactly as
an unattached labelled container is. Client IDs are `k8s-<pod uid>`.

The pod's route intent is `Verified` only when Multus reports `172.30.0.2` as
its gateway. A default route that comes from IPAM `routes` is not reported by
Multus, so the intent is then `Unknown`, which is not attested either way.
Pod IPv6 on the attachment is not supported; it is reported and rejected.

## Address binding (anti-spoof)

Pods share a Layer-2 bridge with the gateway and the Docker clients, so a pod
could otherwise send frames with another client's address. When Kubernetes
discovery is on, the isolation policy carries each participant's MAC and the
pod range, and the host isolation agent renders these rules first in the
bridge `forward` chain, before conntrack or any allowance:

- a frame carrying a participant's IPv4 address (IP or ARP) from any other MAC
  is dropped;
- a frame from a participant's MAC with any other source address is dropped
  (except the gateway, which forwards return traffic for outside addresses;
  its own address is still bound to its MAC);
- any source address in `kubernetes.address_range` that is not a discovered,
  running pod is dropped. An unannotated pod on the bridge therefore cannot
  send anything until it is discovered.

Docker containers are bound by the MAC Docker reports for their endpoint.
An address or MAC claimed by more than one Docker container is never bound;
the policy reports it as an issue, as before.

Pod annotations can never widen access or weaken enforcement:

- **Allowances need the destination's consent.** A Docker container's
  `egressy.isolation-allow` is granted by the source alone, as before. A
  pod's allowance is honoured only when the destination's
  `egressy.isolation-accept` label or annotation names the pod's isolation
  identity. Without it a pod cannot open any Docker container's or other
  pod's port.
- **Docker wins every conflict.** A pod that claims a Docker participant's
  address, MAC or isolation identity, shares one with another pod, or lacks a
  valid `egressy.isolation-id`, is left out of the policy. Only that pod is
  affected: it is unbound, so its address fails closed, and the bridge stays
  eligible for `enforce`. A pod's malformed or unaccepted allowance is
  dropped the same way. Each case is listed in the policy's `rejected` notes
  and logged.
- **Docker keeps its leases.** A pod whose `egressy.usage-id` or
  `egressy.target-port` collides with a Docker client is not forwarded; the
  Docker client keeps its lease. Docker clients also take lease slots before
  pods when `max_leases` is reached. Collisions only among pods, or only among
  containers, still make every colliding client non-compliant. These rules drop in `audit` mode too, and are counted as
`isolation_spoofed`; the agent logs an increase as a violation. They need the
isolation agent running in `audit` or `enforce`; with isolation `disabled`
nothing is rendered, so do not enable Kubernetes discovery without the agent.

If a pod listing fails, the last good listing is kept and
`kubernetes.discovery` turns degraded. Stale bindings can only drop a
replacement pod's frames, never admit an unknown sender. The listing is kept
for at most `max_stale_seconds` (default 300); after that every pod is
dropped, so deleted pods lose their clients and leases and every source in
the pod range is dropped until a listing succeeds.

Only pods in `kubernetes.namespaces` are discovered. A pod writes its own
annotations, and Multus lets a pod in any namespace reference the attachment
by default, so the allowlist is what decides who may enrol. List only
namespaces whose pod authors you trust (usually just the attachment's).
Egressy refuses to start with discovery on and no namespaces.

The `network-status` annotation is written by Multus, but anyone who can patch
pods in the namespace can also edit it. Restrict pod `patch`/`update` in the
attachment's namespace to the controllers that need it.

## Configuration

```yaml
kubernetes:
  enabled: true
  node_name: node-b
  network_attachment: personal-arr/vpn-egress
  namespaces: [personal-arr]
  address_range: 172.30.0.192/26
  # Omit api_url in-cluster; KUBERNETES_SERVICE_HOST/PORT are used.
  api_url: https://192.168.1.10:6443
  token_path: /run/secrets/egressy-k8s/token
  ca_path: /run/secrets/egressy-k8s/ca.crt
  timeout_seconds: 10
  max_stale_seconds: 300
```

`address_range` must sit inside `network.subnet` and exclude the bridge and
gateway addresses. Keep Docker's own `ip_range` for the network outside it so
Docker IPAM and the CNI never hand out the same address.

## Credentials

Egressy needs only `list` on `pods`, in each trusted namespace.
`deploy/kubernetes/rbac.yaml` creates a ServiceAccount, a namespaced Role and
RoleBinding granting that verb in `personal-arr`, and a long-lived token
Secret for a gateway that runs outside the cluster. Repeat the Role and
RoleBinding for every other namespace in `kubernetes.namespaces`. There is no
ClusterRole: the account cannot read pods anywhere else. `deploy/kubernetes/vpn-egress-nad.yaml` is an example
attachment.

- **In-cluster** (only if the gateway itself runs as a pod): leave `api_url`
  unset and keep the default `token_path` and `ca_path` of the projected
  service-account volume. The token is re-read on every listing, so rotation
  works.
- **Outside the cluster** (the gateway on Docker): Egressy does not parse a
  kubeconfig. Take the API server URL and CA from the cluster's kubeconfig
  (`clusters[].cluster.server` and `certificate-authority-data`, base64
  decoded), mount the CA and the ServiceAccount token as files with mode
  `0600`, and point `api_url`, `ca_path` and `token_path` at them. The API URL
  must be `https`. Never commit the token or bake it into an image.

### Token storage and rotation

The long-lived token from `egressy-discovery-token` is a credential and lives
in Infisical, never in Git or the transcript:

- Store it, with the CA, in the estate Infisical `infrastructure` project
  (for example `EGRESSY_K8S_DISCOVERY_TOKEN` and `EGRESSY_K8S_CA`), written
  from stdin with the `secret set` wrapper.
- The gateway's deployment renders both into `0600` files at `token_path` and
  `ca_path`. Egressy re-reads the token on every listing, so a new value takes
  effect without a restart.
- Rotate it at least every 90 days, and at once if it may have leaked: delete
  and recreate the `egressy-discovery-token` Secret (Kubernetes mints a new
  token and the old one stops working), store the new value in Infisical,
  and redeploy the files. Discovery fails while the old token is in place;
  after `max_stale_seconds` pods fail closed until the new token lands.
- The token can only `list` pods in the trusted namespaces, so a leak exposes
  those pod specs (including any inline env) and nothing else.

Egressy lists pods through `/api/v1/namespaces/<ns>/pods` for each trusted
namespace, with the field selector `spec.nodeName=<node_name>`, so it
only ever sees pods on its own node.
