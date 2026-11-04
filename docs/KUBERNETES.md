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
   | `egressy.isolation-allow` | Comma-separated `identity:port/proto` allowances. |

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
An address or MAC claimed by more than one participant is never bound; the
policy reports it as an issue and, inside the pod range, that address fails
closed. These rules drop in `audit` mode too, and are counted as
`isolation_spoofed`; the agent logs an increase as a violation. They need the
isolation agent running in `audit` or `enforce`; with isolation `disabled`
nothing is rendered, so do not enable Kubernetes discovery without the agent.

If a pod listing fails, the last good listing is kept and
`kubernetes.discovery` turns degraded. Stale bindings can only drop a
replacement pod's frames, never admit an unknown sender.

The `network-status` annotation is written by Multus, but anyone who can patch
pods in the namespace can also edit it. Restrict pod `patch`/`update` in the
attachment's namespace to the controllers that need it.

## Configuration

```yaml
kubernetes:
  enabled: true
  node_name: node-b
  network_attachment: personal-arr/vpn-egress
  address_range: 172.30.0.192/26
  # Omit api_url in-cluster; KUBERNETES_SERVICE_HOST/PORT are used.
  api_url: https://192.168.1.10:6443
  token_path: /run/secrets/egressy-k8s/token
  ca_path: /run/secrets/egressy-k8s/ca.crt
  timeout_seconds: 10
```

`address_range` must sit inside `network.subnet` and exclude the bridge and
gateway addresses. Keep Docker's own `ip_range` for the network outside it so
Docker IPAM and the CNI never hand out the same address.

## Credentials

Egressy needs only `get`, `list` and `watch` on `pods`.
`deploy/kubernetes/rbac.yaml` creates a ServiceAccount, a ClusterRole with
those verbs, a binding, and a long-lived token Secret for a gateway that runs
outside the cluster. `deploy/kubernetes/vpn-egress-nad.yaml` is an example
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

Egressy lists pods with the field selector `spec.nodeName=<node_name>`, so it
only ever sees pods on its own node.
