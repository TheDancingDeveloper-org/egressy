# Provider-neutral WireGuard profile management

Status: Egressy 0.2.0 implementation specification

## Purpose

Egressy should accept a conventional IPv4 full-tunnel WireGuard profile
without requiring provider-specific daemon configuration. Operators may supply
the profile as a mounted secret or import it through the dashboard. A process
with no usable profile must still start its management interface while keeping
enrolled client traffic fail closed.

This design replaces Proton-shaped core configuration with provider-neutral
WireGuard, DNS, validation, and optional port-allocation capabilities. Proton
and Mullvad become documented and tested examples rather than runtime provider
types.

## Product boundaries

The refactor does not change Egressy's fundamental model:

- Egressy remains a Linux-only transparent Layer-3 Docker gateway.
- Clients keep independent network namespaces and join the Egressy network.
- Egressy does not become an HTTP or SOCKS proxy.
- The priority-90 management exception and priority-100 enrolled-subnet rule
  remain owned by Egressy.
- Enrolled IPv4 traffic exits through `wg0` or fails closed.
- Docker discovery remains read-only. Egressy must not restart its own or any
  application container to apply a profile.
- Client enrollment and leak protection remain IPv4-only. IPv6 fields may be
  preserved in a profile, but their presence does not imply IPv6 protection.
- A tunnel may supply at most one forwarded port to one unique compliant
  target.

## Intended operator experience

### Mounted-profile workflow

An infrastructure-managed deployment supplies a protected WireGuard file and
points Egressy at it:

```yaml
wireguard:
  config_path: /run/secrets/wg0.conf
```

For a normal full-tunnel profile containing a usable `DNS` value, this is
sufficient for protected IPv4 egress. Egressy parses the file, installs its
fail-closed policy, creates a normalized tmpfs copy, starts WireGuard, and
derives required in-tunnel DNS routes.

The dashboard exposes the parsed, redacted configuration and runtime state. It
never overwrites a mounted profile.

### Click-ops workflow

With no mounted or stored profile, Egressy starts in `unconfigured` state. The
dashboard offers a profile setup flow:

1. Upload a `.conf` file or paste its contents.
2. Review parsed interface, peer, DNS, routing, and compatibility information.
3. Resolve blocking validation errors and review warnings.
4. Optionally configure capabilities that WireGuard does not describe, such
   as NAT-PMP or provider identity validation.
5. Click **Apply**.

Egressy stores the managed profile securely, applies it transactionally, and
reports the result without returning private or preshared keys to the browser.

### Advanced workflow

The dashboard provides a structured advanced editor for supported WireGuard
fields. It pre-fills non-secret values parsed from the imported profile and
represents secrets only as `configured` or `not configured`.

Updating a non-secret field preserves a stored secret unless the operator
explicitly supplies a replacement. Placeholder text must never be serialized
into the runtime profile.

## Valid startup states

Both configured and unconfigured startup are valid process states:

| State | Meaning | Client traffic |
|---|---|---|
| `unconfigured` | No active profile exists | Rejected |
| `validating` | A candidate is being parsed and checked | Existing active profile remains in force, otherwise rejected |
| `applying` | A validated candidate is being applied | Fail-closed policy remains installed |
| `active` | The active profile and tunnel are usable | Routed through `wg0` |
| `degraded` | The configured tunnel is unhealthy | Rejected when the tunnel path is unavailable |
| `apply_failed` | Candidate application failed | Previous active profile is restored when possible, otherwise rejected |
| `recovering` | Egressy is recycling or recovering the tunnel | Rejected until the protected route is usable |

The daemon startup sequence becomes:

1. Parse daemon configuration that does not require an active VPN profile.
2. Open the protected application state store.
3. Install and verify the base fail-closed gateway policy.
4. Start the management API and dashboard.
5. Load the selected mounted or GUI-managed profile, if present.
6. Validate and apply a usable profile.
7. Start or enable tunnel-dependent DNS, monitoring, recovery, and optional
   capabilities.

The firewall must be installed before any WireGuard interface is brought up.

## Health semantics

- `/livez` reports whether the Egressy process and management server are
  running. It succeeds in `unconfigured` state.
- `/readyz` reports whether management dependencies are ready. It may succeed
  while the VPN is unconfigured, provided the response makes that state
  explicit.
- `/healthz` continues to represent tunnel health and fails when no usable
  tunnel exists.
- Container orchestration should use `/livez` for the process healthcheck so
  an unconfigured instance remains available for setup.

Advisory identity and external validation results do not alter protection,
readiness, or recovery.

## Profile sources and precedence

Egressy supports two sources:

```text
mounted | gui_managed
```

Source selection must be explicit. A mounted profile remains read-only and is
never modified by dashboard actions. If both sources exist, Egressy must not
silently choose one based on filesystem timing. Configuration selects the
active source, and changing sources uses the same transactional apply flow as
changing a profile.

Suggested configuration:

```yaml
wireguard:
  interface: wg0
  source: mounted
  config_path: /run/secrets/wg0.conf
  manage: true
```

For click-ops installations:

```yaml
wireguard:
  interface: wg0
  source: gui_managed
  manage: true
```

Absence of the selected profile is an `unconfigured` runtime condition, not a
fatal process-start error.

## Profile parsing and normalization

Egressy parses a profile once into a safe structured model and renders the
runtime file from that model. Parsing is not merely a dashboard concern; the
same validated representation drives routing, DNS, application, redaction,
and diagnostics.

### Supported interface fields

- `PrivateKey`
- `Address`
- `DNS`
- `ListenPort`
- `MTU`

### Supported peer fields

- `PublicKey`
- `PresharedKey`
- `Endpoint`
- `AllowedIPs`
- `PersistentKeepalive`

Profiles may contain multiple peers. Managed full-tunnel mode requires an
unambiguous peer route for `0.0.0.0/0`. Multiple peers must not make endpoint
reporting a fatal startup dependency; ambiguous advisory metadata is reported
as unknown.

### Egressy-owned and prohibited fields

Egressy injects `Table = off` into the protected runtime copy and rejects an
operator-supplied `Table` value. It also rejects:

- `SaveConfig`
- `PreUp`
- `PostUp`
- `PreDown`
- `PostDown`

The hook directives execute commands with gateway privileges and can compete
with Egressy's routing or firewall ownership. They therefore cannot be
accepted from either mounted or GUI-managed profiles.

Unknown directives are rejected with line-specific validation errors rather
than silently discarded.

### Runtime copy

The normalized profile is decoded only into `/run/egressy`, which must be
tmpfs-backed. Its directory uses mode `0700` and its profile uses mode `0600`.
The normalized profile must never enter an image, log, API response, event,
diagnostic bundle, or history record.

## Derived configuration and GUI pre-fill

The parser supplies a redacted view containing:

- interface addresses;
- DNS servers;
- MTU and listen port;
- peer count;
- public keys;
- whether private and preshared keys are configured;
- endpoint hosts and ports;
- allowed IP ranges;
- persistent keepalive values;
- IPv4 full-tunnel compatibility;
- warnings about IPv6 fields not protected by Egressy;
- whether a change can be hot-applied or needs tunnel recycling.

The GUI may infer a provider or region as advisory display metadata, but
runtime behavior must never depend on provider-name inference. Raw IP
endpoints legitimately result in unknown provider and region values.

## Provider-neutral capability model

The daemon models behavior, not provider brands.

### WireGuard transport

The WireGuard component owns profile validation, normalized rendering,
interface lifecycle, handshakes, endpoints, counters, and recovery.

### Tunnel route plan

A pure route planner produces the desired Linux state from:

- the enrolled client subnet;
- the Egressy management address;
- the WireGuard interface;
- the IPv4 full-tunnel posture;
- configured in-tunnel service destinations.

The plan always preserves:

- priority 90: gateway-originated management replies use `main`;
- priority 100: the enrolled subnet uses the dedicated Egressy table;
- a dedicated-table default route through `wg0`.

DNS, NAT-PMP, or future tunnel services contribute their own explicit on-link
routes. A NAT-PMP gateway must not double as an implicit general tunnel
gateway. No provider-specific service route is installed by default.

### DNS

DNS upstream selection supports:

```yaml
dns:
  enabled: true
  upstream:
    source: profile
```

and an explicit override:

```yaml
dns:
  enabled: true
  upstream:
    source: explicit
    addresses:
      - 10.64.0.1:53
```

When `source: profile` is selected, Egressy consumes `DNS` fields instead of
letting `wg-quick` configure the container resolver. It installs explicit
routes needed to reach in-tunnel resolvers. A profile without DNS is a clear
configuration error unless DNS forwarding is disabled or explicit upstreams
are configured.

The current bounded UDP/TCP forwarder and plain-DNS enforcement remain in
place.

### Port forwarding

Port forwarding is disabled by default:

```yaml
port_forwarding:
  backend: disabled
```

Proton-style NAT-PMP is an optional backend:

```yaml
port_forwarding:
  backend: nat_pmp
  gateway: 10.2.0.1
  refresh_seconds: 45
  lifetime_seconds: 60
```

The existing requirements remain unchanged: matching TCP and UDP allocation,
bounded retries, early renewal, and immediate DNAT removal when no unique
compliant target exists. NAT-PMP routes and UDP port 5351 firewall acceptance
exist only while that backend is configured.

Mullvad uses `backend: disabled` because it does not supply forwarded ports.

### Identity validation

Identity validation is optional and advisory. It supports a small declarative,
bounded matcher set rather than arbitrary scripts:

- plain-text substring;
- JSON string-field substring over an explicit field allowlist;
- JSON boolean field equality.

Example Mullvad validation:

```yaml
validation:
  identity:
    enabled: true
    url: https://am.i.mullvad.net/json
    matcher:
      type: json_boolean
      field: mullvad_exit_ip
      value: true
```

Example generic organization validation:

```yaml
validation:
  identity:
    enabled: true
    url: https://ifconfig.co/json
    matcher:
      type: json_string_contains
      fields: [asn_org, as_name, org]
      value: Datacamp
```

URLs, response sizes, redirects, DNS resolution, timeouts, and safe response
parsing retain strict bounds. Identity failure must not weaken fail-closed
policy or trigger tunnel recovery.

## Secure profile management

WireGuard private keys and preshared keys are credentials. GUI management must
not turn Egressy into an endpoint that exposes them.

### API rules

- Import and secret replacement operations are write-only.
- No GET, event, metric, log, history record, error, or OpenAPI example returns
  a private key, preshared key, or complete profile.
- Redacted responses expose only whether each secret is configured.
- Request bodies containing profiles are excluded from access and tracing
  logs.
- Validation errors identify fields and line numbers without echoing secret
  values or complete source lines.
- The raw active profile cannot be downloaded through the API.
- Browser state containing an imported profile is cleared after submission and
  is not persisted in local storage, URLs, analytics, or error reporting.

Public peer keys are not treated as private credentials, but responses remain
bounded and escaped.

### Storage rules

GUI-managed profiles must be encrypted at rest using an authenticated
encryption scheme. The encryption key must come from a protected deployment
secret or equivalent platform key source; it must not be stored alongside the
ciphertext in the application database. Losing the key makes the stored
profile unavailable and must never cause plaintext fallback.

The state store records versioned ciphertext, non-secret parsed metadata,
source, timestamps, and activation state. It does not store plaintext profile
copies.

Mounted profiles retain their existing filesystem mode checks. GUI-managed
profiles are decrypted only when validating or rendering the tmpfs runtime
copy, and plaintext buffers should have the shortest practical lifetime.

### Dashboard access

Profile-management endpoints require administrative protection. The design
must include:

- an authentication mechanism suitable for local and reverse-proxy use;
- origin and CSRF protection for browser mutations;
- secure cookie and session behavior when cookie authentication is used;
- explicit trusted-proxy handling rather than trusting forwarded headers by
  default;
- TLS at Egressy or at a reviewed trusted reverse proxy for remote access.

Until administrative protection is configured, profile mutation should be
limited to a demonstrably local management path. Merely binding the example
dashboard to localhost is not a complete authorization design.

## Apply, hot reload, and rollback

Egressy applies the narrowest safe operation based on a semantic diff between
the active and candidate structured profiles.

| Change | Apply behavior |
|---|---|
| DNS upstream only | Reload or reconfigure the DNS forwarder and service routes |
| Endpoint, keepalive, or peer key | Apply with `wg syncconf` |
| Allowed IPs with valid unchanged full-tunnel posture | `wg syncconf`, then route reconciliation |
| MTU or interface address | Controlled `wg0` recycle |
| Interface name or incompatible structural change | Controlled tunnel replacement/recycle |

Hot reload is an optimization, not a relaxation of validation. The apply
transaction is:

1. Accept the candidate without logging its body.
2. Parse and validate its complete structured representation.
3. Build and validate the route, DNS, firewall, and capability plans.
4. Persist an encrypted staged revision for a GUI-managed profile.
5. Verify that the fail-closed firewall owner is active.
6. Hot-apply the candidate where safe, otherwise recycle only the WireGuard
   interface.
7. Reconcile routes, DNS, firewall, monitoring, and optional capabilities.
8. Verify interface presence and obtain bounded tunnel evidence.
9. Mark the candidate active and retire the staged state.

If application fails, Egressy removes candidate-only state and attempts to
restore the previous profile and plans. If restoration fails, the runtime
enters `apply_failed`, leaves client traffic blocked, keeps the management API
available, and reports a safe error.

Egressy must not request Docker container restart privileges. A full Egressy
container restart may remain an operator-controlled recovery action, but it is
not the profile-application mechanism.

## Management API shape

Exact paths remain subject to OpenAPI design, but the API needs operations
equivalent to:

- get profile-management status and redacted active metadata;
- validate an uploaded or pasted candidate without activating it;
- import and stage a managed candidate;
- apply a staged revision;
- replace selected secrets without retrieving existing values;
- activate a selected source or managed revision;
- delete an inactive managed revision;
- observe apply progress and safe results.

Mutation requests use revision identifiers or entity tags to prevent one
browser session from overwriting another session's update. Apply is serialized
with firewall enforcement and tunnel recovery so those actors cannot race to
replace shared state.

`src/state.rs` and `openapi/v2.json` are external contracts. New lifecycle and
profile-management fields require serialization, handler, redaction, and
compatibility tests.

## Dashboard requirements

The dashboard profile area includes:

- an unconfigured setup screen;
- upload and paste import controls;
- a redacted source preview;
- structured basic and advanced editors;
- explicit validation errors and non-blocking warnings;
- active source and revision information;
- apply classification: hot reload or tunnel recycle;
- apply progress and rollback result;
- tunnel, handshake, DNS, and optional capability status;
- clear IPv4-only protection language;
- provider presets only as optional suggestions.

All container-controlled and profile-controlled strings must be escaped. The
UI must not place raw profile contents or secret fields into browser storage.

## Provider examples

### Mullvad

A standard Mullvad full-tunnel profile should normally require only the
profile. Egressy reads its interface DNS setting, accepts its single peer and
IPv4 default `AllowedIPs`, and leaves port forwarding disabled. Optional
identity validation can use Mullvad's boolean connection result.

### Proton

A standard Proton full-tunnel profile supplies baseline transport and DNS.
Port forwarding is an explicit NAT-PMP capability with its own service gateway
and lease settings. It is not enabled merely because a profile or endpoint
looks like Proton.

## Migration from 0.1.x

This is intentionally a configuration-breaking 0.2.0 refactor. The existing
top-level `proton` section should be replaced by provider-neutral
`port_forwarding`, DNS, and validation sections rather than retained as a
permanent compatibility layer.

Migration tooling or `egressy check` should report actionable mappings:

| 0.1.x setting | 0.2.0 destination |
|---|---|
| `proton.port_forwarding` | `port_forwarding.backend` |
| `proton.natpmp_gateway` | `port_forwarding.gateway` |
| `proton.refresh_seconds` | `port_forwarding.refresh_seconds` |
| `proton.lifetime_seconds` | `port_forwarding.lifetime_seconds` |
| `dns.upstream` | explicit DNS upstream or profile-derived DNS |
| `probe.expected_identity` | `validation.identity.matcher` |

The default mounted path and Compose variable should use provider-neutral
names. Proton-specific logs, comments, state documentation, and example text
must be removed or confined to a Proton example.

## Implementation outline

1. Add a structured WireGuard parser, redactor, normalizer, fixtures, and
   semantic diff model.
2. Extract a pure tunnel route planner and remove the NAT-PMP gateway's hidden
   routing role.
3. Introduce provider-neutral DNS, port-forwarding, and identity-validation
   configuration.
4. Refactor runtime startup into a persistent management plane plus a
   serialized tunnel lifecycle state machine.
5. Add encrypted GUI-managed profile revisions and protected key loading.
6. Add redacted management APIs, concurrency control, authentication, and
   browser mutation protection.
7. Build the unconfigured, import, validation, advanced edit, apply, and
   rollback dashboard flows.
8. Migrate examples, Compose, documentation, OpenAPI, compatibility behavior,
   and healthchecks.
9. Add namespace-based integration coverage and validate Proton and Mullvad
   examples.

## Required tests

At minimum, automated coverage must include:

- Proton and Mullvad single-hop fixtures with fake credentials;
- a Mullvad-style multihop fixture;
- raw-IP, hostname, IPv4, and bracketed IPv6 endpoints;
- comments, whitespace, repeated fields, malformed sections, and bounded input;
- multiple peers with valid and ambiguous IPv4 default routing;
- profiles missing `0.0.0.0/0`;
- rejection of hooks, `SaveConfig`, operator `Table`, and unknown directives;
- redaction of private and preshared keys from every response and error path;
- encrypted storage and failure with a missing or incorrect storage key;
- unconfigured startup with a usable dashboard and fail-closed client path;
- profile-derived and explicitly configured DNS service routes;
- DNS changes without tunnel recycling;
- `wg syncconf` classification and failure rollback;
- controlled recycle for address and MTU changes;
- startup, tunnel loss, gateway loss, recovery, and target removal;
- conditional NAT-PMP route and firewall rendering;
- immediate DNAT removal for target loss or ambiguity;
- concurrent apply, recovery, and firewall reconciliation serialization;
- mounted profile immutability and explicit source switching;
- OpenAPI serialization and handler authorization;
- UI escaping, secret-field clearing, and browser-storage exclusion.

An opt-in Linux network-namespace integration test should exercise:

```text
client namespace -> Egressy namespace -> WireGuard -> simulated provider
```

It must prove successful IPv4 egress, return traffic, DNS, tunnel loss, and no
fallback to the ordinary uplink without mutating host routing or firewall
state in ordinary local tests.

## Acceptance criteria

The refactor is complete when:

1. A user can mount or upload a conventional supported IPv4 full-tunnel
   WireGuard profile and obtain protected egress without selecting a provider.
2. Egressy boots to a usable authenticated management experience with no
   profile while enrolled traffic remains fail closed.
3. The GUI accurately pre-fills and safely edits supported fields without ever
   returning stored secret values.
4. Safe changes hot-apply, structural changes recycle only WireGuard, and
   failures restore the previous profile or remain fail closed.
5. DNS and optional tunnel services receive explicit derived routes without
   Proton-specific coupling.
6. Port forwarding is disabled by default and NAT-PMP remains correct when
   explicitly enabled.
7. Proton and Mullvad fixtures and integration scenarios pass using the same
   provider-neutral runtime paths.
8. No API, log, metric, event, history record, image, or repository artifact
   contains a private key, preshared key, or complete profile.
