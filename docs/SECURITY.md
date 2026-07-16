# Egressy security model

## Protected properties

Egressy is intended to preserve these properties for enrolled IPv4 clients:

1. traffic exits through `wg0` or is rejected;
2. plain DNS goes only to the gateway forwarder and tunnel resolver;
3. only one unique compliant target receives a provider-forwarded port;
4. provider keys and application secrets do not enter API responses or normal
   logs;
5. management traffic from the gateway is not accidentally policy-routed into
   the tunnel.

The host root user, Docker daemon administrator, gateway `NET_ADMIN` process,
and anyone controlling the WireGuard profile are trusted. Egressy is not a
security boundary against a compromised Docker host.

## Enforcement layers

Client Compose declares the egress network and DNS. Host policy routes the
enrolled source subnet to the gateway and rejects fallback. Gateway nftables
rejects invalid input and forwarding, permits the tunnel path, applies NAT, and
owns optional DNAT. WireGuard encrypts traffic from the host to the provider.

No one layer is treated as sufficient. Labels and Docker gateway priorities
are desired-state evidence, not proof of an effective in-container route.

## Docker API boundary

The bundled HAProxy is the sole socket consumer. Its ACL permits container
listing and a named network inspection using GET. Egressy itself has no socket
mount and never mutates Docker. A read-only socket mount still permits broad
Docker reads, so do not bypass the proxy merely because the filesystem mount is
read-only.

## Dashboard and API

The HTTP server has no built-in authentication. The notification settings API
also changes local state. Bind it to localhost or a trusted management network
and add authenticated TLS at a reverse proxy if remote administration is
needed. Never expose it directly to the public internet.

Container-controlled strings rendered by the UI must remain escaped. API
errors and status messages must be bounded and safe for public display.

## Secrets

- Keep WireGuard profiles and decoded copies mode `0600`.
- Put runtime copies on tmpfs.
- Treat base64 content as plaintext credentials.
- Store probe tokens, notification destinations, HMAC keys, and OTLP headers in
  protected files or a secret manager.
- Avoid command-line secrets because process listings and shell history can
  expose them.
- Rotate anything disclosed in logs, chat, source control, or CI output.

The API must never return private keys, complete profiles, raw stored webhook
URLs, external-validator tokens, or observed public source addresses.

## External validator

The validator is optional and advisory. It is intentionally disabled by
default because it creates an outbound request and may expose a reachable test
surface. The client requires HTTPS with a DNS hostname, rejects private,
loopback, link-local, CGNAT, multicast, unspecified, and tailnet destinations,
and must not follow an unchecked route to a different destination.

The service authenticates, bounds bodies, checks freshness and replay, rate
limits, classifies the direct caller, and connects only back to that verified
source address for port testing. It never accepts an arbitrary callback
address. Trust forwarded-source headers only from an exact reverse-proxy
address.

## Shared bridge

Clients on one Docker bridge can normally communicate directly without
traversing the gateway namespace. The optional host isolation agent adds a
reviewed Layer-3/4 allow policy, but does not prevent Layer-2 spoofing and is not
designed for hostile tenants. Keep the default disabled until every participant
and dependency is inventoried.

## IPv6

Client enrollment is IPv4-only. A provider profile may contain IPv6 tunnel
addresses, but that does not create host source routing or a complete
fail-closed policy for client IPv6. Disable independent IPv6 egress for enrolled
workloads and do not claim IPv6 leak protection.

## Supply chain

Pin immutable container image digests for production, review dependency and
base-image updates, protect CI publishing credentials, and require review for
workflow changes. A mutable `latest` tag is not a rollback artifact.

## Reporting a vulnerability

Do not open a public issue containing secrets, public IPs, or an exploitable
configuration. Use the repository owner's private security-reporting channel
once the public project enables it. Include a minimal reproduction with fake
keys and generalized addresses.
