# Changelog

## Unreleased

### Added

- Opt-in IPv6 routing for enrolled clients (`network.ipv6`). When enabled,
  enrolled IPv6 leaves through the tunnel or fails closed; when disabled, the
  host and gateway reject it. See `docs/NETWORKING.md`.

### Changed

- **Compatibility:** the host nftables table (`inet egressy_host`) is replaced
  with one that carries an IPv6 kill switch in both modes. As a result, IPv6
  port publishing for enrolled clients stops working, even with
  `network.ipv6` disabled. Inbound forwarding stays IPv4-only.
- `render-host-setup` now installs the host kill switch first, replacing the
  nftables table in a single transaction, before it enables IPv4 or IPv6
  forwarding or adds routes and rules. IPv6 routes, with `unreachable` first,
  are added before the IPv6 source rule. A failed step can no longer leave
  enrolled traffic forwarded without the kill switch.
