import type { NotificationSettings, Snapshot } from './api'

const now = () => Date.now()

const check = (id: string, status: 'healthy' | 'degraded' = 'healthy', message = 'Healthy') => ({
  id, status, impact: id === 'external_probe' ? 'advisory' as const : 'critical' as const,
  observed_at_unix_ms: now() - 2_000, changed_at_unix_ms: now() - 3_600_000,
  reason_code: `${id}.${status}`, safe_message: message, consecutive_failures: 0,
})

const snapshot = (): Snapshot => ({
  schema_version: 2,
  sequence: Math.floor(now() / 5_000),
  generated_at_unix_ms: now(),
  protection: 'enforced',
  availability: 'healthy',
  checks: {
    'gateway.firewall': check('gateway.firewall', 'healthy', 'Fail-closed gateway policy is installed'),
    'gateway.routes': check('gateway.routes', 'healthy', 'Source policy routes are installed'),
    'wireguard.handshake': check('wireguard.handshake', 'healthy', 'A recent WireGuard handshake was observed'),
    'client_path.dns': check('client_path.dns', 'healthy', 'UDP and TCP DNS passed through the tunnel'),
    'client_path.egress': check('client_path.egress', 'healthy', 'HTTPS egress matched the expected provider identity'),
    external_probe: check('external_probe', 'healthy', 'Independent internet-path validation succeeded'),
    'history.persistence': { ...check('history.persistence'), impact: 'advisory' },
  },
  transitions: [
    { sequence: 21, timestamp_unix_ms: now() - 90_000, component: 'wireguard.handshake', from_status: 'degraded', to_status: 'healthy', reason_code: 'wireguard.handshake_recent', safe_message: 'A recent WireGuard handshake was observed' },
    { sequence: 20, timestamp_unix_ms: now() - 125_000, component: 'client_path.egress', from_status: 'pending', to_status: 'healthy', reason_code: 'client_path.egress_healthy', safe_message: 'Enrolled-path HTTPS validation succeeded' },
  ],
  port_forward: {
    phase: 'verified', requested_target: 'download-client:6881', external_port: 45123,
    dnat_installed: true, lease_acquired_at_unix_ms: now() - 15_000,
    lease_expires_at_unix_ms: now() + 45_000, externally_verified: true,
  },
  recovery: { active: false, attempt: 0 },
  external_probe: {
    status: 'healthy', observed_at_unix_ms: now() - 10_000,
    source_public_non_tailscale: true, source_matches_claimed_ip: true,
    tcp_port_reachable: true, forwarded_port: 45123,
    lease_acquired_at_unix_ms: now() - 15_000, request_started_at_unix_ms: now() - 10_400,
    reason_code: 'external_probe.healthy', safe_message: 'Independent internet-path validation succeeded',
  },
  vpn_server: {
    configured_endpoint_host: 'vpn.example.net', configured_endpoint_port: 51820,
    configured_address_family: 'hostname', allowed_ips_posture: 'ipv4_default',
    runtime_endpoint_address: '198.51.100.24', runtime_endpoint_port: 51820,
    provider_inferred: 'Example VPN', region_inferred: 'Example region',
    inference_source: 'configured_endpoint_hostname', inference_confidence: 'low',
    active: true, latest_handshake_unix: Math.floor(now() / 1000) - 2,
    handshake_age_seconds: 2, observed_at_unix_ms: now() - 2_000,
    latency: { status: 'measured', sampled_at_unix_ms: now() - 2_000, latest_rtt_ms: 18.4, recent_min_rtt_ms: 16.8, recent_average_rtt_ms: 19.2, recent_max_rtt_ms: 24.1, loss_ratio: 0, sample_count: 20 },
  },
  isolation_policy: {
    schema_version: 1, generated_at_unix_ms: now(), network: 'vpn-egress', bridge: 'br-vpn-egress',
    subnet: '172.30.0.0/24', eligible_for_enforcement: true,
    reason_code: 'isolation.policy_complete', safe_message: 'The example participant policy is complete', issues: [],
    participants: [
      { container_id: 'demo-client', name: 'download-client', isolation_id: 'download-client', ipv4_address: '172.30.0.10', allowances: [] },
      { container_id: 'demo-probe', name: 'egressy-probe', isolation_id: 'egressy-probe', ipv4_address: '172.30.0.5', allowances: [] },
    ],
  },
  topology: {
    network: 'vpn-egress', subnet: '172.30.0.0/24', gateway_address: '172.30.0.2',
    host_bridge: 'br-vpn-egress', policy_table: 200, client_ipv6_supported: false,
    default_route_verifiable: false, client_isolation: 'shared_bridge_policy_available',
  },
  clients: {
    'demo-client': {
      container_id: 'demo-client', usage_id: 'example/download-client', usage_id_source: 'explicit_label',
      name: 'download-client', ipv4_address: '172.30.0.10', port_forward_target: true,
      target_port: 6881, compliant: true, compliance_message: 'Client enrollment is compliant',
      running: true, ipv6_address: null, networks: ['app', 'vpn-egress'], port_forward_label_valid: true,
      route_intent: { status: 'verified', ipv4_default_network: 'vpn-egress', ipv6_default_network: null, egress_gateway_priority: 100, gateway_priorities: { app: 0, 'vpn-egress': 100 }, reason_code: 'route_intent.egress_selected', safe_message: 'Docker declares vpn-egress as the selected IPv4 default' },
      traffic: { download_packets: 18231, downloaded_bytes: 987_654_321, upload_packets: 8932, uploaded_bytes: 123_456_789, sampled_at_unix_ms: now(), history: Array.from({ length: 10 }, (_, index) => ({ sampled_at_unix_ms: now() - (9 - index) * 5_000, downloaded_bytes: 985_000_000 + index * 294_925, uploaded_bytes: 122_000_000 + index * 161_865 })) },
    },
    'demo-probe': {
      container_id: 'demo-probe', usage_id: 'example/probe', usage_id_source: 'explicit_label',
      name: 'egressy-probe', ipv4_address: '172.30.0.5', port_forward_target: false,
      target_port: null, compliant: true, compliance_message: 'Client enrollment is compliant',
      running: true, ipv6_address: null, networks: ['vpn-egress'], port_forward_label_valid: true,
      route_intent: { status: 'verified', ipv4_default_network: 'vpn-egress', ipv6_default_network: null, egress_gateway_priority: 100, gateway_priorities: { 'vpn-egress': 100 }, reason_code: 'route_intent.egress_selected', safe_message: 'Docker declares vpn-egress as the selected IPv4 default' },
      traffic: { download_packets: 231, downloaded_bytes: 1_654_321, upload_packets: 220, uploaded_bytes: 1_234_567, sampled_at_unix_ms: now(), history: [] },
    },
  },
  traffic: {
    download_bytes_per_second: 7_420_000 + Math.round(Math.sin(now() / 4_000) * 1_200_000),
    upload_bytes_per_second: 1_180_000 + Math.round(Math.cos(now() / 5_000) * 280_000),
    downloaded_bytes: 989_308_642, uploaded_bytes: 124_691_356, sampled_at_unix_ms: now(),
  },
  last_client_path_success_at_unix_ms: now() - 8_000,
})

const notificationSettings: NotificationSettings = {
  enabled: false, provider: 'generic', destination: null, webhook_configured: false,
  telegram_chat_id_configured: false, hmac_secret_configured: false,
  timeout_seconds: 10, rtt_threshold_ms: 100, alert_stack_started: true,
  alert_vpn_disconnected: true, alert_vpn_reconnected: true,
  alert_rtt_above_threshold: true, alert_diagnostic_failed: true, updated_at_unix_ms: now(),
}

const response = (body: unknown, status = 200) => Promise.resolve(new Response(
  status === 204 ? null : JSON.stringify(body),
  { status, headers: { 'content-type': 'application/json' } },
))

export const installDemoApi = () => {
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(href, window.location.href)
    if (url.pathname.endsWith('/api/v2/status')) return response(snapshot())
    if (url.pathname.endsWith('/api/v2/history/usage')) return response({
      from_unix_ms: now() - 86_400_000, to_unix_ms: now(), bucket_seconds: 300, truncated: false,
      points: [{ bucket_start_unix_ms: now() - 300_000, usage_id: 'example/download-client', usage_id_source: 'explicit_label', name: 'download-client', download_bytes: 987_654_321, upload_bytes: 123_456_789, download_packets: 18231, upload_packets: 8932, sample_count: 288 }],
    })
    if (url.pathname.endsWith('/api/v2/history/events')) return response({ events: snapshot().transitions.map((event, index) => ({ id: index + 1, timestamp_unix_ms: event.timestamp_unix_ms, kind: 'transition', component: event.component, from_status: event.from_status, to_status: event.to_status, reason_code: event.reason_code, safe_message: event.safe_message, external_port: null, port_forward_phase: null })), next_before_id: null })
    if (url.pathname.endsWith('/api/v2/history/vpn-server')) return response({ from_unix_ms: now() - 86_400_000, to_unix_ms: now(), bucket_seconds: 300, truncated: false, points: [{ bucket_start_unix_ms: now() - 300_000, configured_endpoint_host: 'vpn.example.net', runtime_endpoint_address: '198.51.100.24', runtime_endpoint_port: 51820, active_sample_count: 60, sample_count: 60, measured_sample_count: 59, minimum_rtt_ms: 16.8, average_rtt_ms: 19.2, maximum_rtt_ms: 24.1 }] })
    if (url.pathname.endsWith('/api/v2/settings/notifications/test')) return response({ error: 'demo_mode' }, 409)
    if (url.pathname.endsWith('/api/v2/settings/notifications')) return response(init?.method === 'PUT' ? { ...notificationSettings, ...JSON.parse(String(init.body)), destination: null, webhook_configured: false, updated_at_unix_ms: now() } : notificationSettings)
    return response({ error: 'not_found' }, 404)
  }) as typeof window.fetch

  class DemoEventSource {
    onerror: ((event: Event) => void) | null = null
    close() {}
    addEventListener() {}
  }
  window.EventSource = DemoEventSource as unknown as typeof EventSource
}
