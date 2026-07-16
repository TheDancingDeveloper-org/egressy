import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { App } from './App'

class EventSourceStub { addEventListener() {} close() {} onerror = () => {} }
afterEach(() => vi.restoreAllMocks())

test('distinguishes protection from unavailable service', async () => {
  vi.stubGlobal('EventSource', EventSourceStub)
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ schema_version: 2, sequence: 1, generated_at_unix_ms: Date.now(), protection: 'enforced', availability: 'unavailable', checks: {}, transitions: [], clients: {}, traffic: { download_bytes_per_second: 1024, upload_bytes_per_second: 512, downloaded_bytes: 0, uploaded_bytes: 0 }, port_forward: { phase: 'unavailable', dnat_installed: false }, recovery: { active: false, attempt: 0 }, external_probe: { status: 'degraded', safe_message: 'The external probe request failed' }, topology: { network: 'vpn-egress', subnet: '172.30.0.0/24', client_isolation: 'shared_bridge_not_enforced' } }) }))
  render(<App />)
  expect(await screen.findByText('enforced')).toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'Availability' }).nextElementSibling).toHaveTextContent('unavailable')
  expect(screen.getAllByRole('heading', { name: 'External probe' })[0].nextElementSibling).toHaveTextContent('degraded')
  expect(screen.getByText(/cannot prove an effective/)).toBeInTheDocument()
  expect(screen.getByText(/1.0 KiB\/s/)).toBeInTheDocument()
})

test('shows Docker route-intent mismatch without changing compliance', async () => {
  vi.stubGlobal('EventSource', EventSourceStub)
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({
    schema_version: 2, sequence: 1, generated_at_unix_ms: Date.now(), protection: 'enforced', availability: 'degraded',
    checks: {}, transitions: [], traffic: {}, port_forward: { phase: 'disabled', dnat_installed: false }, recovery: { active: false, attempt: 0 }, external_probe: { status: 'unknown' },
    topology: { network: 'vpn-egress', subnet: '172.30.0.0/24', client_isolation: 'shared_bridge_not_enforced' },
    clients: { one: { container_id: 'one', name: 'dual-network', ipv4_address: '172.30.0.10', port_forward_target: false, target_port: null, compliant: false, compliance_message: 'Docker declares an alternate IPv4 default network', running: true, ipv6_address: null, networks: ['app', 'vpn-egress'], port_forward_label_valid: true, route_intent: { status: 'mismatch', ipv4_default_network: 'app', ipv6_default_network: null, egress_gateway_priority: 100, gateway_priorities: { app: 200, 'vpn-egress': 100 }, reason_code: 'route_intent.alternate_selected', safe_message: 'Docker declares app as the selected IPv4 default.' }, traffic: { download_packets: 3, downloaded_bytes: 2048, upload_packets: 4, uploaded_bytes: 1024, sampled_at_unix_ms: Date.now(), history: [{ sampled_at_unix_ms: Date.now(), downloaded_bytes: 2048, uploaded_bytes: 1024 }] } } }
  }) }))
  window.location.hash = '#clients'
  render(<App />)
  expect(await screen.findByText('dual-network')).toBeInTheDocument()
  expect(screen.getByText('mismatch')).toBeInTheDocument()
  expect(screen.getByText('non-compliant')).toBeInTheDocument()
  expect(screen.getByText('↓ 2.0 KiB')).toBeInTheDocument()
  expect(screen.getByText('↑ 1.0 KiB')).toBeInTheDocument()
  expect(screen.getByText(/reports declared route intent only/)).toBeInTheDocument()
})

test('loads app-owned usage and event history with range controls', async () => {
  vi.stubGlobal('EventSource', EventSourceStub)
  const snapshot = { schema_version: 2, sequence: 1, generated_at_unix_ms: Date.now(), protection: 'enforced', availability: 'healthy', checks: {}, transitions: [], clients: {}, traffic: {}, port_forward: { phase: 'disabled', dnat_installed: false }, recovery: { active: false, attempt: 0 }, external_probe: { status: 'unknown' }, vpn_server: { active: true, configured_endpoint_host: 'us-ny.protonvpn.net', configured_endpoint_port: 51820, configured_address_family: 'hostname', allowed_ips_posture: 'ipv4_default', runtime_endpoint_address: '198.51.100.10', runtime_endpoint_port: 51820, provider_inferred: 'Proton VPN', region_inferred: 'US', inference_source: 'configured_endpoint_hostname', inference_confidence: 'low', latest_handshake_unix: null, handshake_age_seconds: 2, observed_at_unix_ms: Date.now(), latency: { status: 'measured', sampled_at_unix_ms: Date.now(), latest_rtt_ms: 12.3, recent_min_rtt_ms: 10, recent_average_rtt_ms: 12.3, recent_max_rtt_ms: 15, loss_ratio: 0, sample_count: 3 } }, topology: { network: 'vpn-egress', subnet: '172.30.0.0/24', client_isolation: 'shared_bridge_not_enforced' } }
  const fetchMock = vi.fn((input: string | URL | Request) => {
    const url = String(input)
    if (url.startsWith('/api/v2/history/usage')) return Promise.resolve({ ok: true, json: async () => ({ from_unix_ms: 1, to_unix_ms: 2, bucket_seconds: 300, truncated: false, points: [{ bucket_start_unix_ms: 1, usage_id: 'media/qbit', usage_id_source: 'explicit_label', name: 'qbittorrent', download_bytes: 4096, upload_bytes: 1024, download_packets: 4, upload_packets: 1, sample_count: 3 }] }) })
    if (url.startsWith('/api/v2/history/events')) return Promise.resolve({ ok: true, json: async () => ({ events: [{ id: 1, timestamp_unix_ms: Date.now(), kind: 'transition', component: 'wireguard.handshake', from_status: 'pending', to_status: 'healthy', reason_code: 'wireguard.handshake_recent', safe_message: 'Recent handshake observed', external_port: null, port_forward_phase: null }], next_before_id: null }) })
    if (url.startsWith('/api/v2/history/vpn-server')) return Promise.resolve({ ok: true, json: async () => ({ from_unix_ms: 1, to_unix_ms: 2, bucket_seconds: 300, truncated: false, points: [{ bucket_start_unix_ms: Date.now(), configured_endpoint_host: 'us-ny.protonvpn.net', runtime_endpoint_address: '198.51.100.10', runtime_endpoint_port: 51820, active_sample_count: 3, sample_count: 3, measured_sample_count: 3, minimum_rtt_ms: 10, average_rtt_ms: 12.3, maximum_rtt_ms: 15 }] }) })
    return Promise.resolve({ ok: true, json: async () => snapshot })
  })
  vi.stubGlobal('fetch', fetchMock)
  window.location.hash = '#history'
  render(<App />)
  expect(await screen.findByText('qbittorrent')).toBeInTheDocument()
  expect(screen.getByText('media/qbit')).toBeInTheDocument()
  expect(screen.getByText('↓ 4.0 KiB')).toBeInTheDocument()
  expect(screen.getByText('Recent handshake observed')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '7 days' }))
  expect(await screen.findByRole('button', { name: '7 days' })).toHaveClass('active')
})

test('edits GUI-managed Omnihook settings without rendering stored secrets', async () => {
  vi.stubGlobal('EventSource', EventSourceStub)
  const snapshot = { schema_version: 2, sequence: 1, generated_at_unix_ms: Date.now(), protection: 'enforced', availability: 'healthy', checks: {}, transitions: [], clients: {}, traffic: {}, port_forward: { phase: 'disabled', dnat_installed: false }, recovery: { active: false, attempt: 0 }, external_probe: { status: 'unknown' }, topology: { network: 'vpn-egress', subnet: '172.30.0.0/24', client_isolation: 'shared_bridge_not_enforced' } }
  const settings = { enabled: true, provider: 'discord', destination: 'https://discord.com/…', webhook_configured: true, telegram_chat_id_configured: false, hmac_secret_configured: false, timeout_seconds: 10, rtt_threshold_ms: 100, alert_stack_started: true, alert_vpn_disconnected: true, alert_vpn_reconnected: true, alert_rtt_above_threshold: true, alert_diagnostic_failed: true, updated_at_unix_ms: 1 }
  const fetchMock = vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v2/settings/notifications' && !init?.method) return Promise.resolve({ ok: true, json: async () => settings })
    if (url === '/api/v2/settings/notifications' && init?.method === 'PUT') return Promise.resolve({ ok: true, json: async () => settings })
    return Promise.resolve({ ok: true, json: async () => snapshot })
  })
  vi.stubGlobal('fetch', fetchMock)
  window.location.hash = '#notifications'
  render(<App />)
  expect(await screen.findByText('Configured: https://discord.com/…. Leave blank to retain it.')).toBeInTheDocument()
  expect(screen.getByLabelText('VPN Disconnected')).toBeChecked()
  fireEvent.change(screen.getByLabelText('RTT threshold (ms)'), { target: { value: '75' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save settings' }))
  expect(await screen.findByText('Omnihook settings saved.')).toBeInTheDocument()
  const put = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT')
  expect(JSON.parse(String(put?.[1]?.body)).rtt_threshold_ms).toBe(75)
})
