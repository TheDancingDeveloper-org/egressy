import { expect, test } from '@playwright/test'

const snapshot = {
  schema_version: 2, sequence: 1, generated_at_unix_ms: Date.now(), protection: 'enforced',
  availability: 'unavailable', checks: {}, transitions: [], clients: {
    dual: { container_id: 'dual', name: 'dual-network', ipv4_address: '172.30.0.10', port_forward_target: false, target_port: null, compliant: false, compliance_message: 'Docker declares an alternate IPv4 default network', running: true, ipv6_address: null, networks: ['app', 'vpn-egress'], port_forward_label_valid: true, route_intent: { status: 'mismatch', ipv4_default_network: 'app', ipv6_default_network: null, egress_gateway_priority: 100, gateway_priorities: { app: 200, 'vpn-egress': 100 }, reason_code: 'route_intent.alternate_selected', safe_message: 'Docker declares app as the selected IPv4 default.' }, traffic: { download_packets: 3, downloaded_bytes: 2048, upload_packets: 4, uploaded_bytes: 1024, sampled_at_unix_ms: Date.now(), history: [{ sampled_at_unix_ms: Date.now(), downloaded_bytes: 2048, uploaded_bytes: 1024 }] } }
  },
  traffic: { download_bytes_per_second: 1024, upload_bytes_per_second: 512, downloaded_bytes: 0, uploaded_bytes: 0 },
  port_forward: { phase: 'verified', dnat_installed: true, externally_verified: true },
  port_forwards: {
    'personal-arr/qbittorrent': { phase: 'verified', requested_target: 'qbittorrent', internal_port: 6881, external_port: 36448, dnat_installed: true, externally_verified: true },
    'prod-indexarr/indexarr': { phase: 'verified', requested_target: 'indexarr', internal_port: 6882, external_port: 39021, dnat_installed: true, externally_verified: true },
  },
  recovery: { active: true, attempt: 2, next_attempt_at_unix_ms: Date.now() + 5000 },
  external_probe: { status: 'healthy', source_public_non_tailscale: true, tcp_port_reachable: true, safe_message: 'Public HTTPS path succeeded and the source was public and non-Tailscale.' },
  topology: { network: 'vpn-egress', subnet: '172.30.0.0/24', gateway_address: '172.30.0.2', host_bridge: 'br-vpn-egress', policy_table: 200, client_ipv6_supported: false, default_route_verifiable: false, client_isolation: 'shared_bridge_not_enforced' }
}

test('renders protected-but-unavailable and operational diagnostics', async ({ page }) => {
  await page.route('**/api/v2/status', route => route.fulfill({ json: snapshot }))
  await page.route('**/api/v2/events', route => route.fulfill({ status: 204 }))
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Protection' }).locator('..')).toContainText('protected')
  await expect(page.getByRole('heading', { name: 'VPN connection' }).locator('..')).toContainText('unavailable')
  await expect(page.getByRole('heading', { name: 'Recovery' }).locator('..')).toContainText('attempt 2')

  await page.getByRole('link', { name: 'Port forwarding' }).click()
  await expect(page.getByRole('heading', { name: 'Primary forwarded port' }).locator('..')).toContainText('reachable')
  await expect(page.getByRole('heading', { name: 'Reachable from the internet' }).locator('..')).toContainText('yes')
  await expect(page.getByRole('region', { name: 'Port forwarding' })).toContainText('prod-indexarr/indexarr')
  await expect(page.getByRole('region', { name: 'Port forwarding' })).toContainText('39021')

  await page.getByRole('link', { name: 'Clients' }).click()
  await expect(page.getByText(/cannot prove the route inside/)).toBeVisible()
  await expect(page.getByText('incorrect route')).toBeVisible()
  await expect(page.getByText('configuration problem')).toBeVisible()
  await expect(page.getByText('↓ 2.0 KiB')).toBeVisible()
  await page.getByText('1 changed samples').click()
  await expect(page.locator('details')).toContainText('↓2.0 KiB ↑1.0 KiB')

  await page.getByRole('link', { name: 'External probe' }).click()
  await expect(page.locator('#external-probe')).toContainText('working')
  await expect(page.locator('#external-probe')).toContainText('Public HTTPS path succeeded')
})

test('configures Omnihook alert hooks from the dashboard', async ({ page }) => {
  const settings = { enabled: false, provider: 'discord', destination: null, webhook_configured: false, telegram_chat_id_configured: false, hmac_secret_configured: false, timeout_seconds: 10, rtt_threshold_ms: 100, alert_stack_started: true, alert_vpn_disconnected: true, alert_vpn_reconnected: true, alert_rtt_above_threshold: true, alert_diagnostic_failed: true, updated_at_unix_ms: 0 }
  await page.route('**/api/v2/status', route => route.fulfill({ json: snapshot }))
  await page.route('**/api/v2/events', route => route.fulfill({ status: 204 }))
  await page.route('**/api/v2/settings/notifications', async route => {
    if (route.request().method() === 'PUT') return route.fulfill({ json: { ...settings, enabled: true, destination: 'https://discord.com/…', webhook_configured: true } })
    return route.fulfill({ json: settings })
  })
  await page.goto('/#notifications')
  await page.getByLabel('Enable notifications').check()
  await page.getByLabel('Webhook URL').fill('https://discord.com/api/webhooks/example/test')
  await page.getByLabel('RTT threshold (ms)').fill('75')
  await page.getByRole('button', { name: 'Save settings' }).click()
  await expect(page.getByText('Omnihook settings saved.')).toBeVisible()
})
