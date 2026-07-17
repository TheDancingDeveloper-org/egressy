export type Protection = 'enforced' | 'unknown' | 'violated'
export type Availability = 'starting' | 'healthy' | 'degraded' | 'unavailable' | 'recovering'
export type CheckStatus = 'pending' | 'healthy' | 'degraded' | 'failed' | 'unknown'

export interface Check {
  id: string; status: CheckStatus; impact: 'critical' | 'advisory' | 'optional'
  observed_at_unix_ms: number; changed_at_unix_ms: number; reason_code: string
  safe_message: string; consecutive_failures: number; next_attempt_at_unix_ms?: number
}
export interface Transition { sequence: number; timestamp_unix_ms: number; component: string; from_status: CheckStatus; to_status: CheckStatus; reason_code: string; safe_message: string }
export interface RouteIntent { status: 'verified' | 'mismatch' | 'unknown'; ipv4_default_network: string | null; ipv6_default_network: string | null; egress_gateway_priority: number | null; gateway_priorities: Record<string, number | null>; reason_code: string; safe_message: string }
export interface ClientTrafficSample { sampled_at_unix_ms: number; downloaded_bytes: number; uploaded_bytes: number }
export interface ClientTraffic { download_packets: number; downloaded_bytes: number; upload_packets: number; uploaded_bytes: number; sampled_at_unix_ms: number | null; history: ClientTrafficSample[] }
export type UsageIdentitySource = 'explicit_label' | 'compose_service' | 'container_lifetime'
export interface UsageHistoryPoint { bucket_start_unix_ms: number; usage_id: string; usage_id_source: UsageIdentitySource; name: string; download_bytes: number; upload_bytes: number; download_packets: number; upload_packets: number; sample_count: number }
export interface UsageHistory { from_unix_ms: number; to_unix_ms: number; bucket_seconds: number; points: UsageHistoryPoint[]; truncated: boolean }
export interface HistoricalEvent { id: number; timestamp_unix_ms: number; kind: 'transition' | 'port_forward'; component: string; from_status: string | null; to_status: string | null; reason_code: string; safe_message: string; external_port: number | null; port_forward_phase: string | null }
export interface EventHistory { events: HistoricalEvent[]; next_before_id: number | null }
export interface VpnServerLatency { status: 'measured' | 'timeout' | 'unsupported' | 'resolution_failed' | 'unavailable'; sampled_at_unix_ms: number | null; latest_rtt_ms: number | null; recent_min_rtt_ms: number | null; recent_average_rtt_ms: number | null; recent_max_rtt_ms: number | null; loss_ratio: number | null; sample_count: number }
export interface VpnServer { configured_endpoint_host: string | null; configured_endpoint_port: number | null; configured_address_family: string | null; allowed_ips_posture: string; runtime_endpoint_address: string | null; runtime_endpoint_port: number | null; provider_inferred: string | null; region_inferred: string | null; inference_source: string | null; inference_confidence: string | null; active: boolean; latest_handshake_unix: number | null; handshake_age_seconds: number | null; observed_at_unix_ms: number | null; latency: VpnServerLatency }
export interface VpnServerHistoryPoint { bucket_start_unix_ms: number; configured_endpoint_host: string; runtime_endpoint_address: string; runtime_endpoint_port: number; active_sample_count: number; sample_count: number; measured_sample_count: number; minimum_rtt_ms: number | null; average_rtt_ms: number | null; maximum_rtt_ms: number | null }
export interface VpnServerHistory { from_unix_ms: number; to_unix_ms: number; bucket_seconds: number; points: VpnServerHistoryPoint[]; truncated: boolean }
export type NotificationProvider = 'discord' | 'slack' | 'telegram' | 'generic'
export interface NotificationSettings {
  enabled: boolean; provider: NotificationProvider; destination: string | null
  webhook_configured: boolean; telegram_chat_id_configured: boolean; hmac_secret_configured: boolean
  timeout_seconds: number; rtt_threshold_ms: number; alert_stack_started: boolean
  alert_vpn_disconnected: boolean; alert_vpn_reconnected: boolean
  alert_rtt_above_threshold: boolean; alert_diagnostic_failed: boolean
  updated_at_unix_ms: number
}
export interface NotificationSettingsInput {
  enabled: boolean; provider: NotificationProvider; webhook_url: string
  telegram_chat_id: string; hmac_secret: string; timeout_seconds: number
  rtt_threshold_ms: number; alert_stack_started: boolean
  alert_vpn_disconnected: boolean; alert_vpn_reconnected: boolean
  alert_rtt_above_threshold: boolean; alert_diagnostic_failed: boolean
}
export interface IsolationPolicy { schema_version: 1; generated_at_unix_ms: number; network: string; bridge: string; subnet: string; eligible_for_enforcement: boolean; reason_code: string; safe_message: string; issues: string[]; participants: { container_id: string; name: string; isolation_id: string | null; ipv4_address: string; allowances: { destination_id: string; destination_address: string; port: number; protocol: 'tcp' | 'udp' }[] }[] }
export interface RedactedProfile {
  interface: { private_key_configured: boolean; addresses: string[]; dns: string[]; listen_port: number | null; mtu: number | null }
  peers: { public_key: string; preshared_key_configured: boolean; endpoint: { host: string; port: number; address_family: string } | null; allowed_ips: string[]; persistent_keepalive: number | null }[]
  peer_count: number; ipv4_full_tunnel: boolean; full_tunnel_peer: number | null
  warnings: { code: string; field: string; message: string }[]
  apply_kind: 'no_change' | 'dns_reload' | 'sync_conf' | 'sync_conf_and_routes' | 'tunnel_recycle'
}
export interface ManagedRevision { id: string; created_at_unix_ms: number; activated_at_unix_ms: number | null; active: boolean; staged: boolean; metadata: RedactedProfile }
export interface ProfileManagement {
  lifecycle: 'unconfigured' | 'validating' | 'applying' | 'active' | 'degraded' | 'apply_failed' | 'recovering'
  source: 'mounted' | 'gui_managed'; source_mutable: boolean; active_revision: string | null
  active: RedactedProfile | null; revisions: ManagedRevision[]; management_available: boolean
  mutation_authorized: boolean; ipv4_only: boolean
  last_apply: { revision: string | null; classification: string; rolled_back: boolean; safe_message: string } | null
}
export interface Snapshot {
  schema_version: 2; sequence: number; generated_at_unix_ms: number; protection: Protection
  availability: Availability; checks: Record<string, Check>; transitions: Transition[]
  port_forward: { phase: string; requested_target: string | null; external_port: number | null; dnat_installed: boolean; lease_acquired_at_unix_ms: number | null; lease_expires_at_unix_ms: number | null; externally_verified: boolean | null }
  recovery: { active: boolean; attempt: number; reason_code?: string; next_attempt_at_unix_ms?: number }
  external_probe: {
    status: 'unknown' | 'healthy' | 'degraded' | 'unavailable'
    observed_at_unix_ms: number | null
    source_public_non_tailscale: boolean | null
    source_matches_claimed_ip: boolean | null
    tcp_port_reachable: boolean | null
    forwarded_port: number | null
    lease_acquired_at_unix_ms: number | null
    request_started_at_unix_ms: number | null
    reason_code: string | null
    safe_message: string | null
  }
  vpn_server: VpnServer
  isolation_policy: IsolationPolicy
  topology: { network: string; subnet: string; gateway_address: string; host_bridge: string; policy_table: number; client_ipv6_supported: boolean; default_route_verifiable: boolean; client_isolation: string }
  clients: Record<string, { container_id: string; usage_id: string; usage_id_source: UsageIdentitySource; name: string; ipv4_address: string; port_forward_target: boolean; target_port: number | null; compliant: boolean; compliance_message: string; running: boolean; ipv6_address: string | null; networks: string[]; port_forward_label_valid: boolean; route_intent: RouteIntent; traffic: ClientTraffic }>
  traffic: { download_bytes_per_second: number; upload_bytes_per_second: number; downloaded_bytes: number; uploaded_bytes: number; sampled_at_unix_ms?: number }
  last_client_path_success_at_unix_ms?: number
  profile_management: ProfileManagement
}

export const fetchSnapshot = async (): Promise<Snapshot> => {
  const response = await fetch('/api/v2/status')
  if (!response.ok) throw new Error(`status API returned ${response.status}`)
  return response.json()
}

export const fetchUsageHistory = async (hours = 24): Promise<UsageHistory> => {
  const to = Date.now()
  const from = to - hours * 60 * 60 * 1000
  const bucket = hours <= 24 ? 300 : hours <= 24 * 31 ? 3600 : 86400
  const response = await fetch(`/api/v2/history/usage?from_unix_ms=${from}&to_unix_ms=${to}&bucket_seconds=${bucket}&limit=10000`)
  if (!response.ok) throw new Error(`usage history API returned ${response.status}`)
  return response.json()
}

export const fetchEventHistory = async (limit = 200): Promise<EventHistory> => {
  const response = await fetch(`/api/v2/history/events?limit=${limit}`)
  if (!response.ok) throw new Error(`event history API returned ${response.status}`)
  return response.json()
}

export const fetchVpnServerHistory = async (hours = 24): Promise<VpnServerHistory> => {
  const to = Date.now()
  const from = to - hours * 60 * 60 * 1000
  const bucket = hours <= 24 ? 300 : hours <= 24 * 31 ? 3600 : 86400
  const response = await fetch(`/api/v2/history/vpn-server?from_unix_ms=${from}&to_unix_ms=${to}&bucket_seconds=${bucket}&limit=10000`)
  if (!response.ok) throw new Error(`VPN-server history API returned ${response.status}`)
  return response.json()
}

const errorMessage = async (response: Response, fallback: string) => {
  const body = await response.json().catch(() => ({})) as { message?: string }
  return body.message ?? fallback
}

export const fetchNotificationSettings = async (): Promise<NotificationSettings> => {
  const response = await fetch('/api/v2/settings/notifications')
  if (!response.ok) throw new Error(`notification settings API returned ${response.status}`)
  return response.json()
}

export const saveNotificationSettings = async (input: NotificationSettingsInput): Promise<NotificationSettings> => {
  const response = await fetch('/api/v2/settings/notifications', {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input),
  })
  if (!response.ok) throw new Error(await errorMessage(response, `notification settings API returned ${response.status}`))
  return response.json()
}

export const sendTestNotification = async (): Promise<void> => {
  const response = await fetch('/api/v2/settings/notifications/test', { method: 'POST' })
  if (!response.ok) throw new Error('Omnihook could not deliver the test notification')
}

const profileRequest = async <T>(path: string, method: string, token: string, profile?: string): Promise<T> => {
  const response = await fetch(path, {
    method,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: profile === undefined ? undefined : JSON.stringify({ profile }),
    credentials: 'same-origin',
  })
  const body = await response.json().catch(() => ({})) as T & { message?: string }
  if (!response.ok) throw new Error(body.message ?? `profile API returned ${response.status}`)
  return body
}

export const validateManagedProfile = (profile: string, token: string) =>
  profileRequest<RedactedProfile>('/api/v2/wireguard/profiles/validate', 'POST', token, profile)
export const stageManagedProfile = (profile: string, token: string) =>
  profileRequest<ManagedRevision>('/api/v2/wireguard/profiles', 'POST', token, profile)
export const applyManagedProfile = (revision: string, token: string) =>
  profileRequest<{ safe_message: string }>(`/api/v2/wireguard/profiles/${encodeURIComponent(revision)}/apply`, 'POST', token)
export const activateProfileSource = async (source: 'mounted' | 'gui_managed', token: string) => {
  const response = await fetch('/api/v2/wireguard/source', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ source }),
  })
  const body = await response.json().catch(() => ({})) as { safe_message?: string; message?: string }
  if (!response.ok) throw new Error(body.message ?? `profile API returned ${response.status}`)
  return body
}

export interface StructuredProfileInput {
  private_key?: string; addresses: string[]; dns: string[]; listen_port: number | null; mtu: number | null
  peers: { public_key: string; preshared_key?: string; endpoint: string | null; allowed_ips: string[]; persistent_keepalive: number | null }[]
}
export const stageStructuredProfile = async (input: StructuredProfileInput, token: string): Promise<ManagedRevision> => {
  const response = await fetch('/api/v2/wireguard/profiles/edit', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(input),
  })
  const body = await response.json().catch(() => ({})) as ManagedRevision & { message?: string }
  if (!response.ok) throw new Error(body.message ?? `profile API returned ${response.status}`)
  return body
}
