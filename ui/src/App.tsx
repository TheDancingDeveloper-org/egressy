import { useEffect, useState, type ReactElement, type MouseEvent as ReactMouseEvent } from 'react'
import { EventHistory, fetchEventHistory, fetchSnapshot, fetchUsageHistory, fetchVpnServerHistory, Snapshot, UsageHistory, VpnServerHistory } from './api'
import { ThroughputChart, TrafficSample, formatRate } from './ThroughputChart'
import { NotificationsPanel } from './NotificationsPanel'

const formatBytes = (bytes: number) => formatRate(bytes).replace('/s', '')

type Tone = 'ok' | 'warn' | 'crit' | 'mut'
const TONES: Record<string, Tone> = {
  healthy: 'ok', enforced: 'ok',
  verified: 'ok', mismatch: 'crit',
  degraded: 'warn', starting: 'warn', recovering: 'warn', unknown: 'warn', pending: 'warn',
  failed: 'crit', unavailable: 'crit', violated: 'crit',
}
const tone = (status?: string): Tone => TONES[status ?? ''] ?? 'mut'

const ago = (now: number, timestamp?: number | null) => {
  if (!timestamp) return 'not yet observed'
  const seconds = Math.max(0, Math.round((now - timestamp) / 1000))
  if (seconds < 90) return `${seconds} s ago`
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`
  return new Date(timestamp).toLocaleString()
}
const clock = (timestamp: number) => new Date(timestamp).toLocaleTimeString([], { hour12: false })

const PATH_CHECKS: [id: string, label: string][] = [
  ['gateway.firewall', 'Firewall'],
  ['gateway.routes', 'Routes'],
  ['wireguard.handshake', 'Handshake'],
  ['client_path.dns', 'Client DNS'],
  ['client_path.egress', 'Client egress'],
  ['external_probe', 'External probe'],
]

const VIEWS = [
  ['overview', 'Overview'], ['path', 'Data path'], ['clients', 'Clients'],
  ['forwarding', 'Port forwarding'], ['server', 'VPN server'], ['probe', 'External probe'],
  ['history', 'History'], ['notifications', 'Notifications'], ['diagnostics', 'Diagnostics'], ['events', 'Events'],
] as const
type ViewId = typeof VIEWS[number][0]

const ICONS: Record<ViewId, ReactElement> = {
  overview: <><rect x="1" y="1" width="5.4" height="5.4" rx="1.2" /><rect x="8.6" y="1" width="5.4" height="5.4" rx="1.2" /><rect x="1" y="8.6" width="5.4" height="5.4" rx="1.2" /><rect x="8.6" y="8.6" width="5.4" height="5.4" rx="1.2" /></>,
  path: <><circle cx="2.6" cy="7.5" r="1.7" /><circle cx="12.4" cy="7.5" r="1.7" /><path d="M4.5 7.5 h6 M8.6 5.6 l2 1.9-2 1.9" /></>,
  clients: <><rect x="1.5" y="2" width="12" height="7.5" rx="1.4" /><path d="M5 12.8 h5 M7.5 9.5 v3.3" /></>,
  forwarding: <><path d="M1.5 7.5 h9 M7.5 4.5 l3.2 3-3.2 3" /><path d="M12.8 3 v9" /></>,
  server: <><circle cx="7.5" cy="7.5" r="5.5" /><path d="M4.5 7.5 h6 M7.5 4.5 v6" /></>,
  probe: <><circle cx="7.5" cy="7.5" r="6" /><path d="M1.5 7.5 h12 M7.5 1.5 c2.4 2.2 2.4 9.8 0 12 M7.5 1.5 c-2.4 2.2-2.4 9.8 0 12" /></>,
  history: <><path d="M2 3.5 h11 M2 7.5 h11 M2 11.5 h11" /><path d="M4 2 v3 M8 6 v3 M11 10 v3" /></>,
  notifications: <><path d="M3 6 a4.5 4.5 0 0 1 9 0 v3 l1.4 2 H1.6 L3 9 Z" /><path d="M6 13 h3" /></>,
  diagnostics: <path d="M1 8 h3 l1.6-4.4 L9 11.4 10.6 8 H14" strokeLinecap="round" strokeLinejoin="round" />,
  events: <path d="M2 3.5 h11 M2 7.5 h11 M2 11.5 h7" strokeLinecap="round" />,
}

const NavIcon = ({ view }: { view: ViewId }) =>
  <svg width="15" height="15" viewBox="0 0 15 15" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">{ICONS[view]}</svg>

const InfoGlyph = () =>
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.3" aria-hidden="true"><circle cx="7" cy="7" r="6" /><path d="M7 4 v3.4 M7 9.8 v.4" /></svg>
const WarnGlyph = () =>
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.3" aria-hidden="true"><path d="M7 1.5 L13 12 H1 Z" strokeLinejoin="round" /><path d="M7 5.5 v3 M7 10.4 v.4" /></svg>

const StatusPill = ({ status }: { status?: string }) =>
  <span className={`pill ${tone(status)}`}>{status ?? 'unknown'}</span>

const triState = (value: boolean | null | undefined, yes: string, no: string) =>
  value == null ? <span className="pill mut">not tested</span>
    : <span className={`pill ${value ? 'ok' : 'crit'}`}>{value ? yes : no}</span>

const initialView = (): ViewId => {
  const hash = window.location.hash.slice(1)
  return (VIEWS.some(([id]) => id === hash) ? hash : 'overview') as ViewId
}

export function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>()
  const [error, setError] = useState<string>()
  const [stale, setStale] = useState(false)
  const [view, setView] = useState<ViewId>(initialView)
  const [samples, setSamples] = useState<TrafficSample[]>([])
  const [historyHours, setHistoryHours] = useState(24)
  const [usageHistory, setUsageHistory] = useState<UsageHistory>()
  const [eventHistory, setEventHistory] = useState<EventHistory>()
  const [vpnServerHistory, setVpnServerHistory] = useState<VpnServerHistory>()
  const [historyError, setHistoryError] = useState<string>()
  const [now, setNow] = useState(Date.now)

  useEffect(() => {
    let mounted = true
    const refresh = () => fetchSnapshot().then(value => {
      if (!mounted) return
      setSnapshot(value); setError(undefined)
      setStale(Date.now() - value.generated_at_unix_ms > 30_000)
      const at = value.traffic?.sampled_at_unix_ms ?? value.generated_at_unix_ms
      setSamples(prev => prev.length && prev[prev.length - 1].at_unix_ms === at ? prev
        : [...prev, { at_unix_ms: at, download: value.traffic?.download_bytes_per_second ?? 0, upload: value.traffic?.upload_bytes_per_second ?? 0 }].slice(-120))
    }).catch(() => mounted && setError('Status API is disconnected. Previously displayed state may be stale.'))
    refresh()
    const poll = window.setInterval(refresh, 5_000)
    const tick = window.setInterval(() => setNow(Date.now()), 1_000)
    const events = new EventSource('/api/v2/events')
    events.addEventListener('transition', refresh)
    events.onerror = () => setStale(true)
    const onHash = () => setView(initialView())
    window.addEventListener('hashchange', onHash)
    return () => { mounted = false; clearInterval(poll); clearInterval(tick); events.close(); window.removeEventListener('hashchange', onHash) }
  }, [])

  useEffect(() => {
    if (view !== 'history') return
    let mounted = true
    setHistoryError(undefined)
    Promise.all([fetchUsageHistory(historyHours), fetchEventHistory(), fetchVpnServerHistory(historyHours)])
      .then(([usage, events, serverHistory]) => {
        if (!mounted) return
        setUsageHistory(usage); setEventHistory(events); setVpnServerHistory(serverHistory)
      })
      .catch(() => mounted && setHistoryError('Local history is unavailable. Live status remains operational.'))
    return () => { mounted = false }
  }, [view, historyHours])

  if (!snapshot) return <div className="boot"><h1>Egressy</h1><div role="status" className="notice">{error ?? 'Loading operational state…'}</div></div>

  const clients = Object.values(snapshot.clients ?? {})
  const checks = Object.values(snapshot.checks)
  const transitions = [...snapshot.transitions].reverse()
  const probe = snapshot.external_probe
  const forward = snapshot.port_forward
  const vpnServer = snapshot.vpn_server
  const usageByClient = [...(usageHistory?.points ?? []).reduce((totals, point) => {
    const existing = totals.get(point.usage_id) ?? { usage_id: point.usage_id, source: point.usage_id_source, name: point.name, down: 0, up: 0, samples: 0 }
    existing.down += point.download_bytes; existing.up += point.upload_bytes; existing.samples += point.sample_count
    totals.set(point.usage_id, existing)
    return totals
  }, new Map<string, { usage_id: string; source: string; name: string; down: number; up: number; samples: number }>()).values()]
    .sort((left, right) => right.down + right.up - (left.down + left.up))
  const link: [Tone, string] = error ? ['crit', 'Disconnected'] : stale ? ['warn', 'Stale'] : ['ok', 'Live']
  const snapshotAge = ago(now, snapshot.generated_at_unix_ms)

  const nav = (target: ViewId) => (event: ReactMouseEvent) => {
    event.preventDefault()
    history.replaceState(null, '', `#${target}`)
    setView(target)
  }

  const pipeline = (detailed: boolean) => <div className="pipe">
    {PATH_CHECKS.map(([id, label]) => {
      const check = snapshot.checks[id]
      return <div key={id} className={`node ${tone(check?.status)}`}>
        <div className="dot" />
        <b>{detailed ? id : label}</b>
        <span className="st">{check?.status ?? 'pending'}</span>
        <small>{check?.safe_message ?? 'Waiting for observation'}</small>
      </div>
    })}
  </div>

  const feed = (items: typeof transitions) => <div className="feed">
    {items.length === 0 && <div className="empty">No transitions recorded yet</div>}
    {items.map(item => <div className="ev" key={item.sequence}>
      <time>{clock(item.timestamp_unix_ms)}</time>
      <span className={`mark ${tone(item.to_status)}`} />
      <span className="what"><b>{item.component}</b>
        <span className="arrow">{item.from_status} → {item.to_status}</span>
        <span className="msg">{item.safe_message}</span></span>
    </div>)}
  </div>

  return <div className="shell">
    <aside>
      <div className="brand">
        <svg width="26" height="26" viewBox="0 0 26 26" fill="none" aria-hidden="true">
          <path d="M13 2 L23 6 V13 C23 19 18.5 23 13 24.5 C7.5 23 3 19 3 13 V6 Z" stroke="#3fd68f" strokeWidth="1.6" fill="rgba(63,214,143,.07)" />
          <path d="M8 13.5 H12 L14 10 L16 16 L17.5 13.5 H18.5" stroke="#67d3f0" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div><b>Egressy</b><small>VPN egress gateway</small></div>
      </div>
      <nav className="side" aria-label="Sections">
        {VIEWS.map(([id, label]) =>
          <a key={id} href={`#${id}`} className={view === id ? 'active' : undefined} onClick={nav(id)}>
            <NavIcon view={id} />{label}</a>)}
      </nav>
      <div className="side-foot">Egressy · AGPL-3.0</div>
    </aside>

    <div>
      <div className="top">
        <span className="fact">net <span className="id-val">{snapshot.topology.network}</span></span><span className="sep">|</span>
        <span className="fact">{snapshot.topology.subnet}</span>
        {snapshot.topology.gateway_address && <><span className="sep">|</span><span className="fact">gw <span className="id-val">{snapshot.topology.gateway_address}</span></span></>}
        {snapshot.topology.host_bridge && <><span className="sep">|</span><span className="fact">{snapshot.topology.host_bridge}</span></>}
        <span className="sep">|</span>
        <span className="fact">seq #{snapshot.sequence}</span>
        <div className="live">
          <span className="clock">updated {snapshotAge}</span>
          <span className={`live-pill ${link[0]}`} role="status"><span className="live-dot" />{link[1]}</span>
        </div>
      </div>

      <div className="content">
        {import.meta.env.VITE_DEMO === 'true' && <div role="status" className="notice" style={{ marginBottom: 14, marginTop: 0 }}>
          <InfoGlyph />Interactive demo — all data is generated in this browser and no gateway is connected.
        </div>}
        {(error || stale) && <div role="alert" className="notice warn" style={{ marginBottom: 14, marginTop: 0 }}>
          <WarnGlyph />{error ?? 'Live events are disconnected or the snapshot is stale.'}</div>}

        <section className={view === 'overview' ? 'view on' : 'view'} aria-labelledby="h-overview">
          <div className="view-head"><h1 id="h-overview">Overview</h1><span className="updated">snapshot {snapshotAge}</span></div>
          <div className="grid tiles">
            <div className="card">
              <h3>Protection</h3>
              <StatusPill status={snapshot.protection} />
              <p className="sub">{snapshot.protection === 'enforced' ? 'Fail-closed policy is observed.' : 'Protection could not be confirmed.'}</p>
            </div>
            <div className="card">
              <h3>Availability</h3>
              <StatusPill status={snapshot.availability} />
              <p className="sub">Availability is tracked separately from leak protection.</p>
            </div>
            <div className="card">
              <h3>External probe</h3>
              <StatusPill status={probe?.status} />
              <p className="sub">{probe?.safe_message ?? 'No external probe result yet.'}</p>
            </div>
            <div className="card">
              <h3>Client-path validation</h3>
              <div className={snapshot.last_client_path_success_at_unix_ms ? 'big' : 'big dim'}>{ago(now, snapshot.last_client_path_success_at_unix_ms)}</div>
              <p className="sub">DNS and egress verified through the tunnel.</p>
            </div>
            <div className="card">
              <h3>Recovery</h3>
              {snapshot.recovery.active
                ? <><span className="pill warn">attempt {snapshot.recovery.attempt}</span>
                  <p className="sub">{snapshot.recovery.next_attempt_at_unix_ms ? `Next attempt ${ago(now, snapshot.recovery.next_attempt_at_unix_ms).replace(' ago', '')}` : 'Recovery cycle in progress.'}</p></>
                : <><div className="big dim">inactive</div><p className="sub">No recovery cycle running.</p></>}
            </div>
          </div>

          <div className="card chart-card">
            <div className="chart-head">
              <h3 style={{ margin: 0 }}>Throughput · WireGuard</h3>
              <span className="hero down">↓ {formatRate(snapshot.traffic?.download_bytes_per_second ?? 0)}</span>
              <span className="hero up">↑ {formatRate(snapshot.traffic?.upload_bytes_per_second ?? 0)}</span>
              <div className="legend">
                <span><i style={{ background: 'var(--s1)' }} />Download</span>
                <span><i style={{ background: 'var(--s2)' }} />Upload</span>
              </div>
            </div>
            <ThroughputChart samples={samples} />
          </div>

          <div className="card" style={{ marginTop: 12 }}><h3>Data path</h3>{pipeline(false)}</div>
          <div className="card" style={{ marginTop: 12 }}><h3>Recent transitions</h3>{feed(transitions.slice(0, 4))}</div>
        </section>

        <section className={view === 'path' ? 'view on' : 'view'} aria-labelledby="h-path">
          <div className="view-head"><h1 id="h-path">Data path</h1><span className="count">{PATH_CHECKS.length} checks</span><span className="updated">snapshot {snapshotAge}</span></div>
          <div className="card">{pipeline(true)}</div>
          <div className="notice"><InfoGlyph />
            Checks are ordered by dependency: an upstream failure leaves downstream checks pending rather than failed.
            Protection state is derived from enforcement checks only — probe results never relax it.</div>
        </section>

        <section className={view === 'clients' ? 'view on' : 'view'} aria-labelledby="h-clients">
          <div className="view-head"><h1 id="h-clients">Clients</h1><span className="count">{clients.length}</span><span className="updated">observed from Docker {snapshotAge}</span></div>
          <div className="tbl">
            <table>
              <thead><tr><th>Name</th><th>State</th><th>Address</th><th>Networks</th><th>Declared IPv4 default</th><th>Traffic</th><th>Compliance</th></tr></thead>
              <tbody>
                {clients.length === 0 && <tr><td colSpan={7} className="empty">No enrolled clients observed</td></tr>}
                {clients.map(client => <tr key={client.container_id}>
                  <td><b>{client.name}</b><div className="reason mono">{client.usage_id}</div><span className="chip dim">{client.usage_id_source}</span></td>
                  <td><span className={`pill ${client.running ? 'ok' : 'mut'}`}>{client.running ? 'running' : 'stopped'}</span></td>
                  <td className="mono"><span className="ip">{client.ipv4_address}</span>
                    {client.ipv6_address && <><br /><span className="chip warn">IPv6 {client.ipv6_address}</span></>}</td>
                  <td>{client.networks.map(network => <span key={network} className="chip dim" style={{ marginRight: 4 }}>{network}</span>)}</td>
                  <td><StatusPill status={client.route_intent.status} />
                    <div className="reason">{client.route_intent.ipv4_default_network ?? 'not determined'}</div>
                    <div className="reason">{client.route_intent.safe_message}</div></td>
                  <td><span className="mono">↓ {formatBytes(client.traffic.downloaded_bytes)}</span><br />
                    <span className="mono">↑ {formatBytes(client.traffic.uploaded_bytes)}</span>
                    <details><summary className="reason">{client.traffic.history.length} changed samples</summary>
                      <div className="reason mono">{client.traffic.history.slice(-5).reverse().map(sample =>
                        <div key={sample.sampled_at_unix_ms}>{clock(sample.sampled_at_unix_ms)} ↓{formatBytes(sample.downloaded_bytes)} ↑{formatBytes(sample.uploaded_bytes)}</div>
                      )}</div>
                    </details></td>
                  <td><span className={`pill ${client.compliant ? 'ok' : 'crit'}`}>{client.compliant ? 'compliant' : 'non-compliant'}</span>
                    {!client.compliant && <div className="reason">{client.compliance_message}</div>}</td>
                </tr>)}
              </tbody>
            </table>
          </div>
          <div className="notice warn"><WarnGlyph />
            Docker gateway metadata reports declared route intent only. It cannot prove an effective in-container default route,
            and IPv6 client leak protection is unsupported.</div>
          <div className={`notice ${snapshot.isolation_policy?.eligible_for_enforcement ? '' : 'warn'}`}><InfoGlyph />
            Bridge isolation policy: {snapshot.isolation_policy?.safe_message ?? 'not observed'}.
            {snapshot.isolation_policy?.issues?.length ? ` Issues: ${snapshot.isolation_policy.issues.join('; ')}` : ''}</div>
        </section>

        <section className={view === 'forwarding' ? 'view on' : 'view'} aria-labelledby="h-forwarding">
          <div className="view-head"><h1 id="h-forwarding">Port forwarding</h1><span className="updated">snapshot {snapshotAge}</span></div>
          <div className="grid tiles">
            <div className="card"><h3>Lifecycle</h3><div className="big mono">{forward.phase}</div>
              {forward.lease_expires_at_unix_ms && <p className="sub">Lease expires {ago(now, forward.lease_expires_at_unix_ms).replace(' ago', '')}.</p>}</div>
            <div className="card"><h3>External port</h3>
              <div className={forward.external_port ? 'big' : 'big dim'} style={forward.external_port ? { color: 'var(--id)' } : undefined}>{forward.external_port ?? 'not assigned'}</div>
              <p className="sub">Assigned by the provider; may change on lease renewal.</p></div>
            <div className="card"><h3>Target</h3>
              <div className={forward.requested_target ? 'big' : 'big dim'}>{forward.requested_target ?? 'none'}</div>
              <p className="sub">Selected by container label.</p></div>
            <div className="card"><h3>DNAT</h3>
              <span className={`pill ${forward.dnat_installed ? 'ok' : 'mut'}`}>{forward.dnat_installed ? 'installed' : 'not installed'}</span>
              <p className="sub">An installed rule does not prove public reachability.</p></div>
            <div className="card"><h3>External verification</h3>{triState(forward.externally_verified, 'verified', 'failed')}
              <p className="sub">Fresh evidence must match the active port and lease acquisition.</p></div>
          </div>
          <div className="notice"><InfoGlyph />
            Public reachability is only demonstrated by the <a href="#probe" onClick={nav('probe')}>external probe</a>, which is advisory.</div>
        </section>

        <section className={view === 'server' ? 'view on' : 'view'} aria-labelledby="h-server">
          <div className="view-head"><h1 id="h-server">VPN server</h1><span className="updated">observed {ago(now, vpnServer?.observed_at_unix_ms)}</span></div>
          <div className="grid tiles">
            <div className="card"><h3>Peer state</h3><span className={`pill ${vpnServer?.active ? 'ok' : 'warn'}`}>{vpnServer?.active ? 'active' : 'not active'}</span>
              <p className="sub">Based on a fresh WireGuard handshake, not configuration presence.</p></div>
            <div className="card"><h3>Configured endpoint</h3><div className="big mono">{vpnServer?.configured_endpoint_host ?? 'unknown'}</div>
              <p className="sub">port {vpnServer?.configured_endpoint_port ?? 'unknown'} · {vpnServer?.configured_address_family ?? 'unknown family'}</p></div>
            <div className="card"><h3>Runtime endpoint</h3><div className="big mono">{vpnServer?.runtime_endpoint_address ?? 'not observed'}</div>
              <p className="sub">port {vpnServer?.runtime_endpoint_port ?? 'unknown'}; resolved/roamed endpoint from wg.</p></div>
            <div className="card"><h3>Endpoint response time</h3><div className={vpnServer?.latency.latest_rtt_ms != null ? 'big' : 'big dim'}>{vpnServer?.latency.latest_rtt_ms != null ? `${vpnServer.latency.latest_rtt_ms.toFixed(1)} ms` : 'not measured'}</div>
              <p className="sub">{vpnServer?.latency.status ?? 'unavailable'} · underlay ICMP, not tunnel application latency.</p></div>
            <div className="card"><h3>Recent latency</h3><div className="big mono">{vpnServer?.latency.recent_average_rtt_ms != null ? `${vpnServer.latency.recent_average_rtt_ms.toFixed(1)} ms avg` : 'unavailable'}</div>
              <p className="sub">min {vpnServer?.latency.recent_min_rtt_ms?.toFixed(1) ?? '—'} · max {vpnServer?.latency.recent_max_rtt_ms?.toFixed(1) ?? '—'} · loss {vpnServer?.latency.loss_ratio != null ? `${(vpnServer.latency.loss_ratio * 100).toFixed(0)}%` : '—'}</p></div>
            <div className="card"><h3>Provider/location inference</h3><div className="big">{vpnServer?.provider_inferred ?? 'unknown'}{vpnServer?.region_inferred ? ` · ${vpnServer.region_inferred}` : ''}</div>
              <p className="sub">{vpnServer?.inference_source ? `Inferred from ${vpnServer.inference_source}; confidence ${vpnServer.inference_confidence ?? 'unknown'}.` : 'No reviewed hostname inference is available.'}</p></div>
          </div>
          <div className="notice warn"><WarnGlyph />A blocked or rate-limited ICMP response is advisory and does not mean the WireGuard tunnel is down.</div>
        </section>

        <section className={view === 'probe' ? 'view on' : 'view'} id="external-probe" aria-labelledby="h-probe">
          <div className="view-head"><h1 id="h-probe">External probe</h1><span className="updated">observed {ago(now, probe?.observed_at_unix_ms)}</span></div>
          <div className="grid tiles">
            <div className="card"><h3>Status</h3><StatusPill status={probe?.status} /><p className="sub">Advisory only; never changes tunnel health.</p></div>
            <div className="card"><h3>Public non-Tailscale path</h3>{triState(probe?.source_public_non_tailscale, 'confirmed', 'failed')}
              <p className="sub">The probe reached the gateway from a public source address.</p></div>
            <div className="card"><h3>Source matches claimed IP</h3>{triState(probe?.source_matches_claimed_ip, 'match', 'mismatch')}
              <p className="sub">Compares the probe source with the claimed egress identity.</p></div>
            <div className="card"><h3>Forwarded port reachability</h3>{triState(probe?.tcp_port_reachable, 'reachable', 'unreachable')}
              <p className="sub">TCP reachability of the forwarded port from outside.</p></div>
          </div>
          <div className="notice"><InfoGlyph />{probe?.safe_message ?? 'No external probe result yet.'}</div>
        </section>

        <section className={view === 'history' ? 'view on' : 'view'} aria-labelledby="h-history">
          <div className="view-head"><h1 id="h-history">Local history</h1><span className="count">SQLite</span><span className="updated">app-owned retention</span></div>
          <div className="notice"><InfoGlyph />Usage and safe events are read from the local Egressy database; no external monitoring service is required.</div>
          <div className="history-range" role="group" aria-label="History range">
            {[[24, '24 hours'], [168, '7 days'], [720, '30 days']].map(([hours, label]) =>
              <button key={hours} type="button" className={historyHours === hours ? 'active' : ''} onClick={() => setHistoryHours(hours as number)}>{label}</button>)}
          </div>
          {historyError && <div role="alert" className="notice warn"><WarnGlyph />{historyError}</div>}
          {!historyError && !usageHistory && <div role="status" className="notice">Loading local history…</div>}
          {usageHistory && <>
            <div className="tbl">
              <table>
                <thead><tr><th>Workload</th><th>Stable identity</th><th>Download</th><th>Upload</th><th>Samples</th></tr></thead>
                <tbody>
                  {usageByClient.length === 0 && <tr><td colSpan={5} className="empty">No usage recorded in this range</td></tr>}
                  {usageByClient.map(item => <tr key={item.usage_id}>
                    <td><b>{item.name}</b></td><td className="mono">{item.usage_id}<div className="reason">{item.source}</div></td>
                    <td className="mono">↓ {formatBytes(item.down)}</td><td className="mono">↑ {formatBytes(item.up)}</td><td>{item.samples}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>
            {usageHistory.truncated && <div className="notice warn"><WarnGlyph />The result reached its bounded row limit; select a shorter range.</div>}
          </>}
          {vpnServerHistory && <div className="card" style={{ marginTop: 12 }}><h3>VPN endpoint latency</h3>
            <div className="tbl"><table><thead><tr><th>Bucket</th><th>Runtime endpoint</th><th>Active</th><th>Measured</th><th>RTT min / avg / max</th></tr></thead><tbody>
              {vpnServerHistory.points.length === 0 && <tr><td colSpan={5} className="empty">No VPN-server latency recorded in this range</td></tr>}
              {vpnServerHistory.points.slice(-100).reverse().map(point => <tr key={point.bucket_start_unix_ms}>
                <td>{new Date(point.bucket_start_unix_ms).toLocaleString()}</td><td className="mono">{point.runtime_endpoint_address}:{point.runtime_endpoint_port}</td>
                <td>{point.active_sample_count}/{point.sample_count}</td><td>{point.measured_sample_count}/{point.sample_count}</td>
                <td className="mono">{point.average_rtt_ms == null ? 'not measured' : `${point.minimum_rtt_ms?.toFixed(1)} / ${point.average_rtt_ms.toFixed(1)} / ${point.maximum_rtt_ms?.toFixed(1)} ms`}</td>
              </tr>)}</tbody></table></div>
          </div>}
          {eventHistory && <div className="card" style={{ marginTop: 12 }}><h3>Persisted events</h3>
            <div className="feed">{eventHistory.events.length === 0 && <div className="empty">No persisted events in this range</div>}
              {eventHistory.events.slice(0, 50).map(item => <div className="ev" key={item.id}>
                <time>{new Date(item.timestamp_unix_ms).toLocaleString()}</time><span className={`mark ${tone(item.to_status ?? item.port_forward_phase ?? undefined)}`} />
                <span className="what"><b>{item.component}</b><span className="arrow">{item.kind}</span><span className="msg">{item.safe_message}</span></span>
              </div>)}</div>
          </div>}
        </section>

        <section className={view === 'diagnostics' ? 'view on' : 'view'} aria-labelledby="h-diagnostics">
          <div className="view-head"><h1 id="h-diagnostics">Diagnostics</h1><span className="count">{checks.length} components</span><span className="updated">snapshot {snapshotAge}</span></div>
          <div className="tbl">
            <table>
              <thead><tr><th>Component</th><th>Status</th><th>Impact</th><th>Reason</th><th>Observed</th></tr></thead>
              <tbody>
                {checks.length === 0 && <tr><td colSpan={5} className="empty">No checks reported yet</td></tr>}
                {checks.map(check => <tr key={check.id}>
                  <td className="mono">{check.id}</td>
                  <td><StatusPill status={check.status} /></td>
                  <td><span className="chip dim">{check.impact}</span></td>
                  <td style={{ whiteSpace: 'normal' }}>{check.safe_message}<div className="reason mono">{check.reason_code}</div></td>
                  <td className="mono">{ago(now, check.observed_at_unix_ms)}</td>
                </tr>)}
              </tbody>
            </table>
          </div>
          <div className="notice"><InfoGlyph />
            Shared-bridge client isolation: <code>{snapshot.topology.client_isolation}</code>. The host agent mode is deployment-owned; policy completeness does not itself prove blocking.</div>
        </section>

        <section className={view === 'notifications' ? 'view on' : 'view'} aria-labelledby="h-notifications">
          <div className="view-head"><h1 id="h-notifications">Notifications</h1><span className="count">Omnihook</span><span className="updated">GUI-managed</span></div>
          <div className="notice" style={{ marginTop: 0 }}><InfoGlyph />Settings are stored in the protected app-owned SQLite database. Webhook URLs, chat IDs, and HMAC secrets are never returned by the API.</div>
          <NotificationsPanel />
        </section>

        <section className={view === 'events' ? 'view on' : 'view'} aria-labelledby="h-events">
          <div className="view-head"><h1 id="h-events">Events</h1><span className="count">{snapshot.transitions.length} recorded</span><span className="updated">streaming via SSE</span></div>
          <div className="card">{feed(transitions.slice(0, 50))}</div>
        </section>
      </div>
    </div>
  </div>
}
