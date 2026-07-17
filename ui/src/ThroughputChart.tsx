import { useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'

export interface TrafficSample { at_unix_ms: number; download: number; upload: number }

export interface ClientTrafficView {
  name: string
  history: { sampled_at_unix_ms: number; downloaded_bytes: number; uploaded_bytes: number }[]
}

const W = 1000, H = 148, PAD_TOP = 8, PAD_BOTTOM = 18
const DOWN = '#3987e5', UP = '#199e70'

export const formatRate = (bytes: number) => {
  const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s']; let value = bytes || 0; let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++ }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

export function ThroughputChart({ samples }: { samples: TrafficSample[] }) {
  const [hover, setHover] = useState<number>()
  const wrap = useRef<HTMLDivElement>(null)

  if (samples.length < 2) return <div className="chart-empty">Collecting throughput samples…</div>

  const max = Math.max(1, ...samples.map(s => Math.max(s.download, s.upload))) * 1.15
  const x = (i: number) => i / (samples.length - 1) * W
  const y = (v: number) => H - PAD_BOTTOM - (v / max) * (H - PAD_BOTTOM - PAD_TOP)
  const line = (pick: (s: TrafficSample) => number) =>
    samples.map((s, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(pick(s)).toFixed(1)}`).join(' ')
  const area = (pick: (s: TrafficSample) => number) =>
    `${line(pick)} L${W} ${H - PAD_BOTTOM} L0 ${H - PAD_BOTTOM} Z`
  const last = samples[samples.length - 1]

  const onMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    const rect = event.currentTarget.getBoundingClientRect()
    const i = Math.round((event.clientX - rect.left) / rect.width * (samples.length - 1))
    setHover(Math.max(0, Math.min(samples.length - 1, i)))
  }
  const hovered = hover === undefined ? undefined : samples[hover]

  return <div className="chart-wrap" ref={wrap}>
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
      aria-label={`WireGuard throughput, latest download ${formatRate(last.download)}, upload ${formatRate(last.upload)}`}
      onPointerMove={onMove} onPointerLeave={() => setHover(undefined)}>
      {[0.25, 0.5, 0.75, 1].map(f =>
        <line key={f} x1={0} x2={W} y1={y(max * f / 1.15)} y2={y(max * f / 1.15)} stroke="#1e2733" strokeWidth={1} />)}
      <line x1={0} x2={W} y1={H - PAD_BOTTOM} y2={H - PAD_BOTTOM} stroke="#1e2733" strokeWidth={1} />
      <path d={area(s => s.download)} fill="rgba(57,135,229,.13)" />
      <path d={area(s => s.upload)} fill="rgba(25,158,112,.15)" />
      <path d={line(s => s.download)} fill="none" stroke={DOWN} strokeWidth={2} vectorEffect="non-scaling-stroke" />
      <path d={line(s => s.upload)} fill="none" stroke={UP} strokeWidth={2} vectorEffect="non-scaling-stroke" />
      <circle cx={x(samples.length - 1)} cy={y(last.download)} r={3.5} fill={DOWN} stroke="#121822" strokeWidth={2} />
      <circle cx={x(samples.length - 1)} cy={y(last.upload)} r={3.5} fill={UP} stroke="#121822" strokeWidth={2} />
      {hover !== undefined && hovered && <>
        <line x1={x(hover)} x2={x(hover)} y1={PAD_TOP} y2={H - PAD_BOTTOM} stroke="#5f6e7d" strokeWidth={1} strokeDasharray="3 3" />
        <circle cx={x(hover)} cy={y(hovered.download)} r={4} fill={DOWN} stroke="#0a0e14" strokeWidth={2} />
        <circle cx={x(hover)} cy={y(hovered.upload)} r={4} fill={UP} stroke="#0a0e14" strokeWidth={2} />
      </>}
    </svg>
    {hover !== undefined && hovered && wrap.current &&
      <div className="tip" style={{ left: Math.min(x(hover) / W * wrap.current.clientWidth + 12, wrap.current.clientWidth - 130) }}>
        <span className="t">{new Date(hovered.at_unix_ms).toLocaleTimeString()}</span><br />
        <b style={{ color: DOWN }}>↓ {formatRate(hovered.download)}</b><br />
        <b style={{ color: UP }}>↑ {formatRate(hovered.upload)}</b>
      </div>}
  </div>
}

const clientRateSamples = (client: ClientTrafficView): TrafficSample[] => client.history.slice(-120).map((sample, index, samples) => {
  const previous = samples[index - 1]
  if (!previous) return { at_unix_ms: sample.sampled_at_unix_ms, download: 0, upload: 0 }
  const seconds = Math.max(0.001, (sample.sampled_at_unix_ms - previous.sampled_at_unix_ms) / 1000)
  return {
    at_unix_ms: sample.sampled_at_unix_ms,
    download: Math.max(0, sample.downloaded_bytes - previous.downloaded_bytes) / seconds,
    upload: Math.max(0, sample.uploaded_bytes - previous.uploaded_bytes) / seconds,
  }
})

export function ClientThroughputChart({ clients }: { clients: ClientTrafficView[] }) {
  const visible = clients.map(client => ({ ...client, samples: clientRateSamples(client) }))
    .filter(client => client.samples.length >= 2)
  if (visible.length === 0) return <div className="chart-empty">Collecting per-container throughput samples…</div>
  return <div className="client-throughput-grid">
    {visible.map(client => <div className="client-throughput" key={client.name}>
      <div className="chart-head"><h4>{client.name}</h4></div>
      <ThroughputChart samples={client.samples} />
    </div>)}
  </div>
}
