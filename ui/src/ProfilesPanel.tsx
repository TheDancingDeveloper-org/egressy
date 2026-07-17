import { useEffect, useRef, useState } from 'react'
import {
  activateProfileSource, applyManagedProfile, ProfileManagement, RedactedProfile, stageManagedProfile,
  stageStructuredProfile, StructuredProfileInput, validateManagedProfile,
} from './api'

const emptyPreview = undefined as RedactedProfile | undefined

const unconfigured: ProfileManagement = {
  lifecycle: 'unconfigured', source: 'mounted', source_mutable: false, active_revision: null,
  active: null, revisions: [], management_available: true, mutation_authorized: false,
  ipv4_only: true, last_apply: null,
}

export function ProfilesPanel({ management = unconfigured }: { management?: ProfileManagement }) {
  const [profile, setProfile] = useState('')
  const [token, setToken] = useState('')
  const [preview, setPreview] = useState<RedactedProfile | undefined>(emptyPreview)
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const [privateKey, setPrivateKey] = useState('')
  const [peerSecrets, setPeerSecrets] = useState<Record<number, string>>({})
  const [edit, setEdit] = useState<RedactedProfile>()
  const file = useRef<HTMLInputElement>(null)

  useEffect(() => () => {
    setProfile('')
    setToken('')
    setPrivateKey('')
    setPeerSecrets({})
  }, [])

  const readFile = async (selected?: File) => {
    if (!selected) return
    setProfile(await selected.text())
    if (file.current) file.current.value = ''
  }
  const validate = async () => {
    setBusy(true); setError(undefined); setPreview(undefined)
    try { setPreview(await validateManagedProfile(profile, token)) }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Profile validation failed') }
    finally { setBusy(false) }
  }
  const stageAndApply = async () => {
    setBusy(true); setError(undefined)
    try {
      const revision = await stageManagedProfile(profile, token)
      setProfile('')
      setPreview(undefined)
      await applyManagedProfile(revision.id, token)
      window.location.reload()
    } catch (caught) {
      setProfile('')
      setPreview(undefined)
      setError(caught instanceof Error ? caught.message : 'Profile application failed')
    } finally { setToken(''); setBusy(false) }
  }
  const applyStructured = async () => {
    if (!edit) return
    setBusy(true); setError(undefined)
    try {
      const input: StructuredProfileInput = {
        ...(privateKey ? { private_key: privateKey } : {}),
        addresses: edit.interface.addresses,
        dns: edit.interface.dns,
        listen_port: edit.interface.listen_port,
        mtu: edit.interface.mtu,
        peers: edit.peers.map((peer, index) => ({
          public_key: peer.public_key,
          ...(peerSecrets[index] ? { preshared_key: peerSecrets[index] } : {}),
          endpoint: peer.endpoint ? `${peer.endpoint.address_family === 'ipv6' ? `[${peer.endpoint.host}]` : peer.endpoint.host}:${peer.endpoint.port}` : null,
          allowed_ips: peer.allowed_ips,
          persistent_keepalive: peer.persistent_keepalive,
        })),
      }
      const revision = await stageStructuredProfile(input, token)
      setPrivateKey(''); setPeerSecrets({})
      await applyManagedProfile(revision.id, token)
      window.location.reload()
    } catch (caught) {
      setPrivateKey(''); setPeerSecrets({})
      setError(caught instanceof Error ? caught.message : 'Structured profile edit failed')
    } finally { setToken(''); setBusy(false) }
  }
  const switchSource = async (source: 'mounted' | 'gui_managed') => {
    setBusy(true); setError(undefined)
    try { await activateProfileSource(source, token); window.location.reload() }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Source activation failed') }
    finally { setToken(''); setBusy(false) }
  }

  const active = management.active
  return <>
    <div className="view-head"><h1 id="h-profiles">WireGuard profile</h1><span className="count">{management.lifecycle}</span></div>
    <div className={`notice ${management.lifecycle === 'active' ? '' : 'warn'}`}>
      Egressy protects enrolled IPv4 traffic only. Source: <b>{management.source}</b>.
      {management.source_mutable ? ' Managed revisions are encrypted at rest.' : ' The mounted source is read-only.'}
    </div>

    {active && <div className="card" style={{ marginTop: 12 }}>
      <h3>Active redacted configuration</h3>
      <div className="grid tiles">
        <div><span className="reason">Interface addresses</span><div className="mono">{active.interface.addresses.join(', ') || 'none'}</div></div>
        <div><span className="reason">DNS servers</span><div className="mono">{active.interface.dns.join(', ') || 'none'}</div></div>
        <div><span className="reason">Peers</span><div className="big">{active.peer_count}</div></div>
        <div><span className="reason">IPv4 full tunnel</span><span className={`pill ${active.ipv4_full_tunnel ? 'ok' : 'crit'}`}>{active.ipv4_full_tunnel ? 'compatible' : 'invalid'}</span></div>
      </div>
      <p className="sub">Private key: {active.interface.private_key_configured ? 'configured' : 'not configured'}. Stored secret values are never returned.</p>
    </div>}

    {management.mutation_authorized && <div className="card profile-editor" style={{ marginTop: 12 }}>
      <h3>Active source</h3>
      <label>Source administrator token<input type="password" autoComplete="off" value={token} onChange={event => setToken(event.target.value)} /></label>
      <div className="actions">
        <button type="button" disabled={busy || !token || management.source === 'mounted'} onClick={() => void switchSource('mounted')}>Activate mounted</button>
        <button type="button" disabled={busy || !token || management.source === 'gui_managed'} onClick={() => void switchSource('gui_managed')}>Activate managed</button>
      </div>
    </div>}

    {management.mutation_authorized && <div className="card profile-editor" style={{ marginTop: 12 }}>
      <h3>{management.lifecycle === 'unconfigured' ? 'Set up protected egress' : 'Import a new revision'}</h3>
      <label>Administrator token<input type="password" autoComplete="off" value={token} onChange={event => setToken(event.target.value)} /></label>
      <label>WireGuard .conf file<input ref={file} type="file" accept=".conf,text/plain" onChange={event => void readFile(event.target.files?.[0])} /></label>
      <label>Or paste profile<textarea rows={12} spellCheck={false} value={profile} onChange={event => setProfile(event.target.value)} /></label>
      <div className="actions"><button type="button" disabled={busy || !profile || !token} onClick={() => void validate()}>Review</button>
        <button type="button" disabled={busy || !preview || !token} onClick={() => void stageAndApply()}>Apply</button></div>
      <p className="sub">The pasted profile and administrator token remain only in this component state and are cleared after submission.</p>
    </div>}

    {management.source_mutable && active && <div className="card profile-editor" style={{ marginTop: 12 }}>
      <h3>Advanced structured editor</h3>
      <button type="button" onClick={() => { setAdvanced(value => !value); setEdit(structuredClone(active)) }}>{advanced ? 'Hide advanced fields' : 'Edit structured fields'}</button>
      {advanced && edit && <>
        <p className="sub">Non-secret values are prefilled below. Secret inputs are intentionally blank; leaving them blank preserves the stored value.</p>
        <label>Interface addresses (comma-separated)<input value={edit.interface.addresses.join(', ')} onChange={event => setEdit({ ...edit, interface: { ...edit.interface, addresses: event.target.value.split(',').map(value => value.trim()).filter(Boolean) } })} /></label>
        <label>DNS servers (comma-separated)<input value={edit.interface.dns.join(', ')} onChange={event => setEdit({ ...edit, interface: { ...edit.interface, dns: event.target.value.split(',').map(value => value.trim()).filter(Boolean) } })} /></label>
        <label>Listen port<input type="number" value={edit.interface.listen_port ?? ''} onChange={event => setEdit({ ...edit, interface: { ...edit.interface, listen_port: event.target.value ? Number(event.target.value) : null } })} /></label>
        <label>MTU<input type="number" value={edit.interface.mtu ?? ''} onChange={event => setEdit({ ...edit, interface: { ...edit.interface, mtu: event.target.value ? Number(event.target.value) : null } })} /></label>
        <label>Replace private key (optional)<input type="password" autoComplete="off" value={privateKey} onChange={event => setPrivateKey(event.target.value)} /></label>
        {edit.peers.map((peer, index) => <div className="profile-peer" key={`${peer.public_key}-${index}`}>
          <b>Peer {index + 1}</b>
          <label>Public key<input value={peer.public_key} onChange={event => setEdit({ ...edit, peers: edit.peers.map((value, peerIndex) => peerIndex === index ? { ...value, public_key: event.target.value } : value) })} /></label>
          <label>Endpoint<input value={peer.endpoint ? `${peer.endpoint.address_family === 'ipv6' ? `[${peer.endpoint.host}]` : peer.endpoint.host}:${peer.endpoint.port}` : ''} onChange={event => { const endpoint = event.target.value; const match = endpoint.match(/^\[([^\]]+)]:(\d+)$/) ?? endpoint.match(/^(.+):(\d+)$/); setEdit({ ...edit, peers: edit.peers.map((value, peerIndex) => peerIndex === index ? { ...value, endpoint: match ? { host: match[1], port: Number(match[2]), address_family: match[1].includes(':') ? 'ipv6' : 'hostname' } : null } : value) }) }} /></label>
          <label>Allowed IPs<input value={peer.allowed_ips.join(', ')} onChange={event => setEdit({ ...edit, peers: edit.peers.map((value, peerIndex) => peerIndex === index ? { ...value, allowed_ips: event.target.value.split(',').map(item => item.trim()).filter(Boolean) } : value) })} /></label>
          <label>Persistent keepalive<input type="number" value={peer.persistent_keepalive ?? ''} onChange={event => setEdit({ ...edit, peers: edit.peers.map((value, peerIndex) => peerIndex === index ? { ...value, persistent_keepalive: event.target.value ? Number(event.target.value) : null } : value) })} /></label>
          <label>Replace preshared key (optional)<input type="password" autoComplete="off" value={peerSecrets[index] ?? ''} onChange={event => setPeerSecrets(values => ({ ...values, [index]: event.target.value }))} /></label>
        </div>)}
        <button type="button" disabled={busy || !token} onClick={() => void applyStructured()}>Stage and apply structured edit</button>
      </>}
    </div>}

    {error && <div role="alert" className="notice warn">{error}</div>}
    {preview && <div className="card" style={{ marginTop: 12 }}>
      <h3>Validated candidate · {preview.apply_kind.replaceAll('_', ' ')}</h3>
      <p>Interface: <span className="mono">{preview.interface.addresses.join(', ')}</span> · DNS: <span className="mono">{preview.interface.dns.join(', ') || 'none'}</span></p>
      {preview.peers.map((peer, index) => <div key={`${peer.public_key}-${index}`} className="profile-peer">
        <b>Peer {index + 1}</b> · <span className="mono">{peer.endpoint ? `${peer.endpoint.host}:${peer.endpoint.port}` : 'no endpoint'}</span>
        <div className="reason">Allowed IPs: {peer.allowed_ips.join(', ')}</div>
        <div className="reason">Public key: {peer.public_key}; preshared key: {peer.preshared_key_configured ? 'configured' : 'not configured'}</div>
      </div>)}
      {preview.warnings.map(warning => <div className="notice warn" key={`${warning.code}-${warning.field}`}>{warning.message}</div>)}
    </div>}

    {management.last_apply && <div className="notice" style={{ marginTop: 12 }}>{management.last_apply.safe_message}</div>}
  </>
}
