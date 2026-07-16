import { FormEvent, useEffect, useState } from 'react'
import {
  fetchNotificationSettings, NotificationProvider, NotificationSettings,
  NotificationSettingsInput, saveNotificationSettings, sendTestNotification,
} from './api'

const PROVIDERS: { value: NotificationProvider; label: string }[] = [
  { value: 'discord', label: 'Discord' }, { value: 'slack', label: 'Slack' },
  { value: 'telegram', label: 'Telegram' }, { value: 'generic', label: 'Generic JSON' },
]

const initialInput = (settings: NotificationSettings): NotificationSettingsInput => ({
  enabled: settings.enabled, provider: settings.provider, webhook_url: '', telegram_chat_id: '',
  hmac_secret: '', timeout_seconds: settings.timeout_seconds, rtt_threshold_ms: settings.rtt_threshold_ms,
  alert_stack_started: settings.alert_stack_started,
  alert_vpn_disconnected: settings.alert_vpn_disconnected,
  alert_vpn_reconnected: settings.alert_vpn_reconnected,
  alert_rtt_above_threshold: settings.alert_rtt_above_threshold,
  alert_diagnostic_failed: settings.alert_diagnostic_failed,
})

const Toggle = ({ id, label, detail, checked, setChecked }: {
  id: string; label: string; detail: string; checked: boolean; setChecked: (value: boolean) => void
}) => <label className="setting-toggle" htmlFor={id}>
  <span><b>{label}</b><small>{detail}</small></span>
  <input id={id} aria-label={label} type="checkbox" checked={checked} onChange={event => setChecked(event.target.checked)} />
</label>

export function NotificationsPanel() {
  const [settings, setSettings] = useState<NotificationSettings>()
  const [input, setInput] = useState<NotificationSettingsInput>()
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ tone: 'ok' | 'warn'; text: string }>()

  useEffect(() => {
    let mounted = true
    fetchNotificationSettings().then(value => {
      if (mounted) { setSettings(value); setInput(initialInput(value)) }
    }).catch(() => mounted && setMessage({ tone: 'warn', text: 'Notification settings are unavailable.' }))
    return () => { mounted = false }
  }, [])

  const update = <K extends keyof NotificationSettingsInput>(key: K, value: NotificationSettingsInput[K]) =>
    setInput(current => current ? { ...current, [key]: value } : current)

  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (!input) return
    setBusy(true); setMessage(undefined)
    try {
      const saved = await saveNotificationSettings(input)
      setSettings(saved); setInput(initialInput(saved))
      setMessage({ tone: 'ok', text: 'Omnihook settings saved.' })
    } catch (error) {
      setMessage({ tone: 'warn', text: error instanceof Error ? error.message : 'Settings could not be saved.' })
    } finally { setBusy(false) }
  }

  const test = async () => {
    setBusy(true); setMessage(undefined)
    try {
      await sendTestNotification()
      setMessage({ tone: 'ok', text: 'Test notification delivered.' })
    } catch (error) {
      setMessage({ tone: 'warn', text: error instanceof Error ? error.message : 'Test notification failed.' })
    } finally { setBusy(false) }
  }

  if (!input) return <div role="status" className={`notice ${message?.tone === 'warn' ? 'warn' : ''}`}>{message?.text ?? 'Loading notification settings…'}</div>

  return <form className="settings-form" onSubmit={save}>
    <div className="card settings-card">
      <h3>Delivery</h3>
      <Toggle id="notifications-enabled" label="Enable notifications" detail="Delivery is advisory and never affects gateway health or recovery."
        checked={input.enabled} setChecked={value => update('enabled', value)} />
      <div className="form-grid">
        <label>Provider<select value={input.provider} onChange={event => update('provider', event.target.value as NotificationProvider)}>
          {PROVIDERS.map(provider => <option key={provider.value} value={provider.value}>{provider.label}</option>)}
        </select></label>
        <label>Request timeout (seconds)<input type="number" min="1" max="30" required value={input.timeout_seconds}
          onChange={event => update('timeout_seconds', Number(event.target.value))} /></label>
        <label className="wide">Webhook URL<input type="url" inputMode="url" autoComplete="off"
          placeholder={settings?.destination ?? 'https://…'} value={input.webhook_url}
          onChange={event => update('webhook_url', event.target.value)} />
          <small>{settings?.webhook_configured ? `Configured: ${settings.destination}. Leave blank to retain it.` : 'HTTPS is required. The saved URL is never returned to the browser.'}</small></label>
        {input.provider === 'telegram' && <label className="wide">Telegram chat ID<input type="password" autoComplete="off"
          placeholder={settings?.telegram_chat_id_configured ? 'Configured — leave blank to retain' : 'Required'} value={input.telegram_chat_id}
          onChange={event => update('telegram_chat_id', event.target.value)} /></label>}
        {input.provider === 'generic' && <label className="wide">HMAC secret (optional)<input type="password" autoComplete="new-password"
          placeholder={settings?.hmac_secret_configured ? 'Configured — leave blank to retain' : 'Optional x-signature secret'} value={input.hmac_secret}
          onChange={event => update('hmac_secret', event.target.value)} /></label>}
      </div>
    </div>

    <div className="card settings-card">
      <h3>Alert hooks</h3>
      <Toggle id="alert-stack-started" label="Stack Started" detail="Sent after the HTTP listener starts and fail-closed policy is installed."
        checked={input.alert_stack_started} setChecked={value => update('alert_stack_started', value)} />
      <Toggle id="alert-vpn-disconnected" label="VPN Disconnected" detail="Sent when the WireGuard handshake becomes failed."
        checked={input.alert_vpn_disconnected} setChecked={value => update('alert_vpn_disconnected', value)} />
      <Toggle id="alert-vpn-reconnected" label="VPN Reconnected" detail="Sent when a failed WireGuard handshake becomes healthy again."
        checked={input.alert_vpn_reconnected} setChecked={value => update('alert_vpn_reconnected', value)} />
      <Toggle id="alert-rtt" label="RTT above threshold" detail="Sent once when measured underlay VPN endpoint RTT crosses the configured value."
        checked={input.alert_rtt_above_threshold} setChecked={value => update('alert_rtt_above_threshold', value)} />
      <label className="threshold">RTT threshold (ms)<input type="number" min="1" max="60000" step="0.1" required value={input.rtt_threshold_ms}
        onChange={event => update('rtt_threshold_ms', Number(event.target.value))} /></label>
      <Toggle id="alert-diagnostic" label="X diagnostic failed" detail="Sent for any non-handshake diagnostic entering failed state; the component name replaces X."
        checked={input.alert_diagnostic_failed} setChecked={value => update('alert_diagnostic_failed', value)} />
    </div>

    {message && <div role="status" className={`notice ${message.tone === 'warn' ? 'warn' : ''}`}>{message.text}</div>}
    <div className="form-actions">
      <button className="secondary" type="button" onClick={test} disabled={busy || !settings?.webhook_configured}>Send test</button>
      <button className="primary" type="submit" disabled={busy}>{busy ? 'Working…' : 'Save settings'}</button>
    </div>
  </form>
}
