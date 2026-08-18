import React, { FormEvent, ReactNode, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'

import { api } from './api'
import './styles.css'

type Row = Record<string, any>
type LoadState<T> = { data?: T; error?: string; loading: boolean }

const NAVIGATION = [
  ['/', 'Dashboard'],
  ['/devices', 'Devices'],
  ['/tickets', 'Tickets'],
  ['/incidents', 'Incidents'],
  ['/actions', 'Actions'],
  ['/approvals', 'Approvals'],
  ['/audit', 'Audit'],
  ['/integrations', 'Integrations'],
  ['/settings', 'Settings'],
] as const

function useApi<T>(path: string): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>({ loading: true })
  const [version, setVersion] = useState(0)
  useEffect(() => {
    let active = true
    setState({ loading: true })
    api<T>(path)
      .then((data) => active && setState({ data, loading: false }))
      .catch((error: Error) => active && setState({ error: error.message, loading: false }))
    return () => { active = false }
  }, [path, version])
  return { ...state, reload: () => setVersion((value) => value + 1) }
}

const label = (value: string) => value.replaceAll('_', ' ')
const when = (value: any) => value ? new Date(value).toLocaleString() : 'Never'
const display = (value: any) => value == null ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const canOperate = (user?: Row) => ['owner', 'admin', 'operator'].includes(user?.role)
const canAdmin = (user?: Row) => ['owner', 'admin'].includes(user?.role)

function Badge({ value }: { value: any }) {
  return <span className={`badge ${String(value).toLowerCase()}`}>{label(String(value))}</span>
}

function Status({ state, children }: { state: LoadState<any>; children: ReactNode }) {
  if (state.loading) return <div className="state">Loading…</div>
  if (state.error) return <div className="state error">{state.error}</div>
  return <>{children}</>
}

function Title({ title, subtitle, actions }: { title: string; subtitle: string; actions?: ReactNode }) {
  return <header className="title"><div><h1>{title}</h1><p>{subtitle}</p></div>{actions}</header>
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="panel"><h2>{title}</h2>{children}</section>
}

function Empty({ children = 'No records yet.' }: { children?: ReactNode }) {
  return <div className="state empty">{children}</div>
}

function Table({ rows, columns, href }: { rows: Row[]; columns: [string, string][]; href?: (row: Row) => string }) {
  if (!rows.length) return <Empty />
  return <div className="table-wrap"><table><thead><tr>{columns.map(([key, heading]) => <th key={key}>{heading}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={row.id ?? index} className={href ? 'clickable' : ''} onClick={() => href && (location.href = href(row))}>{columns.map(([key]) => <td key={key}>{['status', 'severity', 'risk', 'os', 'priority'].includes(key) ? <Badge value={row[key]} /> : key.endsWith('_at') ? when(row[key]) : display(row[key])}</td>)}</tr>)}</tbody></table></div>
}

function Timeline({ rows }: { rows?: Row[] }) {
  if (!rows?.length) return <Empty>No audit activity for this resource.</Empty>
  return <div className="timeline">{rows.map((row) => <article key={row.sequence}><div><strong>{label(row.event_type)}</strong><span>{when(row.occurred_at)} · {row.actor_id}</span></div><pre>{JSON.stringify(row.details, null, 2)}</pre></article>)}</div>
}

function Login({ onLogin }: { onLogin: (user: Row) => void }) {
  const users = useApi<Row[]>('/v1/auth/development/users')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  async function login(user: Row) {
    setBusy(user.id)
    setError('')
    try {
      const result = await api<Row>(`/v1/auth/development/login?user_id=${encodeURIComponent(user.id)}`, { method: 'POST' })
      localStorage.setItem('helpdesk_session', result.access_token)
      onLogin(result.user)
    } catch (reason) {
      setError((reason as Error).message)
    } finally {
      setBusy('')
    }
  }
  return <main className="login"><section><div className="brandmark">H</div><h1>Helpdesktool</h1><p>Deterministic, policy-controlled IT operations.</p><div className="dev-note">Development login · unavailable in production mode</div>{error && <div className="state error">{error}</div>}<Status state={users}>{users.data?.length ? <div className="login-users">{users.data.map((user) => <button disabled={!!busy} key={user.id} onClick={() => login(user)}><Badge value={user.role} /><span><strong>{user.email}</strong><small>{user.tenant}</small></span><b>{busy === user.id ? 'Signing in…' : 'Continue →'}</b></button>)}</div> : <Empty>Run the development seed to create demo users.</Empty>}</Status></section></main>
}

function Dashboard() {
  const state = useApi<Row>('/v1/dashboard')
  return <Status state={state}>{state.data && <><Title title="Operations overview" subtitle="Current device health, incidents, and remediation activity" /><div className="cards">{Object.entries(state.data.counts).map(([key, value]) => <article className="metric" key={key}><span>{label(key)}</span><strong>{String(value)}</strong></article>)}</div><div className="three-column"><Panel title="Recent incidents"><Table rows={state.data.recent_incidents} columns={[["summary", "Incident"], ["severity", "Severity"], ["status", "Status"]]} href={(row) => `/incidents/${row.id}`} /></Panel><Panel title="Recent tickets"><Table rows={state.data.recent_tickets} columns={[["title", "Ticket"], ["priority", "Priority"], ["status", "Status"]]} href={(row) => `/tickets/${row.id}`} /></Panel><Panel title="Recent actions"><Table rows={state.data.recent_actions} columns={[["skill_id", "Skill"], ["risk", "Risk"], ["status", "Status"]]} href={(row) => `/actions/${row.id}`} /></Panel></div></>}</Status>
}

function SearchablePage({ title, subtitle, state, columns, href, actions }: { title: string; subtitle: string; state: LoadState<Row[]>; columns: [string, string][]; href?: (row: Row) => string; actions?: ReactNode }) {
  const [query, setQuery] = useState('')
  const rows = useMemo(() => (state.data ?? []).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [state.data, query])
  return <><Title title={title} subtitle={subtitle} actions={actions} /><input className="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={`Filter ${title.toLowerCase()}…`} /><Status state={state}><Table rows={rows} columns={columns} href={href} /></Status></>
}

function Devices() {
  const state = useApi<Row[]>('/v1/devices')
  return <SearchablePage title="Devices" subtitle="Enrolled endpoint inventory and connectivity" state={state} columns={[["hostname", "Hostname"], ["os", "OS"], ["status", "Status"], ["last_seen_at", "Last seen"], ["open_incidents", "Open incidents"]]} href={(row) => `/devices/${row.id}`} />
}

function LowDiskSimulator({ deviceId, onComplete }: { deviceId: string; onComplete: () => void }) {
  const [used, setUsed] = useState('96')
  const [message, setMessage] = useState('')
  async function simulate() {
    setMessage('Submitting simulated telemetry…')
    try {
      const result = await api<Row>('/v1/development/simulations/low-disk', { method: 'POST', body: JSON.stringify({ device_id: deviceId, mountpoint: '/', used_percent: Number(used) }) })
      setMessage(result.incident ? `Incident ${result.incident.status}; occurrence ${result.incident.occurrence_count}` : 'Healthy telemetry accepted; no open incident.')
      onComplete()
    } catch (error) { setMessage((error as Error).message) }
  }
  return <div className="simulator"><label>Simulated disk use<input type="number" min="0" max="100" value={used} onChange={(event) => setUsed(event.target.value)} /></label><button onClick={simulate}>Submit telemetry</button><small>{message || 'Use 96% to create/correlate; use 40% to resolve.'}</small></div>
}

function DeviceDetail({ id, user }: { id: string; user?: Row }) {
  const state = useApi<Row>(`/v1/devices/${id}`)
  return <Status state={state}>{state.data && <><a className="back" href="/devices">← Devices</a><Title title={state.data.hostname} subtitle={`${state.data.os} endpoint · ${state.data.external_id}`} actions={canOperate(user) && state.data.os === 'linux' ? <LowDiskSimulator deviceId={id} onComplete={state.reload} /> : undefined} /><div className="summary-grid"><Panel title="Status"><Badge value={state.data.status} /><p>Last seen: {when(state.data.last_seen_at)}</p><pre>{JSON.stringify(state.data.latest_heartbeat, null, 2)}</pre></Panel><Panel title="Inventory"><pre>{JSON.stringify(state.data.inventory, null, 2)}</pre></Panel></div><Panel title="Incidents"><Table rows={state.data.incidents} columns={[["summary", "Summary"], ["severity", "Severity"], ["status", "Status"], ["last_observed_at", "Observed"]]} href={(row) => `/incidents/${row.id}`} /></Panel><Panel title="Tickets"><Table rows={state.data.tickets} columns={[["title", "Title"], ["priority", "Priority"], ["status", "Status"]]} href={(row) => `/tickets/${row.id}`} /></Panel><Panel title="Actions"><Table rows={state.data.actions} columns={[["skill_id", "Skill"], ["risk", "Risk"], ["status", "Status"]]} href={(row) => `/actions/${row.id}`} /></Panel><Panel title="Audit activity"><Timeline rows={state.data.audit} /></Panel></>}</Status>
}

function TicketForm({ devices, onSaved }: { devices: Row[]; onSaved: () => void }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('')
    const data = new FormData(event.currentTarget)
    try {
      await api('/v1/tickets', { method: 'POST', body: JSON.stringify({ title: data.get('title'), description: data.get('description'), priority: data.get('priority'), device_id: data.get('device_id') || null }) })
      setOpen(false); onSaved()
    } catch (reason) { setError((reason as Error).message) }
  }
  return <>{!open ? <button onClick={() => setOpen(true)}>Create ticket</button> : <div className="modal"><form onSubmit={submit}><h2>Create ticket</h2>{error && <div className="state error">{error}</div>}<label>Summary<input name="title" required maxLength={300} /></label><label>Description<textarea name="description" rows={4} /></label><label>Priority<select name="priority"><option>normal</option><option>low</option><option>high</option><option>critical</option></select></label><label>Device<select name="device_id"><option value="">None</option>{devices.map((device) => <option value={device.id} key={device.id}>{device.hostname}</option>)}</select></label><div><button type="button" className="secondary" onClick={() => setOpen(false)}>Cancel</button><button>Save ticket</button></div></form></div>}</>
}

function Tickets({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/tickets'); const devices = useApi<Row[]>('/v1/devices')
  return <SearchablePage title="Tickets" subtitle="Operator-owned work and incident escalation" state={state} columns={[["title", "Summary"], ["priority", "Priority"], ["status", "Status"], ["updated_at", "Updated"]]} href={(row) => `/tickets/${row.id}`} actions={canOperate(user) && <TicketForm devices={devices.data ?? []} onSaved={state.reload} />} />
}

function TicketDetail({ id, user }: { id: string; user?: Row }) {
  const state = useApi<Row>(`/v1/tickets/${id}`); const [error, setError] = useState('')
  async function update(field: string, value: string) { try { await api(`/v1/tickets/${id}`, { method: 'PATCH', body: JSON.stringify({ [field]: value }) }); state.reload() } catch (reason) { setError((reason as Error).message) } }
  return <Status state={state}>{state.data && <><a className="back" href="/tickets">← Tickets</a><Title title={state.data.title} subtitle={`Ticket ${state.data.id}`} actions={canOperate(user) && <div className="button-row"><select value={state.data.status} onChange={(event) => update('status', event.target.value)}><option>open</option><option>in_progress</option><option>resolved</option><option>closed</option></select><select value={state.data.priority} onChange={(event) => update('priority', event.target.value)}><option>low</option><option>normal</option><option>high</option><option>critical</option></select></div>} />{error && <div className="state error">{error}</div>}<div className="summary-grid"><Panel title="Description"><p>{state.data.description || 'No description.'}</p><p>Device: {state.data.device_id || 'Not linked'}</p></Panel><Panel title="Linked incident"><pre>{JSON.stringify(state.data.incident, null, 2)}</pre></Panel></div><Panel title="Actions"><Table rows={state.data.actions} columns={[["skill_id", "Skill"], ["risk", "Risk"], ["status", "Status"]]} href={(row) => `/actions/${row.id}`} /></Panel><Panel title="Timeline"><Timeline rows={state.data.timeline} /></Panel></>}</Status>
}

function Incidents() { const state = useApi<Row[]>('/v1/incidents'); return <SearchablePage title="Incidents" subtitle="Deterministically correlated endpoint conditions" state={state} columns={[["summary", "Summary"], ["severity", "Severity"], ["status", "Status"], ["occurrence_count", "Occurrences"], ["last_observed_at", "Last observed"]]} href={(row) => `/incidents/${row.id}`} /> }
function IncidentDetail({ id }: { id: string }) { const state = useApi<Row>(`/v1/incidents/${id}`); return <Status state={state}>{state.data && <><a className="back" href="/incidents">← Incidents</a><Title title={state.data.summary} subtitle={`${state.data.incident_type} · ${state.data.id}`} /><div className="summary-grid"><Panel title="Condition"><p><Badge value={state.data.severity} /> <Badge value={state.data.status} /></p><p>Device: {state.data.device_id}</p><p>Occurrences: {state.data.occurrence_count}</p><p>First: {when(state.data.first_observed_at)}<br />Last: {when(state.data.last_observed_at)}</p></Panel><Panel title="Evidence"><pre>{JSON.stringify(state.data.evidence, null, 2)}</pre></Panel><Panel title="Linked ticket"><pre>{JSON.stringify(state.data.ticket, null, 2)}</pre></Panel></div><Panel title="Remediation actions"><Table rows={state.data.actions} columns={[["skill_id", "Skill"], ["risk", "Risk"], ["status", "Status"]]} href={(row) => `/actions/${row.id}`} /></Panel><Panel title="Timeline"><Timeline rows={state.data.timeline} /></Panel></>}</Status> }

function ActionForm({ devices, onSaved }: { devices: Row[]; onSaved: () => void }) {
  const [open, setOpen] = useState(false); const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = new FormData(event.currentTarget); try { await api('/v1/actions', { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ device_id: data.get('device_id'), skill_id: 'service.restart', parameters: { service: data.get('service') }, ticket_id: data.get('ticket_id') || null }) }); setOpen(false); onSaved() } catch (reason) { setError((reason as Error).message) } }
  return <>{!open ? <button onClick={() => setOpen(true)}>Request action</button> : <div className="modal"><form onSubmit={submit}><h2>Request controlled action</h2><p>Policy will require an independent approval before this reaches an agent.</p>{error && <div className="state error">{error}</div>}<label>Device<select name="device_id" required>{devices.map((device) => <option value={device.id} key={device.id}>{device.hostname}</option>)}</select></label><label>Allowlisted service<input name="service" required placeholder="helpdesk-demo.service" /></label><label>Optional ticket ID<input name="ticket_id" /></label><div><button type="button" className="secondary" onClick={() => setOpen(false)}>Cancel</button><button>Submit to policy</button></div></form></div>}</>
}
function Actions({ user }: { user?: Row }) { const state = useApi<Row[]>('/v1/actions'); const devices = useApi<Row[]>('/v1/devices'); return <SearchablePage title="Actions" subtitle="Policy, approval, execution, verification, and rollback lifecycle" state={state} columns={[["skill_id", "Skill"], ["device_id", "Device"], ["risk", "Risk"], ["status", "Status"], ["created_at", "Created"]]} href={(row) => `/actions/${row.id}`} actions={canOperate(user) && <ActionForm devices={devices.data ?? []} onSaved={state.reload} />} /> }
function ActionDetail({ id }: { id: string }) { const state = useApi<Row>(`/v1/actions/${id}`); return <Status state={state}>{state.data && <><a className="back" href="/actions">← Actions</a><Title title={state.data.skill_id} subtitle={`Action ${state.data.id}`} /><div className="summary-grid"><Panel title="Lifecycle"><p><Badge value={state.data.risk} /> <Badge value={state.data.status} /></p><p>Device: {state.data.device_id}<br />Requester: {state.data.requested_by}<br />Approver: {state.data.approved_by || 'Pending'}</p></Panel><Panel title="Parameters"><pre>{JSON.stringify(state.data.parameters, null, 2)}</pre></Panel><Panel title="Execution and rollback"><pre>{JSON.stringify(state.data.execution_results, null, 2)}</pre></Panel></div><Panel title="Approval history"><pre>{JSON.stringify(state.data.approvals, null, 2)}</pre></Panel><Panel title="Timeline"><Timeline rows={state.data.timeline} /></Panel></>}</Status> }

function Approvals({ user }: { user?: Row }) { const state = useApi<Row[]>('/v1/approvals'); const [error, setError] = useState(''); async function decide(row: Row, decision: 'approve' | 'deny') { if (!confirm(`${decision === 'approve' ? 'Approve' : 'Deny'} ${row.skill_id} for device ${row.device_id}?`)) return; try { await api(`/v1/actions/${row.id}/decision`, { method: 'POST', body: JSON.stringify({ decision, reason: `${decision}d in operator console` }) }); state.reload() } catch (reason) { setError((reason as Error).message) } } return <><Title title="Approvals" subtitle="Independent human gate for risky endpoint changes" />{error && <div className="state error">{error}</div>}<Status state={state}>{state.data?.length ? <div className="approval-list">{state.data.map((row) => <article key={row.id}><div><h2>{row.skill_id}</h2><p>Device {row.device_id} · <Badge value={row.risk} /></p><pre>{JSON.stringify(row.parameters, null, 2)}</pre></div>{canAdmin(user) ? <div className="button-row"><button onClick={() => decide(row, 'approve')}>Approve</button><button className="danger" onClick={() => decide(row, 'deny')}>Deny</button></div> : <Badge value="read only" />}</article>)}</div> : <Empty>No actions are waiting for approval.</Empty>}</Status></> }

function Audit() { const [eventType, setEventType] = useState(''); const [correlation, setCorrelation] = useState(''); const query = new URLSearchParams(); if (eventType) query.set('event_type', eventType); if (correlation) query.set('correlation_id', correlation); const state = useApi<Row[]>(`/v1/audit?${query}`); return <><Title title="Audit trail" subtitle="Tenant-scoped, hash-chained decisions and state transitions" /><div className="filters"><input placeholder="Exact event type" value={eventType} onChange={(event) => setEventType(event.target.value)} /><input placeholder="Device, ticket, incident, or action ID" value={correlation} onChange={(event) => setCorrelation(event.target.value)} /></div><Status state={state}>{state.data?.length ? <div className="timeline"><Timeline rows={state.data} /></div> : <Empty>No audit events match the filters.</Empty>}</Status></> }

function Integrations({ user }: { user?: Row }) { const subscriptions = useApi<Row[]>('/v1/integrations/webhooks'); const deliveries = useApi<Row[]>('/v1/integrations/webhooks/deliveries'); const [error, setError] = useState(''); async function create(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); try { await api('/v1/integrations/webhooks', { method: 'POST', body: JSON.stringify({ name: data.get('name'), url: data.get('url'), secret_ref: data.get('secret_ref'), event_types: ['incident.created', 'incident.resolved', 'remediation.succeeded', 'remediation.failed'] }) }); form.reset(); subscriptions.reload() } catch (reason) { setError((reason as Error).message) } } async function disable(id: string) { if (!confirm('Disable this webhook?')) return; try { await api(`/v1/integrations/webhooks/${id}`, { method: 'DELETE' }); subscriptions.reload() } catch (reason) { setError((reason as Error).message) } } return <><Title title="Integrations" subtitle="Signed outbound events for n8n and external systems" />{error && <div className="state error">{error}</div>}{canAdmin(user) && <form className="integration-form" onSubmit={create}><input name="name" required placeholder="Integration name" /><input name="url" type="url" required placeholder="https://example.com/webhook" /><input name="secret_ref" required pattern="env:HELPDESK_WEBHOOK_SECRET_[A-Z0-9_]+" defaultValue="env:HELPDESK_WEBHOOK_SECRET_DEMO" /><button>Create webhook</button></form>}<Status state={subscriptions}>{subscriptions.data?.length ? <div className="integration-list">{subscriptions.data.map((row) => <article key={row.id}><div><h3>{row.name} <Badge value={row.active ? 'active' : 'disabled'} /></h3><p>{row.url}</p><small>{row.event_types.join(', ')}</small></div>{row.active && canAdmin(user) && <button className="danger secondary" onClick={() => disable(row.id)}>Disable</button>}</article>)}</div> : <Empty>No webhook subscriptions configured.</Empty>}</Status><Panel title="Recent deliveries"><Status state={deliveries}><Table rows={deliveries.data ?? []} columns={[["status", "Status"], ["event_id", "Event"], ["attempt_count", "Attempts"], ["last_attempt_at", "Last attempt"], ["response_status", "HTTP"]]} /></Status></Panel></> }

function Settings() { const state = useApi<Row>('/v1/settings'); return <Status state={state}>{state.data && <><Title title="Settings" subtitle="Safe, non-secret tenant and runtime configuration" /><div className="summary-grid"><Panel title="Tenant"><h3>{state.data.tenant.name}</h3><code>{state.data.tenant.id}</code></Panel><Panel title="Environment"><p><Badge value={state.data.environment} /></p><p>Development login: {String(state.data.development_login_enabled)}</p></Panel><Panel title="Incident policy"><p>Low-disk threshold: <strong>{state.data.low_disk_threshold_percent}%</strong></p><p>Allowed services: {state.data.allowed_services.join(', ') || 'None'}</p></Panel></div><Panel title="Users and roles"><Table rows={state.data.users} columns={[["email", "Email"], ["role", "Role"], ["active", "Active"]]} /></Panel><Panel title="Supported domain events"><p>{state.data.supported_events.join(' · ')}</p></Panel></>}</Status> }

function Route({ user }: { user?: Row }) { const parts = location.pathname.split('/').filter(Boolean); const [resource, id] = parts; if (!resource) return <Dashboard />; if (resource === 'devices') return id ? <DeviceDetail id={id} user={user} /> : <Devices />; if (resource === 'tickets') return id ? <TicketDetail id={id} user={user} /> : <Tickets user={user} />; if (resource === 'incidents') return id ? <IncidentDetail id={id} /> : <Incidents />; if (resource === 'actions') return id ? <ActionDetail id={id} /> : <Actions user={user} />; if (resource === 'approvals') return <Approvals user={user} />; if (resource === 'audit') return <Audit />; if (resource === 'integrations') return <Integrations user={user} />; if (resource === 'settings') return <Settings />; return <div className="state error">Page not found.</div> }

function App() { const [user, setUser] = useState<Row>(); const [checking, setChecking] = useState(!!localStorage.getItem('helpdesk_session')); useEffect(() => { if (!checking) return; api<Row>('/v1/auth/me').then(setUser).catch(() => localStorage.removeItem('helpdesk_session')).finally(() => setChecking(false)) }, []); if (checking) return <div className="state full">Restoring session…</div>; if (!user) return <Login onLogin={setUser} />; const path = location.pathname; return <div className="shell"><aside><div className="logo"><span>H</span><b>Helpdesktool</b></div><nav>{NAVIGATION.map(([href, text]) => <a key={href} className={(href === '/' ? path === '/' : path.startsWith(href)) ? 'active' : ''} href={href}>{text}</a>)}</nav><div className="identity"><strong>{user.email}</strong><Badge value={user.role} /><button onClick={() => { localStorage.removeItem('helpdesk_session'); setUser(undefined) }}>Sign out</button></div></aside><main className="content"><div className="topbar"><strong>Acme IT</strong><span>Development MVP</span></div><Route user={user} /></main></div> }

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
