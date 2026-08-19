import { useState } from 'react'
import { api } from '../api'
import { Panel, SearchablePage, Status, Table, Timeline, Title, canOperate, when } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

function LowDiskSimulator({ deviceId, onComplete }: { deviceId: string; onComplete: () => void }) {
  const [used, setUsed] = useState('96')
  const [message, setMessage] = useState('')
  async function simulate() {
    setMessage('Submitting simulated telemetry…')
    try {
      const result = await api<Row>('/v1/development/simulations/low-disk', {
        method: 'POST',
        body: JSON.stringify({ device_id: deviceId, mountpoint: '/', used_percent: Number(used) }),
      })
      setMessage(
        result.incident
          ? `Incident ${result.incident.status}; occurrence ${result.incident.occurrence_count}`
          : 'Healthy telemetry accepted; no open incident.',
      )
      onComplete()
    } catch (error) {
      setMessage((error as Error).message)
    }
  }
  return (
    <div className="simulator">
      <label>
        Simulated disk use
        <input type="number" min="0" max="100" value={used} onChange={(event) => setUsed(event.target.value)} />
      </label>
      <button onClick={simulate}>Submit telemetry</button>
      <small>{message || 'Use 96% to create/correlate; use 40% to resolve.'}</small>
    </div>
  )
}

export function Devices() {
  const state = useApi<Row[]>('/v1/devices')
  return (
    <SearchablePage
      title="Devices"
      subtitle="Enrolled endpoint inventory and connectivity"
      state={state}
      columns={[
        ['hostname', 'Hostname'],
        ['os', 'OS'],
        ['status', 'Status'],
        ['last_seen_at', 'Last seen'],
        ['open_incidents', 'Open incidents'],
      ]}
      href={(row) => `/devices/${row.id}`}
    />
  )
}

export function DeviceDetail({ id, user }: { id: string; user?: Row }) {
  const state = useApi<Row>(`/v1/devices/${id}`)
  return (
    <Status state={state}>
      {state.data && (
        <>
          <a className="back" href="/devices">
            ← Devices
          </a>
          <Title
            title={state.data.hostname}
            subtitle={`${state.data.os} endpoint · ${state.data.external_id}`}
            actions={
              canOperate(user) && state.data.os === 'linux' ? (
                <LowDiskSimulator deviceId={id} onComplete={state.reload} />
              ) : undefined
            }
          />
          <div className="summary-grid">
            <Panel title="Status">
              <span className={`badge ${state.data.status}`}>{state.data.status}</span>
              <p>Last seen: {when(state.data.last_seen_at)}</p>
              <pre>{JSON.stringify(state.data.latest_heartbeat, null, 2)}</pre>
            </Panel>
            <Panel title="Inventory">
              <pre>{JSON.stringify(state.data.inventory, null, 2)}</pre>
            </Panel>
          </div>
          <Panel title="Incidents">
            <Table
              rows={state.data.incidents}
              columns={[
                ['summary', 'Summary'],
                ['severity', 'Severity'],
                ['status', 'Status'],
                ['last_observed_at', 'Observed'],
              ]}
              href={(row) => `/incidents/${row.id}`}
            />
          </Panel>
          <Panel title="Tickets">
            <Table
              rows={state.data.tickets}
              columns={[
                ['title', 'Title'],
                ['priority', 'Priority'],
                ['status', 'Status'],
              ]}
              href={(row) => `/tickets/${row.id}`}
            />
          </Panel>
          <Panel title="Actions">
            <Table
              rows={state.data.actions}
              columns={[
                ['skill_id', 'Skill'],
                ['risk', 'Risk'],
                ['status', 'Status'],
              ]}
              href={(row) => `/actions/${row.id}`}
            />
          </Panel>
          <Panel title="Audit activity">
            <Timeline rows={state.data.audit} />
          </Panel>
        </>
      )}
    </Status>
  )
}
