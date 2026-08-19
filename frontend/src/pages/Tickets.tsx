import { FormEvent, useState } from 'react'
import { api } from '../api'
import { Panel, SearchablePage, Status, Table, Timeline, Title, canOperate } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

function TicketForm({ devices, onSaved }: { devices: Row[]; onSaved: () => void }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    const data = new FormData(event.currentTarget)
    try {
      await api('/v1/tickets', {
        method: 'POST',
        body: JSON.stringify({
          title: data.get('title'),
          description: data.get('description'),
          priority: data.get('priority'),
          device_id: data.get('device_id') || null,
        }),
      })
      setOpen(false)
      onSaved()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }
  if (!open) return <button onClick={() => setOpen(true)}>Create ticket</button>
  return (
    <div className="modal">
      <form onSubmit={submit}>
        <h2>Create ticket</h2>
        {error && <div className="state error">{error}</div>}
        <label>
          Summary
          <input name="title" required maxLength={300} />
        </label>
        <label>
          Description
          <textarea name="description" rows={4} />
        </label>
        <label>
          Priority
          <select name="priority">
            <option>normal</option>
            <option>low</option>
            <option>high</option>
            <option>critical</option>
          </select>
        </label>
        <label>
          Device
          <select name="device_id">
            <option value="">None</option>
            {devices.map((device) => (
              <option value={device.id} key={device.id}>
                {device.hostname}
              </option>
            ))}
          </select>
        </label>
        <div>
          <button type="button" className="secondary" onClick={() => setOpen(false)}>
            Cancel
          </button>
          <button>Save ticket</button>
        </div>
      </form>
    </div>
  )
}

export function Tickets({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/tickets')
  const devices = useApi<Row[]>('/v1/devices')
  return (
    <SearchablePage
      title="Tickets"
      subtitle="Operator-owned work and incident escalation"
      state={state}
      columns={[
        ['title', 'Summary'],
        ['priority', 'Priority'],
        ['status', 'Status'],
        ['updated_at', 'Updated'],
      ]}
      href={(row) => `/tickets/${row.id}`}
      actions={canOperate(user) && <TicketForm devices={devices.data ?? []} onSaved={state.reload} />}
    />
  )
}

export function TicketDetail({ id, user }: { id: string; user?: Row }) {
  const state = useApi<Row>(`/v1/tickets/${id}`)
  const [error, setError] = useState('')
  async function update(field: string, value: string) {
    try {
      await api(`/v1/tickets/${id}`, { method: 'PATCH', body: JSON.stringify({ [field]: value }) })
      state.reload()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }
  return (
    <Status state={state}>
      {state.data && (
        <>
          <a className="back" href="/tickets">
            ← Tickets
          </a>
          <Title
            title={state.data.title}
            subtitle={`Ticket ${state.data.id}`}
            actions={
              canOperate(user) && (
                <div className="button-row">
                  <select value={state.data.status} onChange={(event) => update('status', event.target.value)}>
                    <option>open</option>
                    <option>in_progress</option>
                    <option>resolved</option>
                    <option>closed</option>
                  </select>
                  <select value={state.data.priority} onChange={(event) => update('priority', event.target.value)}>
                    <option>low</option>
                    <option>normal</option>
                    <option>high</option>
                    <option>critical</option>
                  </select>
                </div>
              )
            }
          />
          {error && <div className="state error">{error}</div>}
          <div className="summary-grid">
            <Panel title="Description">
              <p>{state.data.description || 'No description.'}</p>
              <p>Device: {state.data.device_id || 'Not linked'}</p>
            </Panel>
            <Panel title="Linked incident">
              <pre>{JSON.stringify(state.data.incident, null, 2)}</pre>
            </Panel>
          </div>
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
          <Panel title="Timeline">
            <Timeline rows={state.data.timeline} />
          </Panel>
        </>
      )}
    </Status>
  )
}
