import { FormEvent, useState } from 'react'
import { api } from '../api'
import { Badge, Panel, SearchablePage, Status, Timeline, Title, canOperate } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

function ActionForm({ devices, onSaved }: { devices: Row[]; onSaved: () => void }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    try {
      await api('/v1/actions', {
        method: 'POST',
        headers: { 'Idempotency-Key': crypto.randomUUID() },
        body: JSON.stringify({
          device_id: data.get('device_id'),
          skill_id: 'service.restart',
          parameters: { service: data.get('service') },
          ticket_id: data.get('ticket_id') || null,
        }),
      })
      setOpen(false)
      onSaved()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }
  if (!open) return <button onClick={() => setOpen(true)}>Request action</button>
  return (
    <div className="modal">
      <form onSubmit={submit}>
        <h2>Request controlled action</h2>
        <p>Policy will require an independent approval before this reaches an agent.</p>
        {error && <div className="state error">{error}</div>}
        <label>
          Device
          <select name="device_id" required>
            {devices.map((device) => (
              <option value={device.id} key={device.id}>
                {device.hostname}
              </option>
            ))}
          </select>
        </label>
        <label>
          Allowlisted service
          <input name="service" required placeholder="helpdesk-demo.service" />
        </label>
        <label>
          Optional ticket ID
          <input name="ticket_id" />
        </label>
        <div>
          <button type="button" className="secondary" onClick={() => setOpen(false)}>
            Cancel
          </button>
          <button>Submit to policy</button>
        </div>
      </form>
    </div>
  )
}

export function Actions({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/actions')
  const devices = useApi<Row[]>('/v1/devices')
  return (
    <SearchablePage
      title="Actions"
      subtitle="Policy, approval, execution, verification, and rollback lifecycle"
      state={state}
      columns={[
        ['skill_id', 'Skill'],
        ['device_id', 'Device'],
        ['risk', 'Risk'],
        ['status', 'Status'],
        ['created_at', 'Created'],
      ]}
      href={(row) => `/actions/${row.id}`}
      actions={canOperate(user) && <ActionForm devices={devices.data ?? []} onSaved={state.reload} />}
    />
  )
}

export function ActionDetail({ id }: { id: string }) {
  const state = useApi<Row>(`/v1/actions/${id}`)
  return (
    <Status state={state}>
      {state.data && (
        <>
          <a className="back" href="/actions">
            ← Actions
          </a>
          <Title title={state.data.skill_id} subtitle={`Action ${state.data.id}`} />
          <div className="summary-grid">
            <Panel title="Lifecycle">
              <p>
                <Badge value={state.data.risk} /> <Badge value={state.data.status} />
              </p>
              <p>
                Device: {state.data.device_id}
                <br />
                Requester: {state.data.requested_by}
                <br />
                Approver: {state.data.approved_by || 'Pending'}
              </p>
            </Panel>
            <Panel title="Parameters">
              <pre>{JSON.stringify(state.data.parameters, null, 2)}</pre>
            </Panel>
            <Panel title="Execution and rollback">
              <pre>{JSON.stringify(state.data.execution_results, null, 2)}</pre>
            </Panel>
          </div>
          <Panel title="Approval history">
            <pre>{JSON.stringify(state.data.approvals, null, 2)}</pre>
          </Panel>
          <Panel title="Timeline">
            <Timeline rows={state.data.timeline} />
          </Panel>
        </>
      )}
    </Status>
  )
}
