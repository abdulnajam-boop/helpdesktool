import { FormEvent, useState } from 'react'
import { api } from '../api'
import { Empty, Status, Table, Title, canAdmin, when } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

function ConnectorForm({ onSaved }: { onSaved: () => void }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    try {
      await api('/v1/connectors', {
        method: 'POST',
        body: JSON.stringify({
          application_id: data.get('application_id'),
          display_name: data.get('display_name'),
          connector_type: data.get('connector_type'),
        }),
      })
      setOpen(false)
      onSaved()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }
  if (!open) return <button onClick={() => setOpen(true)}>Add application</button>
  return (
    <div className="modal">
      <form onSubmit={submit}>
        <h2>Connect an application</h2>
        <p>
          Self-service password reset, account unlock, and MFA reset for this application will
          route through the policy-gated connector framework -- every credential-affecting
          operation requires independent admin approval before it runs.
        </p>
        {error && <div className="state error">{error}</div>}
        <label>
          Application ID
          <input name="application_id" required placeholder="salesforce" pattern="[a-z0-9_.-]+" />
        </label>
        <label>
          Display name
          <input name="display_name" required placeholder="Salesforce" />
        </label>
        <label>
          Connector type
          <select name="connector_type" defaultValue="mock">
            <option value="mock">Mock (demo/test)</option>
          </select>
        </label>
        <div>
          <button type="button" className="secondary" onClick={() => setOpen(false)}>
            Cancel
          </button>
          <button>Connect</button>
        </div>
      </form>
    </div>
  )
}

function ConnectorRequestList({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/connector-requests')
  async function decide(id: string, decision: 'approve' | 'deny') {
    await api(`/v1/connector-requests/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({ decision, reason: '' }),
    })
    state.reload()
  }
  if (!canAdmin(user)) return null
  return (
    <Status state={state}>
      {state.data?.length ? (
        <div className="approval-list">
          {state.data.map((row) => (
            <article key={row.id}>
              <div>
                <h2>{row.operation.replace('_', ' ')}</h2>
                <p>
                  For {row.target_email} &middot; requested {when(row.created_at)}
                </p>
              </div>
              <div className="button-row">
                <button onClick={() => decide(row.id, 'approve')}>Approve</button>
                <button className="danger" onClick={() => decide(row.id, 'deny')}>
                  Deny
                </button>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <Empty>No pending connector requests.</Empty>
      )}
    </Status>
  )
}

export function Applications({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/connectors')
  return (
    <>
      <Title
        title="Applications"
        subtitle="Connected applications available for self-service account actions via chat"
        actions={canAdmin(user) && <ConnectorForm onSaved={state.reload} />}
      />
      <Status state={state}>
        {state.data?.length ? (
          <Table
            rows={state.data}
            columns={[
              ['display_name', 'Application'],
              ['connector_type', 'Connector'],
              ['active', 'Active'],
              ['created_at', 'Connected'],
            ]}
          />
        ) : (
          <Empty>No applications connected yet.</Empty>
        )}
      </Status>
      <h2 className="section-heading">Pending connector requests</h2>
      <ConnectorRequestList user={user} />
    </>
  )
}
