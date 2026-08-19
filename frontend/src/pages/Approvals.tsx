import { useState } from 'react'
import { api } from '../api'
import { Badge, Empty, Status, Title, canAdmin } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function Approvals({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/approvals')
  const [error, setError] = useState('')

  async function decide(row: Row, decision: 'approve' | 'deny') {
    if (!confirm(`${decision === 'approve' ? 'Approve' : 'Deny'} ${row.skill_id} for device ${row.device_id}?`)) {
      return
    }
    try {
      await api(`/v1/actions/${row.id}/decision`, {
        method: 'POST',
        body: JSON.stringify({ decision, reason: `${decision}d in operator console` }),
      })
      state.reload()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }

  return (
    <>
      <Title title="Approvals" subtitle="Independent human gate for risky endpoint changes" />
      {error && <div className="state error">{error}</div>}
      <Status state={state}>
        {state.data?.length ? (
          <div className="approval-list">
            {state.data.map((row) => (
              <article key={row.id}>
                <div>
                  <h2>{row.skill_id}</h2>
                  <p>
                    Device {row.device_id} · <Badge value={row.risk} />
                  </p>
                  <pre>{JSON.stringify(row.parameters, null, 2)}</pre>
                </div>
                {canAdmin(user) ? (
                  <div className="button-row">
                    <button onClick={() => decide(row, 'approve')}>Approve</button>
                    <button className="danger" onClick={() => decide(row, 'deny')}>
                      Deny
                    </button>
                  </div>
                ) : (
                  <Badge value="read only" />
                )}
              </article>
            ))}
          </div>
        ) : (
          <Empty>No actions are waiting for approval.</Empty>
        )}
      </Status>
    </>
  )
}
