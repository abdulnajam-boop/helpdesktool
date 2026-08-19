import { useState } from 'react'
import { Empty, Status, Timeline, Title } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function Audit() {
  const [eventType, setEventType] = useState('')
  const [correlation, setCorrelation] = useState('')
  const query = new URLSearchParams()
  if (eventType) query.set('event_type', eventType)
  if (correlation) query.set('correlation_id', correlation)
  const state = useApi<Row[]>(`/v1/audit?${query}`)
  return (
    <>
      <Title title="Audit trail" subtitle="Tenant-scoped, hash-chained decisions and state transitions" />
      <div className="filters">
        <input
          placeholder="Exact event type"
          value={eventType}
          onChange={(event) => setEventType(event.target.value)}
        />
        <input
          placeholder="Device, ticket, incident, or action ID"
          value={correlation}
          onChange={(event) => setCorrelation(event.target.value)}
        />
      </div>
      <Status state={state}>
        {state.data?.length ? (
          <div className="timeline">
            <Timeline rows={state.data} />
          </div>
        ) : (
          <Empty>No audit events match the filters.</Empty>
        )}
      </Status>
    </>
  )
}
