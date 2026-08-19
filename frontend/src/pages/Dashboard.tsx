import { Panel, Status, Table, Title, label } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function Dashboard() {
  const state = useApi<Row>('/v1/dashboard')
  return (
    <Status state={state}>
      {state.data && (
        <>
          <Title
            title="Operations overview"
            subtitle="Current device health, incidents, and remediation activity"
          />
          <div className="cards">
            {Object.entries(state.data.counts).map(([key, value]) => (
              <article className="metric" key={key}>
                <span>{label(key)}</span>
                <strong>{String(value)}</strong>
              </article>
            ))}
          </div>
          <div className="three-column">
            <Panel title="Recent incidents">
              <Table
                rows={state.data.recent_incidents}
                columns={[
                  ['summary', 'Incident'],
                  ['severity', 'Severity'],
                  ['status', 'Status'],
                ]}
                href={(row) => `/incidents/${row.id}`}
              />
            </Panel>
            <Panel title="Recent tickets">
              <Table
                rows={state.data.recent_tickets}
                columns={[
                  ['title', 'Ticket'],
                  ['priority', 'Priority'],
                  ['status', 'Status'],
                ]}
                href={(row) => `/tickets/${row.id}`}
              />
            </Panel>
            <Panel title="Recent actions">
              <Table
                rows={state.data.recent_actions}
                columns={[
                  ['skill_id', 'Skill'],
                  ['risk', 'Risk'],
                  ['status', 'Status'],
                ]}
                href={(row) => `/actions/${row.id}`}
              />
            </Panel>
          </div>
        </>
      )}
    </Status>
  )
}
