import { Badge, Panel, Status, Table, Title } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function Settings() {
  const state = useApi<Row>('/v1/settings')
  return (
    <Status state={state}>
      {state.data && (
        <>
          <Title title="Settings" subtitle="Safe, non-secret tenant and runtime configuration" />
          <div className="summary-grid">
            <Panel title="Tenant">
              <h3>{state.data.tenant.name}</h3>
              <code>{state.data.tenant.id}</code>
            </Panel>
            <Panel title="Environment">
              <p>
                <Badge value={state.data.environment} />
              </p>
              <p>Development login: {String(state.data.development_login_enabled)}</p>
            </Panel>
            <Panel title="Incident policy">
              <p>
                Low-disk threshold: <strong>{state.data.low_disk_threshold_percent}%</strong>
              </p>
              <p>Allowed services: {state.data.allowed_services.join(', ') || 'None'}</p>
            </Panel>
          </div>
          <Panel title="Users and roles">
            <Table
              rows={state.data.users}
              columns={[
                ['email', 'Email'],
                ['role', 'Role'],
                ['active', 'Active'],
              ]}
            />
          </Panel>
          <Panel title="Supported domain events">
            <p>{state.data.supported_events.join(' · ')}</p>
          </Panel>
        </>
      )}
    </Status>
  )
}
