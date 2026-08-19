import { FormEvent, useState } from 'react'
import { api } from '../api'
import { Badge, Empty, Panel, Status, Table, Title, canAdmin } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function Integrations({ user }: { user?: Row }) {
  const subscriptions = useApi<Row[]>('/v1/integrations/webhooks')
  const deliveries = useApi<Row[]>('/v1/integrations/webhooks/deliveries')
  const [error, setError] = useState('')

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      await api('/v1/integrations/webhooks', {
        method: 'POST',
        body: JSON.stringify({
          name: data.get('name'),
          url: data.get('url'),
          secret_ref: data.get('secret_ref'),
          event_types: ['incident.created', 'incident.resolved', 'remediation.succeeded', 'remediation.failed'],
        }),
      })
      form.reset()
      subscriptions.reload()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }

  async function disable(id: string) {
    if (!confirm('Disable this webhook?')) return
    try {
      await api(`/v1/integrations/webhooks/${id}`, { method: 'DELETE' })
      subscriptions.reload()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }

  return (
    <>
      <Title title="Integrations" subtitle="Signed outbound events for n8n and external systems" />
      {error && <div className="state error">{error}</div>}
      {canAdmin(user) && (
        <form className="integration-form" onSubmit={create}>
          <input name="name" required placeholder="Integration name" />
          <input name="url" type="url" required placeholder="https://example.com/webhook" />
          <input
            name="secret_ref"
            required
            pattern="env:HELPDESK_WEBHOOK_SECRET_[A-Z0-9_]+"
            defaultValue="env:HELPDESK_WEBHOOK_SECRET_DEMO"
          />
          <button>Create webhook</button>
        </form>
      )}
      <Status state={subscriptions}>
        {subscriptions.data?.length ? (
          <div className="integration-list">
            {subscriptions.data.map((row) => (
              <article key={row.id}>
                <div>
                  <h3>
                    {row.name} <Badge value={row.active ? 'active' : 'disabled'} />
                  </h3>
                  <p>{row.url}</p>
                  <small>{row.event_types.join(', ')}</small>
                </div>
                {row.active && canAdmin(user) && (
                  <button className="danger secondary" onClick={() => disable(row.id)}>
                    Disable
                  </button>
                )}
              </article>
            ))}
          </div>
        ) : (
          <Empty>No webhook subscriptions configured.</Empty>
        )}
      </Status>
      <Panel title="Recent deliveries">
        <Status state={deliveries}>
          <Table
            rows={deliveries.data ?? []}
            columns={[
              ['status', 'Status'],
              ['event_id', 'Event'],
              ['attempt_count', 'Attempts'],
              ['last_attempt_at', 'Last attempt'],
              ['response_status', 'HTTP'],
            ]}
          />
        </Status>
      </Panel>
    </>
  )
}
