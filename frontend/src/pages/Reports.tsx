import { useMemo, useState } from 'react'
import { Panel, Table, Title, when } from '../components'
import { useApi } from '../hooks'

const PERIODS = [
  ['1', 'Last 24 hours'],
  ['7', 'Last 7 days'],
  ['30', 'Last 30 days'],
  ['90', 'Last 90 days'],
] as const

function formatDuration(seconds: number | null | undefined) {
  if (seconds == null) return '—'
  const total = Math.round(seconds)
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (hours >= 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m ${total % 60}s`
  return `${total}s`
}

function formatRate(rate: number | null | undefined) {
  return rate == null ? '—' : `${Math.round(rate * 100)}%`
}

export function Reports() {
  const [days, setDays] = useState('7')
  // Computed once per `days` selection, not on every render: useApi's
  // effect re-fires whenever this path string changes, so deriving `end`
  // from `new Date()` directly in the render body (a fresh timestamp,
  // and therefore a fresh path, on every single render) created an
  // infinite fetch loop that a real browser test caught -- the page never
  // stopped re-requesting long enough for any single response to render.
  const path = useMemo(() => {
    const end = new Date()
    const start = new Date(end.getTime() - Number(days) * 86400000)
    return `/v1/reports/summary?start=${encodeURIComponent(start.toISOString())}&end=${encodeURIComponent(end.toISOString())}`
  }, [days])
  const state = useApi<any>(path)
  const report = state.data
  return (
    <>
      <Title
        title="Reports"
        subtitle="Operational summary: incidents, tickets, remediation outcomes, and approval activity for the selected period"
        actions={
          <select value={days} onChange={(event) => setDays(event.target.value)}>
            {PERIODS.map(([value, text]) => (
              <option key={value} value={value}>
                {text}
              </option>
            ))}
          </select>
        }
      />
      {state.loading && <div className="state">Loading…</div>}
      {state.error && <div className="state error">{state.error}</div>}
      {report && (
        <>
          <div className="cards">
            <article className="metric">
              <span>Incidents detected</span>
              <strong>{report.incidents.detected}</strong>
            </article>
            <article className="metric">
              <span>Incidents resolved</span>
              <strong>{report.incidents.resolved}</strong>
            </article>
            <article className="metric">
              <span>Mean time to resolve</span>
              <strong>{formatDuration(report.incidents.mttr_seconds)}</strong>
            </article>
            <article className="metric">
              <span>Remediation success rate</span>
              <strong>{formatRate(report.remediation.success_rate)}</strong>
            </article>
            <article className="metric">
              <span>Devices online</span>
              <strong>
                {report.devices.online} / {report.devices.total}
              </strong>
            </article>
          </div>
          <div className="three-column">
            <Panel title="Incidents">
              <dl className="report-stats">
                <div>
                  <dt>Detected</dt>
                  <dd>{report.incidents.detected}</dd>
                </div>
                <div>
                  <dt>Resolved</dt>
                  <dd>{report.incidents.resolved}</dd>
                </div>
                <div>
                  <dt>Reopened</dt>
                  <dd>{report.incidents.reopened}</dd>
                </div>
                <div>
                  <dt>Open now</dt>
                  <dd>{report.incidents.open_now}</dd>
                </div>
                <div>
                  <dt>MTTR</dt>
                  <dd>{formatDuration(report.incidents.mttr_seconds)}</dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Tickets">
              <dl className="report-stats">
                <div>
                  <dt>Opened</dt>
                  <dd>{report.tickets.opened}</dd>
                </div>
                <div>
                  <dt>Resolved</dt>
                  <dd>{report.tickets.resolved}</dd>
                </div>
                <div>
                  <dt>Open now</dt>
                  <dd>{report.tickets.open_now}</dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Remediation">
              <dl className="report-stats">
                <div>
                  <dt>Attempts</dt>
                  <dd>{report.remediation.attempts}</dd>
                </div>
                <div>
                  <dt>Succeeded</dt>
                  <dd>{report.remediation.succeeded}</dd>
                </div>
                <div>
                  <dt>Failed</dt>
                  <dd>{report.remediation.failed}</dd>
                </div>
                <div>
                  <dt>Success rate</dt>
                  <dd>{formatRate(report.remediation.success_rate)}</dd>
                </div>
                <div>
                  <dt>Rollbacks attempted</dt>
                  <dd>{report.remediation.rollback_attempted}</dd>
                </div>
                <div>
                  <dt>Rollbacks succeeded</dt>
                  <dd>{report.remediation.rollback_succeeded}</dd>
                </div>
              </dl>
            </Panel>
          </div>
          <div className="three-column">
            <Panel title="Approvals">
              <dl className="report-stats">
                <div>
                  <dt>Approved</dt>
                  <dd>{report.approvals.approved}</dd>
                </div>
                <div>
                  <dt>Denied</dt>
                  <dd>{report.approvals.denied}</dd>
                </div>
                <div>
                  <dt>Avg time to decision</dt>
                  <dd>{formatDuration(report.approvals.avg_time_to_decision_seconds)}</dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Devices">
              <dl className="report-stats">
                <div>
                  <dt>Total</dt>
                  <dd>{report.devices.total}</dd>
                </div>
                <div>
                  <dt>Online</dt>
                  <dd>{report.devices.online}</dd>
                </div>
                <div>
                  <dt>Offline</dt>
                  <dd>{report.devices.offline}</dd>
                </div>
              </dl>
            </Panel>
            <Panel title="Security">
              <dl className="report-stats">
                <div>
                  <dt>Policy denials</dt>
                  <dd>{report.security.policy_denials}</dd>
                </div>
                <div>
                  <dt>Approval denials</dt>
                  <dd>{report.security.approval_denials}</dd>
                </div>
              </dl>
            </Panel>
          </div>
          <Panel title="Recurring problems">
            {report.recurring_incidents.length ? (
              <Table
                rows={report.recurring_incidents.map((row: any, index: number) => ({
                  id: index,
                  ...row,
                }))}
                columns={[
                  ['incident_type', 'Incident type'],
                  ['device_id', 'Device'],
                  ['occurrence_count', 'Occurrences'],
                  ['status', 'Status'],
                  ['last_observed_at', 'Last observed'],
                ]}
              />
            ) : (
              <div className="state empty">No recurring incidents.</div>
            )}
          </Panel>
          <p className="hint">
            Period: {when(report.period.start)} – {when(report.period.end)}
          </p>
        </>
      )}
    </>
  )
}
