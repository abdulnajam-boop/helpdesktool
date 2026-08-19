import { useState } from 'react'
import { api } from '../api'
import { Badge, Panel, SearchablePage, Status, Table, Timeline, Title, canOperate, when } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function Incidents() {
  const state = useApi<Row[]>('/v1/incidents')
  return (
    <SearchablePage
      title="Incidents"
      subtitle="Deterministically correlated endpoint conditions"
      state={state}
      columns={[
        ['summary', 'Summary'],
        ['severity', 'Severity'],
        ['status', 'Status'],
        ['occurrence_count', 'Occurrences'],
        ['last_observed_at', 'Last observed'],
      ]}
      href={(row) => `/incidents/${row.id}`}
    />
  )
}

function DiagnosisPanel({ incidentId, diagnoses, user, onDiagnosed }: {
  incidentId: string
  diagnoses: Row[]
  user?: Row
  onDiagnosed: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function diagnose() {
    setBusy(true)
    setError('')
    try {
      await api(`/v1/incidents/${incidentId}/diagnose`, { method: 'POST' })
      onDiagnosed()
    } catch (reason) {
      setError((reason as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel title="AI diagnosis">
      <p className="hint">
        Advisory only. A diagnosis is never executed automatically -- an operator still has to
        submit a remediation request through the normal policy/approval pipeline.
      </p>
      {canOperate(user) && (
        <button onClick={diagnose} disabled={busy}>
          {busy ? 'Diagnosing…' : 'Run AI diagnosis'}
        </button>
      )}
      {error && <div className="state error">{error}</div>}
      {diagnoses.length ? (
        <div className="diagnosis-list">
          {diagnoses.map((diagnosis) => (
            <article key={diagnosis.id}>
              <div>
                <strong>{diagnosis.summary}</strong>
                <span>
                  {diagnosis.provider_name} · {when(diagnosis.created_at)}
                  {diagnosis.fallback_used ? ' · fallback' : ''}
                </span>
              </div>
              {diagnosis.likely_root_cause && <p>Likely cause: {diagnosis.likely_root_cause}</p>}
              {diagnosis.suggested_skill_id && (
                <p>
                  Suggested skill: <code>{diagnosis.suggested_skill_id}</code>
                  {' '}(confidence {Math.round(diagnosis.confidence * 100)}%)
                </p>
              )}
              {diagnosis.escalate && <Badge value="escalate" />}
            </article>
          ))}
        </div>
      ) : (
        <p className="hint">No diagnosis has been run for this incident yet.</p>
      )}
    </Panel>
  )
}

export function IncidentDetail({ id, user }: { id: string; user?: Row }) {
  const state = useApi<Row>(`/v1/incidents/${id}`)
  return (
    <Status state={state}>
      {state.data && (
        <>
          <a className="back" href="/incidents">
            ← Incidents
          </a>
          <Title title={state.data.summary} subtitle={`${state.data.incident_type} · ${state.data.id}`} />
          <div className="summary-grid">
            <Panel title="Condition">
              <p>
                <Badge value={state.data.severity} /> <Badge value={state.data.status} />
              </p>
              <p>Device: {state.data.device_id}</p>
              <p>Occurrences: {state.data.occurrence_count}</p>
              <p>
                First: {when(state.data.first_observed_at)}
                <br />
                Last: {when(state.data.last_observed_at)}
              </p>
            </Panel>
            <Panel title="Evidence">
              <pre>{JSON.stringify(state.data.evidence, null, 2)}</pre>
            </Panel>
            <Panel title="Linked ticket">
              <pre>{JSON.stringify(state.data.ticket, null, 2)}</pre>
            </Panel>
          </div>
          <DiagnosisPanel
            incidentId={id}
            diagnoses={state.data.diagnoses ?? []}
            user={user}
            onDiagnosed={state.reload}
          />
          <Panel title="Remediation actions">
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
