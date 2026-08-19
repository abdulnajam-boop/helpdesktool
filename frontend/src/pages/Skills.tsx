import { FormEvent, useState } from 'react'
import { api } from '../api'
import { Empty, Status, Table, Title, canAdmin } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

function SkillForm({ onSaved }: { onSaved: () => void }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const supportedOs = data.getAll('supported_os') as string[]
    if (!supportedOs.length) {
      setError('Select at least one supported OS.')
      return
    }
    try {
      await api('/v1/skills', {
        method: 'POST',
        body: JSON.stringify({
          skill_id: data.get('skill_id'),
          risk: data.get('risk'),
          supported_os: supportedOs,
          timeout_seconds: Number(data.get('timeout_seconds')) || 30,
          rollback_skill_id: data.get('rollback_skill_id') || null,
          parameters: {},
        }),
      })
      setOpen(false)
      onSaved()
    } catch (reason) {
      setError((reason as Error).message)
    }
  }
  if (!open) return <button onClick={() => setOpen(true)}>Register skill</button>
  return (
    <div className="modal">
      <form onSubmit={submit}>
        <h2>Register a skill manifest</h2>
        <p>
          Registering policy metadata here is not enough on its own to make a skill executable --
          the endpoint agent still needs its own deterministic executor code for the skill id
          before any job can actually run.
        </p>
        {error && <div className="state error">{error}</div>}
        <label>
          Skill ID
          <input name="skill_id" required placeholder="diagnostics.network" />
        </label>
        <label>
          Risk
          <select name="risk">
            <option value="read_only">read_only</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="prohibited">prohibited</option>
          </select>
        </label>
        <label>
          Supported OS
          <span className="checkbox-row">
            <label>
              <input type="checkbox" name="supported_os" value="linux" defaultChecked /> linux
            </label>
            <label>
              <input type="checkbox" name="supported_os" value="windows" defaultChecked /> windows
            </label>
          </span>
        </label>
        <label>
          Timeout (seconds)
          <input name="timeout_seconds" type="number" min="1" max="300" defaultValue="30" />
        </label>
        <label>
          Rollback skill ID (optional)
          <input name="rollback_skill_id" />
        </label>
        <div>
          <button type="button" className="secondary" onClick={() => setOpen(false)}>
            Cancel
          </button>
          <button>Register</button>
        </div>
      </form>
    </div>
  )
}

export function Skills({ user }: { user?: Row }) {
  const state = useApi<Row[]>('/v1/skills')
  return (
    <>
      <Title
        title="Skills"
        subtitle="Versioned, integrity-checked remediation skill registry"
        actions={canAdmin(user) && <SkillForm onSaved={state.reload} />}
      />
      <Status state={state}>
        {state.data?.length ? (
          <Table
            rows={state.data}
            columns={[
              ['skill_id', 'Skill'],
              ['version', 'Version'],
              ['risk', 'Risk'],
              ['timeout_seconds', 'Timeout (s)'],
              ['created_at', 'Registered'],
            ]}
          />
        ) : (
          <Empty>No skills are registered.</Empty>
        )}
      </Status>
    </>
  )
}
