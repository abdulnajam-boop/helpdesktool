import { useState } from 'react'
import { api } from '../api'
import { Badge, Empty, Status } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

export function DevLogin({ onLogin }: { onLogin: (user: Row) => void }) {
  const users = useApi<Row[]>('/v1/auth/development/users')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  async function login(user: Row) {
    setBusy(user.id)
    setError('')
    try {
      const result = await api<Row>(
        `/v1/auth/development/login?user_id=${encodeURIComponent(user.id)}`,
        { method: 'POST' },
      )
      localStorage.setItem('helpdesk_session', result.access_token)
      onLogin(result.user)
    } catch (reason) {
      setError((reason as Error).message)
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <div className="dev-note">Development login · unavailable in production mode</div>
      {error && <div className="state error">{error}</div>}
      <Status state={users}>
        {users.data?.length ? (
          <div className="login-users">
            {users.data.map((user) => (
              <button disabled={!!busy} key={user.id} onClick={() => login(user)}>
                <Badge value={user.role} />
                <span>
                  <strong>{user.email}</strong>
                  <small>{user.tenant}</small>
                </span>
                <b>{busy === user.id ? 'Signing in…' : 'Continue →'}</b>
              </button>
            ))}
          </div>
        ) : (
          <Empty>Run the development seed to create demo users.</Empty>
        )}
      </Status>
    </>
  )
}
