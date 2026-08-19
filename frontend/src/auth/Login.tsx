import { useState } from 'react'
import { Row } from '../types'
import { DevLogin } from './DevLogin'
import { beginLogin, getOidcConfig, isOidcConfigured } from './oidc'

export function Login({ onLogin }: { onLogin: (user: Row) => void }) {
  const [error, setError] = useState('')
  const [redirecting, setRedirecting] = useState(false)
  const oidcConfigured = isOidcConfigured()

  async function signInWithOidc() {
    setError('')
    setRedirecting(true)
    try {
      await beginLogin(getOidcConfig())
    } catch (reason) {
      setError((reason as Error).message)
      setRedirecting(false)
    }
  }

  return (
    <main className="login">
      <section>
        <div className="brandmark">H</div>
        <h1>Helpdesktool</h1>
        <p>Deterministic, policy-controlled IT operations.</p>
        {error && <div className="state error">{error}</div>}
        {oidcConfigured ? (
          <button className="oidc-signin" disabled={redirecting} onClick={signInWithOidc}>
            {redirecting ? 'Redirecting to your identity provider…' : 'Sign in'}
          </button>
        ) : (
          <DevLogin onLogin={onLogin} />
        )}
      </section>
    </main>
  )
}
