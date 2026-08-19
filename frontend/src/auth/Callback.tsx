import { useEffect, useState } from 'react'
import { completeLogin, getOidcConfig } from './oidc'

/** Rendered at /auth/callback -- the identity provider redirects here after login. */
export function Callback() {
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    completeLogin(getOidcConfig(), window.location.href)
      .then((accessToken) => {
        if (!active) return
        localStorage.setItem('helpdesk_session', accessToken)
        window.location.href = '/'
      })
      .catch((reason: Error) => active && setError(reason.message))
    return () => {
      active = false
    }
  }, [])

  return (
    <main className="login">
      <section>
        <div className="brandmark">H</div>
        <h1>Helpdesktool</h1>
        {error ? (
          <>
            <div className="state error">{error}</div>
            <a className="back" href="/">
              ← Back to sign in
            </a>
          </>
        ) : (
          <p>Completing sign-in…</p>
        )}
      </section>
    </main>
  )
}
