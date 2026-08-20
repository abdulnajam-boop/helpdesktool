import { useEffect, useState } from 'react'
import { api } from './api'
import { Callback } from './auth/Callback'
import { Login } from './auth/Login'
import { Badge } from './components'
import { Actions, ActionDetail } from './pages/Actions'
import { Approvals } from './pages/Approvals'
import { Audit } from './pages/Audit'
import { Dashboard } from './pages/Dashboard'
import { DeviceDetail, Devices } from './pages/Devices'
import { IncidentDetail, Incidents } from './pages/Incidents'
import { Integrations } from './pages/Integrations'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'
import { Skills } from './pages/Skills'
import { TicketDetail, Tickets } from './pages/Tickets'
import { Row } from './types'

const NAVIGATION = [
  ['/', 'Dashboard'],
  ['/devices', 'Devices'],
  ['/tickets', 'Tickets'],
  ['/incidents', 'Incidents'],
  ['/actions', 'Actions'],
  ['/approvals', 'Approvals'],
  ['/skills', 'Skills'],
  ['/reports', 'Reports'],
  ['/audit', 'Audit'],
  ['/integrations', 'Integrations'],
  ['/settings', 'Settings'],
] as const

function Route({ user }: { user?: Row }) {
  const parts = location.pathname.split('/').filter(Boolean)
  const [resource, id] = parts
  if (!resource) return <Dashboard />
  if (resource === 'devices') return id ? <DeviceDetail id={id} user={user} /> : <Devices />
  if (resource === 'tickets') return id ? <TicketDetail id={id} user={user} /> : <Tickets user={user} />
  if (resource === 'incidents') return id ? <IncidentDetail id={id} user={user} /> : <Incidents />
  if (resource === 'actions') return id ? <ActionDetail id={id} /> : <Actions user={user} />
  if (resource === 'approvals') return <Approvals user={user} />
  if (resource === 'skills') return <Skills user={user} />
  if (resource === 'reports') return <Reports />
  if (resource === 'audit') return <Audit />
  if (resource === 'integrations') return <Integrations user={user} />
  if (resource === 'settings') return <Settings />
  return <div className="state error">Page not found.</div>
}

export function App() {
  const [user, setUser] = useState<Row>()
  const [checking, setChecking] = useState(!!localStorage.getItem('helpdesk_session'))

  useEffect(() => {
    if (!checking) return
    api<Row>('/v1/auth/me')
      .then(setUser)
      .catch(() => localStorage.removeItem('helpdesk_session'))
      .finally(() => setChecking(false))
  }, [])

  if (location.pathname === '/auth/callback') return <Callback />
  if (checking) return <div className="state full">Restoring session…</div>
  if (!user) return <Login onLogin={setUser} />

  const path = location.pathname
  return (
    <div className="shell">
      <aside>
        <div className="logo">
          <span>H</span>
          <b>Helpdesktool</b>
        </div>
        <nav>
          {NAVIGATION.map(([href, text]) => (
            <a key={href} className={(href === '/' ? path === '/' : path.startsWith(href)) ? 'active' : ''} href={href}>
              {text}
            </a>
          ))}
        </nav>
        <div className="identity">
          <strong>{user.email}</strong>
          <Badge value={user.role} />
          <button
            onClick={() => {
              localStorage.removeItem('helpdesk_session')
              setUser(undefined)
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="content">
        <div className="topbar">
          <strong>Acme IT</strong>
          <span>Development MVP</span>
        </div>
        <Route user={user} />
      </main>
    </div>
  )
}
