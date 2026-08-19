import { ReactNode, useMemo, useState } from 'react'
import { LoadState, Row } from './types'

export const label = (value: string) => value.replaceAll('_', ' ')
export const when = (value: any) => (value ? new Date(value).toLocaleString() : 'Never')
export const display = (value: any) =>
  value == null ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value)
export const canOperate = (user?: Row) => ['owner', 'admin', 'operator'].includes(user?.role)
export const canAdmin = (user?: Row) => ['owner', 'admin'].includes(user?.role)

export function Badge({ value }: { value: any }) {
  return <span className={`badge ${String(value).toLowerCase()}`}>{label(String(value))}</span>
}

export function Status({ state, children }: { state: LoadState<any>; children: ReactNode }) {
  if (state.loading) return <div className="state">Loading…</div>
  if (state.error) return <div className="state error">{state.error}</div>
  return <>{children}</>
}

export function Title({
  title,
  subtitle,
  actions,
}: {
  title: string
  subtitle: string
  actions?: ReactNode
}) {
  return (
    <header className="title">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {actions}
    </header>
  )
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  )
}

export function Empty({ children = 'No records yet.' }: { children?: ReactNode }) {
  return <div className="state empty">{children}</div>
}

export function Table({
  rows,
  columns,
  href,
}: {
  rows: Row[]
  columns: [string, string][]
  href?: (row: Row) => string
}) {
  if (!rows.length) return <Empty />
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map(([key, heading]) => (
              <th key={key}>{heading}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={row.id ?? index}
              className={href ? 'clickable' : ''}
              onClick={() => href && (location.href = href(row))}
            >
              {columns.map(([key]) => (
                <td key={key}>
                  {['status', 'severity', 'risk', 'os', 'priority'].includes(key) ? (
                    <Badge value={row[key]} />
                  ) : key.endsWith('_at') ? (
                    when(row[key])
                  ) : (
                    display(row[key])
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Timeline({ rows }: { rows?: Row[] }) {
  if (!rows?.length) return <Empty>No audit activity for this resource.</Empty>
  return (
    <div className="timeline">
      {rows.map((row) => (
        <article key={row.sequence}>
          <div>
            <strong>{label(row.event_type)}</strong>
            <span>
              {when(row.occurred_at)} · {row.actor_id}
            </span>
          </div>
          <pre>{JSON.stringify(row.details, null, 2)}</pre>
        </article>
      ))}
    </div>
  )
}

export function SearchablePage({
  title,
  subtitle,
  state,
  columns,
  href,
  actions,
}: {
  title: string
  subtitle: string
  state: LoadState<Row[]>
  columns: [string, string][]
  href?: (row: Row) => string
  actions?: ReactNode
}) {
  const [query, setQuery] = useState('')
  const rows = useMemo(
    () => (state.data ?? []).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())),
    [state.data, query],
  )
  return (
    <>
      <Title title={title} subtitle={subtitle} actions={actions} />
      <input
        className="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={`Filter ${title.toLowerCase()}…`}
      />
      <Status state={state}>
        <Table rows={rows} columns={columns} href={href} />
      </Status>
    </>
  )
}
