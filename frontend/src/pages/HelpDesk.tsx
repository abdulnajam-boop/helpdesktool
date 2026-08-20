import { FormEvent, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { Title, when } from '../components'
import { useApi } from '../hooks'
import { Row } from '../types'

type ChatMessage = { role: 'user' | 'assistant'; content: string; created_at?: string }

export function HelpDesk() {
  const [conversationId, setConversationId] = useState<string>()
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content:
        `Hi, I'm the Helpdesktool AI assistant. Tell me what's wrong -- e.g. ` +
        `"my laptop is slow" or "reset my Salesforce password".`,
    },
  ])
  const [draft, setDraft] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function send(event: FormEvent) {
    event.preventDefault()
    const message = draft.trim()
    if (!message || sending) return
    setMessages((prev) => [...prev, { role: 'user', content: message }])
    setDraft('')
    setSending(true)
    setError('')
    try {
      const result = await api<Row>('/v1/chat/message', {
        method: 'POST',
        body: JSON.stringify({ message, conversation_id: conversationId }),
      })
      setConversationId(result.conversation_id)
      setMessages((prev) => [...prev, { role: 'assistant', content: result.reply }])
    } catch (reason) {
      setError((reason as Error).message)
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <Title
        title="AI Help Desk"
        subtitle="Chat with the Helpdesktool assistant -- account issues, password resets, and general IT requests"
      />
      <div className="chat-panel">
        <div className="chat-history">
          {messages.map((entry, index) => (
            <div key={index} className={`chat-bubble ${entry.role}`}>
              <p>{entry.content}</p>
              {entry.created_at && <span>{when(entry.created_at)}</span>}
            </div>
          ))}
          {sending && <div className="chat-bubble assistant chat-typing">…</div>}
          <div ref={bottomRef} />
        </div>
        {error && <div className="state error">{error}</div>}
        <form className="chat-composer" onSubmit={send}>
          <input
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder="Describe your issue…"
            disabled={sending}
            autoFocus
          />
          <button disabled={sending || !draft.trim()}>Send</button>
        </form>
      </div>
    </>
  )
}

export function Conversations() {
  const state = useApi<Row[]>('/v1/conversations')
  return (
    <>
      <Title title="Conversations" subtitle="Chat history across every help-desk channel" />
      {state.loading && <div className="state">Loading…</div>}
      {state.error && <div className="state error">{state.error}</div>}
      {state.data && !state.data.length && <div className="state empty">No conversations yet.</div>}
      {state.data && state.data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Channel</th>
                <th>Status</th>
                <th>Ticket</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {state.data.map((row) => (
                <tr key={row.id}>
                  <td>{row.channel}</td>
                  <td>
                    <span className={`badge ${row.status}`}>{row.status}</span>
                  </td>
                  <td>{row.ticket_id ? row.ticket_id.slice(0, 8) : '—'}</td>
                  <td>{when(row.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
