import { useEffect, useState, useCallback } from 'react'
import nacl from 'tweetnacl'
import {
  accountIdToEdPub,
  buildOnion,
  buildPackedEmail,
  decryptWith,
  encryptFor,
  fromB64,
  fromHex,
  generateKeys,
  packSigned,
  parseEmail,
  signChallenge,
  toB64,
  toHex,
  unpackSigned,
} from './lib/crypto.js'

const LS_KEYS = 'session-email-keys'
const LS_SERVER = 'session-email-server'

function loadKeys() {
  try {
    const raw = localStorage.getItem(LS_KEYS)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

function short(id, n = 10) {
  if (!id) return ''
  return id.length > n * 2 + 3 ? `${id.slice(0, n)}…${id.slice(-n)}` : id
}

function fmtTime(ts) {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  const now = new Date()
  const sameDay = d.toDateString() === now.toDateString()
  if (sameDay) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const AVATAR_COLORS = ['bg-rose-500', 'bg-sky-500', 'bg-emerald-500', 'bg-amber-500', 'bg-violet-500', 'bg-teal-500']

function avatarColor(id) {
  return AVATAR_COLORS[(id?.charCodeAt(4) || 0) % AVATAR_COLORS.length]
}

function Avatar({ id, size = 'h-9 w-9 text-xs' }) {
  const label = (id || '?').replace(/^05/, '').slice(0, 2).toUpperCase() || '?'
  return (
    <span className={`flex ${size} shrink-0 items-center justify-center rounded-full font-bold text-white ${avatarColor(id)}`}>
      {label}
    </span>
  )
}

function CopyButton({ text, className = '' }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        const ta = document.createElement('textarea')
        ta.value = text
        ta.style.position = 'fixed'
        ta.style.left = '-9999px'
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }, [text])

  return (
    <button onClick={handleCopy} className={`transition-colors ${className}`}>
      {copied ? (
        <span className="inline-flex items-center gap-1 text-emerald-600">
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          Copied
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 text-zinc-500 hover:text-zinc-700">
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
          Copy
        </span>
      )}
    </button>
  )
}

export default function App() {
  const [serverUrl, setServerUrl] = useState(() => localStorage.getItem(LS_SERVER) || 'http://localhost:8080')
  const [keys, setKeys] = useState(loadKeys)
  const [view, setView] = useState('inbox')
  const [inbox, setInbox] = useState([])
  const [sent, setSent] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [readIds, setReadIds] = useState(new Set())
  const [composing, setComposing] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [revealKeys, setRevealKeys] = useState(false)
  const [to, setTo] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [circuit, setCircuit] = useState(null)

  useEffect(() => localStorage.setItem(LS_SERVER, serverUrl), [serverUrl])

  useEffect(() => {
    fetch(serverUrl.replace(/\/$/, '') + '/api/circuit')
      .then((r) => r.json())
      .then(setCircuit)
      .catch(() => {})
  }, [serverUrl])

  function handleGenerate() {
    const k = generateKeys()
    setKeys(k)
    localStorage.setItem(LS_KEYS, JSON.stringify(k))
    setInbox([])
    setSent([])
    setSelectedId(null)
    setReadIds(new Set())
    setRevealKeys(false)
    setMenuOpen(false)
  }

  async function handleSend() {
    if (!keys || !circuit || circuit.length === 0) return
    setBusy(true)
    try {
      const toTrim = to.trim()
      const recipientEdPub = accountIdToEdPub(toTrim)
      const padded = buildPackedEmail({ from: keys.accountId, to: toTrim, subject, body })
      const sig = nacl.sign.detached(padded, fromHex(keys.secretKeyHex))
      const packed = packSigned(padded, fromHex(keys.publicKeyHex), sig)
      const payload = encryptFor(packed, recipientEdPub)

      const onionJson = buildOnion({ recipient: toTrim, payload, circuit })
      const entryNode = circuit[0]
      const res = await fetch(entryNode.url + '/onion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: onionJson,
      })
      if (res.status !== 201 && res.status !== 200) throw new Error(`onion ${res.status}`)
      setSent((s) => [{ id: crypto.randomUUID(), to: toTrim, subject, body, at: Math.floor(Date.now() / 1000) }, ...s])
      setTo('')
      setSubject('')
      setBody('')
      setComposing(false)
      setView('sent')
    } catch (e) {
    } finally {
      setBusy(false)
    }
  }

  async function handleRefresh() {
    if (!keys || !circuit || circuit.length === 0) return
    setBusy(true)
    try {
      const storageNode = circuit[circuit.length - 1]
      const timestamp = String(Math.floor(Date.now() / 1000))
      const sigHex = signChallenge(keys.accountId, timestamp, fromHex(keys.secretKeyHex))
      const res = await fetch(`${storageNode.url}/messages?recipient=${encodeURIComponent(keys.accountId)}`, {
        headers: { 'X-Timestamp': timestamp, 'X-Signature': sigHex },
      })
      if (res.status !== 200) throw new Error(`server ${res.status}`)
      const msgs = await res.json()
      const mySecret = fromHex(keys.secretKeyHex)
      const decoded = msgs.map((m) => {
        try {
          const opened = decryptWith(fromB64(m.payload), mySecret)
          const { padded, senderPub, sig } = unpackSigned(opened)
          if (!nacl.sign.detached.verify(padded, sig, senderPub)) throw new Error('bad signature')
          return { ...m, ok: true, mail: parseEmail(padded) }
        } catch (e) {
          return { ...m, ok: false, error: e.message }
        }
      })
      setInbox(decoded)
    } catch (e) {
    } finally {
      setBusy(false)
    }
  }

  const list = view === 'inbox' ? inbox : sent
  const selected = list.find((m) => m.id === selectedId) || null
  const unread = inbox.filter((m) => !readIds.has(m.id)).length

  function openMsg(m) {
    setSelectedId(m.id)
    setReadIds((r) => new Set(r).add(m.id))
  }

  return (
    <div className="flex h-screen flex-col bg-zinc-100 text-zinc-800">
      <header className="relative z-30 flex items-center border-b border-zinc-200 bg-white px-4 h-16">
        <div className="flex items-center gap-3">
          <span className="text-red-500 text-2xl font-black">S</span>
          <span className="text-base font-medium text-zinc-600 hidden sm:block">Session Mail</span>
        </div>
        <div className="ml-auto flex items-center gap-3">
          {keys ? (
            <button onClick={() => { setMenuOpen((o) => !o); setRevealKeys(false) }} className="rounded-full hover:ring-2 hover:ring-zinc-200 transition-all">
              <Avatar id={keys.accountId} size="h-9 w-9 text-xs" />
            </button>
          ) : (
            <button onClick={handleGenerate} className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700 transition-colors">
              Generate identity
            </button>
          )}
        </div>
        {menuOpen && keys && (
          <>
            <div className="fixed inset-0 z-30" onClick={() => setMenuOpen(false)} />
            <div className="absolute right-4 top-[68px] z-40 w-80 overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-2xl">
              <div className="flex items-center gap-3 border-b border-zinc-100 p-4">
                <Avatar id={keys.accountId} size="h-11 w-11 text-sm" />
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">My identity</p>
                  <p className="text-[11px] text-zinc-400 font-mono">{short(keys.accountId, 14)}</p>
                </div>
              </div>
              <div className="p-3 space-y-2">
                <div className="rounded-lg bg-zinc-50 p-3">
                  <p className="text-[11px] font-medium text-zinc-400 mb-1">Account ID</p>
                  <p className="text-[11px] font-mono break-all leading-relaxed">{keys.accountId}</p>
                  <div className="mt-2"><CopyButton text={keys.accountId} /></div>
                </div>
                {revealKeys ? (
                  <div className="space-y-2">
                    <div className="rounded-lg bg-zinc-50 p-3">
                      <p className="text-[11px] font-medium text-zinc-400 mb-1">Public key</p>
                      <p className="text-[10px] font-mono break-all leading-relaxed text-zinc-600">{keys.publicKeyHex}</p>
                      <div className="mt-2"><CopyButton text={keys.publicKeyHex} /></div>
                    </div>
                    <div className="rounded-lg bg-zinc-50 p-3">
                      <p className="text-[11px] font-medium text-zinc-400 mb-1">Private key</p>
                      <p className="text-[10px] font-mono break-all leading-relaxed text-red-600">{keys.secretKeyHex}</p>
                      <div className="mt-2"><CopyButton text={keys.secretKeyHex} /></div>
                    </div>
                  </div>
                ) : (
                  <button onClick={() => setRevealKeys(true)} className="w-full rounded-lg border border-zinc-200 py-2 text-xs text-zinc-500 hover:bg-zinc-50 transition-colors">
                    Reveal keys
                  </button>
                )}
                <button onClick={handleGenerate} className="w-full rounded-lg py-2 text-xs text-zinc-500 hover:bg-zinc-50 transition-colors">
                  Generate new identity
                </button>
              </div>
            </div>
          </>
        )}
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className="flex w-56 shrink-0 flex-col bg-white border-r border-zinc-200">
          <div className="p-3">
            <button
              onClick={() => keys && setComposing(true)}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-zinc-900 py-3 text-sm font-medium text-white hover:bg-zinc-700 transition-colors"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
              Compose
            </button>
          </div>
          <nav className="flex-1 space-y-0.5 px-2">
            <button
              onClick={() => { setView('inbox'); setSelectedId(null) }}
              className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors ${view === 'inbox' ? 'bg-red-50 text-red-600 font-semibold' : 'text-zinc-600 hover:bg-zinc-100'}`}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" /></svg>
              <span className="flex-1 text-left">Inbox</span>
              {unread > 0 && <span className="rounded-full bg-red-500 px-2 py-0.5 text-[11px] font-semibold text-white">{unread}</span>}
            </button>
            <button
              onClick={() => { setView('sent'); setSelectedId(null) }}
              className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors ${view === 'sent' ? 'bg-zinc-100 text-zinc-900 font-semibold' : 'text-zinc-600 hover:bg-zinc-100'}`}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" /></svg>
              <span className="flex-1 text-left">Sent</span>
              {sent.length > 0 && <span className="text-[11px] text-zinc-400">{sent.length}</span>}
            </button>
          </nav>
          <div className="p-3 border-t border-zinc-100">
            <button
              onClick={handleRefresh}
              disabled={busy || !keys}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-zinc-200 py-2 text-xs text-zinc-500 hover:bg-zinc-50 disabled:opacity-40 transition-colors"
            >
              <svg className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
              {busy ? 'Refreshing…' : 'Refresh inbox'}
            </button>
          </div>
        </aside>

        <section className="w-80 shrink-0 overflow-y-auto bg-white border-r border-zinc-200">
          <div className="sticky top-0 border-b border-zinc-100 bg-white/95 backdrop-blur px-4 py-3">
            <p className="text-sm font-semibold">{view === 'inbox' ? 'Inbox' : 'Sent'}</p>
          </div>
          {list.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-300">
              <p className="text-4xl mb-3">{view === 'inbox' ? '📥' : '📤'}</p>
              <p className="text-sm text-zinc-400">{view === 'inbox' ? 'Nothing here yet.' : 'No sent messages.'}</p>
            </div>
          ) : (
            <div>
              {list.map((m) => {
                const isSent = view === 'sent'
                const title = isSent ? m.subject : m.ok ? m.mail.subject : '(unreadable)'
                const who = isSent ? m.to : m.ok ? m.mail.from : m.recipient
                const preview = isSent ? m.body : m.ok ? m.mail.body : m.error
                const active = m.id === selectedId
                const unreadRow = !isSent && !readIds.has(m.id)
                return (
                  <button
                    key={m.id}
                    onClick={() => openMsg(m)}
                    className={`w-full border-b border-zinc-100 px-4 py-3 text-left transition-colors ${active ? 'bg-red-50' : 'hover:bg-zinc-50'}`}
                  >
                    <div className="flex items-start gap-3">
                      <Avatar id={who} size="h-9 w-9 text-[10px]" />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between">
                          <p className={`text-[13px] truncate ${unreadRow ? 'font-semibold' : ''}`}>
                            {isSent ? 'To: ' : ''}{short(who, 18)}
                          </p>
                          <span className="ml-2 shrink-0 text-[11px] text-zinc-400">{fmtTime(isSent ? m.at : m.ok ? m.mail.timestamp : m.created_at)}</span>
                        </div>
                        <p className={`text-[13px] font-medium mt-0.5 truncate ${unreadRow ? 'text-zinc-800' : 'text-zinc-600'}`}>{title || '(no subject)'}</p>
                        <p className="text-[12px] text-zinc-400 mt-0.5 truncate">{preview ? preview.slice(0, 60) : ''}</p>
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </section>

        <main className="min-w-0 flex-1 overflow-y-auto bg-white">
          {!selected ? (
            <div className="flex h-full flex-col items-center justify-center text-zinc-300">
              <svg className="h-16 w-16 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
              <p className="text-sm text-zinc-400">Open a message to read it here</p>
            </div>
          ) : view === 'sent' ? (
            <article className="mx-auto max-w-2xl p-8">
              <h1 className="text-2xl font-bold text-zinc-900">{selected.subject || '(no subject)'}</h1>
              <div className="mt-5 rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Avatar id={keys?.accountId} size="h-10 w-10 text-xs" />
                    <div>
                      <p className="text-sm font-semibold text-zinc-800">You</p>
                      <p className="text-[11px] font-mono text-zinc-400">{short(keys?.accountId, 14)}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-zinc-400">{fmtTime(selected.at)}</p>
                    <div className="flex items-center gap-1 mt-1">
                      <svg className="h-3.5 w-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                      <span className="text-[11px] text-emerald-600 font-medium">Sent</span>
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex items-center gap-2 border-t border-zinc-200 pt-3">
                  <span className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">To</span>
                  <div className="flex items-center gap-2">
                    <Avatar id={selected.to} size="h-5 w-5 text-[8px]" />
                    <span className="text-[12px] font-mono text-zinc-600">{short(selected.to, 16)}</span>
                  </div>
                </div>
              </div>
              <div className="mt-6 px-1">
                <p className="whitespace-pre-wrap text-[15px] leading-relaxed text-zinc-700">{selected.body}</p>
              </div>
              <div className="mt-8 pt-4 border-t border-zinc-100">
                <p className="text-[11px] text-zinc-300 font-mono">End of message</p>
              </div>
            </article>
          ) : !selected.ok ? (
            <div className="flex flex-col items-center justify-center h-full py-16">
              <div className="w-16 h-16 rounded-full bg-red-50 flex items-center justify-center mb-4">
                <svg className="h-8 w-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" /></svg>
              </div>
              <p className="text-sm font-medium text-zinc-500">Failed to decrypt</p>
              <p className="text-xs text-zinc-400 mt-1 max-w-xs text-center">{selected.error}</p>
            </div>
          ) : (
            <article className="mx-auto max-w-2xl p-8">
              <h1 className="text-2xl font-bold text-zinc-900">{selected.mail.subject || '(no subject)'}</h1>
              <div className="mt-5 rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Avatar id={selected.mail.from} size="h-10 w-10 text-xs" />
                    <div>
                      <p className="text-sm font-semibold text-zinc-800">From</p>
                      <p className="text-[11px] font-mono text-zinc-400">{short(selected.mail.from, 14)}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-zinc-400">{fmtTime(selected.mail.timestamp)}</p>
                    <div className="flex items-center gap-1 mt-1">
                      <svg className="h-3.5 w-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                      <span className="text-[11px] text-emerald-600 font-medium">Verified</span>
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex items-center gap-2 border-t border-zinc-200 pt-3">
                  <span className="text-[11px] font-medium text-zinc-400 uppercase tracking-wide">To</span>
                  <div className="flex items-center gap-2">
                    <Avatar id={selected.mail.to} size="h-5 w-5 text-[8px]" />
                    <span className="text-[12px] font-mono text-zinc-600">{short(selected.mail.to, 16)}</span>
                  </div>
                  <span className="text-zinc-300 mx-1">·</span>
                  <div className="flex items-center gap-1">
                    <svg className="h-3.5 w-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                    <span className="text-[11px] text-emerald-600">Encrypted</span>
                  </div>
                </div>
              </div>
              <div className="mt-6 px-1">
                <p className="whitespace-pre-wrap text-[15px] leading-relaxed text-zinc-700">{selected.mail.body}</p>
              </div>
              <div className="mt-8 pt-4 border-t border-zinc-100 flex items-center gap-4">
                <p className="text-[11px] text-zinc-300 font-mono">End of message</p>
                <div className="flex-1" />
                <div className="flex items-center gap-1.5">
                  <svg className="h-3.5 w-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                  <span className="text-[11px] text-emerald-600 font-medium">Signature verified</span>
                </div>
              </div>
            </article>
          )}
        </main>
      </div>

      {composing && (
        <div className="fixed bottom-0 right-6 z-50 w-[32rem] max-w-[calc(100vw-2rem)] rounded-t-xl border border-zinc-200 bg-white shadow-2xl overflow-hidden">
          <div className="flex items-center justify-between bg-zinc-800 px-4 py-2.5 text-sm font-medium text-white">
            <span>New message</span>
            <button onClick={() => setComposing(false)} className="rounded px-2 py-1 hover:bg-white/10 transition-colors">✕</button>
          </div>
          <div className="p-4 space-y-2">
            <div className="flex items-center gap-2 border-b border-zinc-200 pb-2">
              <span className="text-xs text-zinc-400 w-12">To</span>
              <input
                value={to}
                onChange={(e) => setTo(e.target.value)}
                placeholder="Paste recipient account ID"
                className="flex-1 bg-transparent text-sm font-mono outline-none placeholder:font-sans placeholder:text-zinc-400"
              />
            </div>
            <div className="flex items-center gap-2 border-b border-zinc-200 pb-2">
              <span className="text-xs text-zinc-400 w-12">Subject</span>
              <input
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="flex-1 bg-transparent text-sm outline-none"
              />
            </div>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={10}
              placeholder="Write your message…"
              className="w-full resize-none bg-transparent text-sm outline-none placeholder:text-zinc-400"
            />
            <div className="flex items-center justify-between border-t border-zinc-100 pt-3">
              <p className="text-[11px] text-zinc-400">{short(keys?.accountId, 12)}</p>
              <button
                onClick={handleSend}
                disabled={busy}
                className="rounded-lg bg-zinc-900 px-6 py-2 text-sm font-medium text-white hover:bg-zinc-700 disabled:opacity-50 transition-colors"
              >
                {busy ? 'Sending…' : 'Send'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
