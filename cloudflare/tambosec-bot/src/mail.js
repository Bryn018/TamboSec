// Path 2 — AI Email Security Desk.
// Receives inbound mail (delivered by Cloudflare Email Routing to this Worker),
// classifies it as phishing/legit with Workers AI, then either re-sends the safe
// message to the verified destination (EMAIL binding) or quarantines it (drops +
// alerts the owner via Telegram). Every message is logged to D1 (mail_log).
//
// No Google. Pure Cloudflare: Email Routing + Workers AI + D1 + Telegram.

import { appendJSON, readJSON } from './storage.js'

function newId(prefix) {
  return `${prefix}_${crypto.randomUUID().slice(0, 8)}`
}

// ─── Minimal MIME parsing (no deps) ───────────────────────
function decodeHeader(val) {
  if (!val) return ''
  // RFC 2047 encoded-word: =?UTF-8?B?...?=
  const m = val.match(/\=\?([^?]+)\?B\?([^?]+)\?\=/i)
  if (m) {
    try { return Buffer.from(m[2], 'base64').toString('utf8') } catch { /* fall through */ }
  }
  return val
}

function parseMessage(raw) {
  const text = typeof raw === 'string' ? raw : new TextDecoder().decode(raw)
  const headerEnd = text.indexOf('\r\n\r\n')
  const headerBlock = headerEnd === -1 ? text : text.slice(0, headerEnd)
  const bodyRaw = headerEnd === -1 ? '' : text.slice(headerEnd + 4)

  const headers = {}
  for (const line of headerBlock.split(/\r\n/)) {
    const idx = line.indexOf(':')
    if (idx > -1) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim()
  }

  let body = bodyRaw
  const cte = (headers['content-transfer-encoding'] || '').toLowerCase()
  if (cte === 'base64') {
    try { body = Buffer.from(bodyRaw.replace(/\s+/g, ''), 'base64').toString('utf8') } catch { /* keep raw */ }
  } else if (cte === 'quoted-printable') {
    body = bodyRaw.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
  }
  // strip HTML tags for a clean text body the model reads
  const textBody = body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()

  return {
    from: decodeHeader(headers['from'] || ''),
    to: decodeHeader(headers['to'] || ''),
    subject: decodeHeader(headers['subject'] || ''),
    body: textBody.slice(0, 4000),
  }
}

// ─── Workers AI phishing classifier ──────────────────────
const MAIL_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast'
async function classifyEmail(msg) {
  if (!_env || !_env.AI) return { score: 0, disposition: 'delivered', reason: 'AI unavailable; delivered', summary: '', raw: '' }
  const prompt =
    `You are a strict email phishing classifier.\n` +
    `Reply with ONLY a single JSON object and absolutely no other text, prose, or preamble.\n` +
    `Decide PHISHING or LEGITIMATE from STRUCTURAL signals only (not the brand name):\n` +
    `- urgency / threats to suspend or lock the account\n` +
    `- links to lookalike or unrelated domains, or bare IP links\n` +
    `- requests for passwords, OTP, cards, or to "verify your identity"\n` +
    `- mismatched sender domain vs the brand it claims\n` +
    `- generic greetings, spelling errors, pressure to act now\n` +
    `A real company name alone does NOT make mail legitimate. Spoofed/lookalike domains and credential requests are phishing.\n` +
    `JSON: {"verdict":"phishing"|"legitimate","confidence":0.0-1.0,"reason":"one sentence","red_flags":["..."]}\n\n` +
    `FROM: ${msg.from}\nSUBJECT: ${msg.subject}\nBODY: ${msg.body.slice(0, 1500)}`

  try {
    const res = await _env.AI.run(MAIL_MODEL, { prompt, max_tokens: 512 })
    let text = ''
    if (res) {
      // Workers AI response shape varies: {text}, {response}, {result},
      // {choices:[{text|message.content}]}, or a raw string/object.
      const pick = (v) => {
        if (!v) return ''
        if (typeof v === 'string') return v
        if (Array.isArray(v) && typeof v[0] === 'string') return v[0]
        if (v.response) return pick(v.response)
        if (v.result) return pick(v.result)
        if (Array.isArray(v.choices) && v.choices[0]) {
          const c = v.choices[0]
          return pick(c.text || (c.message && c.message.content) || c)
        }
        if (v.text) return pick(v.text)
        // Fallback: serialize so extractJson can still find the embedded JSON.
        return JSON.stringify(v)
      }
      text = pick(res)
    }
    text = (text || '').trim()
    const json = extractJson(text)
    if (!json) {
      // Fail CLOSED: ambiguous output is quarantined for human review, never delivered.
      return { score: 0.7, disposition: 'quarantined', reason: 'unparseable model output; quarantined for review', summary: text.slice(0, 200), raw: text }
    }
    // score = model's confidence in ITS verdict (not phishing probability). Use the verdict.
    const verdict = (json.verdict || '').toLowerCase()
    const confidence = Math.max(0, Math.min(1, Number(json.confidence) || (verdict === 'phishing' ? 0.8 : 0.2)))
    const isPhish = verdict === 'phishing'
    // A legitimate verdict with low confidence is suspicious -> quarantine for review.
    const disposition = isPhish || confidence < 0.4 ? 'quarantined' : 'delivered'
    const summary = [json.reason || '', ...(json.red_flags || []).map((f) => '• ' + f)].join(' ').trim()
    return { score: confidence, disposition, reason: json.reason || (isPhish ? 'phishing' : 'looks legitimate'), summary, raw: text }
  } catch (e) {
    return { score: 0.7, disposition: 'quarantined', reason: 'classifier error: ' + e.message + '; quarantined for review', summary: '', raw: '' }
  }
}

function extractJson(text) {
  if (!text) return null
  let t = text.trim()
  // strip markdown code fences if present
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fence) t = fence[1].trim()
  // accept single-quoted JSON
  if (t.includes("'")) t = t.replace(/'/g, '"')
  const start = t.indexOf('{')
  if (start === -1) return null
  // Brace-balance from the first '{' to capture the FIRST complete JSON object,
  // ignoring any leader prose and any trailing commentary the model appends.
  let depth = 0
  let inStr = false
  let esc = false
  for (let i = start; i < t.length; i++) {
    const ch = t[i]
    if (inStr) {
      if (esc) esc = false
      else if (ch === '\\') esc = true
      else if (ch === '"') inStr = false
      continue
    }
    if (ch === '"') inStr = true
    else if (ch === '{') depth++
    else if (ch === '}') {
      depth--
      if (depth === 0) {
        const candidate = t.slice(start, i + 1)
        try { return JSON.parse(candidate) } catch { /* malformed; stop */ }
        break
      }
    }
  }
  // Fallback: a truncated object (model ran out of tokens mid-JSON).
  const slice = t.slice(start)
  for (const c of [slice, slice + '}', slice + '"}']) {
    try { return JSON.parse(c) } catch { /* try next */ }
  }
  return null
}

// ─── Telegram alert to the captured owner chat ───────────
async function alertOwner(env, text) {
  const chatId = await getOwnerChat(env)
  if (!chatId || !env.BOT_TOKEN) return
  try {
    await fetch('https://api.telegram.org/bot' + env.BOT_TOKEN + '/sendMessage', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
    })
  } catch (e) {
    console.error('[mail] owner alert failed', e.message)
  }
}

async function getOwnerChat(env) {
  try {
    const { data } = await readJSON('config.json')
    const row = data.find((c) => c.key === 'owner_chat_id')
    return row ? row.value : null
  } catch { return null }
}

// ─── Public entrypoint, called by the Worker's email handler ──
export async function handleInboundEmail(message, env) {
  setEnv(env)
  const msg = parseMessage(message.raw)
  const cls = await classifyEmail(msg)

  await appendJSON('mail_log.json', {
    id: newId('mail'),
    from_addr: msg.from,
    to_addr: msg.to,
    subject: msg.subject,
    disposition: cls.disposition,
    score: cls.score,
    reason: cls.reason,
    summary: cls.summary,
    received_at: new Date().toISOString(),
    tenant_id: null,
  })

  if (cls.disposition === 'delivered') {
    // Re-send the (already-classified) message to the verified destination.
    try {
      await env.EMAIL.send({
        from: msg.from || 'secops@insights.autos',
        to: env.EMAIL.destination_address || 'bolesapit@gmail.com',
        subject: msg.subject,
        text: msg.body,
      })
    } catch (e) {
      console.error('[mail] forward failed', e.message)
    }
    await alertOwner(env, `📧 *Mail delivered* — ${msg.from}\nSubject: ${msg.subject}\nConfidence legit: ${(1 - cls.score).toFixed(2)}`)
    return { disposition: 'delivered', score: cls.score, reason: cls.reason }
  }

  // quarantined: drop + alert
  await alertOwner(env, `🛑 *Phishing quarantined* — ${msg.from}\nSubject: ${msg.subject}\nConfidence: ${cls.score.toFixed(2)}\n${cls.summary}`)
  return { disposition: 'quarantined', score: cls.score, reason: cls.reason, summary: cls.summary }
}

// Module-level env (injected by the Worker).
let _env = null
export function setEnv(env) { _env = env }

// ─── Test hook used by GET /api/classify (no email round-trip) ──
export async function classifyText(from, subject, body, env) {
  setEnv(env)
  const cls = await classifyEmail({ from, to: '', subject, body })
  return {
    disposition: cls.disposition,
    score: cls.score,
    reason: cls.reason,
    summary: cls.summary,
    verdict: cls.disposition === 'quarantined' ? 'phishing' : 'legitimate',
    raw: cls.raw || '',
  }
}
