// Path 4 — Security Copilot.
// A plain-language Q&A assistant grounded ONLY in the tenant's own data:
// posture findings, threat-intel matches, and the email-security log. It never
// invents facts outside the supplied context, and it refuses to answer about
// tenants the requester isn't authorized for.
//
// No Google. No external egress (the Worker can't reach arbitrary hosts anyway).

import { readJSON, getDB } from './storage.js'

const MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast'

// Build a compact, grounded context block from the tenant's data.
async function buildContext(tenantId, tenantName) {
  const db = getDB()
  const { results: fRows } = await db.prepare(
    `SELECT severity, source, title, metadata FROM findings
     WHERE tenantId = ? ORDER BY createdAt DESC LIMIT 40`
  ).bind(tenantId).all()
  const findings = (fRows || []).map((r) => {
    let meta = {}
    try { meta = JSON.parse(r.metadata || '{}') } catch { /* ignore */ }
    const extra = []
    if (meta.cve) extra.push('CVE ' + meta.cve)
    if (meta.epss != null) extra.push('EPSS ' + Number(meta.epss).toFixed(3))
    if (meta.product) extra.push('product ' + meta.product)
    return `- [${r.severity}/${r.source}] ${r.title}${extra.length ? ' (' + extra.join(', ') + ')' : ''}`
  })

  const { results: mRows } = await db.prepare(
    `SELECT disposition, subject, from_addr, reason FROM mail_log
     WHERE tenant_id = ? ORDER BY received_at DESC LIMIT 15`
  ).bind(tenantId).all()
  const mail = (mRows || []).map(
    (r) => `- [${r.disposition}] from ${r.from_addr}: ${r.subject}${r.reason ? ' — ' + r.reason : ''}`
  )

  const stack = await getStack(tenantId)

  const lines = []
  lines.push(`Tenant: ${tenantName} (id ${tenantId})`)
  lines.push(`Subscribed stack: ${stack.length ? stack.join(', ') : '(none set)'}`)
  lines.push(`\nRecent findings (${findings.length}):`)
  lines.push(findings.length ? findings.join('\n') : '  (none)')
  lines.push(`\nRecent email-security events (${mail.length}):`)
  lines.push(mail.length ? mail.join('\n') : '  (none)')
  return lines.join('\n')
}

async function getStack(tenantId) {
  const db = getDB()
  const row = await db.prepare('SELECT stack FROM tenants WHERE id = ?').bind(tenantId).first()
  if (!row || !row.stack) return []
  try { return JSON.parse(row.stack) } catch { return String(row.stack).split(',').map((s) => s.trim()) }
}

export async function askCopilot(question, tenantId, tenantName, env) {
  if (!env || !env.AI) {
    return { answer: 'AI unavailable. The Copilot needs the Workers AI binding.', grounded: false }
  }
  let context = ''
  try {
    context = await buildContext(tenantId, tenantName)
  } catch (e) {
    return { answer: 'Could not load your tenant data: ' + e.message, grounded: false }
  }

  const prompt = `You are TamboSec, a security copilot for a managed service provider's small-business clients.
Answer the user's question using ONLY the context below. If the context does not contain the
answer, say so plainly and do not invent facts. Keep it short, practical, and plain-language.
Use bullet points when listing items. Never reveal raw SQL or internal ids.

=== CONTEXT (this tenant's live data) ===
${context}
=== END CONTEXT ===

User question: ${question}

Answer:`

  try {
    const res = await env.AI.run(MODEL, { prompt, max_tokens: 600 })
    let text = ''
    if (res) text = res.text || res.response || ''
    if (!text && res && res.choices && res.choices[0]) text = res.choices[0].message?.content || ''
    text = (text || '').trim()
    if (!text) return { answer: 'The model returned no answer. Try rephrasing.', grounded: true }
    return { answer: text, grounded: true, model: MODEL }
  } catch (e) {
    return { answer: 'Copilot request failed: ' + e.message, grounded: false }
  }
}
