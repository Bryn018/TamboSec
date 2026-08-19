import { setDB, getDB } from './storage.js'
import { setEnv, runPostureScan, getEnv } from './scanner.js'
import { handleInboundEmail, classifyText } from './mail.js'
import { probeThreatScope, correlateThreats } from './threatintel.js'
import { askCopilot } from './copilot.js'
import { getDashboardData } from './dashboard.js'

// Security hardening headers applied to every Worker response.
const SEC = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
}

// JSON helper with CORS so the Pages dashboard can call the API cross-origin.
// Endpoints stay token-gated (DASHBOARD_TOKEN) — CORS only relaxes the browser
// same-origin check; it does not bypass auth. Security headers are included on
// every response.
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({
      'content-type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'content-type, x-tambosec-token',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    }, SEC),
  })
}

// Atomic rate limiting via a Durable Object (separate Worker: tambosec-ratelimiter,
// referenced by script_name). The DO is single-threaded per instance, so parallel
// hits can't lose increments — the failure mode of a KV read-modify-write counter.
// Two buckets per request class:
//   • per-IP   — blunts a single abuser / token brute-force (120 read / 20 write per min)
//   • global   — blunts a flood spread across many IPs (Cloudflare edges assign
//                different CF-Connecting-IP per request, so per-IP alone is leaky)
// Fail-open if the DO binding is missing so the service stays up.
async function rateLimit(env, request, kind) {
  if (!env.RATE_LIMITER) return null
  const id = env.RATE_LIMITER.idFromName(kind) // one instance per class (read|write)
  const stub = env.RATE_LIMITER.get(id)
  const res = await stub.fetch('https://rl/' + kind, {
    headers: { 'CF-Connecting-IP': request.headers.get('CF-Connecting-IP') || 'unknown' },
  }).catch(() => null)
  if (!res || !res.ok) {
    if (res && res.status === 429) {
      const body = await res.json().catch(() => ({}))
      return { limited: true, retryAfter: body.retryAfter || 60 }
    }
    return null // fail-open
  }
  return null
}

// Every API endpoint requires the DASHBOARD_TOKEN (passed as ?token= or the
// X-TamboSec-Token header). The site is additionally wrapped in Cloudflare
// Access, so this is defense-in-depth.
function authErr() { return json({ error: 'unauthorized' }, 403) }
function tokenOf(request, url) {
  return url.searchParams.get('token') || request.headers.get('X-TamboSec-Token')
}
function authed(request, url, env) {
  return tokenOf(request, url) === env.DASHBOARD_TOKEN
}
function q(request, url, name) { return url.searchParams.get(name) }
function bodyJson(request) { return request.json().catch(() => ({})) }

export default {
  async fetch(request, env) {
    setDB(env.DB)
    setEnv(env)
    const url = new URL(request.url)

    // CORS preflight for the Pages dashboard.
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'content-type, x-tambosec-token',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Max-Age': '86400',
        },
      })
    }

    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true, service: 'tambosec-bot' })
    }

    // Per-IP rate limiting on every request (incl. auth attempts) to blunt
    // token brute-force and abuse. Fail-open if the KV store is unavailable.
    const rl = await rateLimit(env, request, request.method === 'POST' ? 'write' : 'read')
    if (rl) {
      return new Response(JSON.stringify({ error: 'rate limited', retryAfter: rl.retryAfter }), {
        status: 429,
        headers: Object.assign({ 'retry-after': String(rl.retryAfter) }, SEC),
      })
    }

    // All endpoints below are token-gated.
    if (!authed(request, url, env)) return authErr()

    if (request.method === 'GET' && url.pathname === '/api/dashboard') {
      const tenantId = q(request, url, 'tenantId')
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      await logAudit(env, tenantId, 'view.dashboard', {})
      return json(await getDashboardData(tenantId))
    }

    if (request.method === 'GET' && url.pathname === '/api/tenants') {
      await logAudit(env, 'all', 'view.tenants', {})
      const { results } = await env.DB.prepare('SELECT id, name, domain, stack, createdAt FROM tenants ORDER BY createdAt DESC').all()
      return json({ tenants: (results || []).map((t) => ({ ...t, stack: safeStack(t.stack) })) })
    }

    if (request.method === 'GET' && url.pathname === '/api/findings') {
      const tenantId = q(request, url, 'tenantId')
      const severity = q(request, url, 'severity')
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      await logAudit(env, tenantId, 'view.findings', { severity: severity || 'all' })
      let sql = 'SELECT * FROM findings WHERE tenantId = ?'
      const binds = [tenantId]
      if (severity) { sql += ' AND severity = ?'; binds.push(severity) }
      sql += ' ORDER BY createdAt DESC LIMIT 200'
      const { results } = await env.DB.prepare(sql).bind(...binds).all()
      const rows = (results || []).map(rowToObj)
      return json({ findings: rows })
    }

    if (request.method === 'GET' && url.pathname === '/api/finding') {
      const id = q(request, url, 'id')
      if (!id) return json({ error: 'id required' }, 400)
      await logAudit(env, 'lookup', 'view.finding', { id })
      const row = await env.DB.prepare('SELECT * FROM findings WHERE id = ?').bind(id).first()
      if (!row) return json({ error: 'not found' }, 404)
      return json({ finding: rowToObj(row) })
    }

    if (request.method === 'GET' && url.pathname === '/api/alerts') {
      const tenantId = q(request, url, 'tenantId')
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      await logAudit(env, tenantId, 'view.alerts', {})
      const { results } = await env.DB.prepare(
        'SELECT * FROM alerts WHERE tenantId = ? AND status = ? ORDER BY createdAt DESC'
      ).bind(tenantId, 'unread').all()
      return json({ alerts: (results || []).map(rowToObj) })
    }

    if (request.method === 'GET' && url.pathname === '/api/maillog') {
      const n = Math.min(Number(q(request, url, 'n')) || 20, 50)
      await logAudit(env, 'all', 'view.maillog', { n })
      const { results } = await env.DB.prepare('SELECT * FROM mail_log ORDER BY received_at DESC LIMIT ?').bind(n).all()
      return json({ mail: (results || []).map(rowToObj) })
    }

    if (request.method === 'GET' && url.pathname === '/api/threat') {
      const tenantId = q(request, url, 'tenantId')
      const tenant = await env.DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?').bind(tenantId).first()
      if (!tenant) return json({ error: 'tenant not found' }, 404)
      await logAudit(env, tenant.id, 'view.threat', {})
      const stack = safeStack(tenant.stack)
      if (!stack.length) return json({ error: 'set a stack first (/api/setstack)' }, 400)
      const ti = await correlateThreats(tenant.id, tenant.name, stack)
      return json({ tenant: tenant.name, stack, intel_source: ti.meta?.kev_source, findings: ti.findings })
    }

    if (request.method === 'GET' && url.pathname === '/api/threattest') {
      return json(await probeThreatScope())
    }

    if (request.method === 'GET' && url.pathname === '/api/corrtest') {
      const stack = (q(request, url, 'stack') || 'wordpress,nginx,apache').split(',').map((s) => s.trim().toLowerCase())
      const ti = await correlateThreats('test', 'TestCorp', stack)
      const ids = ti.findings.map((f) => f.id)
      return json({ count: ti.findings.length, uniqueIds: new Set(ids).size, duplicates: ids.filter((id, i) => ids.indexOf(id) !== i), sample: ti.findings.slice(0, 5) })
    }

    // ─── Scan (POST) ─────────────────────────────────────
    if (request.method === 'POST' && url.pathname === '/api/scan') {
      const tenantId = q(request, url, 'tenantId')
      const tenant = await env.DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?').bind(tenantId).first()
      if (!tenant) return json({ error: 'tenant not found' }, 404)
      await logAudit(env, tenant.id, 'scan.manual', {})
      const result = await runPostureScan(tenant.id, tenant.domain || 'demo.local', tenant.stack)
      return json({ tenant: tenant.name, domain: tenant.domain, ...result })
    }

    // ─── Ask the Security Copilot (GET) ─────────────────
    if (request.method === 'GET' && url.pathname === '/api/ask') {
      const tenantId = q(request, url, 'tenantId')
      const question = q(request, url, 'q') || ''
      if (!tenantId || !question) return json({ error: 'tenantId and q required' }, 400)
      const tenant = await env.DB.prepare('SELECT id, name FROM tenants WHERE id = ?').bind(tenantId).first()
      if (!tenant) return json({ error: 'tenant not found' }, 404)
      await logAudit(env, tenant.id, 'copilot.ask', { qlen: question.length })
      const ans = await askCopilot(question, tenant.id, tenant.name, env)
      return json(ans)
    }

    // ─── Summary (GET) ───────────────────────────────────
    if (request.method === 'GET' && url.pathname === '/api/summary') {
      const tenantId = q(request, url, 'tenantId')
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      await logAudit(env, tenantId, 'view.summary', {})
      const { results } = await env.DB.prepare('SELECT text FROM summaries WHERE tenantId = ? ORDER BY createdAt DESC LIMIT 1').bind(tenantId).all()
      return json({ summary: (results && results[0] && results[0].text) || null })
    }

    // ─── Set stack (POST) ────────────────────────────────
    if (request.method === 'POST' && url.pathname === '/api/setstack') {
      const b = await bodyJson(request)
      const tenantId = b.tenantId || q(request, url, 'tenantId')
      const stack = (b.stack || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
      if (!tenantId || !stack.length) return json({ error: 'tenantId and stack required' }, 400)
      const existing = await env.DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?').bind(tenantId).first()
      if (!existing) return json({ error: 'tenant not found' }, 404)
      await env.DB.prepare('UPDATE tenants SET stack = ? WHERE id = ?').bind(JSON.stringify(stack), tenantId).run()
      await logAudit(env, tenantId, 'tenant.stack.updated', { stack })
      return json({ ok: true, stack })
    }

    // ─── Schedule (GET view + POST set) ──────────────────
    if (url.pathname === '/api/schedule') {
      const tenantId = q(request, url, 'tenantId') || (await bodyJson(request)).tenantId
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      if (request.method === 'GET') {
        const row = await env.DB.prepare('SELECT * FROM schedules WHERE tenantId = ?').bind(tenantId).first()
        return json({ schedule: row || null })
      }
      const b = await bodyJson(request)
      const everyHours = Number(b.everyHours || q(request, url, 'hours'))
      if (!Number.isFinite(everyHours) || everyHours < 1 || everyHours > 168) return json({ error: 'hours must be 1-168' }, 400)
      await env.DB.prepare(
        `INSERT INTO schedules (tenantId, everyHours, enabled, nextRunAt, updatedAt, updatedBy)
         VALUES (?, ?, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now', (? ) || ' hours'), strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'web')
         ON CONFLICT(tenantId) DO UPDATE SET everyHours=excluded.everyHours, enabled=1, nextRunAt=excluded.nextRunAt, updatedAt=excluded.updatedAt, updatedBy='web'`
      ).bind(tenantId, everyHours, everyHours).run()
      await logAudit(env, tenantId, 'scan.schedule.updated', { everyHours })
      return json({ ok: true, everyHours })
    }

    // ─── Remediate request (POST) ────────────────────────
    if (request.method === 'POST' && url.pathname === '/api/remediate') {
      const b = await bodyJson(request)
      const { tenantId, findingId, actionType } = b
      const allowed = ['force_password_reset', 'revoke_admin_role', 'revoke_active_sessions']
      if (!tenantId || !findingId || !allowed.includes(actionType)) return json({ error: 'need tenantId, findingId, actionType(' + allowed.join('|') + ')' }, 400)
      const finding = await env.DB.prepare('SELECT id FROM findings WHERE id = ? AND tenantId = ?').bind(findingId, tenantId).first()
      if (!finding) return json({ error: 'finding not found' }, 404)
      const id = 'apr_' + crypto.randomUUID().slice(0, 8)
      await env.DB.prepare(
        `INSERT INTO approvals (id, tenantId, findingId, actionType, reason, status, requestedAt, decidedAt, decisionBy)
         VALUES (?, ?, ?, ?, 'Requested via web', 'pending', strftime('%Y-%m-%dT%H:%M:%SZ','now'), NULL, NULL)`
      ).bind(id, tenantId, findingId, actionType).run()
      await logAudit(env, tenantId, 'remediation.requested', { actionType, approvalId: id })
      return json({ ok: true, approvalId: id })
    }

    // ─── Approvals (GET list + POST decide) ──────────────
    if (url.pathname === '/api/approvals') {
      const tenantId = q(request, url, 'tenantId') || (await bodyJson(request)).tenantId
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      if (request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT * FROM approvals WHERE tenantId = ? ORDER BY requestedAt DESC').bind(tenantId).all()
        return json({ approvals: (results || []).map(rowToObj) })
      }
      const b = await bodyJson(request)
      const { approvalId, decision } = b
      if (!approvalId || !['approve', 'reject'].includes(decision)) return json({ error: 'need approvalId and decision(approve|reject)' }, 400)
      const status = decision === 'approve' ? 'approved' : 'rejected'
      await env.DB.prepare("UPDATE approvals SET status = ?, decidedAt = strftime('%Y-%m-%dT%H:%M:%SZ','now'), decisionBy = 'web' WHERE id = ?")
        .bind(status, approvalId).run()
      await logAudit(env, tenantId, 'remediation.' + status, { approvalId })
      return json({ ok: true, status })
    }

    // ─── Mail classify test (POST) ───────────────────────
    if (request.method === 'POST' && url.pathname === '/api/classify') {
      const b = await bodyJson(request)
      const cls = await classifyText(b.from || 'unknown@unknown', b.subject || '', b.body || '', env)
      await logAudit(env, 'all', 'mail.classify', { from: b.from || 'unknown@unknown', verdict: cls.verdict })
      return json(cls)
    }

    // ─── Acknowledge an alert or finding (POST) ──────────
    if (request.method === 'POST' && url.pathname === '/api/ack') {
      const b = await bodyJson(request)
      const { tenantId, kind, id } = b
      if (!tenantId || !['alert', 'finding'].includes(kind) || !id) return json({ error: 'need tenantId, kind(alert|finding), id' }, 400)
      const table = kind === 'alert' ? 'alerts' : 'findings'
      const status = kind === 'alert' ? 'read' : 'resolved'
      await env.DB.prepare('UPDATE ' + table + ' SET status = ? WHERE id = ? AND tenantId = ?').bind(status, id, tenantId).run()
      await logAudit(env, tenantId, 'item.acked', { kind, id })
      return json({ ok: true, kind, id, status })
    }

    // ─── Tenants: list (GET) + create (POST) ────────────
    if (url.pathname === '/api/tenant') {
      if (request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, name, domain, stack, createdAt FROM tenants ORDER BY createdAt DESC').all()
        return json({ tenants: (results || []).map((t) => ({ ...t, stack: safeStack(t.stack) })) })
      }
      const b = await bodyJson(request)
      const { name, domain, stack } = b
      if (!name || !domain) return json({ error: 'name and domain required' }, 400)
      const id = 'tnt_' + crypto.randomUUID().slice(0, 8)
      const stk = Array.isArray(stack) ? stack : (stack || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
      await env.DB.prepare('INSERT INTO tenants (id, name, domain, stack, createdAt) VALUES (?, ?, ?, ?, strftime(\'%Y-%m-%dT%H:%M:%SZ\',\'now\'))')
        .bind(id, name, domain, JSON.stringify(stk)).run()
      await logAudit(env, id, 'tenant.created', { name, domain })
      return json({ ok: true, id, name, domain, stack: stk }, 201)
    }

    // ─── Audit trail (GET, token-gated) ─────────────────
    if (request.method === 'GET' && url.pathname === '/api/audit') {
      const tenantId = q(request, url, 'tenantId') || 'all'
      const n = Math.min(Number(q(request, url, 'n')) || 50, 200)
      let sql = 'SELECT id, tenantId, type, actor, ts, metadata FROM audit'
      const binds = []
      if (tenantId !== 'all') { sql += ' WHERE tenantId = ?'; binds.push(tenantId) }
      sql += ' ORDER BY ts DESC LIMIT ?'
      const { results } = await env.DB.prepare(sql).bind(...binds, n).all()
      return json({ audit: (results || []).map((a) => ({ ...a, metadata: safeStack(a.metadata) })) })
    }

    // ─── Dashboard HTML fallback (also served from Pages) ─
    if (request.method === 'GET' && url.pathname === '/dashboard') {
      return new Response('', { status: 302, headers: { 'Location': 'https://tambosec.insights.autos/' } })
    }

    return new Response('not found', { status: 404 })
  },

  // Email Routing delivers mail to secops@insights.autos here (Path 2).
  async email(message, env, ctx) {
    setDB(env.DB)
    setEnv(env)
    try {
      await handleInboundEmail(message, env)
    } catch (e) {
      console.error('[email] handler error', e.message)
    }
  },

  // Cron: hourly scheduled posture scans.
  async scheduled(event, env, ctx) {
    setDB(env.DB)
    setEnv(env)
    const { DB } = env
    const { results } = await DB.prepare(
      `SELECT tenantId, everyHours, nextRunAt FROM schedules
       WHERE enabled = 1 AND nextRunAt <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).all()
    for (const row of results || []) {
      const tenant = await DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?').bind(row.tenantId).first()
      if (!tenant) continue
      const { findings, alerts, summary } = await runPostureScan(tenant.id, tenant.domain || 'demo.local', tenant.stack)
      console.log('[scheduled] scanned', tenant.id, 'findings=', findings.length, 'alerts=', alerts.length)
    }
    await DB.prepare(
      `UPDATE schedules SET nextRunAt = strftime('%Y-%m-%dT%H:%M:%SZ','now', (everyHours) || ' hours')
       WHERE enabled = 1 AND nextRunAt <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).run()
  },
}

// ─── helpers ───────────────────────────────────────────────
function safeStack(s) {
  if (!s) return []
  try { return JSON.parse(s) } catch { return String(s).split(',').map((x) => x.trim()) }
}
function rowToObj(row) {
  if (!row) return row
  const out = { ...row }
  if (typeof out.metadata === 'string') { try { out.metadata = JSON.parse(out.metadata) } catch { out.metadata = {} } }
  return out
}
async function logAudit(env, tenantId, type, metadata) {
  try {
    await env.DB.prepare(
      "INSERT INTO audit (id, tenantId, type, actor, findingId, approvalId, metadata, ts) VALUES (?, ?, ?, 'web', NULL, NULL, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
    ).bind('evt_' + crypto.randomUUID().slice(0, 8), tenantId, type, JSON.stringify(metadata || {})).run()
  } catch (e) { console.error('[audit] log failed', e.message) }
}
