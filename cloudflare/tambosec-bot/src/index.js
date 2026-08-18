import { setDB, getDB } from './storage.js'
import { setEnv } from './scanner.js'
import { handleCommand, handleCallback } from './commands-core.js'
import { runPostureScan } from './scanner.js'
import { handleInboundEmail, classifyText } from './mail.js'
import { probeThreatScope, correlateThreats } from './threatintel.js'
import { askCopilot } from './copilot.js'
import { getDashboardData, dashboardHtml } from './dashboard.js'
import { getUser, resolveRole, roleSatisfies, upsertUser, listUsers, seedOwnerFromConfig, ROLES, countUsers } from './storage.js'

// ─── Telegram transport ────────────────────────────────────
function tg(token, method, body = {}) {
  return fetch('https://api.telegram.org/bot' + token + '/' + method, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then((r) => r.json())
}

function makeReply(token, chatId) {
  return (text, extra) =>
    tg(token, 'sendMessage', Object.assign({ chat_id: chatId, text, parse_mode: 'Markdown' }, extra || {}))
}

// ─── Request router ────────────────────────────────────────
export default {
  async fetch(request, env) {
    setDB(env.DB)
    setEnv(env)
    await seedOwnerFromConfig()
    const url = new URL(request.url)

    // CORS preflight for the Pages dashboard (tambosec.insights.autos) calling
    // the API cross-origin. Endpoints stay token-gated; this only adds headers.
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'content-type, x-tambosec-token',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Max-Age': '86400',
        },
      })
    }

    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true, service: 'tambosec-bot' })
    }

    // Admin / verification endpoint (also the future dashboard API).
    // Gated by the same Telegram secret header.
    if (request.method === 'GET' && url.pathname === '/api/scan') {
      if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      const tenantId = url.searchParams.get('tenantId')
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      const tenant = await env.DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?')
        .bind(tenantId).first()
      if (!tenant) return json({ error: 'tenant not found' }, 404)
      const stack = tenant.stack // may be JSON string; runPostureScan parses it
      try {
        const result = await runPostureScan(tenant.id, tenant.domain || 'demo.local', stack)
        return json({ tenant: tenant.name, domain: tenant.domain, ...result })
      } catch (e) {
        return json({ error: String(e.message || e), stack: e.stack }, 500)
      }
    }

    // Classify a sample email with Workers AI (Path 2 verification endpoint).
    // Usage: /api/classify?from=...&subject=...&body=...  (secret-gated)
    if (request.method === 'GET' && url.pathname === '/api/classify') {
      if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      const from = url.searchParams.get('from') || 'unknown@unknown'
      const subject = url.searchParams.get('subject') || ''
      const body = url.searchParams.get('body') || ''
      if (!subject && !body) return json({ error: 'provide subject and/or body' }, 400)
      const cls = await classifyText(from, subject, body, env)
      return json(cls)
    }

    // Full email round-trip test (Path 2): builds a synthetic EmailMessage and
    // runs the real handleInboundEmail (parse -> classify -> EMAIL.send -> D1 log).
    // Secret-gated. Returns the decision + whether the forward fired.
    if (request.method === 'GET' && url.pathname === '/api/mailtest') {
      if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      const from = url.searchParams.get('from') || 'probe@external.test'
      const subject = url.searchParams.get('subject') || 'Mail test'
      const body = url.searchParams.get('body') || 'Test message body.'
      const raw = `From: ${from}\r\nTo: secops@insights.autos\r\nSubject: ${subject}\r\nContent-Type: text/plain\r\n\r\n${body}`
      // Minimal EmailMessage shape Cloudflare provides.
      const message = { raw: new TextEncoder().encode(raw), from, to: 'secops@insights.autos' }
      const forwarded = { fired: false }
      const origSend = env.EMAIL && env.EMAIL.send
      if (env.EMAIL) env.EMAIL.send = async (opts) => { forwarded.fired = true; return { ok: true } }
      const result = await handleInboundEmail(message, env)
      if (origSend) env.EMAIL.send = origSend
      return json({ ...result, forwarded: forwarded.fired, destination: env.EMAIL && env.EMAIL.destination_address })
    }

    // Path 3 reachability probe: can this Worker reach the Threat-Scope feeds?
    // Secret-gated. Confirms KEV/EPSS/ATT&CK are live (or reports fallback).
    if (request.method === 'GET' && url.pathname === '/api/threattest') {
      if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      const probe = await probeThreatScope()
      return json(probe)
    }

    // Path 3 correlation test (no external fetch; reads D1 cache only).
    if (request.method === 'GET' && url.pathname === '/api/corrtest') {
      if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      const stack = (url.searchParams.get('stack') || 'wordpress,nginx,apache').split(',').map((s) => s.trim().toLowerCase())
      const ti = await correlateThreats('test', 'TestCorp', stack)
      const ids = ti.findings.map((f) => f.id)
      const dups = ids.filter((id, i) => ids.indexOf(id) !== i)
      return json({ count: ti.findings.length, uniqueIds: new Set(ids).size, duplicates: [...new Set(dups)], sample: ti.findings.slice(0, 5) })
    }

    // Path 4 — Security Copilot (token-gated API). Grounded in tenant data.
    if (request.method === 'GET' && url.pathname === '/api/ask') {
      const token = url.searchParams.get('token') || request.headers.get('X-TamboSec-Token')
      if (token !== env.DASHBOARD_TOKEN) return new Response('forbidden', { status: 403 })
      const tenantId = url.searchParams.get('tenantId')
      const question = url.searchParams.get('q') || ''
      if (!tenantId || !question) return json({ error: 'tenantId and q required' }, 400)
      const tenant = await env.DB.prepare('SELECT id, name FROM tenants WHERE id = ?').bind(tenantId).first()
      if (!tenant) return json({ error: 'tenant not found' }, 404)
      const ans = await askCopilot(question, tenant.id, tenant.name, env)
      return json(ans)
    }

    // Path 4 — Dashboard JSON feed (token-gated).
    if (request.method === 'GET' && url.pathname === '/api/dashboard') {
      const token = url.searchParams.get('token') || request.headers.get('X-TamboSec-Token')
      if (token !== env.DASHBOARD_TOKEN) return new Response('forbidden', { status: 403 })
      const tenantId = url.searchParams.get('tenantId')
      if (!tenantId) return json({ error: 'tenantId required' }, 400)
      const data = await getDashboardData(tenantId)
      return json(data)
    }

    // Path 4 — Dashboard HTML view (token-gated via ?token=).
    if (request.method === 'GET' && url.pathname === '/dashboard') {
      const token = url.searchParams.get('token') || request.headers.get('X-TamboSec-Token')
      if (token !== env.DASHBOARD_TOKEN) return new Response('forbidden', { status: 403 })
      return new Response(dashboardHtml(), { headers: { 'content-type': 'text/html; charset=utf-8' } })
    }

    // One-time webhook registration (call this once after deploy).
    if (request.method === 'GET' && url.pathname === '/setup') {
      const hook = url.origin + '/telegram'
      const res = await tg(env.BOT_TOKEN, 'setWebhook', {
        url: hook,
        secret_token: env.TELEGRAM_SECRET,
        allowed_updates: ['message', 'callback_query'],
      })
      return json({ ok: res.ok, result: res, webhook_url: hook })
    }

    // Telegram webhook endpoint.
    if (request.method === 'POST' && url.pathname === '/telegram') {
      const secret = request.headers.get('X-Telegram-Bot-Api-Secret-Token')
      if (secret !== env.TELEGRAM_SECRET) return new Response('forbidden', { status: 403 })
      const update = await request.json().catch(() => null)
      if (!update) return new Response('bad request', { status: 400 })

      try {
        await route(token(env), update)
      } catch (e) {
        console.error('[webhook] error', e.message)
      }
      return new Response('ok', { status: 200 }) // always ack Telegram fast
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
    // Acknowledge so Email Routing records the message as processed.
  },

  // Cron: hourly scheduled posture scans.
  async scheduled(event, env, ctx) {
    setDB(env.DB)
    setEnv(env)
    const { DB, BOT_TOKEN } = env
    const { results } = await DB.prepare(
      `SELECT tenantId, everyHours, nextRunAt FROM schedules
       WHERE enabled = 1 AND nextRunAt <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).all()
    for (const row of results || []) {
      const tenant = await DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?')
        .bind(row.tenantId).first()
      if (!tenant) continue
      const stack = tenant.stack // JSON string or array; runPostureScan parses it
      const { findings, alerts, summary } = await runPostureScan(tenant.id, tenant.domain || 'demo.local', stack)
      console.log('[scheduled] scanned', tenant.id, 'findings=', findings.length, 'alerts=', alerts.length)
    }
    // advance nextRunAt for processed schedules
    await DB.prepare(
      `UPDATE schedules SET nextRunAt = strftime('%Y-%m-%dT%H:%M:%SZ','now', (everyHours) || ' hours')
       WHERE enabled = 1 AND nextRunAt <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).run()
  },
}

function token(env) { return env.BOT_TOKEN }

// Persist the owner's Telegram chat id in the config table so Path 2 email
// alerts can be pushed there. Captured ONLY on the first message (bootstrap
// owner); later messages must NOT overwrite it, or RBAC breaks (whoever
// messaged last would become the "owner" via resolveRole's config fallback).
async function rememberOwnerChat(chatId) {
  try {
    const db = getDB()
    if (!db) return
    await db
      .prepare(
        `INSERT INTO config (key, value) VALUES ('owner_chat_id', ?)
         ON CONFLICT(key) DO NOTHING`
      )
      .bind(String(chatId))
      .run()
  } catch (e) {
    console.error('[chat] remember failed', e.message)
  }
}

async function route(token, update) {
  if (update.callback_query) {
    const cq = update.callback_query
    const chatId = cq.message.chat.id
    const reply = makeReply(token, chatId)
    await handleCallback({
      reply,
      editMessage: (suffix) =>
        tg(token, 'editMessageText', {
          chat_id: chatId,
          message_id: cq.message.message_id,
          text: cq.message.text + '\n\n_' + suffix + '_',
          parse_mode: 'Markdown',
        }),
      answerCallback: (text) =>
        tg(token, 'answerCallbackQuery', { callback_query_id: cq.id, text }),
      callbackData: cq.data,
      chatId,
    })
    return
  }
  if (update.message && update.message.text) {
    const msg = update.message
    const chatId = msg.chat.id
    const reply = makeReply(token, chatId)
    // Remember the owner's chat so email alerts (Path 2) can reach them.
    await rememberOwnerChat(chatId)
    // Path 4 RBAC: resolve role. Bootstrap: if no users exist yet, the first
    // person to message becomes the owner (standard zero-config setup).
    const existing = await getUser(chatId)
    if (!existing) {
      const total = await countUsers()
      const role = total === 0 ? 'owner' : (await resolveRole(chatId) || null)
      if (!role) {
        await reply('🔒 You are not registered. Ask the TamboSec owner to run /grant <your-chat-id> <role>.')
        return
      }
      await upsertUser(chatId, null, role, null)
    }
    const role = await resolveRole(chatId)
    const text = msg.text
    if (text.startsWith('/')) {
      const parts = text.slice(1).split(/\s+/)
      const command = parts[0].toLowerCase()
      const args = parts.slice(1)
      // Enforce role minimums per command.
      const minRole = MIN_ROLE[command] || 'viewer'
      if (!roleSatisfies(role, minRole)) {
        await reply(`🔒 \`/${command}\` requires *${minRole}* role. Your role: *${role}*.`)
        return
      }
      await handleCommand({ command, args, reply, chatId, role, userId: String(chatId), env })
    } else {
      await reply('Send /start to see available commands.')
    }
  }
}

// Minimum role required per Telegram command (Path 4 RBAC).
const MIN_ROLE = {
  start: 'viewer',
  help: 'viewer',
  ask: 'viewer',
  summary: 'viewer',
  maillog: 'viewer',
  threat: 'viewer',
  tenants: 'viewer',
  tenant: 'viewer',
  findings: 'viewer',
  finding: 'viewer',
  alerts: 'viewer',
  ack: 'viewer',
  stack: 'viewer',
  me: 'viewer',
  dashboard: 'viewer',
  scan: 'analyst',
  setstack: 'analyst',
  schedule: 'admin',
  grant: 'owner',
  users: 'admin',
  revoke: 'owner',
}

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: {
      'content-type': 'application/json',
      // Allow the Pages dashboard (tambosec.insights.autos) to call the API
      // cross-origin. Endpoints remain token-gated (DASHBOARD_TOKEN).
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'content-type, x-tambosec-token',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
    },
  })
}
