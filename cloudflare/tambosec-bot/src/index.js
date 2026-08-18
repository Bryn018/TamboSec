import { setDB, getDB } from './storage.js'
import { setEnv } from './scanner.js'
import { handleCommand, handleCallback } from './commands-core.js'
import { runPostureScan } from './scanner.js'
import { handleInboundEmail, classifyText } from './mail.js'

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
    const url = new URL(request.url)

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
      const result = await runPostureScan(tenant.id, tenant.domain || 'demo.local', stack)
      return json({ tenant: tenant.name, domain: tenant.domain, ...result })
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
      `SELECT tenant_id, every_hours, next_run_at FROM schedules
       WHERE enabled = 1 AND next_run_at <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).all()
    for (const row of results || []) {
      const tenant = await DB.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?')
        .bind(row.tenant_id).first()
      if (!tenant) continue
      const stack = tenant.stack // JSON string or array; runPostureScan parses it
      const { findings, alerts, summary } = await runPostureScan(tenant.id, tenant.domain || 'demo.local', stack)
      console.log('[scheduled] scanned', tenant.id, 'findings=', findings.length, 'alerts=', alerts.length)
    }
    // advance next_run_at for processed schedules
    await DB.prepare(
      `UPDATE schedules SET next_run_at = strftime('%Y-%m-%dT%H:%M:%SZ','now', (every_hours) || ' hours')
       WHERE enabled = 1 AND next_run_at <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).run()
  },
}

function token(env) { return env.BOT_TOKEN }

// Persist the owner's Telegram chat id in the config table so Path 2 email
// alerts can be pushed there. Idempotent upsert.
async function rememberOwnerChat(chatId) {
  try {
    const db = getDB()
    if (!db) return
    await db
      .prepare(
        `INSERT INTO config (key, value) VALUES ('owner_chat_id', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`
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
    const text = msg.text
    if (text.startsWith('/')) {
      const parts = text.slice(1).split(/\s+/)
      const command = parts[0].toLowerCase()
      const args = parts.slice(1)
      await handleCommand({ command, args, reply, chatId })
    } else {
      await reply('Send /start to see available commands.')
    }
  }
}

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { 'content-type': 'application/json' },
  })
}
