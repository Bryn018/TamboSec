import { setDB } from './storage.js'
import { handleCommand, handleCallback } from './commands-core.js'
import { runPostureScan } from './scanner.js'

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
    const url = new URL(request.url)

    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true, service: 'tambosec-bot' })
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

  // Cron: hourly scheduled posture scans.
  async scheduled(event, env, ctx) {
    setDB(env.DB)
    const { DB, BOT_TOKEN } = env
    const { results } = await DB.prepare(
      `SELECT tenant_id, every_hours, next_run_at FROM schedules
       WHERE enabled = 1 AND next_run_at <= strftime('%Y-%m-%dT%H:%M:%SZ','now')`
    ).all()
    for (const row of results || []) {
      const tenant = await DB.prepare('SELECT id, name, domain FROM tenants WHERE id = ?')
        .bind(row.tenant_id).first()
      if (!tenant) continue
      const { findings, alerts } = await runPostureScan(tenant.id, tenant.domain || 'demo.local')
      // notify the tenant owner chat if we can resolve one (best-effort)
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
