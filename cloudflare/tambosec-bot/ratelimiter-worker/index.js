// Standalone Durable Object Worker — atomic rate limiter for TamboSec.
// Deployed separately as "tambosec-ratelimiter"; the main Worker binds it via
// [[durable_objects.bindings]] with script_name="tambosec-ratelimiter".

const WINDOW = 60 // seconds
const LIMITS = {
  read: { ip: 120, global: 600 },
  write: { ip: 20, global: 60 },
}

export class RateLimiter {
  constructor(state, env) {
    this.state = state
    this.kind = env?.KIND || 'read'
  }

  async fetch(request) {
    const now = Math.floor(Date.now() / 1000)
    let s = await this.state.storage.get('s')
    if (!s || s.reset <= now) s = { reset: now + WINDOW, ips: {}, global: 0 }
    const lim = LIMITS[this.kind] || LIMITS.read
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown'

    s.global++
    s.ips[ip] = (s.ips[ip] || 0) + 1
    await this.state.storage.put('s', s)

    const retryAfter = Math.max(1, s.reset - now)
    if (s.ips[ip] > lim.ip || s.global > lim.global) {
      return new Response(JSON.stringify({ error: 'rate limited', retryAfter }), {
        status: 429,
        headers: { 'content-type': 'application/json', 'retry-after': String(retryAfter) },
      })
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
}

export default {
  async fetch() {
    return new Response('tambosec-ratelimiter DO worker', { status: 200 })
  },
}
