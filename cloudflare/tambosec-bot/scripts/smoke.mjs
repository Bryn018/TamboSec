#!/usr/bin/env node
// TamboSec API smoke test — runs against the LIVE Worker.
// Usage: DASHBOARD_TOKEN=xxx node scripts/smoke.mjs [tenantId] [baseUrl]
// Falls back to the worker default + tnt_real if not provided.
//
// What it checks:
//   1. /health returns ok
//   2. /api/dashboard without token -> 403 (auth gate)
//   3. /api/dashboard with token    -> 200 + data
//   4. Security headers present on a 403 (strict-transport-security, etc.)
//   5. /api/audit (new read endpoint) returns recent audit rows
//   6. malformed/unknown endpoint -> 404
//
// It does NOT hammer rate limits (separate manual check). Exit code 0 = pass.

const BASE = process.argv[3] || 'https://tambosec-bot.walybewillin.workers.dev'
const TOKEN = process.env.DASHBOARD_TOKEN || ''
const TENANT = process.argv[2] || 'tnt_real'

let failures = 0
function check(name, cond, detail = '') {
  const tag = cond ? 'PASS' : 'FAIL'
  if (!cond) failures++
  console.log(`[${tag}] ${name}${detail ? ' — ' + detail : ''}`)
}

async function main() {
  if (!TOKEN) {
    console.error('ERROR: set DASHBOARD_TOKEN env var (the shared API token).')
    process.exit(2)
  }

  // 1. health
  let r = await fetch(`${BASE}/health`)
  let j = await r.json().catch(() => ({}))
  check('health ok', r.ok && j.ok === true, `http=${r.status}`)

  // 2. auth gate — no token
  r = await fetch(`${BASE}/api/dashboard?tenantId=${TENANT}`)
  check('dashboard without token -> 403', r.status === 403, `http=${r.status}`)

  // 4. security headers on the 403
  const wantHdr = ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'content-security-policy']
  const gotHdr = wantHdr.filter((h) => r.headers.get(h))
  check('security headers on 403', gotHdr.length === wantHdr.length, `present=${gotHdr.join(',')}`)

  // 3. dashboard with token
  r = await fetch(`${BASE}/api/dashboard?tenantId=${TENANT}&token=${TOKEN}`)
  j = await r.json().catch(() => ({}))
  check('dashboard with token -> 200', r.ok && j.tenant, `http=${r.status} tenant=${j.tenant?.name}`)

  // 5. audit trail populated (we just did view.dashboard)
  r = await fetch(`${BASE}/api/audit?tenantId=${TENANT}&token=${TOKEN}`)
  j = await r.json().catch(() => ({}))
  const rows = j.audit || []
  check('audit endpoint returns rows', Array.isArray(rows), `count=${rows.length}`)
  const sawView = rows.some((a) => a.type === 'view.dashboard')
  check('audit recorded view.dashboard', sawView, sawView ? 'ok' : `recent=${rows.slice(0,3).map(a=>a.type).join(',')}`)

  // 6. unknown endpoint -> 404
  r = await fetch(`${BASE}/api/does-not-exist?token=${TOKEN}`)
  check('unknown endpoint -> 404', r.status === 404, `http=${r.status}`)

  console.log(`\n${failures === 0 ? 'ALL PASS' : failures + ' FAILURE(S)'}`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((e) => { console.error('SMOKE ERROR', e); process.exit(3) })
