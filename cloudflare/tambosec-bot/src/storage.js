// D1-backed storage for the TamboSec Worker.
// Exposes JSON-style accessors (readJSON / appendJSON / updateJSON) that map
// to D1 tables, so scanner.js and the API handlers run unchanged. The
// "database" is a Cloudflare D1 SQLite instance — no JSON files in the repo.

const TABLE = {
  'tenants.json': 'tenants',
  'findings.json': 'findings',
  'alerts.json': 'alerts',
  'approvals.json': 'approvals',
  'audit.json': 'audit',
  'schedules.json': 'schedules',
  'summaries.json': 'summaries',
  'mail_log.json': 'mail_log',
  'epss.json': 'epss',
  'attack.json': 'attack',
}

function tableFor(fileName) {
  const t = TABLE[fileName]
  if (!t) throw new Error('no table for ' + fileName)
  return t
}

function rowToObj(row) {
  if (!row) return row
  const out = { ...row }
  if (typeof out.metadata === 'string') {
    try { out.metadata = JSON.parse(out.metadata) } catch { out.metadata = {} }
  }
  return out
}

function objToRow(obj) {
  const out = { ...obj }
  if (out.metadata && typeof out.metadata !== 'string') {
    out.metadata = JSON.stringify(out.metadata)
  }
  return out
}

export async function readJSON(fileName) {
  const db = getDB()
  const table = tableFor(fileName)
  const { results } = await db.prepare(`SELECT * FROM ${table}`).all()
  return { data: (results || []).map(rowToObj), sha: null }
}

export async function appendJSON(fileName, item) {
  const db = getDB()
  const table = tableFor(fileName)
  const r = objToRow(item)
  const cols = Object.keys(r)
  const placeholders = cols.map(() => '?').join(',')
  await db
    .prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${placeholders})`)
    .bind(...cols.map((c) => r[c]))
    .run()
  return item
}

// Replace prior open findings + unread alerts for a tenant so each scan
// is a fresh point-in-time snapshot (no duplicate pile-up).
export async function clearOpenForTenant(tenantId) {
  const db = getDB()
  await db.prepare("DELETE FROM findings WHERE tenantId = ? AND status = 'open'").bind(tenantId).run()
  await db.prepare("DELETE FROM alerts WHERE tenantId = ? AND status = 'unread'").bind(tenantId).run()
  return true
}

// Load the cached CISA KEV catalog (populated out-of-band from this machine,
// since the Worker cannot reliably fetch external hosts). Returns array of rows.
export async function getKev() {
  const db = getDB()
  const { results } = await db.prepare(
    'SELECT cveID, vendorProject, product, vulnerabilityName, shortDescription, knownRansomwareCampaignUse FROM kev'
  ).all()
  return results || []
}

// Module-level DB handle, injected by the Worker on each request.
let _db = null
export function setDB(db) { _db = db }
export function getDB() {
  if (!_db) throw new Error('DB not initialised')
  return _db
}

// Bulk insert many rows into a table in a single transaction (avoids the
// per-row round-trip cost of appendJSON when a scan yields hundreds of rows).
// Defensive: dedupe by `id` (a stray duplicate must never 500 the whole scan)
// and use INSERT OR IGNORE so re-scans of a tenant never collide with rows
// that clearOpenForTenant didn't catch.
export async function bulkInsert(fileName, rows) {
  const db = getDB()
  const table = tableFor(fileName)
  if (!rows.length) return 0
  const seen = new Set()
  const CHUNK = 200
  let inserted = 0
  for (let i = 0; i < rows.length; i += CHUNK) {
    const slice = rows.slice(i, i + CHUNK).filter((item) => {
      const id = item && item.id
      if (id == null) return true
      if (seen.has(id)) return false
      seen.add(id)
      return true
    })
    if (!slice.length) continue
    const stmts = slice.map((item) => {
      const r = objToRow(item)
      const cols = Object.keys(r)
      const placeholders = cols.map(() => '?').join(',')
      return db.prepare(`INSERT OR IGNORE INTO ${table} (${cols.join(',')}) VALUES (${placeholders})`).bind(...cols.map((c) => r[c]))
    })
    await db.batch(stmts)
    inserted += slice.length
  }
  return inserted
}
