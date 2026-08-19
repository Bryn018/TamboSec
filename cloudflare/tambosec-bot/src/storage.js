// D1-backed storage for the TamboSec Worker.
// Exposes the SAME signatures as the legacy GitHub-JSON storage layer
// (readJSON / writeJSON / appendJSON / updateJSON / queryJSON) so that
// scanner.js and the API handlers run unchanged. The "database" is now a
// Cloudflare D1 SQLite instance instead of JSON files in the repo.

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

export async function writeJSON(fileName, data, _sha = null) {
  const db = getDB()
  const table = tableFor(fileName)
  // Full replace (used by scheduler upserts on the small schedules table).
  const tx = db.batch()
  tx.add(db.prepare(`DELETE FROM ${table}`))
  for (const item of data) {
    const r = objToRow(item)
    const cols = Object.keys(r)
    const placeholders = cols.map(() => '?').join(',')
    tx.add(
      db.prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${placeholders})`).bind(
        ...cols.map((c) => r[c])
      )
    )
  }
  await tx.submit()
  return data
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

export async function updateJSON(fileName, predicate, updater) {
  const db = getDB()
  const table = tableFor(fileName)
  const { results } = await db.prepare(`SELECT * FROM ${table}`).all()
  const rows = (results || []).map(rowToObj)
  const idx = rows.findIndex(predicate)
  if (idx === -1) return null
  const updated = updater(rows[idx])
  const r = objToRow(updated)
  const cols = Object.keys(r)
  const setClause = cols.map((c) => `${c} = ?`).join(', ')
  await db
    .prepare(`UPDATE ${table} SET ${setClause} WHERE id = ?`)
    .bind(...cols.map((c) => r[c]), r.id)
    .run()
  return updated
}

export async function queryJSON(fileName, predicate) {
  const { data } = await readJSON(fileName)
  return data.filter(predicate)
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

// ─── Path 4: RBAC ──────────────────────────────────────────
// role rank: higher = more privilege
export const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3, owner: 4 }
export const ROLES = ['viewer', 'analyst', 'admin', 'owner']

export async function getUser(chatId) {
  const db = getDB()
  const row = await db.prepare('SELECT * FROM users WHERE id = ?').bind(String(chatId)).first()
  if (!row) return null
  return rowToObj(row)
}

export async function upsertUser(chatId, tenantId, role, name) {
  const db = getDB()
  await db
    .prepare(
      `INSERT INTO users (id, tenantId, role, name, createdAt)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET tenantId = excluded.tenantId, role = excluded.role, name = excluded.name`
    )
    .bind(String(chatId), tenantId, role, name || null, new Date().toISOString())
    .run()
  return getUser(chatId)
}

export async function listUsers() {
  const db = getDB()
  const { results } = await db.prepare('SELECT * FROM users ORDER BY role DESC').all()
  return (results || []).map(rowToObj)
}

export async function countUsers() {
  const db = getDB()
  const row = await db.prepare('SELECT COUNT(*) AS c FROM users').first()
  return row ? row.c : 0
}

// Resolve requester role. The owner chat id (captured in config by Path 2) is a
// global superuser. If no users exist yet, the first configured owner acts as owner.
export async function resolveRole(chatId) {
  const u = await getUser(chatId)
  if (u) return u.role
  // fall back to owner_chat_id from config
  try {
    const db = getDB()
    const row = await db.prepare("SELECT value FROM config WHERE key = 'owner_chat_id'").first()
    if (row && String(row.value) === String(chatId)) return 'owner'
  } catch { /* ignore */ }
  return null
}

// Does the requester with `role` satisfy the minimum required role?
export function roleSatisfies(role, minRole) {
  const have = ROLE_RANK[role] || 0
  const need = ROLE_RANK[minRole] || 0
  return have >= need
}

// Seed the owner from config (idempotent) — run at startup. Only CREATES the
// owner user if no row exists for the config chat; it never demotes or
// promotes an existing user (that would let rememberOwnerChat's legacy
// Path-2 capture accidentally re-grant owner to whoever messaged last).
export async function seedOwnerFromConfig() {
  try {
    const db = getDB()
    const row = await db.prepare("SELECT value FROM config WHERE key = 'owner_chat_id'").first()
    if (!row) return
    const chatId = String(row.value)
    const existing = await getUser(chatId)
    if (!existing) {
      await upsertUser(chatId, null, 'owner', null)
      console.log('[rbac] seeded owner from config:', chatId)
    }
  } catch (e) {
    console.error('[rbac] seed failed', e.message)
  }
}
