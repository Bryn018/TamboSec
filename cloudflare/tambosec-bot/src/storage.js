// D1-backed storage for the TamboSec bot.
// Exposes the SAME signatures as the legacy GitHub-JSON storage.js
// (readJSON / writeJSON / appendJSON / updateJSON / queryJSON) so that
// commands-core.js and scanner.js run unchanged. The "database" is now a
// Cloudflare D1 SQLite instance instead of JSON files in the repo.

const TABLE = {
  'tenants.json': 'tenants',
  'findings.json': 'findings',
  'alerts.json': 'alerts',
  'approvals.json': 'approvals',
  'audit.json': 'audit',
  'schedules.json': 'schedules',
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

// Module-level DB handle, injected by the Worker on each request.
let _db = null
export function setDB(db) { _db = db }
function getDB() {
  if (!_db) throw new Error('DB not initialised')
  return _db
}
