// scripts/refresh-threatintel.mjs
// Populates the Tambosec D1 database with the threat-intel feeds curated by the
// Threat-Scope project: CISA KEV, FIRST.org EPSS, MITRE ATT&CK.
//
// WHY THIS SCRIPT EXISTS:
// The Tambosec Worker cannot fetch external hosts at runtime (Cloudflare blocks
// Worker->Worker and Worker->public egress with error 1042 in this account). So
// the feeds are cached into D1 OUT-OF-BAND, from this machine, which CAN reach
// Threat-Scope. Run it on a schedule (cron) to keep Path 3 correlation fresh.
//
// Usage:  node scripts/refresh-threatintel.mjs
// Requires: wrangler authenticated, and the tambosec-bot project in cwd (or set
// TAMBOSEC_DIR). Uses the Threat-Scope public Worker API.

import { execFileSync } from 'node:child_process'
import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const THREAT_SCOPE = 'https://threat-scope-sync.walybewillin.workers.dev'
const DB = 'tambosec-db'

async function getJson(path) {
  const r = await fetch(THREAT_SCOPE + path)
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`)
  return r.json()
}

// Write a SQL file and execute it via wrangler --file (avoids E2BIG from huge
// --command argument strings when there are thousands of rows).
function d1ExecuteFile(sql) {
  const dir = mkdtempSync(join(tmpdir(), 'tambo-'))
  const file = join(dir, 'batch.sql')
  writeFileSync(file, sql)
  execFileSync('npx', ['wrangler', 'd1', 'execute', DB, '--remote', '--file', file], {
    stdio: 'inherit',
  })
}

async function main() {
  console.log('[refresh] pulling KEV from Threat-Scope...')
  const kev = await getJson('/kev')
  const vulns = kev.vulnerabilities || []
  console.log(`[refresh] ${vulns.length} KEV entries`)

  const kevRows = vulns.map((v) => {
    const esc = (s) => (s == null ? "''" : `'${String(s).replace(/'/g, "''")}'`)
    return `(${esc(v.cveID)}, ${esc(v.vendorProject)}, ${esc(v.product)}, ${esc(v.vulnerabilityName)}, ${esc(v.shortDescription)}, ${esc(v.knownRansomwareCampaignUse)})`
  })
  let sql = 'DELETE FROM kev;\n'
  for (let i = 0; i < kevRows.length; i += 200) {
    sql += `INSERT INTO kev (cveID, vendorProject, product, vulnerabilityName, shortDescription, knownRansomwareCampaignUse) VALUES ${kevRows.slice(i, i + 200).join(', ')};\n`
  }
  d1ExecuteFile(sql)

  console.log('[refresh] pulling EPSS...')
  const epss = await getJson('/epss')
  const epssEntries = Object.entries(epss).map(([cve, v]) => {
    const esc = (s) => (s == null ? "''" : `'${String(s).replace(/'/g, "''")}'`)
    return `(${esc(cve)}, ${Number(v.epss)}, ${Number(v.percentile)})`
  })
  sql = 'DELETE FROM epss;\n'
  for (let i = 0; i < epssEntries.length; i += 500) {
    sql += `INSERT INTO epss (cve, epss, percentile) VALUES ${epssEntries.slice(i, i + 500).join(', ')};\n`
  }
  d1ExecuteFile(sql)
  console.log(`[refresh] ${epssEntries.length} EPSS entries`)

  console.log('[refresh] pulling ATT&CK enterprise...')
  const attack = await getJson('/attack-enterprise')
  const techniques = attack.techniques || []
  const attackRows = techniques.map((t, i) => {
    const esc = (s) => (s == null ? "''" : `'${String(s).replace(/'/g, "''")}'`)
    return `(${i + 1}, ${esc(t.id)}, ${esc(t.name)}, ${esc((t.description || '').slice(0, 600))})`
  })
  // One INSERT per row (each statement stays small; batched VALUES strings hit SQLITE_TOOBIG).
  sql = 'DELETE FROM attack;\n' + attackRows.map((r) => `INSERT INTO attack (id, tid, name, description) VALUES ${r};\n`).join('')
  d1ExecuteFile(sql)
  console.log(`[refresh] ${techniques.length} ATT&CK techniques`)

  console.log('[refresh] done. Path 3 correlation is now fed from D1.')
}

main().catch((e) => {
  console.error('[refresh] FAILED:', e.message)
  process.exit(1)
})
