// Populates the D1 `kev` table from the authoritative CISA KEV catalog.
// Run locally (the machine can reach CISA; the Worker cannot fetch externally).
//   node scripts/refresh-kev.mjs
import { execFileSync } from 'node:child_process'

const URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'

async function main() {
  const res = await fetch(URL, { headers: { 'user-agent': 'TamboSec/1.0' } })
  if (!res.ok) throw new Error('KEV fetch failed: ' + res.status)
  const j = await res.json()
  const items = j.vulnerabilities || []
  console.log('KEV entries:', items.length)

  const esc = (v) => {
    if (v === null || v === undefined) return "''"
    return "'" + String(v).replace(/'/g, "''").replace(/\n/g, ' ').slice(0, 4000) + "'"
  }

  const rows = items.map((k) => {
    const cve = k.cveID || ''
    const vp = k.vendorProject || ''
    const pr = k.product || ''
    const nm = k.vulnerabilityName || ''
    const sd = (k.shortDescription || '').replace(/\n/g, ' ').slice(0, 2000)
    const rw = k.knownRansomwareCampaignUse || ''
    return `('${cve.replace(/'/g, "''")}',${esc(vp)},${esc(pr)},${esc(nm)},${esc(sd)},${esc(rw)})`
  })

  const fs = await import('node:fs')
  const path = await import('node:path')
  const tmp = path.join('/tmp', 'tambosec_kev_seed.sql')

  // Chunk into batches (SQLite has a per-statement size limit).
  const BATCH = 100
  const stmts = ['DELETE FROM kev;']
  for (let i = 0; i < rows.length; i += BATCH) {
    const chunk = rows.slice(i, i + BATCH)
    stmts.push(
      'INSERT INTO kev (cveID, vendorProject, product, vulnerabilityName, shortDescription, knownRansomwareCampaignUse) VALUES\n' +
        chunk.join(',\n') + ';'
    )
  }
  fs.writeFileSync(tmp, stmts.join('\n'))

  execFileSync('npx', ['wrangler', 'd1', 'execute', 'tambosec-db', '--remote', '--file=' + tmp], {
    stdio: ['ignore', 'inherit', 'inherit'],
    maxBuffer: 50 * 1024 * 1024,
  })
  console.log('KEV catalog loaded into D1.')
}

main().catch((e) => {
  console.error('refresh-kev failed:', e.message)
  process.exit(1)
})
