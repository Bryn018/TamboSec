// Path 3 — Threat-Intel Wrapper.
// Reuses the threat intelligence curated by the Threat-Scope project (CISA KEV +
// FIRST.org EPSS + MITRE ATT&CK) so an SMB can subscribe its tech stack and be
// told, in plain terms, when it is exposed to an EXPLOITED or HIGH-likelihood
// vulnerability — and which attacker technique is involved.
//
// IMPORTANT (Cloudflare egress constraint): a Worker subrequest to another
// *.workers.dev (even our own Threat-Scope Worker) is blocked at runtime with
// error 1042 in this account. So the feeds are cached into the Tambosec D1
// database OUT-OF-BAND (scripts/refresh-threatintel.mjs on this machine pulls
// from Threat-Scope, which itself pulls from the public sources). The Worker
// reads exclusively from D1 — no runtime egress. This is the same pattern as the
// Path 1 KEV cache.
//
// No Google. No external egress from this Worker.

import { getKev, readJSON } from './storage.js'

// ─── D1-backed feed readers (source of truth) ───────────
async function getKevData() {
  try {
    const cached = await getKev()
    if (cached.length) return { rows: cached, source: 'd1-cache', count: cached.length }
  } catch { /* ignore */ }
  return { rows: [], source: 'none', count: 0 }
}

async function getEpss() {
  try {
    const { data } = await readJSON('epss.json')
    if (data.length) {
      const map = {}
      for (const r of data) map[r.cve] = { epss: Number(r.epss), percentile: Number(r.percentile) }
      return map
    }
  } catch { /* ignore */ }
  return null
}

async function getAttack() {
  try {
    const { data } = await readJSON('attack.json')
    if (data.length) {
      return data.map((r) => ({ id: r.tid, name: r.name, description: r.description || '' }))
    }
  } catch { /* ignore */ }
  return null
}

// ─── Stack matching ───────────────────────────────────────
function tokenize(stack) {
  const out = []
  for (const s of stack) {
    const lc = String(s).toLowerCase().trim()
    if (lc.length >= 3) out.push(lc)
    // also index multi-word product tokens (e.g. "apache http server")
    for (const w of lc.split(/[\s,.\-/]+/).filter((w) => w.length >= 3)) out.push(w)
  }
  return out
}

function matches(stackTokens, hay) {
  const h = String(hay).toLowerCase()
  return stackTokens.some((tok) => h.includes(tok))
}

// ─── Public entrypoint: correlate a tenant's stack against cached intel ──
export async function correlateThreats(tenantId, tenantName, stack = []) {
  if (!stack || !stack.length) {
    return { findings: [], meta: { note: 'set a tech stack with /setstack to enable threat-intel correlation' } }
  }
  const tokens = tokenize(stack)

  const kev = await getKevData()
  const epss = await getEpss()
  const attack = await getAttack()

  const findings = []
  const seen = new Set()

  for (const k of kev.rows) {
    const hay = [k.product, k.vendorProject, k.vulnerabilityName, k.shortDescription, (k.cpes || []).join(' ')].join(' ')
    if (!matches(tokens, hay)) continue
    const cve = k.cveID || k.id
    if (seen.has(cve)) continue
    seen.add(cve)

    const ep = epss && epss[cve] ? epss[cve] : null
    const epssScore = ep ? Number(ep.epss) : null
    const percentile = ep ? Number(ep.percentile) : null

    // severity: KEV (exploited) is at least critical; EPSS >=0.9 bumps to critical too.
    let severity = 'critical' // KEV = actively exploited
    if (epssScore != null && epssScore >= 0.9) severity = 'critical'
    else if (epssScore != null && epssScore >= 0.5) severity = 'high'

    // Map to ATT&CK technique if the description references one (best-effort).
    let technique = null
    if (attack && k.shortDescription) {
      const lc = k.shortDescription.toLowerCase()
      const hit = attack.find((t) => t.name && lc.includes(t.name.toLowerCase()))
      if (hit) technique = { id: hit.id, name: hit.name }
    }

    findings.push({
      id: `ti_${cve}`,
      tenantId,
      title: `Actively exploited vulnerability in ${stack.join(', ')}: ${cve}`,
      severity,
      source: 'threat-intel',
      category: 'threat_intel',
      status: 'open',
      metadata: {
        cve,
        product: k.product || '',
        ransomware: k.knownRansomwareCampaignUse === 'Known',
        name: k.vulnerabilityName || '',
        description: (k.shortDescription || '').slice(0, 320),
        epss: epssScore,
        percentile,
        technique,
        intel_source: kev.source,
        attack_available: !!attack,
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    })
  }

  // EPSS-only high-likelihood exposures not in KEV (still worth a high finding)
  if (epss) {
    for (const cve of Object.keys(epss)) {
      if (seen.has(cve)) continue
      const ep = epss[cve]
      if (Number(ep.epss) >= 0.95) {
        findings.push({
          id: `ti_${cve}`,
          tenantId,
          title: `High exploitation likelihood (EPSS ${(Number(ep.epss) * 100).toFixed(0)}%) for ${cve}`,
          severity: 'high',
          source: 'threat-intel',
          category: 'threat_intel',
          status: 'open',
          metadata: {
            cve,
            epss: Number(ep.epss),
            percentile: Number(ep.percentile),
            intel_source: 'd1-cache',
            note: 'Not yet in CISA KEV; high EPSS score.',
          },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        })
        seen.add(cve)
      }
    }
  }

  return {
    findings,
    meta: {
      kev_source: kev.source,
      kev_count: kev.count,
      epss_available: !!epss,
      attack_available: !!attack,
      stack: stack,
    },
  }
}

// ─── Cache-status probe (verification endpoint) ──
// Live Threat-Scope fetch is blocked (1042) at runtime, so this just reports the
// D1 cache state + confirms the block, so we can verify Path 3 is wired correctly.
export async function probeThreatScope() {
  const kev = await getKevData()
  let epssCount = 0
  let attackCount = 0
  try { const { data } = await readJSON('epss.json'); epssCount = data.length } catch { /* ignore */ }
  try { const { data } = await readJSON('attack.json'); attackCount = data.length } catch { /* ignore */ }
  return {
    live_fetch: 'blocked (Cloudflare 1042 — Worker->Worker egress disabled)',
    d1_cache: {
      kev: kev.count,
      epss: epssCount,
      attack_techniques: attackCount,
    },
    populated: kev.count > 0 && epssCount > 0,
    refresh: 'run scripts/refresh-threatintel.mjs on this machine to populate D1 from Threat-Scope',
  }
}
