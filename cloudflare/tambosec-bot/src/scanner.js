import { appendJSON, readJSON, clearOpenForTenant, getKev, bulkInsert } from './storage.js'
import { randomBytes } from 'node:crypto'
import { correlateThreats } from './threatintel.js'

function newId(prefix) {
  return `${prefix}_${randomBytes(6).toString('hex')}`
}

// Module-level env (set by the Worker on each request/scheduled run).
let _env = null
export function setEnv(env) { _env = env }

// ─── Real checks (Cloudflare-only, no Google) ─────────────

// 1) HTTP security headers + HTTPS reachability
async function checkHeaders(domain) {
  const url = 'https://' + domain
  const findings = []
  let headers = {}
  let body = ''
  let reachable = true
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: { 'user-agent': 'TamboSec/1.0' },
      signal: AbortSignal.timeout(8000),
    })
    for (const [k, v] of res.headers.entries()) headers[k.toLowerCase()] = v
    // read a bit of body for mixed-content check
    try { body = await res.text() } catch { body = '' }
  } catch (e) {
    reachable = false
    findings.push({
      title: `Website unreachable over HTTPS (${e.message || 'connection error'})`,
      severity: 'high',
      source: 'cloudflare-http',
      category: 'transport_security',
      metadata: { domain, error: String(e.message || e) },
    })
    return findings
  }

  const checks = [
    { key: 'strict-transport-security', label: 'HSTS (HTTP Strict Transport Security)' },
    { key: 'content-security-policy', label: 'Content-Security-Policy' },
    { key: 'x-frame-options', label: 'X-Frame-Options (clickjacking protection)' },
    { key: 'x-content-type-options', label: 'X-Content-Type-Options: nosniff' },
    { key: 'referrer-policy', label: 'Referrer-Policy' },
  ]
  for (const c of checks) {
    if (!headers[c.key]) {
      findings.push({
        title: `Missing security header: ${c.label}`,
        severity: 'medium',
        source: 'cloudflare-http',
        category: 'security_headers',
        metadata: { domain, header: c.key },
      })
    }
  }

  // mixed content: http:// resources referenced on an https page
  if (body && /http:\/\//.test(body)) {
    const count = (body.match(/http:\/\//g) || []).length
    findings.push({
      title: `Mixed content detected (${count} insecure http:// reference(s))`,
      severity: 'medium',
      source: 'cloudflare-http',
      category: 'transport_security',
      metadata: { domain, count },
    })
  }
  return findings
}

// 2) Email authentication (SPF / DMARC / MX) via Cloudflare DoH
async function checkEmailAuth(domain) {
  const findings = []
  const doh = (_env && _env.DOH_URL) || 'https://cloudflare-dns.com/dns-query'
  async function txt(name) {
    try {
      const r = await fetch(`${doh}?name=${encodeURIComponent(name)}&type=TXT`, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(8000),
      })
      const j = await r.json()
      return (j.Answer || []).map((a) => a.data.replace(/^"|"$/g, '')).join(' ')
    } catch { return '' }
  }
  async function hasMX(name) {
    try {
      const r = await fetch(`${doh}?name=${encodeURIComponent(name)}&type=MX`, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(8000),
      })
      const j = await r.json()
      return (j.Answer || []).length > 0
    } catch { return false }
  }

  const spf = await txt(domain)
  if (!/v=spf1/.test(spf)) {
    findings.push({
      title: 'No SPF record (email spoofing risk)',
      severity: 'high',
      source: 'cloudflare-dns',
      category: 'email_authentication',
      metadata: { domain, spf: spf || 'none' },
    })
  } else if (/[+]all/.test(spf)) {
    findings.push({
      title: 'SPF ends with +all (permissive — anyone can spoof)',
      severity: 'high',
      source: 'cloudflare-dns',
      category: 'email_authentication',
      metadata: { domain, spf },
    })
  }

  const dmarc = await txt('_dmarc.' + domain)
  if (!/v=DMARC1/.test(dmarc)) {
    findings.push({
      title: 'No DMARC policy (no phishing protection / reporting)',
      severity: 'high',
      source: 'cloudflare-dns',
      category: 'email_authentication',
      metadata: { domain, dmarc: dmarc || 'none' },
    })
  } else if (/p=none/.test(dmarc)) {
    findings.push({
      title: 'DMARC policy is p=none (monitor-only, not enforced)',
      severity: 'medium',
      source: 'cloudflare-dns',
      category: 'email_authentication',
      metadata: { domain, dmarc },
    })
  }

  const mx = await hasMX(domain)
  if (!mx) {
    findings.push({
      title: 'No MX record (cannot receive email)',
      severity: 'low',
      source: 'cloudflare-dns',
      category: 'email_authentication',
      metadata: { domain },
    })
  }
  return findings
}

// 3) CISA KEV exposure vs declared tech stack
// KEV catalog is cached in D1 (populated out-of-band) because the Worker
// cannot reliably fetch external hosts at runtime.
async function checkKevExposure(domain, stack) {
  const findings = []
  if (!stack || stack.length === 0) return findings
  let kev = []
  try {
    kev = await getKev()
  } catch (e) {
    findings.push({
      title: 'KEV catalog unavailable',
      severity: 'low',
      source: 'cisa-kev',
      category: 'threat_intel',
      metadata: { error: String(e.message || e) },
    })
    return findings
  }
  if (!kev.length) {
    findings.push({
      title: 'KEV catalog not loaded',
      severity: 'low',
      source: 'cisa-kev',
      category: 'threat_intel',
      metadata: { note: 'run /api/refresh-kev' },
    })
    return findings
  }
  const stackLc = stack.map((s) => s.toLowerCase())
  for (const k of kev) {
    const hay = [k.product, k.vendorProject, k.shortDescription, k.vulnerabilityName, (k.cpes || []).join(' ')]
      .join(' ').toLowerCase()
    let matchedProd = null
    for (const prod of stackLc) {
      const words = prod.split(/[\s,]+/).filter((w) => w.length >= 3)
      if (prod.length >= 3 && hay.includes(prod)) { matchedProd = prod; break }
      if (words.some((w) => hay.includes(w))) { matchedProd = prod; break }
    }
    if (matchedProd) {
      findings.push({
        title: `Exploited vulnerability in ${matchedProd}: ${k.cveID || k.id}`,
        severity: 'critical',
        source: 'cisa-kev',
        category: 'threat_intel',
        metadata: {
          cve: k.cveID || k.id,
          product: matchedProd,
          name: k.vulnerabilityName || '',
          ransomware: k.knownRansomwareCampaignUse === 'Known',
          description: (k.shortDescription || '').slice(0, 280),
        },
      })
    }
  }
  return findings
}

// ─── Workers AI plain-language summary ────────────────────
async function aiSummary(tenantName, rawFindings) {
  if (!_env || !_env.AI) return null
  if (!rawFindings.length) return 'No issues detected. Posture looks good — re-run a scan after changes.'
  const compact = rawFindings.map((f) => `${f.severity.toUpperCase()}: ${f.title}`).join('\n')
  const prompt =
    `You are a security advisor for a small business owner (non-technical). ` +
    `Tenant: ${tenantName}. Summarize the following security findings in 2-3 plain sentences, ` +
    `in priority order, with one concrete first action. Avoid jargon.\n\n${compact}`
  try {
    const res = await _env.AI.run('@cf/meta/llama-3.2-3b-instruct', {
      prompt,
      max_tokens: 220,
    })
    let text = ''
    if (res) {
      text = res.text || res.response || res.output || ''
      if (!text && res.choices && res.choices[0]) {
        text = res.choices[0].text || res.choices[0].message?.content || ''
      }
    }
    text = (text || '').trim()
    if (text) return text
    console.error('[ai] empty response', JSON.stringify(res).slice(0, 200))
    return null
  } catch (e) {
    console.error('[ai] summary failed', e.message)
    return null
  }
}

// ─── Public entrypoint (same shape as the old simulator) ──
export async function runPostureScan(tenantId, domain, stack = []) {
  if (typeof stack === 'string') {
    try { stack = JSON.parse(stack) } catch { stack = [] }
  }
  if (!Array.isArray(stack)) stack = []
  // Fresh snapshot: clear prior open findings + unread alerts for this tenant
  await clearOpenForTenant(tenantId)
  const tenant = (await readJSON('tenants.json')).data.find((t) => t.id === tenantId)
  const tenantName = tenant ? tenant.name : domain

  const raw = [
    ...(await checkHeaders(domain)),
    ...(await checkEmailAuth(domain)),
    ...(await checkKevExposure(domain, stack)),
  ]

  const findings = []
  const alerts = []
  const auditEvents = []

  // Accumulate rows, then bulk-insert (hundreds of threat-intel findings would
  // otherwise mean hundreds of sequential D1 round-trips and time out the scan).
  const findingRows = []
  const alertRows = []
  const auditRows = []

  // Path 3: threat-intel correlation (live Threat-Scope feeds) — findings carry
  // their own stable ids (ti_<cve>) so re-scans don't pile up duplicates.
  const ti = await correlateThreats(tenantId, tenantName, stack)
  for (const f of ti.findings || []) {
    findingRows.push(f)
    findings.push(f)
    auditRows.push({
      id: newId('evt'),
      tenantId,
      type: 'finding.created',
      actor: 'threat-intel',
      findingId: f.id,
      approvalId: null,
      metadata: { severity: f.severity, source: f.source, category: f.category },
      ts: new Date().toISOString(),
    })
    if (f.severity === 'critical' || f.severity === 'high') {
      const alert = {
        id: newId('alt'),
        tenantId,
        findingId: f.id,
        severity: f.severity,
        status: 'unread',
        message: `${f.severity.toUpperCase()}: ${f.title}`,
        createdAt: new Date().toISOString(),
        acknowledgedAt: null,
        acknowledgedBy: null,
      }
      alertRows.push(alert)
      alerts.push(alert)
    }
  }

  for (const r of raw) {
    const finding = {
      id: newId('fdg'),
      tenantId,
      title: r.title,
      severity: r.severity,
      source: r.source,
      category: r.category,
      status: 'open',
      metadata: r.metadata || {},
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
    findingRows.push(finding)
    findings.push(finding)
    auditRows.push({
      id: newId('evt'),
      tenantId,
      type: 'finding.created',
      actor: 'scanner',
      findingId: finding.id,
      approvalId: null,
      metadata: { severity: finding.severity, source: finding.source, category: finding.category },
      ts: new Date().toISOString(),
    })
    if (finding.severity === 'critical' || finding.severity === 'high') {
      const alert = {
        id: newId('alt'),
        tenantId,
        findingId: finding.id,
        severity: finding.severity,
        status: 'unread',
        message: `${finding.severity.toUpperCase()}: ${finding.title}`,
        createdAt: new Date().toISOString(),
        acknowledgedAt: null,
        acknowledgedBy: null,
      }
      alertRows.push(alert)
      alerts.push(alert)
    }
  }

  // Single batched transaction per table.
  await bulkInsert('findings.json', findingRows)
  await bulkInsert('alerts.json', alertRows)
  await bulkInsert('audit.json', auditRows)

  const summary = await aiSummary(tenantName, raw)
  if (summary) {
    await appendJSON('summaries.json', {
      id: newId('sum'),
      tenantId,
      text: summary,
      ts: new Date().toISOString(),
    })
  }

  return { findings, alerts, summary }
}
