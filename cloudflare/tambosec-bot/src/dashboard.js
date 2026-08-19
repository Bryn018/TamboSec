// Dashboard data feed — returns JSON consumed by the Cloudflare Pages
// static dashboard at https://tambosec.insights.autos
// (The HTML is a standalone SPA at dashboard/index.html, not generated here.)

import { getDB } from './storage.js'

export async function getDashboardData(tenantId) {
  const db = getDB()
  const { results: fRows } = await db.prepare(
    `SELECT severity, source, status FROM findings WHERE tenantId = ?`
  ).bind(tenantId).all()
  const findings = fRows || []

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  const sourceCounts = {}
  let open = 0
  for (const f of findings) {
    if (sevCounts[f.severity] != null) sevCounts[f.severity]++
    sourceCounts[f.source] = (sourceCounts[f.source] || 0) + 1
    if (f.status === 'open') open++
  }

  const { results: aRows } = await db.prepare(
    `SELECT status, severity FROM alerts WHERE tenantId = ?`
  ).bind(tenantId).all()
  const alerts = aRows || []
  const unread = alerts.filter((a) => a.status === 'unread').length

  const { results: mRows } = await db.prepare(
    `SELECT disposition, COUNT(*) c FROM mail_log WHERE tenant_id = ? GROUP BY disposition`
  ).bind(tenantId).all()
  const mail = {}
  for (const m of mRows || []) mail[m.disposition] = m.c

  const { results: tRows } = await db.prepare(
    `SELECT id, title, severity, source, metadata, createdAt FROM findings
     WHERE tenantId = ? ORDER BY createdAt DESC LIMIT 25`
  ).bind(tenantId).all()
  const top = (tRows || []).map((r) => {
    let meta = {}
    try { meta = JSON.parse(r.metadata || '{}') } catch { /* ignore */ }
    return {
      id: r.id,
      title: r.title,
      severity: r.severity,
      source: r.source,
      cve: meta.cve || null,
      epss: meta.epss != null ? Number(meta.epss) : null,
      stack: meta.product || null,
      createdAt: r.createdAt,
    }
  })

  const tenant = await db.prepare('SELECT id, name, domain, stack FROM tenants WHERE id = ?')
    .bind(tenantId).first()

  return {
    tenant: tenant ? { id: tenant.id, name: tenant.name, domain: tenant.domain, stack: safeStack(tenant.stack) } : null,
    summary: { total: findings.length, open, unreadAlerts: unread, sevCounts, sourceCounts, mail },
    findings: top,
  }
}

function safeStack(s) {
  if (!s) return []
  try { return JSON.parse(s) } catch { return String(s).split(',').map((x) => x.trim()) }
}
