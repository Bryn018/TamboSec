// Path 4 — Dashboard data + self-contained HTML view.
// The dashboard is served FROM this Worker (no separate Pages project needed),
// so everything stays in one deployable unit. The HTML embeds no external
// assets (pure Cloudflare) and pulls its data from /api/dashboard.

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

// Self-contained dark dashboard. No external fonts/CDNs — renders on Cloudflare.
export function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>TamboSec Dashboard</title>
<style>
  :root { --bg:#0b1020; --panel:#141b2e; --ink:#e6ebf5; --muted:#8b97b0; --line:#22304d;
          --crit:#ff5c7a; --high:#ff9f43; --med:#ffd23f; --low:#4cc9f0; --ok:#38d39f; }
  * { box-sizing:border-box }
  body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
  header { padding:18px 22px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; letter-spacing:.3px }
  .badge { font-size:11px; color:var(--muted); border:1px solid var(--line); padding:3px 8px; border-radius:999px }
  main { padding:22px; max-width:1100px; margin:0 auto }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:22px }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px }
  .card .n { font-size:28px; font-weight:700 }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px }
  .crit{color:var(--crit)} .high{color:var(--high)} .med{color:var(--med)} .low{color:var(--low)} .ok{color:var(--ok)}
  section { margin-bottom:24px }
  h2 { font-size:14px; color:var(--muted); text-transform:uppercase; letter-spacing:.6px; margin:0 0 10px }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:12px; overflow:hidden }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase }
  tr:last-child td { border-bottom:none }
  .row { font-size:13px }
  .pill { display:inline-block; font-size:11px; padding:2px 8px; border-radius:999px; border:1px solid var(--line); color:var(--muted) }
  .empty { color:var(--muted); padding:14px 4px }
  footer { color:var(--muted); font-size:12px; padding:0 22px 30px; max-width:1100px; margin:0 auto }
  code { background:#0e1530; padding:1px 5px; border-radius:5px; color:#bcd2ff }
</style>
</head>
<body>
<header>
  <h1>🛡 TamboSec</h1>
  <span class="badge" id="tenant">loading…</span>
  <span class="badge" id="clock"></span>
</header>
<main>
  <div class="grid" id="cards"></div>
  <section>
    <h2>Top findings</h2>
    <table><thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>CVE / EPSS</th></tr></thead>
    <tbody id="rows"><tr><td colspan="4" class="empty">Loading…</td></tr></tbody></table>
  </section>
</main>
<footer>
  TamboSec Security Posture Dashboard · data pulled live from your Cloudflare D1 · powered by Workers AI.
</footer>
<script>
  const TENANT = new URLSearchParams(location.search).get('tenant') || 'tnt_real';
  const TOKEN = new URLSearchParams(location.search).get('token') || '';
  async function load(){
    const res = await fetch('/api/dashboard?tenantId='+encodeURIComponent(TENANT)+'&token='+encodeURIComponent(TOKEN));
    if(!res.ok){ document.getElementById('tenant').textContent='auth error'; return; }
    const d = await res.json();
    const t = d.tenant || {};
    document.getElementById('tenant').textContent = (t.name||'unknown') + (t.domain? ' · '+t.domain : '');
    document.getElementById('clock').textContent = new Date().toLocaleString();
    const s = d.summary || {};
    const sc = s.sevCounts || {};
    const cards = [
      ['Total findings', s.total||0, ''],
      ['Open', s.open||0, ''],
      ['Critical', sc.critical||0, 'crit'],
      ['High', sc.high||0, 'high'],
      ['Unread alerts', s.unreadAlerts||0, 'high'],
      ['Phishing blocked', (s.mail&&s.mail.quarantined)||0, 'ok'],
    ];
    document.getElementById('cards').innerHTML = cards.map(c=>
      '<div class="card"><div class="n '+(c[2]||'')+'">'+c[1]+'</div><div class="l">'+c[0]+'</div></div>').join('');
    const rows = (d.findings||[]).map(f=>{
      const sev = (f.severity||'').toLowerCase();
      const ce = (f.cve? f.cve : '') + (f.epss!=null? ' · '+Number(f.epss).toFixed(3) : '');
      return '<tr class="row"><td class="'+(sev==='critical'?'crit':sev==='high'?'high':sev==='medium'?'med':'low')+'"><b>'+(f.severity||'')+'</b></td>'+
        '<td>'+escapeHtml(f.title||'')+'</td>'+
        '<td><span class="pill">'+(f.source||'')+'</span></td>'+
        '<td>'+(ce||'<span class="muted">—</span>')+'</td></tr>';
    }).join('');
    document.getElementById('rows').innerHTML = rows || '<tr><td colspan="4" class="empty">No findings for this tenant.</td></tr>';
  }
  function escapeHtml(s){ return String(s).replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
  load(); setInterval(load, 60000);
</script>
</body>
</html>`
}
