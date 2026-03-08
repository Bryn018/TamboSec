const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 8080;
app.use(express.json());

// CORS for web console -> API calls
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-tenant-id');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

const nowIso = () => new Date().toISOString();
const newId = (prefix) => `${prefix}_${crypto.randomBytes(6).toString('hex')}`;

const DATABASE_URL = process.env.DATABASE_URL;
const useDb = Boolean(DATABASE_URL);
const pool = useDb ? new Pool({ connectionString: DATABASE_URL, ssl: process.env.DB_SSL === '1' ? { rejectUnauthorized: false } : undefined }) : null;

// Fallback in-memory stores when DB not configured
const mem = {
  tenants: new Map(),
  findings: new Map(),
  approvals: new Map(),
  alerts: new Map(),
  scheduledScans: new Map(),
  events: [],
};

async function initDb() {
  if (!pool) return;
  await pool.query(`
    create table if not exists tenants (
      id text primary key,
      name text not null,
      domain text,
      created_at timestamptz not null default now()
    );
    create table if not exists findings (
      id text primary key,
      tenant_id text not null references tenants(id) on delete cascade,
      title text not null,
      severity text not null check (severity in ('critical','high','medium','low')),
      source text not null,
      category text not null,
      status text not null default 'open' check (status in ('open','closed')),
      metadata jsonb not null default '{}'::jsonb,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );
    create table if not exists remediation_approvals (
      id text primary key,
      tenant_id text not null references tenants(id) on delete cascade,
      finding_id text not null references findings(id) on delete cascade,
      action_type text not null check (action_type in ('force_password_reset','revoke_admin_role','revoke_active_sessions')),
      reason text,
      status text not null default 'pending' check (status in ('pending','approved','rejected')),
      requested_at timestamptz not null default now(),
      decided_at timestamptz,
      decision_by text
    );
    create table if not exists audit_events (
      id text primary key,
      tenant_id text not null references tenants(id) on delete cascade,
      type text not null,
      actor text,
      finding_id text,
      approval_id text,
      metadata jsonb not null default '{}'::jsonb,
      ts timestamptz not null default now()
    );
    create table if not exists alerts (
      id text primary key,
      tenant_id text not null references tenants(id) on delete cascade,
      finding_id text not null references findings(id) on delete cascade,
      severity text not null check (severity in ('critical','high')),
      status text not null default 'unread' check (status in ('unread','acknowledged')),
      message text not null,
      created_at timestamptz not null default now(),
      acknowledged_at timestamptz,
      acknowledged_by text
    );
    create index if not exists idx_findings_tenant_status on findings(tenant_id, status);
    create index if not exists idx_findings_tenant_severity on findings(tenant_id, severity);
    create index if not exists idx_audit_tenant_ts on audit_events(tenant_id, ts desc);
    create index if not exists idx_alerts_tenant_status on alerts(tenant_id, status, created_at desc);
  `);
}

async function withTenant(req, res, next) {
  const tenantId = req.header('x-tenant-id') || req.query.tenantId || req.body.tenantId;
  if (!tenantId) return res.status(400).json({ error: 'tenantId required (header x-tenant-id or body/query)' });

  if (pool) {
    const r = await pool.query('select id from tenants where id=$1', [tenantId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'tenant not found' });
  } else if (!mem.tenants.has(tenantId)) {
    return res.status(404).json({ error: 'tenant not found' });
  }

  req.tenantId = tenantId;
  next();
}

async function auditEvent({ tenantId, type, actor = null, findingId = null, approvalId = null, metadata = {} }) {
  const id = newId('evt');
  if (pool) {
    await pool.query(
      `insert into audit_events (id, tenant_id, type, actor, finding_id, approval_id, metadata)
       values ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
      [id, tenantId, type, actor, findingId, approvalId, JSON.stringify(metadata)]
    );
  } else {
    mem.events.push({ id, tenantId, type, actor, findingId, approvalId, metadata, ts: nowIso() });
    if (mem.events.length > 5000) mem.events.shift();
  }
}

async function createDashboardAlert(finding) {
  if (!['high', 'critical'].includes(finding.severity)) return;

  const id = newId('alt');
  const message = `${finding.severity.toUpperCase()}: ${finding.title}`;

  if (pool) {
    await pool.query(
      `insert into alerts (id, tenant_id, finding_id, severity, message)
       values ($1,$2,$3,$4,$5)`,
      [id, finding.tenantId, finding.id, finding.severity, message]
    );
  } else {
    mem.alerts.set(id, {
      id,
      tenantId: finding.tenantId,
      findingId: finding.id,
      severity: finding.severity,
      status: 'unread',
      message,
      createdAt: nowIso(),
      acknowledgedAt: null,
      acknowledgedBy: null,
    });
  }
}

async function notifySlackFinding(finding) {
  const webhook = process.env.SLACK_WEBHOOK_URL;
  if (!webhook) return;
  if (!['high', 'critical'].includes(finding.severity)) return;

  const payload = {
    text: `🚨 TamboSec ${finding.severity.toUpperCase()} finding`,
    blocks: [
      { type: 'section', text: { type: 'mrkdwn', text: `*${finding.title}*` } },
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: `tenant: \`${finding.tenantId}\` • source: \`${finding.source}\` • category: \`${finding.category}\`` }
        ]
      }
    ]
  };

  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.error('slack notify failed', e.message);
  }
}

async function createFinding({ tenantId, title, severity = 'medium', source = 'manual', category = 'identity_hygiene', metadata = {} }) {
  const id = newId('fdg');
  if (pool) {
    const q = await pool.query(
      `insert into findings (id, tenant_id, title, severity, source, category, metadata)
       values ($1,$2,$3,$4,$5,$6,$7::jsonb)
       returning id, tenant_id as "tenantId", title, severity, source, category, status,
       metadata, created_at as "createdAt", updated_at as "updatedAt"`,
      [id, tenantId, title, severity, source, category, JSON.stringify(metadata)]
    );
    const finding = q.rows[0];
    await auditEvent({ tenantId, type: 'finding.created', findingId: finding.id, metadata: { severity, source, category } });
    await createDashboardAlert(finding);
    await notifySlackFinding(finding);
    return finding;
  }

  const finding = { id, tenantId, title, severity, source, category, status: 'open', metadata, createdAt: nowIso(), updatedAt: nowIso() };
  mem.findings.set(id, finding);
  await auditEvent({ tenantId, type: 'finding.created', findingId: id, metadata: { severity, source, category } });
  await createDashboardAlert(finding);
  await notifySlackFinding(finding);
  return finding;
}

function simulateGooglePosture({ tenantId, domain }) {
  const defs = [
    { title: 'Admin account without MFA', severity: 'high', category: 'identity_hygiene', metadata: { user: `admin@${domain}`, control: 'mfa', state: 'missing' } },
    { title: 'Dormant privileged account detected', severity: 'medium', category: 'privilege_hygiene', metadata: { user: `ops-admin@${domain}`, lastLoginDaysAgo: 92 } },
    { title: 'External collaborator with elevated access', severity: 'high', category: 'access_governance', metadata: { user: 'contractor@external.tld', access: 'admin-like' } }
  ];
  return Promise.all(defs.map((d) => createFinding({ tenantId, ...d, source: 'google-workspace-posture' })));
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'tambosec-api', ts: nowIso(), version: '0.4.0-postgres', storage: pool ? 'postgres' : 'memory' });
});

app.get('/', (_req, res) => {
  res.json({ name: 'TamboSec API', status: 'mvp-core-online' });
});

app.post('/v1/tenants', async (req, res) => {
  const { name, domain } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
  const id = newId('tnt');

  if (pool) {
    const q = await pool.query(
      'insert into tenants (id, name, domain) values ($1,$2,$3) returning id, name, domain, created_at as "createdAt"',
      [id, name, domain || null]
    );
    await auditEvent({ tenantId: id, type: 'tenant.created', actor: 'api', metadata: { name, domain: domain || null } });
    return res.status(201).json(q.rows[0]);
  }

  const tenant = { id, name, domain: domain || null, createdAt: nowIso() };
  mem.tenants.set(id, tenant);
  await auditEvent({ tenantId: id, type: 'tenant.created', actor: 'api', metadata: { name, domain: domain || null } });
  res.status(201).json(tenant);
});

app.get('/v1/tenants', async (_req, res) => {
  if (pool) {
    const q = await pool.query('select id, name, domain, created_at as "createdAt" from tenants order by created_at desc');
    return res.json({ items: q.rows });
  }
  res.json({ items: Array.from(mem.tenants.values()) });
});

app.post('/v1/findings', withTenant, async (req, res) => {
  const { title, severity = 'medium', source = 'manual', category = 'identity_hygiene', metadata = {} } = req.body || {};
  if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title is required' });
  if (!new Set(['critical', 'high', 'medium', 'low']).has(severity)) return res.status(400).json({ error: 'severity must be critical|high|medium|low' });
  const finding = await createFinding({ tenantId: req.tenantId, title, severity, source, category, metadata });
  res.status(201).json(finding);
});

app.get('/v1/findings', withTenant, async (req, res) => {
  const severity = req.query.severity;
  if (pool) {
    const params = [req.tenantId];
    let sql = `select id, tenant_id as "tenantId", title, severity, source, category, status, metadata,
               created_at as "createdAt", updated_at as "updatedAt"
               from findings where tenant_id=$1`;
    if (severity) {
      params.push(severity);
      sql += ` and severity=$2`;
    }
    sql += ' order by created_at desc';
    const q = await pool.query(sql, params);
    return res.json({ items: q.rows, total: q.rowCount });
  }
  const items = Array.from(mem.findings.values()).filter((f) => f.tenantId === req.tenantId && (!severity || f.severity === severity));
  res.json({ items, total: items.length });
});

app.post('/v1/findings/:id/close', withTenant, async (req, res) => {
  if (pool) {
    const q = await pool.query(
      `update findings set status='closed', updated_at=now()
       where id=$1 and tenant_id=$2
       returning id, tenant_id as "tenantId", title, severity, source, category, status, metadata,
                 created_at as "createdAt", updated_at as "updatedAt"`,
      [req.params.id, req.tenantId]
    );
    if (q.rowCount === 0) return res.status(404).json({ error: 'finding not found' });
    await auditEvent({ tenantId: req.tenantId, type: 'finding.closed', findingId: req.params.id, actor: 'api' });
    return res.json(q.rows[0]);
  }
  const finding = mem.findings.get(req.params.id);
  if (!finding || finding.tenantId !== req.tenantId) return res.status(404).json({ error: 'finding not found' });
  finding.status = 'closed';
  finding.updatedAt = nowIso();
  mem.findings.set(finding.id, finding);
  await auditEvent({ tenantId: req.tenantId, type: 'finding.closed', findingId: finding.id, actor: 'api' });
  res.json(finding);
});

app.post('/v1/connectors/google-workspace/posture-scan', withTenant, async (req, res) => {
  let domain = req.body?.domain;
  if (!domain && pool) {
    const q = await pool.query('select domain from tenants where id=$1', [req.tenantId]);
    domain = q.rows[0]?.domain;
  } else if (!domain) {
    domain = mem.tenants.get(req.tenantId)?.domain;
  }
  if (!domain) return res.status(400).json({ error: 'domain required (body.domain or tenant.domain)' });

  const created = await simulateGooglePosture({ tenantId: req.tenantId, domain });
  await auditEvent({ tenantId: req.tenantId, type: 'connector.scan.google_workspace.completed', actor: 'worker-simulated', metadata: { createdFindings: created.length, domain } });
  res.status(201).json({ tenantId: req.tenantId, source: 'google-workspace-posture', mode: 'simulated', createdFindings: created.length, findings: created });
});

app.post('/v1/remediations/request', withTenant, async (req, res) => {
  const { findingId, actionType, reason } = req.body || {};
  const allowedActions = new Set(['force_password_reset', 'revoke_admin_role', 'revoke_active_sessions']);
  if (!findingId) return res.status(400).json({ error: 'valid findingId required' });
  if (!allowedActions.has(actionType)) return res.status(400).json({ error: 'invalid actionType' });

  if (pool) {
    const fk = await pool.query('select id from findings where id=$1 and tenant_id=$2', [findingId, req.tenantId]);
    if (fk.rowCount === 0) return res.status(400).json({ error: 'valid findingId required' });

    const id = newId('apr');
    const q = await pool.query(
      `insert into remediation_approvals (id, tenant_id, finding_id, action_type, reason)
       values ($1,$2,$3,$4,$5)
       returning id, tenant_id as "tenantId", finding_id as "findingId", action_type as "actionType",
       reason, status, requested_at as "requestedAt", decided_at as "decidedAt", decision_by as "decisionBy"`,
      [id, req.tenantId, findingId, actionType, reason || 'No reason provided']
    );
    await auditEvent({ tenantId: req.tenantId, type: 'remediation.requested', approvalId: id, findingId, metadata: { actionType } });
    return res.status(201).json(q.rows[0]);
  }

  if (!mem.findings.has(findingId)) return res.status(400).json({ error: 'valid findingId required' });
  const id = newId('apr');
  const approval = { id, tenantId: req.tenantId, findingId, actionType, reason: reason || 'No reason provided', status: 'pending', requestedAt: nowIso(), decidedAt: null, decisionBy: null };
  mem.approvals.set(id, approval);
  await auditEvent({ tenantId: req.tenantId, type: 'remediation.requested', approvalId: id, findingId, metadata: { actionType } });
  res.status(201).json(approval);
});

async function decideApproval(req, res, status) {
  if (pool) {
    const q = await pool.query(
      `update remediation_approvals set status=$1, decided_at=now(), decision_by=$2
       where id=$3 and tenant_id=$4
       returning id, tenant_id as "tenantId", finding_id as "findingId", action_type as "actionType",
       reason, status, requested_at as "requestedAt", decided_at as "decidedAt", decision_by as "decisionBy"`,
      [status, req.body?.decisionBy || 'human-operator', req.params.id, req.tenantId]
    );
    if (q.rowCount === 0) return res.status(404).json({ error: 'approval not found' });
    await auditEvent({ tenantId: req.tenantId, type: `remediation.${status}`, approvalId: req.params.id, metadata: { actionType: q.rows[0].actionType }, actor: q.rows[0].decisionBy });
    return res.json(q.rows[0]);
  }
  const approval = mem.approvals.get(req.params.id);
  if (!approval || approval.tenantId !== req.tenantId) return res.status(404).json({ error: 'approval not found' });
  approval.status = status;
  approval.decidedAt = nowIso();
  approval.decisionBy = req.body?.decisionBy || 'human-operator';
  mem.approvals.set(approval.id, approval);
  await auditEvent({ tenantId: req.tenantId, type: `remediation.${status}`, approvalId: approval.id, metadata: { actionType: approval.actionType }, actor: approval.decisionBy });
  res.json(approval);
}

app.post('/v1/remediations/:id/approve', withTenant, async (req, res) => decideApproval(req, res, 'approved'));
app.post('/v1/remediations/:id/reject', withTenant, async (req, res) => decideApproval(req, res, 'rejected'));

app.get('/v1/remediations', withTenant, async (req, res) => {
  if (pool) {
    const q = await pool.query(
      `select id, tenant_id as "tenantId", finding_id as "findingId", action_type as "actionType", reason,
              status, requested_at as "requestedAt", decided_at as "decidedAt", decision_by as "decisionBy"
       from remediation_approvals where tenant_id=$1 order by requested_at desc`,
      [req.tenantId]
    );
    return res.json({ items: q.rows, total: q.rowCount });
  }
  const items = Array.from(mem.approvals.values()).filter((a) => a.tenantId === req.tenantId);
  res.json({ items, total: items.length });
});

app.get('/v1/audit-events', withTenant, async (req, res) => {
  if (pool) {
    const q = await pool.query(
      `select id, tenant_id as "tenantId", type, actor, finding_id as "findingId", approval_id as "approvalId", metadata, ts
       from audit_events where tenant_id=$1 order by ts desc limit 200`,
      [req.tenantId]
    );
    return res.json({ items: q.rows, total: q.rowCount });
  }
  const items = mem.events.filter((e) => e.tenantId === req.tenantId).slice(-200).reverse();
  res.json({ items, total: items.length });
});

app.get('/v1/alerts', withTenant, async (req, res) => {
  if (pool) {
    const q = await pool.query(
      `select id, tenant_id as "tenantId", finding_id as "findingId", severity, status, message,
              created_at as "createdAt", acknowledged_at as "acknowledgedAt", acknowledged_by as "acknowledgedBy"
       from alerts where tenant_id=$1 order by created_at desc limit 200`,
      [req.tenantId]
    );
    return res.json({ items: q.rows, total: q.rowCount });
  }
  const items = Array.from(mem.alerts.values()).filter((a) => a.tenantId === req.tenantId).sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt));
  res.json({ items, total: items.length });
});

app.post('/v1/alerts/:id/ack', withTenant, async (req, res) => {
  if (pool) {
    const q = await pool.query(
      `update alerts set status='acknowledged', acknowledged_at=now(), acknowledged_by=$1
       where id=$2 and tenant_id=$3
       returning id, tenant_id as "tenantId", finding_id as "findingId", severity, status, message,
       created_at as "createdAt", acknowledged_at as "acknowledgedAt", acknowledged_by as "acknowledgedBy"`,
      [req.body?.ackBy || 'dashboard-user', req.params.id, req.tenantId]
    );
    if (q.rowCount === 0) return res.status(404).json({ error: 'alert not found' });
    await auditEvent({ tenantId: req.tenantId, type: 'alert.acknowledged', actor: q.rows[0].acknowledgedBy, metadata: { alertId: req.params.id } });
    return res.json(q.rows[0]);
  }

  const alert = mem.alerts.get(req.params.id);
  if (!alert || alert.tenantId !== req.tenantId) return res.status(404).json({ error: 'alert not found' });
  alert.status = 'acknowledged';
  alert.acknowledgedAt = nowIso();
  alert.acknowledgedBy = req.body?.ackBy || 'dashboard-user';
  mem.alerts.set(alert.id, alert);
  await auditEvent({ tenantId: req.tenantId, type: 'alert.acknowledged', actor: alert.acknowledgedBy, metadata: { alertId: alert.id } });
  res.json(alert);
});

app.post('/v1/scans/schedule', withTenant, async (req, res) => {
  const everyHours = Number(req.body?.everyHours || 24);
  if (!Number.isFinite(everyHours) || everyHours < 1 || everyHours > 168) {
    return res.status(400).json({ error: 'everyHours must be between 1 and 168' });
  }
  const schedule = { tenantId: req.tenantId, everyHours, updatedAt: nowIso() };
  mem.scheduledScans.set(req.tenantId, schedule);
  await auditEvent({ tenantId: req.tenantId, type: 'scan.schedule.updated', actor: req.body?.updatedBy || 'dashboard-user', metadata: { everyHours } });
  res.json({ ok: true, schedule, note: 'Scheduler persistence currently in-memory; cron wiring next.' });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'internal_error', message: err.message });
});

initDb()
  .then(() => {
    app.listen(port, () => {
      console.log(`TamboSec API listening on ${port}`);
      console.log(`[storage] ${pool ? 'postgres' : 'memory'}`);
    });
  })
  .catch((e) => {
    console.error('DB init failed', e);
    process.exit(1);
  });
