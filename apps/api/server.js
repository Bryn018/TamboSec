const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 8080;
app.use(express.json({ limit: '256kb' }));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_PER_MIN || 180),
  standardHeaders: true,
  legacyHeaders: false,
}));

// Basic security headers + CORS for web console -> API calls
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-tenant-id, x-api-key');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

const nowIso = () => new Date().toISOString();
const newId = (prefix) => `${prefix}_${crypto.randomBytes(6).toString('hex')}`;

const DATABASE_URL = process.env.DATABASE_URL;
const useDb = Boolean(DATABASE_URL);
const pool = useDb ? new Pool({ connectionString: DATABASE_URL, ssl: process.env.DB_SSL === '1' ? { rejectUnauthorized: false } : undefined }) : null;
const SCHEDULER_ENABLED = process.env.SCHEDULER_ENABLED !== '0';
const SCHEDULER_TICK_MS = Number(process.env.SCHEDULER_TICK_MS || 60000);
const AUTH_DISABLED = process.env.AUTH_DISABLED === '1';

const roleRank = { viewer: 1, analyst: 2, admin: 3, owner: 4 };
const apiKeyPairs = (process.env.TAMBOSEC_API_KEYS || '').split(',').map(s => s.trim()).filter(Boolean);
const apiKeyMap = new Map();
for (const pair of apiKeyPairs) {
  const [role, key] = pair.split(':');
  if (role && key && roleRank[role]) apiKeyMap.set(key, role);
}

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
    create table if not exists scan_schedules (
      tenant_id text primary key references tenants(id) on delete cascade,
      every_hours int not null check (every_hours between 1 and 168),
      enabled boolean not null default true,
      next_run_at timestamptz not null,
      updated_at timestamptz not null default now(),
      updated_by text
    );
    create index if not exists idx_findings_tenant_status on findings(tenant_id, status);
    create index if not exists idx_findings_tenant_severity on findings(tenant_id, severity);
    create index if not exists idx_audit_tenant_ts on audit_events(tenant_id, ts desc);
    create index if not exists idx_alerts_tenant_status on alerts(tenant_id, status, created_at desc);
  `);
}

function asCleanString(v, max = 256) {
  if (typeof v !== 'string') return null;
  const out = v.trim();
  if (!out || out.length > max) return null;
  return out;
}

function asSafeDomain(v) {
  const s = asCleanString(v, 253);
  if (!s) return null;
  if (!/^[a-zA-Z0-9.-]+$/.test(s)) return null;
  return s.toLowerCase();
}

function requireAuth(req, res, next) {
  if (AUTH_DISABLED) {
    req.auth = { role: 'owner', subject: 'auth-disabled' };
    return next();
  }

  const key = req.header('x-api-key');
  if (!key) return res.status(401).json({ error: 'missing_api_key' });
  const role = apiKeyMap.get(key);
  if (!role) return res.status(401).json({ error: 'invalid_api_key' });
  req.auth = { role, subject: 'api-key' };
  next();
}

function requireRole(minRole) {
  return (req, res, next) => {
    const current = req.auth?.role;
    if (!current) return res.status(401).json({ error: 'unauthorized' });
    if ((roleRank[current] || 0) < (roleRank[minRole] || 0)) return res.status(403).json({ error: 'forbidden', need: minRole, have: current });
    next();
  };
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

async function getTenantDomain(tenantId) {
  if (pool) {
    const q = await pool.query('select domain from tenants where id=$1', [tenantId]);
    return q.rows[0]?.domain || null;
  }
  return mem.tenants.get(tenantId)?.domain || null;
}

async function runScheduledScansTick() {
  if (!SCHEDULER_ENABLED) return;

  try {
    if (pool) {
      const lock = await pool.query(`select pg_try_advisory_lock(90442001) as locked`);
      if (!lock.rows[0]?.locked) return;
      try {
        const due = await pool.query(
          `select tenant_id as "tenantId", every_hours as "everyHours"
           from scan_schedules
           where enabled=true and next_run_at <= now()
           order by next_run_at asc
           limit 20`
        );

        for (const s of due.rows) {
          const domain = await getTenantDomain(s.tenantId);
          if (!domain) continue;

          const created = await simulateGooglePosture({ tenantId: s.tenantId, domain });
          await auditEvent({ tenantId: s.tenantId, type: 'scan.schedule.executed', actor: 'scheduler', metadata: { createdFindings: created.length, everyHours: s.everyHours } });
          await pool.query(
            `update scan_schedules set next_run_at = now() + make_interval(hours => every_hours), updated_at=now() where tenant_id=$1`,
            [s.tenantId]
          );
        }
      } finally {
        await pool.query(`select pg_advisory_unlock(90442001)`);
      }
      return;
    }

    for (const [tenantId, s] of mem.scheduledScans.entries()) {
      if (!s.enabled) continue;
      if (new Date(s.nextRunAt) > new Date()) continue;
      const domain = await getTenantDomain(tenantId);
      if (!domain) continue;
      const created = await simulateGooglePosture({ tenantId, domain });
      await auditEvent({ tenantId, type: 'scan.schedule.executed', actor: 'scheduler', metadata: { createdFindings: created.length, everyHours: s.everyHours } });
      s.nextRunAt = new Date(Date.now() + s.everyHours * 3600 * 1000).toISOString();
      s.updatedAt = nowIso();
      mem.scheduledScans.set(tenantId, s);
    }
  } catch (e) {
    console.error('scheduler tick failed', e.message);
  }
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'tambosec-api', ts: nowIso(), version: '0.4.0-postgres', storage: pool ? 'postgres' : 'memory' });
});

app.get('/', (_req, res) => {
  res.json({ name: 'TamboSec API', status: 'mvp-core-online' });
});

app.get('/v1/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, role: req.auth.role, subject: req.auth.subject });
});

app.use('/v1', requireAuth);

app.post('/v1/tenants', requireRole('admin'), async (req, res) => {
  const name = asCleanString(req.body?.name, 120);
  const domain = req.body?.domain ? asSafeDomain(req.body?.domain) : null;
  if (!name) return res.status(400).json({ error: 'name is required (1-120 chars)' });
  if (req.body?.domain && !domain) return res.status(400).json({ error: 'domain format invalid' });
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

app.post('/v1/findings', requireRole('analyst'), withTenant, async (req, res) => {
  const title = asCleanString(req.body?.title, 300);
  const severity = req.body?.severity || 'medium';
  const source = asCleanString(req.body?.source || 'manual', 80);
  const category = asCleanString(req.body?.category || 'identity_hygiene', 80);
  const metadata = typeof req.body?.metadata === 'object' && req.body?.metadata !== null ? req.body.metadata : {};

  if (!title) return res.status(400).json({ error: 'title is required' });
  if (!new Set(['critical', 'high', 'medium', 'low']).has(severity)) return res.status(400).json({ error: 'severity must be critical|high|medium|low' });
  if (!source || !category) return res.status(400).json({ error: 'source/category invalid' });

  const finding = await createFinding({ tenantId: req.tenantId, title, severity, source, category, metadata });
  res.status(201).json(finding);
});

app.get('/v1/findings', requireRole('viewer'), withTenant, async (req, res) => {
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

app.post('/v1/findings/:id/close', requireRole('analyst'), withTenant, async (req, res) => {
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

app.post('/v1/connectors/google-workspace/posture-scan', requireRole('analyst'), withTenant, async (req, res) => {
  let domain = req.body?.domain ? asSafeDomain(req.body.domain) : null;
  if (req.body?.domain && !domain) return res.status(400).json({ error: 'domain format invalid' });
  if (!domain) domain = await getTenantDomain(req.tenantId);
  if (!domain) return res.status(400).json({ error: 'domain required (body.domain or tenant.domain)' });

  const created = await simulateGooglePosture({ tenantId: req.tenantId, domain });
  await auditEvent({ tenantId: req.tenantId, type: 'connector.scan.google_workspace.completed', actor: 'worker-simulated', metadata: { createdFindings: created.length, domain } });
  res.status(201).json({ tenantId: req.tenantId, source: 'google-workspace-posture', mode: 'simulated', createdFindings: created.length, findings: created });
});

app.post('/v1/remediations/request', requireRole('analyst'), withTenant, async (req, res) => {
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

app.post('/v1/remediations/:id/approve', requireRole('admin'), withTenant, async (req, res) => decideApproval(req, res, 'approved'));
app.post('/v1/remediations/:id/reject', requireRole('admin'), withTenant, async (req, res) => decideApproval(req, res, 'rejected'));

app.get('/v1/remediations', requireRole('viewer'), withTenant, async (req, res) => {
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

app.get('/v1/audit-events', requireRole('viewer'), withTenant, async (req, res) => {
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

app.get('/v1/alerts', requireRole('viewer'), withTenant, async (req, res) => {
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

app.post('/v1/alerts/:id/ack', requireRole('analyst'), withTenant, async (req, res) => {
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

app.get('/v1/scans/schedule', requireRole('viewer'), withTenant, async (req, res) => {
  if (pool) {
    const q = await pool.query(
      `select tenant_id as "tenantId", every_hours as "everyHours", enabled,
              next_run_at as "nextRunAt", updated_at as "updatedAt", updated_by as "updatedBy"
       from scan_schedules where tenant_id=$1`,
      [req.tenantId]
    );
    return res.json({ schedule: q.rows[0] || null });
  }
  return res.json({ schedule: mem.scheduledScans.get(req.tenantId) || null });
});

app.post('/v1/scans/schedule', requireRole('admin'), withTenant, async (req, res) => {
  const everyHours = Number(req.body?.everyHours || 24);
  const enabled = req.body?.enabled !== false;
  const updatedBy = req.body?.updatedBy || 'dashboard-user';

  if (!Number.isFinite(everyHours) || everyHours < 1 || everyHours > 168) {
    return res.status(400).json({ error: 'everyHours must be between 1 and 168' });
  }

  if (pool) {
    const q = await pool.query(
      `insert into scan_schedules (tenant_id, every_hours, enabled, next_run_at, updated_by)
       values ($1,$2,$3, now() + make_interval(hours => $2), $4)
       on conflict (tenant_id) do update set
         every_hours=excluded.every_hours,
         enabled=excluded.enabled,
         next_run_at=now() + make_interval(hours => excluded.every_hours),
         updated_at=now(),
         updated_by=excluded.updated_by
       returning tenant_id as "tenantId", every_hours as "everyHours", enabled,
                 next_run_at as "nextRunAt", updated_at as "updatedAt", updated_by as "updatedBy"`,
      [req.tenantId, everyHours, enabled, updatedBy]
    );
    await auditEvent({ tenantId: req.tenantId, type: 'scan.schedule.updated', actor: updatedBy, metadata: { everyHours, enabled } });
    return res.json({ ok: true, schedule: q.rows[0] });
  }

  const schedule = {
    tenantId: req.tenantId,
    everyHours,
    enabled,
    nextRunAt: new Date(Date.now() + everyHours * 3600 * 1000).toISOString(),
    updatedAt: nowIso(),
    updatedBy,
  };
  mem.scheduledScans.set(req.tenantId, schedule);
  await auditEvent({ tenantId: req.tenantId, type: 'scan.schedule.updated', actor: updatedBy, metadata: { everyHours, enabled } });
  res.json({ ok: true, schedule });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'internal_error', message: err.message });
});

initDb()
  .then(() => {
    if (SCHEDULER_ENABLED) {
      setInterval(runScheduledScansTick, SCHEDULER_TICK_MS);
      runScheduledScansTick().catch(() => null);
    }

    app.listen(port, () => {
      console.log(`TamboSec API listening on ${port}`);
      console.log(`[storage] ${pool ? 'postgres' : 'memory'}`);
      console.log(`[scheduler] ${SCHEDULER_ENABLED ? `enabled @ ${SCHEDULER_TICK_MS}ms` : 'disabled'}`);
    });
  })
  .catch((e) => {
    console.error('DB init failed', e);
    process.exit(1);
  });
