const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 8080;
app.use(express.json());

// MVP in-memory stores (replace with Postgres in next phase)
const tenants = new Map();
const findings = new Map();
const remediationApprovals = new Map();
const auditEvents = [];

const nowIso = () => new Date().toISOString();
const newId = (prefix) => `${prefix}_${crypto.randomBytes(6).toString('hex')}`;

function pushAudit(event) {
  auditEvents.push({ id: newId('evt'), ts: nowIso(), ...event });
  if (auditEvents.length > 5000) auditEvents.shift();
}

function requireTenant(req, res, next) {
  const tenantId = req.header('x-tenant-id') || req.query.tenantId || req.body.tenantId;
  if (!tenantId) return res.status(400).json({ error: 'tenantId required (header x-tenant-id or body/query)' });
  if (!tenants.has(tenantId)) return res.status(404).json({ error: 'tenant not found' });
  req.tenantId = tenantId;
  next();
}

function createFinding({ tenantId, title, severity = 'medium', source = 'manual', category = 'identity_hygiene', metadata = {} }) {
  const id = newId('fdg');
  const finding = {
    id,
    tenantId,
    title,
    severity,
    source,
    category,
    status: 'open',
    metadata,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  findings.set(id, finding);
  pushAudit({ tenantId, type: 'finding.created', findingId: id, severity, source, category });
  return finding;
}

function runGoogleWorkspacePostureChecks({ tenantId, domain }) {
  // Phase-1 deterministic checks (simulated until live Admin SDK wiring is completed)
  const simulated = [
    {
      title: 'Admin account without MFA',
      severity: 'high',
      category: 'identity_hygiene',
      metadata: { user: `admin@${domain}`, control: 'mfa', state: 'missing' },
    },
    {
      title: 'Dormant privileged account detected',
      severity: 'medium',
      category: 'privilege_hygiene',
      metadata: { user: `ops-admin@${domain}`, lastLoginDaysAgo: 92 },
    },
    {
      title: 'External collaborator with elevated access',
      severity: 'high',
      category: 'access_governance',
      metadata: { user: `contractor@external.tld`, access: 'admin-like' },
    },
  ];

  return simulated.map((f) =>
    createFinding({
      tenantId,
      title: f.title,
      severity: f.severity,
      source: 'google-workspace-posture',
      category: f.category,
      metadata: f.metadata,
    }),
  );
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'tambosec-api', ts: nowIso(), version: '0.3.0-gw-collector-mvp' });
});

app.get('/', (_req, res) => {
  res.json({ name: 'TamboSec API', status: 'mvp-core-online' });
});

// Tenants
app.post('/v1/tenants', (req, res) => {
  const { name, domain } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
  const id = newId('tnt');
  const tenant = { id, name, domain: domain || null, createdAt: nowIso() };
  tenants.set(id, tenant);
  pushAudit({ tenantId: id, type: 'tenant.created', actor: 'api', metadata: { name, domain: domain || null } });
  res.status(201).json(tenant);
});

app.get('/v1/tenants', (_req, res) => {
  res.json({ items: Array.from(tenants.values()) });
});

// Findings
app.post('/v1/findings', requireTenant, (req, res) => {
  const { title, severity = 'medium', source = 'manual', category = 'identity_hygiene', metadata = {} } = req.body || {};
  if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title is required' });

  const allowed = new Set(['critical', 'high', 'medium', 'low']);
  if (!allowed.has(severity)) return res.status(400).json({ error: 'severity must be critical|high|medium|low' });

  const finding = createFinding({ tenantId: req.tenantId, title, severity, source, category, metadata });
  res.status(201).json(finding);
});

app.get('/v1/findings', requireTenant, (req, res) => {
  const severity = req.query.severity;
  const items = Array.from(findings.values()).filter((f) => f.tenantId === req.tenantId);
  const filtered = severity ? items.filter((f) => f.severity === severity) : items;
  res.json({ items: filtered, total: filtered.length });
});

app.post('/v1/findings/:id/close', requireTenant, (req, res) => {
  const finding = findings.get(req.params.id);
  if (!finding || finding.tenantId !== req.tenantId) return res.status(404).json({ error: 'finding not found' });
  finding.status = 'closed';
  finding.updatedAt = nowIso();
  findings.set(finding.id, finding);
  pushAudit({ tenantId: req.tenantId, type: 'finding.closed', findingId: finding.id, actor: 'api' });
  res.json(finding);
});

// Google Workspace posture collector (MVP simulation mode)
app.post('/v1/connectors/google-workspace/posture-scan', requireTenant, (req, res) => {
  const tenant = tenants.get(req.tenantId);
  const domain = req.body?.domain || tenant?.domain;
  if (!domain) return res.status(400).json({ error: 'domain required (body.domain or tenant.domain)' });

  const created = runGoogleWorkspacePostureChecks({ tenantId: req.tenantId, domain });
  pushAudit({
    tenantId: req.tenantId,
    type: 'connector.scan.google_workspace.completed',
    actor: 'worker-simulated',
    metadata: { createdFindings: created.length, domain },
  });

  res.status(201).json({
    tenantId: req.tenantId,
    source: 'google-workspace-posture',
    mode: 'simulated',
    createdFindings: created.length,
    findings: created,
  });
});

// Approval queue for high-impact remediations
app.post('/v1/remediations/request', requireTenant, (req, res) => {
  const { findingId, actionType, reason } = req.body || {};
  const allowedActions = new Set(['force_password_reset', 'revoke_admin_role', 'revoke_active_sessions']);

  if (!findingId || !findings.has(findingId)) return res.status(400).json({ error: 'valid findingId required' });
  if (!allowedActions.has(actionType)) return res.status(400).json({ error: 'invalid actionType' });

  const approvalId = newId('apr');
  const approval = {
    id: approvalId,
    tenantId: req.tenantId,
    findingId,
    actionType,
    reason: reason || 'No reason provided',
    status: 'pending',
    requestedAt: nowIso(),
    decidedAt: null,
    decisionBy: null,
  };
  remediationApprovals.set(approvalId, approval);
  pushAudit({ tenantId: req.tenantId, type: 'remediation.requested', approvalId, findingId, actionType });
  res.status(201).json(approval);
});

app.post('/v1/remediations/:id/approve', requireTenant, (req, res) => {
  const approval = remediationApprovals.get(req.params.id);
  if (!approval || approval.tenantId !== req.tenantId) return res.status(404).json({ error: 'approval not found' });
  approval.status = 'approved';
  approval.decidedAt = nowIso();
  approval.decisionBy = req.body?.decisionBy || 'human-operator';
  remediationApprovals.set(approval.id, approval);
  pushAudit({ tenantId: req.tenantId, type: 'remediation.approved', approvalId: approval.id, actionType: approval.actionType, actor: approval.decisionBy });
  res.json(approval);
});

app.post('/v1/remediations/:id/reject', requireTenant, (req, res) => {
  const approval = remediationApprovals.get(req.params.id);
  if (!approval || approval.tenantId !== req.tenantId) return res.status(404).json({ error: 'approval not found' });
  approval.status = 'rejected';
  approval.decidedAt = nowIso();
  approval.decisionBy = req.body?.decisionBy || 'human-operator';
  remediationApprovals.set(approval.id, approval);
  pushAudit({ tenantId: req.tenantId, type: 'remediation.rejected', approvalId: approval.id, actionType: approval.actionType, actor: approval.decisionBy });
  res.json(approval);
});

app.get('/v1/remediations', requireTenant, (req, res) => {
  const items = Array.from(remediationApprovals.values()).filter((a) => a.tenantId === req.tenantId);
  res.json({ items, total: items.length });
});

app.get('/v1/audit-events', requireTenant, (req, res) => {
  const items = auditEvents.filter((e) => e.tenantId === req.tenantId).slice(-200).reverse();
  res.json({ items, total: items.length });
});

app.listen(port, () => {
  console.log(`TamboSec API listening on ${port}`);
});
