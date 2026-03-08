const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 8080;
app.use(express.json());

// MVP in-memory stores (replace with Postgres in next phase)
const tenants = new Map();
const findings = new Map();
const remediationApprovals = new Map();

const nowIso = () => new Date().toISOString();
const newId = (prefix) => `${prefix}_${crypto.randomBytes(6).toString('hex')}`;

function requireTenant(req, res, next) {
  const tenantId = req.header('x-tenant-id') || req.query.tenantId || req.body.tenantId;
  if (!tenantId) return res.status(400).json({ error: 'tenantId required (header x-tenant-id or body/query)' });
  if (!tenants.has(tenantId)) return res.status(404).json({ error: 'tenant not found' });
  req.tenantId = tenantId;
  next();
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'tambosec-api', ts: nowIso(), version: '0.2.0-mvp-core' });
});

app.get('/', (_req, res) => {
  res.json({ name: 'TamboSec API', status: 'mvp-core-online' });
});

// Tenants
app.post('/v1/tenants', (req, res) => {
  const { name } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' });
  const id = newId('tnt');
  const tenant = { id, name, createdAt: nowIso() };
  tenants.set(id, tenant);
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

  const id = newId('fdg');
  const finding = {
    id,
    tenantId: req.tenantId,
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
  res.json(finding);
});

// Approval queue for high-impact remediations
app.post('/v1/remediations/request', requireTenant, (req, res) => {
  const { findingId, actionType, reason } = req.body || {};
  const allowedActions = new Set([
    'force_password_reset',
    'revoke_admin_role',
    'revoke_active_sessions',
  ]);

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
  res.status(201).json(approval);
});

app.post('/v1/remediations/:id/approve', requireTenant, (req, res) => {
  const approval = remediationApprovals.get(req.params.id);
  if (!approval || approval.tenantId !== req.tenantId) return res.status(404).json({ error: 'approval not found' });
  approval.status = 'approved';
  approval.decidedAt = nowIso();
  approval.decisionBy = req.body?.decisionBy || 'human-operator';
  remediationApprovals.set(approval.id, approval);
  res.json(approval);
});

app.post('/v1/remediations/:id/reject', requireTenant, (req, res) => {
  const approval = remediationApprovals.get(req.params.id);
  if (!approval || approval.tenantId !== req.tenantId) return res.status(404).json({ error: 'approval not found' });
  approval.status = 'rejected';
  approval.decidedAt = nowIso();
  approval.decisionBy = req.body?.decisionBy || 'human-operator';
  remediationApprovals.set(approval.id, approval);
  res.json(approval);
});

app.get('/v1/remediations', requireTenant, (req, res) => {
  const items = Array.from(remediationApprovals.values()).filter((a) => a.tenantId === req.tenantId);
  res.json({ items, total: items.length });
});

app.listen(port, () => {
  console.log(`TamboSec API listening on ${port}`);
});
