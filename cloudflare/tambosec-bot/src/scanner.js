import { appendJSON } from './storage.js';
import { randomBytes } from 'node:crypto';

function newId(prefix) {
  return `${prefix}_${randomBytes(6).toString('hex')}`;
}

export const POSTURE_CHECKS = [
  {
    title: 'Admin account without MFA',
    severity: 'high',
    category: 'identity_hygiene',
    metadata: (domain) => ({ user: `admin@${domain}`, control: 'mfa', state: 'missing' }),
  },
  {
    title: 'Dormant privileged account detected',
    severity: 'medium',
    category: 'privilege_hygiene',
    metadata: (domain) => ({ user: `ops-admin@${domain}`, lastLoginDaysAgo: 92 }),
  },
  {
    title: 'External collaborator with elevated access',
    severity: 'high',
    category: 'access_governance',
    metadata: (domain) => ({ user: 'contractor@external.tld', access: 'admin-like' }),
  },
  {
    title: 'Password policy below recommended strength',
    severity: 'medium',
    category: 'identity_hygiene',
    metadata: (domain) => ({ minLength: 6, recommended: 12, enforced: false }),
  },
  {
    title: 'OAuth app with excessive permissions approved',
    severity: 'high',
    category: 'app_governance',
    metadata: (domain) => ({ appName: 'Third-party analytics', scopes: ['data.read', 'user.write', 'admin'] }),
  },
  {
    title: 'Audit logging not enabled on shared drives',
    severity: 'low',
    category: 'data_governance',
    metadata: (domain) => ({ resource: 'shared-drive', logging: false }),
  },
];

export async function runPostureScan(tenantId, domain) {
  const findings = [];
  const auditEvents = [];
  const alerts = [];

  for (const check of POSTURE_CHECKS) {
    const finding = {
      id: newId('fdg'),
      tenantId,
      title: check.title,
      severity: check.severity,
      source: 'google-workspace-posture',
      category: check.category,
      status: 'open',
      metadata: check.metadata(domain),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await appendJSON('findings.json', finding);
    findings.push(finding);

    auditEvents.push({
      id: newId('evt'),
      tenantId,
      type: 'finding.created',
      actor: 'scanner',
      findingId: finding.id,
      approvalId: null,
      metadata: { severity: finding.severity, source: finding.source, category: finding.category },
      ts: new Date().toISOString(),
    });

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
      };
      await appendJSON('alerts.json', alert);
      alerts.push(alert);
    }
  }

  for (const evt of auditEvents) {
    await appendJSON('audit.json', evt);
  }

  return { findings, alerts };
}
