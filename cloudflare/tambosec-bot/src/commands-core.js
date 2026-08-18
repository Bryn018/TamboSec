import { readJSON, writeJSON, appendJSON, updateJSON } from './storage.js';
import { runPostureScan } from './scanner.js';
import { randomBytes } from 'node:crypto';

function newId(prefix) {
  return `${prefix}_${randomBytes(6).toString('hex')}`;
}

function sevEmoji(sev) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' }[sev] || '⚪';
}

function sevOrder(sev) {
  return { critical: 4, high: 3, medium: 2, low: 1 }[sev] || 0;
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ─── /start ───────────────────────────────────────────────
export async function cmdStart({ reply }) {
  await reply(
    `🛡 *TamboSec — Security Operations Bot*\n\n` +
    `I help you monitor security posture and manage findings.\n\n` +
    `*Commands:*\n` +
    `/newtenant <name> <domain> — Add an organisation\n` +
    `/tenants — List all tenants\n` +
    `/scan <tenantId> — Run posture scan\n` +
    `/findings <tenantId> [severity] — List findings\n` +
    `/alerts <tenantId> — View high/critical alerts\n` +
    `/remediate <tenantId> <findingId> <action> — Request remediation\n` +
    `/approvals <tenantId> — View pending approvals\n` +
    `/audit <tenantId> — Recent audit events\n` +
    `/schedule <tenantId> <hours> — Set scan schedule\n` +
    `/setstack <tenantId> <p1,p2> — Set tech stack (for threat-intel)\n` +
    `/threat <tenantId> — Threat-intel exposure (KEV/EPSS/ATT&CK)\n` +
    `/ask <question> — 🤖 Security Copilot (ask about your posture)\n` +
    `/maillog [n] — Email-security log\n` +
    `/summary <tenantId> — Advisor summary\n\n` +
    `_Owner only:_ /grant <chatId> <role>, /users, /revoke <chatId>\n\n` +
    `_All data stored in Cloudflare D1 (no Google)._`
  );
}

// ─── /newtenant ───────────────────────────────────────────
export async function cmdNewTenant({ reply, args }) {
  if (args.length < 2) {
    return reply('Usage: `/newtenant <name> <domain>`\nExample: `/newtenant AcmeCorp acme.com`');
  }
  const name = args[0];
  const domain = args[1].toLowerCase().replace(/[^a-z0-9.-]/g, '');
  const id = newId('tnt');
  const tenant = { id, name, domain, createdAt: new Date().toISOString() };
  await appendJSON('tenants.json', tenant);
  await appendJSON('audit.json', {
    id: newId('evt'), tenantId: id, type: 'tenant.created', actor: 'telegram',
    findingId: null, approvalId: null, metadata: { name, domain }, ts: new Date().toISOString(),
  });
  await reply(`✅ Tenant created:\n*${name}* \`${id}\`\nDomain: \`${domain}\``);
}

// ─── /tenants ─────────────────────────────────────────────
export async function cmdTenants({ reply }) {
  const { data: tenants } = await readJSON('tenants.json');
  if (tenants.length === 0) return reply('No tenants yet. Use `/newtenant` to create one.');
  const lines = tenants.map(t => `• *${t.name}* \`${t.id}\` (${t.domain || 'no domain'})`);
  await reply(`*Tenants:*\n${lines.join('\n')}`);
}

// ─── /scan ────────────────────────────────────────────────
export async function cmdScan({ reply, args }) {
  const tenantId = args[0];
  if (!tenantId) return reply('Usage: `/scan <tenantId>`');

  const { data: tenants } = await readJSON('tenants.json');
  const tenant = tenants.find(t => t.id === tenantId);
  if (!tenant) return reply('❌ Tenant not found. Use `/tenants` to see available.');

  await reply(`🔍 Running posture scan for *${tenant.name}*...`);

  const stack = tenant.stack // JSON string or array; runPostureScan parses it
  const { findings, alerts, summary } = await runPostureScan(tenantId, tenant.domain || 'demo.local', stack);

  let msg = `📊 *Scan Complete — ${tenant.name}*\n\n`;
  msg += `*Findings:* ${findings.length}\n`;
  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;
  if (critical) msg += `🔴 Critical: ${critical}\n`;
  if (high) msg += `🟠 High: ${high}\n`;
  if (medium) msg += `🟡 Medium: ${medium}\n`;
  if (low) msg += `🟢 Low: ${low}\n`;

  if (alerts.length > 0) {
    msg += `\n⚠️ *${alerts.length} alert${alerts.length > 1 ? 's' : ''} generated* — check /alerts`;
  }

  if (summary) {
    msg += `\n\n🤖 *Advisor:* ${summary}`;
  }

  await reply(msg);

  for (const alert of alerts) {
    const finding = findings.find(f => f.id === alert.findingId);
    await reply(
      `${sevEmoji(alert.severity)} *${alert.severity.toUpperCase()}*\n` +
      `${finding.title}\n` +
      `Source: \`${finding.source}\` | Category: \`${finding.category}\``,
      {
        reply_markup: {
          inline_keyboard: [[
            { text: '✅ Acknowledge', callback_data: `ack:${alert.id}` },
            { text: '🔧 Remediate', callback_data: `rem:${alert.id}` },
          ]],
        },
      }
    );
  }
}

// ─── /findings ────────────────────────────────────────────
export async function cmdFindings({ reply, args }) {
  const tenantId = args[0];
  const severity = args[1];
  if (!tenantId) return reply('Usage: `/findings <tenantId> [critical|high|medium|low]`');

  const { data: findings } = await readJSON('findings.json');
  let items = findings.filter(f => f.tenantId === tenantId);
  if (severity) items = items.filter(f => f.severity === severity);
  items.sort((a, b) => sevOrder(b.severity) - sevOrder(a.severity));

  if (items.length === 0) return reply('No findings for this tenant.');

  const lines = items.slice(0, 20).map(f =>
    `${sevEmoji(f.severity)} *${f.title}* \`${f.status}\`\n   \`${f.id}\` | ${f.category}`
  );
  await reply(`*Findings (${items.length}):*\n\n${lines.join('\n\n')}`);
}

// ─── /alerts ──────────────────────────────────────────────
export async function cmdAlerts({ reply, args }) {
  const tenantId = args[0];
  if (!tenantId) return reply('Usage: `/alerts <tenantId>`');

  const { data: alerts } = await readJSON('alerts.json');
  const items = alerts.filter(a => a.tenantId === tenantId && a.status === 'unread');

  if (items.length === 0) return reply('✅ No unread alerts.');

  for (const alert of items) {
    await reply(
      `${sevEmoji(alert.severity)} *${alert.message}*`,
      {
        reply_markup: {
          inline_keyboard: [[
            { text: '✅ Acknowledge', callback_data: `ack:${alert.id}` },
            { text: '🔧 Remediate', callback_data: `rem:${alert.id}` },
          ]],
        },
      }
    );
  }
}

// ─── /remediate ───────────────────────────────────────────
export async function cmdRemediate({ reply, args }) {
  if (args.length < 3) {
    return reply(
      'Usage: `/remediate <tenantId> <findingId> <action>`\n' +
      'Actions: `force_password_reset`, `revoke_admin_role`, `revoke_active_sessions`'
    );
  }
  const [tenantId, findingId, actionType] = args;
  const allowed = ['force_password_reset', 'revoke_admin_role', 'revoke_active_sessions'];
  if (!allowed.includes(actionType)) {
    return reply(`❌ Invalid action. Allowed: ${allowed.join(', ')}`);
  }

  const { data: findings } = await readJSON('findings.json');
  const finding = findings.find(f => f.id === findingId && f.tenantId === tenantId);
  if (!finding) return reply('❌ Finding not found for this tenant.');

  const approval = {
    id: newId('apr'),
    tenantId,
    findingId,
    actionType,
    reason: 'Requested via Telegram',
    status: 'pending',
    requestedAt: new Date().toISOString(),
    decidedAt: null,
    decisionBy: null,
  };
  await appendJSON('approvals.json', approval);
  await appendJSON('audit.json', {
    id: newId('evt'), tenantId, type: 'remediation.requested', actor: 'telegram',
    findingId, approvalId: approval.id, metadata: { actionType }, ts: new Date().toISOString(),
  });

  await reply(
    `⏳ *Remediation Requested*\n` +
    `Action: \`${actionType}\`\n` +
    `Finding: ${finding.title}\n` +
    `Approval ID: \`${approval.id}\``,
    {
      reply_markup: {
        inline_keyboard: [[
          { text: '✅ Approve', callback_data: `approve:${approval.id}` },
          { text: '❌ Reject', callback_data: `reject:${approval.id}` },
        ]],
      },
    }
  );
}

// ─── /approvals ───────────────────────────────────────────
export async function cmdApprovals({ reply, args }) {
  const tenantId = args[0];
  if (!tenantId) return reply('Usage: `/approvals <tenantId>`');

  const { data: approvals } = await readJSON('approvals.json');
  const items = approvals.filter(a => a.tenantId === tenantId);

  if (items.length === 0) return reply('No remediation requests for this tenant.');

  const lines = items.map(a => {
    const status = a.status === 'pending' ? '⏳' : a.status === 'approved' ? '✅' : '❌';
    return `${status} \`${a.actionType}\` — ${a.status}\n   \`${a.id}\` | ${fmtTime(a.requestedAt)}`;
  });
  await reply(`*Remediation Queue:*\n\n${lines.join('\n\n')}`);
}

// ─── /audit ───────────────────────────────────────────────
export async function cmdAudit({ reply, args }) {
  const tenantId = args[0];
  if (!tenantId) return reply('Usage: `/audit <tenantId>`');

  const { data: events } = await readJSON('audit.json');
  const items = events.filter(e => e.tenantId === tenantId).slice(-15).reverse();

  if (items.length === 0) return reply('No audit events for this tenant.');

  const lines = items.map(e =>
    `\`${fmtTime(e.ts)}\` ${e.type}\n   ${e.actor || 'system'} ${e.findingId ? '| ' + e.findingId : ''}`
  );
  await reply(`*Recent Audit Events:*\n\n${lines.join('\n\n')}`);
}

// ─── /schedule ────────────────────────────────────────────
export async function cmdSchedule({ reply, args }) {
  if (args.length < 2) return reply('Usage: `/schedule <tenantId> <hours>`\nExample: `/schedule tnt_abc123 24`');
  const tenantId = args[0];
  const everyHours = Number(args[1]);
  if (!Number.isFinite(everyHours) || everyHours < 1 || everyHours > 168) {
    return reply('❌ hours must be between 1 and 168.');
  }

  const schedule = {
    tenantId,
    everyHours,
    enabled: true,
    nextRunAt: new Date(Date.now() + everyHours * 3600 * 1000).toISOString(),
    updatedAt: new Date().toISOString(),
    updatedBy: 'telegram',
  };

  const { data: schedules, sha } = await readJSON('schedules.json');
  const idx = schedules.findIndex(s => s.tenantId === tenantId);
  if (idx !== -1) schedules[idx] = schedule;
  else schedules.push(schedule);
  await writeJSON('schedules.json', schedules, sha);

  await appendJSON('audit.json', {
    id: newId('evt'), tenantId, type: 'scan.schedule.updated', actor: 'telegram',
    findingId: null, approvalId: null, metadata: { everyHours }, ts: new Date().toISOString(),
  });

  await reply(
    `📅 Scan schedule set for \`${tenantId}\`\nEvery *${everyHours}h*\nNext run: ${fmtTime(schedule.nextRunAt)}`
  );
}

// ─── Inline button callback handler ───────────────────────
export async function handleCallback({ reply, editMessage, answerCallback, callbackData, chatId }) {
  const [action, id] = callbackData.split(':');

  if (action === 'ack') {
    await updateJSON('alerts.json', a => a.id === id, a => ({
      ...a, status: 'acknowledged', acknowledgedAt: new Date().toISOString(), acknowledgedBy: 'telegram-user',
    }));
    await answerCallback('✅ Alert acknowledged');
    await editMessage('✅ Acknowledged');
  }

  if (action === 'rem') {
    const { data: alerts } = await readJSON('alerts.json');
    const alert = alerts.find(a => a.id === id);
    if (!alert) return answerCallback('Alert not found');
    await answerCallback('Use /remediate to request a remediation action');
    await reply(
      `To request remediation for this finding, use:\n` +
      `\`/remediate ${alert.tenantId} ${alert.findingId} <action>\`\n\n` +
      `Actions: \`force_password_reset\`, \`revoke_admin_role\`, \`revoke_active_sessions\``
    );
  }

  if (action === 'approve') {
    const approval = await updateJSON('approvals.json', a => a.id === id, a => ({
      ...a, status: 'approved', decidedAt: new Date().toISOString(), decisionBy: 'telegram-user',
    }));
    if (!approval) return answerCallback('Approval not found');
    await appendJSON('audit.json', {
      id: newId('evt'), tenantId: approval.tenantId, type: 'remediation.approved',
      actor: 'telegram-user', findingId: approval.findingId, approvalId: approval.id,
      metadata: { actionType: approval.actionType }, ts: new Date().toISOString(),
    });
    await answerCallback('✅ Remediation approved');
    await editMessage('✅ Approved by telegram-user');
  }

  if (action === 'reject') {
    const approval = await updateJSON('approvals.json', a => a.id === id, a => ({
      ...a, status: 'rejected', decidedAt: new Date().toISOString(), decisionBy: 'telegram-user',
    }));
    if (!approval) return answerCallback('Approval not found');
    await appendJSON('audit.json', {
      id: newId('evt'), tenantId: approval.tenantId, type: 'remediation.rejected',
      actor: 'telegram-user', findingId: approval.findingId, approvalId: approval.id,
      metadata: { actionType: approval.actionType }, ts: new Date().toISOString(),
    });
    await answerCallback('❌ Remediation rejected');
    await editMessage('❌ Rejected by telegram-user');
  }
}

// ─── /setstack ───────────────────────────────────────────
export async function cmdSetStack({ reply, args }) {
  if (args.length < 2) {
    return reply('Usage: `/setstack <tenantId> <product1,product2,...>`\nExample: `/setstack tnt_abc nginx,wordpress,apache`\nUsed to check CISA KEV exposure against your tech stack.');
  }
  const tenantId = args[0];
  const stack = args[1].split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

  const { data: tenants } = await readJSON('tenants.json');
  const idx = tenants.findIndex((t) => t.id === tenantId);
  if (idx === -1) return reply('❌ Tenant not found. Use `/tenants`.');

  tenants[idx] = { ...tenants[idx], stack };
  await writeJSON('tenants.json', tenants);
  await appendJSON('audit.json', {
    id: newId('evt'), tenantId, type: 'tenant.stack.updated', actor: 'telegram',
    findingId: null, approvalId: null, metadata: { stack }, ts: new Date().toISOString(),
  });
  await reply(`🧩 Tech stack set for *${tenants[idx].name}*:\n\`${stack.join(', ')}\`\nRun /scan to check CISA KEV exposure.`);
}

// ─── /summary ─────────────────────────────────────────────
export async function cmdSummary({ reply, args }) {
  const tenantId = args[0];
  if (!tenantId) return reply('Usage: `/summary <tenantId>`');

  const { data: summaries } = await readJSON('summaries.json');
  const items = summaries.filter((s) => s.tenantId === tenantId).slice(-1);
  if (items.length === 0) return reply('No summary yet. Run `/scan` first.');
  await reply(`🤖 *Advisor summary:*\n\n${items[0].text}`);
}

// ─── /maillog ────────────────────────────────────────────
export async function cmdMailLog({ reply, args }) {
  const limit = Math.min(Number(args[0]) || 10, 30);
  const { data: logs } = await readJSON('mail_log.json');
  if (logs.length === 0) return reply('📭 No mail analyzed yet. Send a message to secops@insights.autos.');
  const items = logs.slice(-limit).reverse();
  const lines = items.map((m) => {
    const icon = m.disposition === 'quarantined' ? '🛑' : '📧';
    return `${icon} ${m.disposition} | score ${(Number(m.score) || 0).toFixed(2)}\n   From: ${m.from_addr}\n   Subj: ${m.subject || '(none)'}\n   ${m.reason || ''}`;
  });
  await reply(`*Email Security Log (${items.length}):*\n\n${lines.join('\n\n')}`);
}

// ─── /threat (Path 3) ─────────────────────────────────────
export async function cmdThreat({ reply, args }) {
  const tenantId = args[0];
  if (!tenantId) return reply('Usage: `/threat <tenantId>`');
  const { data: tenants } = await readJSON('tenants.json');
  const tenant = tenants.find((t) => t.id === tenantId);
  if (!tenant) return reply('❌ Tenant not found. Use `/tenants`.');
  const stack = tenant.stack || [];
  if (!stack.length) return reply('ℹ️ Set a tech stack first: `/setstack ' + tenantId + ' wordpress,nginx,apache`');

  const { correlateThreats } = await import('./threatintel.js');
  await reply(`🛰 Running threat-intel correlation for *${tenant.name}*...`);
  const ti = await correlateThreats(tenantId, tenant.name, stack);
  if (!ti.findings.length) {
    return reply(`✅ *No active exploited-vuln exposure* for ${tenant.name}.\nStack: \`${stack.join(', ')}\`\nIntel source: ${ti.meta.kev_source}`);
  }
  let msg = `🛰 *Threat-Intel Exposure — ${tenant.name}*\n\n`;
  for (const f of ti.findings.slice(0, 15)) {
    const m = f.metadata || {};
    msg += `${f.severity === 'critical' ? '🔴' : '🟠'} *${m.cve || f.title}* ${m.product ? '(' + m.product + ')' : ''}\n`;
    if (m.ransomware) msg += `   ⚠️ Linked to ransomware campaign\n`;
    if (m.epss != null) msg += `   EPSS: ${(m.epss * 100).toFixed(0)}% (p${((m.percentile || 0) * 100).toFixed(0)})\n`;
    if (m.technique) msg += `   ATT&CK: ${m.technique.id} ${m.technique.name}\n`;
    if (m.intel_source) msg += `   Source: ${m.intel_source}\n`;
    msg += `\n`;
  }
  await reply(msg);
}

// ─── /ask (Path 4 — Security Copilot) ─────────────────────
export async function cmdAsk({ reply, args, chatId, role }) {
  const question = args.join(' ').trim()
  if (!question) return reply('Usage: `/ask <your security question>`\nExample: `/ask Which of my findings are actively exploited?`')
  await reply('🤖 Thinking…')
  // The Copilot grounds on the requester's own tenant(s). Owners see all; for
  // now a user is scoped to their own tenant (or the first tenant if viewer).
  const tenantId = await resolveCopilotTenant(chatId, role)
  if (!tenantId) return reply('No tenant associated with your account. Ask the owner to grant you one.')
  const { getDB } = await import('./storage.js')
  const db = getDB()
  const tenant = await db.prepare('SELECT id, name FROM tenants WHERE id = ?').bind(tenantId).first()
  const { askCopilot } = await import('./copilot.js')
  const ans = await askCopilot(question, tenantId, tenant ? tenant.name : tenantId, undefined)
  await reply(`🤖 *Copilot*\n\n${ans.answer}`, { parse_mode: 'Markdown' })
}

async function resolveCopilotTenant(chatId, role) {
  const { getDB } = await import('./storage.js')
  const db = getDB()
  if (role === 'owner') {
    const t = await db.prepare('SELECT id FROM tenants LIMIT 1').first()
    return t ? t.id : 'tnt_real'
  }
  const u = await db.prepare('SELECT tenantId FROM users WHERE id = ?').bind(String(chatId)).first()
  if (u && u.tenantId) return u.tenantId
  // fall back to config owner chat
  const cfg = await db.prepare("SELECT value FROM config WHERE key = 'owner_chat_id'").first()
  return cfg ? 'tnt_real' : null
}

// ─── /grant (Path 4 — RBAC, owner only) ──────────────────
export async function cmdGrant({ reply, args }) {
  if (args.length < 2) return reply('Usage: `/grant <chatId> <role>`\nRoles: viewer, analyst, admin, owner')
  const chatId = args[0]
  const role = args[1].toLowerCase()
  const { ROLES, upsertUser, getDB } = await import('./storage.js')
  if (!ROLES.includes(role)) return reply('❌ Invalid role. Use: ' + ROLES.join(', '))
  // assign to the first tenant by default (owner can reassign)
  const db = getDB()
  const t = await db.prepare('SELECT id FROM tenants LIMIT 1').first()
  const tenantId = t ? t.id : null
  await upsertUser(chatId, tenantId, role, null)
  await reply(`✅ Granted *${role}* to chat \`${chatId}\``)
}

// ─── /users (Path 4 — RBAC, admin+) ──────────────────────
export async function cmdUsers({ reply }) {
  const { listUsers } = await import('./storage.js')
  const users = await listUsers()
  if (!users.length) return reply('No users registered yet.')
  const lines = users.map((u) => `• \`${u.id}\` — *${u.role}* ${u.tenantId ? '(tenant ' + u.tenantId + ')' : '(no tenant)'}`)
  await reply(`*Registered users:*\n${lines.join('\n')}`)
}

// ─── /revoke (Path 4 — RBAC, owner only) ─────────────────
export async function cmdRevoke({ reply, args }) {
  if (args.length < 1) return reply('Usage: `/revoke <chatId>`')
  const chatId = args[0]
  const { getDB } = await import('./storage.js')
  const db = getDB()
  await db.prepare('DELETE FROM users WHERE id = ?').bind(String(chatId)).run()
  await reply(`🗑 Revoked access for \`${chatId}\``)
}

// ─── Command router ───────────────────────────────────────
const commands = {
  start: cmdStart,
  newtenant: cmdNewTenant,
  tenants: cmdTenants,
  scan: cmdScan,
  findings: cmdFindings,
  alerts: cmdAlerts,
  remediate: cmdRemediate,
  approvals: cmdApprovals,
  audit: cmdAudit,
  schedule: cmdSchedule,
  setstack: cmdSetStack,
  summary: cmdSummary,
  maillog: cmdMailLog,
  threat: cmdThreat,
  ask: cmdAsk,
  grant: cmdGrant,
  users: cmdUsers,
  revoke: cmdRevoke,
};

export async function handleCommand({ command, args, reply, chatId, role, userId }) {
  const fn = commands[command]
  if (!fn) return reply('Unknown command. Use /start to see available commands.')
  await fn({ reply, args, chatId, role, userId })
}
