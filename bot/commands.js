import { readJSON, writeJSON, appendJSON, updateJSON, queryJSON } from './storage.js';
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
export async function cmdStart(ctx) {
  await ctx.reply(
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
    `/schedule <tenantId> <hours> — Set scan schedule\n\n` +
    `_All data stored in this repo as JSON files._`,
    { parse_mode: 'Markdown' }
  );
}

// ─── /newtenant ───────────────────────────────────────────
export async function cmdNewTenant(ctx, args) {
  if (args.length < 2) {
    return ctx.reply('Usage: `/newtenant <name> <domain>`\nExample: `/newtenant AcmeCorp acme.com`', { parse_mode: 'Markdown' });
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
  await ctx.reply(`✅ Tenant created:\n*${name}* \`${id}\`\nDomain: \`${domain}\``, { parse_mode: 'Markdown' });
}

// ─── /tenants ─────────────────────────────────────────────
export async function cmdTenants(ctx) {
  const { data: tenants } = await readJSON('tenants.json');
  if (tenants.length === 0) return ctx.reply('No tenants yet. Use `/newtenant` to create one.', { parse_mode: 'Markdown' });
  const lines = tenants.map(t => `• *${t.name}* \`${t.id}\` (${t.domain || 'no domain'})`);
  await ctx.reply(`*Tenants:*\n${lines.join('\n')}`, { parse_mode: 'Markdown' });
}

// ─── /scan ────────────────────────────────────────────────
export async function cmdScan(ctx, args) {
  const tenantId = args[0];
  if (!tenantId) return ctx.reply('Usage: `/scan <tenantId>`', { parse_mode: 'Markdown' });

  const { data: tenants } = await readJSON('tenants.json');
  const tenant = tenants.find(t => t.id === tenantId);
  if (!tenant) return ctx.reply('❌ Tenant not found. Use `/tenants` to see available.', { parse_mode: 'Markdown' });

  await ctx.reply(`🔍 Running posture scan for *${tenant.name}*...`, { parse_mode: 'Markdown' });

  const { findings, alerts } = await runPostureScan(tenantId, tenant.domain || 'demo.local');

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

  await ctx.reply(msg, { parse_mode: 'Markdown' });

  // Send each alert as a separate message with inline buttons
  for (const alert of alerts) {
    const finding = findings.find(f => f.id === alert.findingId);
    await ctx.reply(
      `${sevEmoji(alert.severity)} *${alert.severity.toUpperCase()}*\n` +
      `${finding.title}\n` +
      `Source: \`${finding.source}\` | Category: \`${finding.category}\``,
      {
        parse_mode: 'Markdown',
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
export async function cmdFindings(ctx, args) {
  const tenantId = args[0];
  const severity = args[1];
  if (!tenantId) return ctx.reply('Usage: `/findings <tenantId> [critical|high|medium|low]`', { parse_mode: 'Markdown' });

  const { data: findings } = await readJSON('findings.json');
  let items = findings.filter(f => f.tenantId === tenantId);
  if (severity) items = items.filter(f => f.severity === severity);
  items.sort((a, b) => sevOrder(b.severity) - sevOrder(a.severity));

  if (items.length === 0) return ctx.reply('No findings for this tenant.', { parse_mode: 'Markdown' });

  const lines = items.slice(0, 20).map(f =>
    `${sevEmoji(f.severity)} *${f.title}* \`${f.status}\`\n   \`${f.id}\` | ${f.category}`
  );
  await ctx.reply(
    `*Findings (${items.length}):*\n\n${lines.join('\n\n')}`,
    { parse_mode: 'Markdown' }
  );
}

// ─── /alerts ──────────────────────────────────────────────
export async function cmdAlerts(ctx, args) {
  const tenantId = args[0];
  if (!tenantId) return ctx.reply('Usage: `/alerts <tenantId>`', { parse_mode: 'Markdown' });

  const { data: alerts } = await readJSON('alerts.json');
  const items = alerts.filter(a => a.tenantId === tenantId && a.status === 'unread');

  if (items.length === 0) return ctx.reply('✅ No unread alerts.', { parse_mode: 'Markdown' });

  for (const alert of items) {
    await ctx.reply(
      `${sevEmoji(alert.severity)} *${alert.message}*`,
      {
        parse_mode: 'Markdown',
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
export async function cmdRemediate(ctx, args) {
  if (args.length < 3) {
    return ctx.reply(
      'Usage: `/remediate <tenantId> <findingId> <action>`\n' +
      'Actions: `force_password_reset`, `revoke_admin_role`, `revoke_active_sessions`',
      { parse_mode: 'Markdown' }
    );
  }
  const [tenantId, findingId, actionType] = args;
  const allowed = ['force_password_reset', 'revoke_admin_role', 'revoke_active_sessions'];
  if (!allowed.includes(actionType)) {
    return ctx.reply(`❌ Invalid action. Allowed: ${allowed.join(', ')}`, { parse_mode: 'Markdown' });
  }

  const { data: findings } = await readJSON('findings.json');
  const finding = findings.find(f => f.id === findingId && f.tenantId === tenantId);
  if (!finding) return ctx.reply('❌ Finding not found for this tenant.', { parse_mode: 'Markdown' });

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

  await ctx.reply(
    `⏳ *Remediation Requested*\n` +
    `Action: \`${actionType}\`\n` +
    `Finding: ${finding.title}\n` +
    `Approval ID: \`${approval.id}\``,
    {
      parse_mode: 'Markdown',
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
export async function cmdApprovals(ctx, args) {
  const tenantId = args[0];
  if (!tenantId) return ctx.reply('Usage: `/approvals <tenantId>`', { parse_mode: 'Markdown' });

  const { data: approvals } = await readJSON('approvals.json');
  const items = approvals.filter(a => a.tenantId === tenantId);

  if (items.length === 0) return ctx.reply('No remediation requests for this tenant.', { parse_mode: 'Markdown' });

  const lines = items.map(a => {
    const status = a.status === 'pending' ? '⏳' : a.status === 'approved' ? '✅' : '❌';
    return `${status} \`${a.actionType}\` — ${a.status}\n   \`${a.id}\` | ${fmtTime(a.requestedAt)}`;
  });
  await ctx.reply(`*Remediation Queue:*\n\n${lines.join('\n\n')}`, { parse_mode: 'Markdown' });
}

// ─── /audit ───────────────────────────────────────────────
export async function cmdAudit(ctx, args) {
  const tenantId = args[0];
  if (!tenantId) return ctx.reply('Usage: `/audit <tenantId>`', { parse_mode: 'Markdown' });

  const { data: events } = await readJSON('audit.json');
  const items = events.filter(e => e.tenantId === tenantId).slice(-15).reverse();

  if (items.length === 0) return ctx.reply('No audit events for this tenant.', { parse_mode: 'Markdown' });

  const lines = items.map(e =>
    `\`${fmtTime(e.ts)}\` ${e.type}\n   ${e.actor || 'system'} ${e.findingId ? '| ' + e.findingId : ''}`
  );
  await ctx.reply(`*Recent Audit Events:*\n\n${lines.join('\n\n')}`, { parse_mode: 'Markdown' });
}

// ─── /schedule ────────────────────────────────────────────
export async function cmdSchedule(ctx, args) {
  if (args.length < 2) return ctx.reply('Usage: `/schedule <tenantId> <hours>`\nExample: `/schedule tnt_abc123 24`', { parse_mode: 'Markdown' });
  const tenantId = args[0];
  const everyHours = Number(args[1]);
  if (!Number.isFinite(everyHours) || everyHours < 1 || everyHours > 168) {
    return ctx.reply('❌ hours must be between 1 and 168.', { parse_mode: 'Markdown' });
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

  await ctx.reply(
    `📅 Scan schedule set for \`${tenantId}\`\nEvery *${everyHours}h*\nNext run: ${fmtTime(schedule.nextRunAt)}`,
    { parse_mode: 'Markdown' }
  );
}

// ─── Callback handler for inline buttons ──────────────────
export async function handleCallback(ctx) {
  const data = ctx.callbackQuery.data;
  const [action, id] = data.split(':');

  if (action === 'ack') {
    await updateJSON('alerts.json', a => a.id === id, a => ({
      ...a, status: 'acknowledged', acknowledgedAt: new Date().toISOString(), acknowledgedBy: 'telegram-user',
    }));
    await ctx.answerCbQuery('✅ Alert acknowledged');
    await ctx.editMessageText(
      `${ctx.callbackQuery.message.text}\n\n_✅ Acknowledged_`,
      { parse_mode: 'Markdown' }
    );
  }

  if (action === 'rem') {
    const { data: alerts } = await readJSON('alerts.json');
    const alert = alerts.find(a => a.id === id);
    if (!alert) return ctx.answerCbQuery('Alert not found');
    await ctx.answerCbQuery('Use /remediate to request a remediation action');
    await ctx.reply(
      `To request remediation for this finding, use:\n` +
      `\`/remediate ${alert.tenantId} ${alert.findingId} <action>\`\n\n` +
      `Actions: \`force_password_reset\`, \`revoke_admin_role\`, \`revoke_active_sessions\``,
      { parse_mode: 'Markdown' }
    );
  }

  if (action === 'approve') {
    const approval = await updateJSON('approvals.json', a => a.id === id, a => ({
      ...a, status: 'approved', decidedAt: new Date().toISOString(), decisionBy: 'telegram-user',
    }));
    if (!approval) return ctx.answerCbQuery('Approval not found');
    await appendJSON('audit.json', {
      id: newId('evt'), tenantId: approval.tenantId, type: 'remediation.approved',
      actor: 'telegram-user', findingId: approval.findingId, approvalId: approval.id,
      metadata: { actionType: approval.actionType }, ts: new Date().toISOString(),
    });
    await ctx.answerCbQuery('✅ Remediation approved');
    await ctx.editMessageText(
      `${ctx.callbackQuery.message.text}\n\n_✅ Approved by telegram-user_`,
      { parse_mode: 'Markdown' }
    );
  }

  if (action === 'reject') {
    const approval = await updateJSON('approvals.json', a => a.id === id, a => ({
      ...a, status: 'rejected', decidedAt: new Date().toISOString(), decisionBy: 'telegram-user',
    }));
    if (!approval) return ctx.answerCbQuery('Approval not found');
    await appendJSON('audit.json', {
      id: newId('evt'), tenantId: approval.tenantId, type: 'remediation.rejected',
      actor: 'telegram-user', findingId: approval.findingId, approvalId: approval.id,
      metadata: { actionType: approval.actionType }, ts: new Date().toISOString(),
    });
    await ctx.answerCbQuery('❌ Remediation rejected');
    await ctx.editMessageText(
      `${ctx.callbackQuery.message.text}\n\n_❌ Rejected by telegram-user_`,
      { parse_mode: 'Markdown' }
    );
  }
}
