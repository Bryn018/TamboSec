import { readJSON, writeJSON, appendJSON } from './storage.js';
import { runPostureScan } from './scanner.js';

const BOT_TOKEN = process.env.BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegram(text, options = {}) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  const body = { chat_id: CHAT_ID, text, parse_mode: 'Markdown', ...options };
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) console.error('telegram send failed', await res.text());
}

async function main() {
  console.log('[scheduled-scan] starting');

  const { data: schedules } = await readJSON('schedules.json');
  const { data: tenants } = await readJSON('tenants.json');

  const now = new Date();
  const due = schedules.filter(s => s.enabled && new Date(s.nextRunAt) <= now);

  if (due.length === 0) {
    console.log('[scheduled-scan] no scans due');
    return;
  }

  for (const sched of due) {
    const tenant = tenants.find(t => t.id === sched.tenantId);
    if (!tenant) {
      console.log(`[scheduled-scan] tenant not found: ${sched.tenantId}`);
      continue;
    }

    console.log(`[scheduled-scan] scanning tenant: ${tenant.name} (${tenant.id})`);
    const { findings, alerts } = await runPostureScan(tenant.id, tenant.domain || 'demo.local');

    // Update next run time
    const nextRunAt = new Date(Date.now() + sched.everyHours * 3600 * 1000).toISOString();
    const { data: schedules2, sha: schedulesSha } = await readJSON('schedules.json');
    const idx = schedules2.findIndex(s => s.tenantId === sched.tenantId);
    if (idx !== -1) {
      schedules2[idx].nextRunAt = nextRunAt;
      schedules2[idx].updatedAt = new Date().toISOString();
      await writeJSON('schedules.json', schedules2, schedulesSha);
    }

    // Send summary to Telegram
    let msg = `📊 *Scheduled Scan — ${tenant.name}*\n`;
    msg += `Findings: ${findings.length} | Alerts: ${alerts.length}\n`;
    const crit = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    if (crit) msg += `🔴 Critical: ${crit}\n`;
    if (high) msg += `🟠 High: ${high}\n`;
    msg += `Next scan: every ${sched.everyHours}h`;

    await sendTelegram(msg);

    // Send individual alerts with inline buttons
    for (const alert of alerts) {
      const finding = findings.find(f => f.id === alert.findingId);
      await sendTelegram(
        `${alert.severity === 'critical' ? '🔴' : '🟠'} *${alert.severity.toUpperCase()}*\n${finding.title}`,
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

    console.log(`[scheduled-scan] completed for ${tenant.name}: ${findings.length} findings`);
  }
}

main().catch(e => { console.error('[scheduled-scan] fatal:', e); process.exit(1); });
