import { Telegraf } from 'telegraf';
import {
  cmdStart, cmdNewTenant, cmdTenants, cmdScan,
  cmdFindings, cmdAlerts, cmdRemediate, cmdApprovals,
  cmdAudit, cmdSchedule, handleCallback,
} from './commands.js';

const BOT_TOKEN = process.env.BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

if (!BOT_TOKEN) {
  console.error('BOT_TOKEN missing');
  process.exit(1);
}

const bot = new Telegraf(BOT_TOKEN);

// ─── Commands ─────────────────────────────────────────────
bot.command('start', (ctx) => cmdStart(ctx));
bot.command('newtenant', (ctx) => cmdNewTenant(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('tenants', (ctx) => cmdTenants(ctx));
bot.command('scan', (ctx) => cmdScan(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('findings', (ctx) => cmdFindings(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('alerts', (ctx) => cmdAlerts(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('remediate', (ctx) => cmdRemediate(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('approvals', (ctx) => cmdApprovals(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('audit', (ctx) => cmdAudit(ctx, ctx.message.text.split(/\s+/).slice(1)));
bot.command('schedule', (ctx) => cmdSchedule(ctx, ctx.message.text.split(/\s+/).slice(1)));

// ─── Inline button callbacks ──────────────────────────────
bot.on('callback_query', (ctx) => handleCallback(ctx));

// ─── Catch-all ────────────────────────────────────────────
bot.on('text', (ctx) => {
  ctx.reply('Unknown command. Use /start to see available commands.');
});

// ─── Launch ───────────────────────────────────────────────
bot.launch().then(() => {
  console.log('TamboSec bot is running');
});

// Graceful shutdown
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
