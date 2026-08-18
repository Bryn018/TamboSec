# TamboSec

AI-native security operations for SMBs — controlled from Telegram, running
entirely on Cloudflare. $0 infrastructure, no servers, no external database,
no Google.

TamboSec turns a Telegram chat into a security command center for small
businesses: posture scanning, an AI email-security desk, threat-intel
correlation, a grounded security copilot, a live dashboard, and role-based
access control — all served by a single Cloudflare Worker + D1 database.

## Why Cloudflare-only

Everything runs on Cloudflare Workers, D1, Workers AI, Email Routing, and
Cron Triggers. The worker cannot make subrequests to other hosts (Cloudflare
egress is disabled), so all external threat intel (CISA KEV, FIRST.org EPSS,
MITRE ATT&CK) is cached into D1 out-of-band by refresh scripts run from a
trusted machine. No Google, no third-party APIs.

## Architecture

```
Telegram  ──webhook──▶  cloudflare/tambosec-bot (Worker)
                            │
        ┌───────────────────┼───────────────────────────┐
        │                   │                            │
   /telegram handler   /dashboard (HTML)         Email Routing
        │                                          secops@insights.autos
   commands-core.js                                  │
        │                                       src/mail.js
   scanner.js (posture)                              │
   threatintel.js (KEV/EPSS/ATT&CK)            Workers AI classify
   copilot.js (ask)                                 │
   storage.js (D1)                          forward safe / quarantine phish
        │
   D1: findings, alerts, mail_log, users,
       kev, epss, attack, tenants, schedules
```

Cron Trigger `7 * * * *` runs posture scans for all scheduled tenants.

## Paths (all shipped + verified)

- **Path 1 — Real posture scanner**: live HTTP-header/HTTPS checks, DNS/email
  auth (SPF/DKIM/DMARC via DoH), and CISA KEV exposure vs the tenant stack.
- **Path 2 — AI Email Security Desk**: Cloudflare Email Routing
  (`secops@insights.autos` → worker) classifies inbound mail with Workers AI
  (llama-3.3-70B); safe mail forwards to the owner, phishing is quarantined
  fail-closed. Events logged to D1.
- **Path 3 — Threat-Intel Wrapper**: reuses Threat-Scope feeds (CISA KEV,
  FIRST EPSS, MITRE ATT&CK) cached in D1. A tenant stack returns plain-language
  findings like "Actively exploited vuln in your stack: CVE-…, EPSS 0.83,
  chainable to RCE" with severity + ATT&CK technique.
- **Path 4 — Security Copilot + Dashboard + RBAC**: `/ask` answers grounded
  ONLY in the tenant's own findings/mail (never invents facts); a self-contained
  dark dashboard at `/dashboard`; role hierarchy owner>admin>analyst>viewer
  with per-command minimum-role enforcement.

## Project layout

```
tambosec/
  cloudflare/tambosec-bot/     # ← the deployed system (this is the real one)
    src/
      index.js                 # Worker entry: /telegram, /dashboard, APIs
      commands-core.js         # Telegram command handlers (RBAC-gated)
      scanner.js               # Path 1 posture scan
      threatintel.js           # Path 3 KEV/EPSS/ATT&CK correlation
      mail.js                  # Path 2 email AI classifier (fail-closed)
      copilot.js               # Path 4 grounded Q&A
      dashboard.js             # Path 4 HTML + JSON feed
      storage.js               # D1 access + RBAC helpers
    scripts/
      refresh-kev.mjs          # populate D1 KEV cache (out-of-band)
      refresh-threatintel.mjs  # populate D1 EPSS/ATT&CK cache (out-of-band)
    schema.sql                 # D1 schema
    wrangler.toml              # bindings: D1, AI, EMAIL, cron, secrets
  bot/  apps/  data/  docs/    # earlier scaffolding (not the deployed path)
```

## Setup

1. **Telegram bot** — create via @BotFather, set the webhook to
   `https://<worker>/telegram` with the `X-Telegram-Bot-Api-Secret-Token`
   header. The first chat to message the bot becomes **owner** automatically.
2. **Cloudflare secrets** (set via `wrangler secret put`):
   - `BOT_TOKEN` — Telegram bot token
   - `TELEGRAM_SECRET` — shared secret for the webhook header
   - `DASHBOARD_TOKEN` — gates `/dashboard` and the `/api/*` endpoints
3. **Email Routing** — create a rule on your zone routing the security address
   (e.g. `secops@yourdomain`) to the worker. The action value MUST be the array
   `["tambosec-bot"]` (a string 422s).
4. **Threat-intel cache** — run the refresh scripts from a trusted machine to
   populate D1 (the worker can't fetch external hosts at runtime):
   - `node scripts/refresh-kev.mjs`
   - `node scripts/refresh-threatintel.mjs`
5. **Deploy** — `cd cloudflare/tambosec-bot && npx wrangler deploy`.

## Bot commands

| Command | Min role | Description |
|---------|----------|-------------|
| `/start` | viewer | Show all commands |
| `/newtenant <name> <domain>` | admin | Add an organisation |
| `/tenants` | viewer | List tenants |
| `/scan <tenantId>` | analyst | Run posture scan |
| `/findings <tenantId> [sev]` | viewer | List findings |
| `/alerts <tenantId>` | viewer | Unread high/critical alerts |
| `/threat <tenantId>` | viewer | Threat-intel exposure (KEV/EPSS/ATT&CK) |
| `/ask <question>` | viewer | Security Copilot (grounded in your data) |
| `/maillog [n]` | viewer | Recent email-security events |
| `/setstack <tenantId> <p1,p2>` | analyst | Set tech stack for threat-intel |
| `/schedule <tenantId> <hours>` | admin | Set recurring scan interval |
| `/grant <chatId> <role>` | owner | Add a user + role |
| `/users` | admin | List users |
| `/revoke <chatId>` | owner | Remove a user |

## Verification status

All four paths verified live against the deployed worker:

- Posture scan: 200, 486 findings + AI summary, persisted to D1.
- Email desk: legit → delivered/forwarded; phishing → quarantined (fail-closed).
- Threat-intel: D1 cache KEV 1666 / EPSS 1666 / ATT&CK 222; 358 correlation
  findings, 0 duplicate IDs.
- Copilot: grounded answers (`grounded=true`).
- Dashboard: 403 without token, 200 with token.
- RBAC: owner bootstrap, `/grant`, and command-level enforcement all proven
  (a viewer's `/scan` is blocked; `/ask` allowed).
- Cron `7 * * * *` active.

## Notes / gotchas

- **Refresh the intel cache regularly** — findings are only as fresh as the last
  `refresh-kev` / `refresh-threatintel` run. Automate it (cron on a trusted
  host) for production.
- **Fail-closed email** — anything the model does not explicitly classify as
  `legitimate` is quarantined, so a misclassification never delivers a phish.
- **First Telegram message = owner** — bootstrap is zero-config; afterwards
  use `/grant` to add your team.
- **No external egress from the worker** — all cross-service data lives in D1.

## Tech stack

- **Runtime**: Cloudflare Workers
- **Database**: Cloudflare D1 (SQLite)
- **AI**: Cloudflare Workers AI (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`,
  `llama-3.2-3b-instruct` for summaries)
- **Email**: Cloudflare Email Routing + `send_email` binding
- **Scheduling**: Cloudflare Cron Triggers
- **Cost**: $0 on Cloudflare free tier
