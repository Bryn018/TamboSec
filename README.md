# TamboSec

AI-native security operations for SMBs — controlled from Telegram, running
entirely on Cloudflare. $0 infrastructure, no servers, no external database,
no Google.

TamboSec turns a Telegram chat into a security command center for small
businesses: posture scanning, an AI email-security desk, threat-intel
correlation, a grounded security copilot, a live dashboard, and role-based
access control — all served by a single Cloudflare Worker + D1 database.

## Why Cloudflare-only

Everything runs on Cloudflare Workers, D1, Workers AI, Email Routing, Pages, and
Cron Triggers. Threat-intel correlation (Path 3) reads Threat-Scope's curated
feeds — CISA KEV, FIRST.org EPSS, MITRE ATT&CK — from a **bound KV namespace**
(shared with the Threat-Scope project). Reading a bound KV is in-cluster, so it
needs no Worker→Worker subrequest and stays fresh automatically (Threat-Scope's
own 6-hour cron refreshes it). The D1 cache remains as an offline fallback.
No Google, no third-party APIs.

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
  FIRST EPSS, MITRE ATT&CK) from a **live bound KV namespace** (zero egress,
  refreshed every 6h by Threat-Scope's own cron). A tenant stack returns
  plain-language findings like "Actively exploited vuln in your stack: CVE-…,
  EPSS 0.83, chainable to RCE" with severity + ATT&CK technique. D1 cache is
  the offline fallback.
- **Path 4 — Security Copilot + Dashboard + RBAC**: `/ask` answers grounded
  ONLY in the tenant's own findings/mail (never invents facts); a dark dashboard
  served both from the Worker at `/dashboard` and as a standalone Cloudflare
  Pages site at **https://tambosec.insights.autos** (token + tenant id in the
  UI, persisted to localStorage); role hierarchy owner>admin>analyst>viewer
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
    dashboard/
      index.html               # Static dashboard deployed to Cloudflare Pages
    scripts/
      refresh-kev.mjs          # populate D1 KEV cache (offline fallback)
      refresh-threatintel.mjs  # populate D1 EPSS/ATT&CK cache (offline fallback)
    schema.sql                 # D1 schema
    wrangler.toml              # bindings: D1, AI, EMAIL, KV, cron, secrets
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

- Posture scan: 200, findings + AI summary, persisted to D1.
- Email desk: legit → delivered/forwarded; phishing → quarantined (fail-closed).
  Verified across 6 live `/api/mailtest` round-trips.
- Threat-intel: **live bound KV** (intel_source=`live-kv`), KEV 1670 / EPSS 1670 /
  ATT&CK 222; correlation findings produced for `tnt_real` (0 duplicate IDs).
- Copilot: grounded answers (`grounded=true`).
- Dashboard: Worker `/dashboard` 403 without token, 200 with token; Pages site
  **https://tambosec.insights.autos** serves 200 with CORS-enabled API calls.
- RBAC: owner bootstrap, `/grant`, and command-level enforcement all proven.
- Cron `7 * * * *` active; `tnt_real` scheduled (24h) and scanning.
- Email Routing: `secops@insights.autos` → `tambosec-bot` worker, rule enabled,
  zone status `ready`.

## Notes / gotchas

- **Dashboard** — served two ways: the Worker at `/dashboard?token=…`, and the
  standalone Cloudflare Pages site **https://tambosec.insights.autos** (enter
  tenant id + DASHBOARD_TOKEN in the UI; both persist in localStorage). The Pages
  site calls the Worker API cross-origin (CORS enabled, still token-gated).
- **Fail-closed email** — anything the model does not explicitly classify as
  `legitimate` is quarantined, so a misclassification never delivers a phish.
- **First Telegram message = owner** — bootstrap is zero-config; afterwards
  use `/grant` to add your team.
- **Threat-intel is live via bound KV** — no out-of-band refresh needed; the D1
  cache (`scripts/refresh-threatintel.mjs`) is only a fallback if the KV binding
  is absent.

## Tech stack

- **Runtime**: Cloudflare Workers
- **Database**: Cloudflare D1 (SQLite)
- **AI**: Cloudflare Workers AI (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`,
  `llama-3.2-3b-instruct` for summaries)
- **Email**: Cloudflare Email Routing + `send_email` binding
- **Scheduling**: Cloudflare Cron Triggers
- **Cost**: $0 on Cloudflare free tier
