# TamboSec

AI-native security operations for SMBs — controlled from a web dashboard,
running entirely on Cloudflare. $0 infrastructure, no servers, no external
database, no Google.

TamboSec is a security command center for small businesses: posture scanning,
an AI email-security desk, threat-intel correlation, a grounded security
copilot, and a live dashboard — all served by a single Cloudflare Worker + D1
database, and used from **https://tambosec.insights.autos**.

> Note: the Telegram bot was removed. TamboSec is now a website product. Email
> alerts are still delivered via Cloudflare Email Routing (Path 2); the web
> dashboard shows verdicts.

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
Browser ──▶ tambosec.insights.autos (Cloudflare Pages, optional Access gate)
                │  (dashboard/index.html, token in localStorage)
                ▼  fetch /api/* (CORS, DASHBOARD_TOKEN)
         cloudflare/tambosec-bot (Worker)
                │
   ┌────────────┼────────────────────────────┐
   │            │                             │
 dashboard.js   scanner.js (posture)    Email Routing
 getDashboardData                  secops@insights.autos
   │            threatintel.js              │
   │            (KEV/EPSS/ATT&CK)     src/mail.js
   │            copilot.js (ask)      Workers AI classify
   │            storage.js (D1)        forward safe / quarantine phish
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
  (llama-3.3-70B); safe mail forwards to the verified destination, phishing is
  quarantined fail-closed. Events logged to D1 and shown in the dashboard.
- **Path 3 — Threat-Intel Wrapper**: reuses Threat-Scope feeds (CISA KEV,
  FIRST EPSS, MITRE ATT&CK) from a **live bound KV namespace** (zero egress,
  refreshed every 6h by Threat-Scope's own cron). A tenant stack returns
  plain-language findings like "Actively exploited vuln in your stack: CVE-…,
  EPSS 0.83, chainable to RCE" with severity + ATT&CK technique. D1 cache is
  the offline fallback.
- **Path 4 — Security Copilot + Dashboard**: `/api/ask` answers grounded
  ONLY in the tenant's own findings/mail (never invents facts); a live dashboard
  at tambosec.insights.autos (token-gated) shows posture, threat-intel, mail
  desk, and remediation queue. The site is the primary interface.

## Project layout

```
tambosec/
  cloudflare/tambosec-bot/     # ← the deployed system (this is the real one)
    src/
      index.js                 # Worker entry: website API endpoints + email + cron
      scanner.js               # Path 1 posture scan
      threatintel.js           # Path 3 KEV/EPSS/ATT&CK correlation
      mail.js                  # Path 2 email AI classifier (fail-closed)
      copilot.js               # Path 4 grounded Q&A
      dashboard.js             # Path 4 JSON feed
      storage.js               # D1 access + audit helpers
    dashboard/
      index.html               # Static web app deployed to Cloudflare Pages
    scripts/
      refresh-kev.mjs          # populate D1 KEV cache (offline fallback)
      refresh-threatintel.mjs  # populate D1 EPSS/ATT&CK cache (offline fallback)
    schema.sql                 # D1 schema
    wrangler.toml              # bindings: D1, AI, EMAIL, KV, cron, secrets
  bot/  apps/  data/  docs/    # earlier scaffolding (not the deployed path)
```

## Setup

1. **Dashboard token** — set via `wrangler secret put DASHBOARD_TOKEN`. This gates
   the website's API calls. Share it with users; they paste it once in the dashboard
   (saved to localStorage). Optionally wrap the site in Cloudflare Access (Zero
   Trust → Access → Applications → add a self-hosted app for
   `tambosec.insights.autos`) for SSO login in front of the token.

   Every request is also rate-limited (per-IP + global fixed window via KV:
   120 read / 20 write per IP per minute, 600 / 60 global) and stamped with
   security headers (HSTS, nosniff, X-Frame-Options: DENY, Referrer-Policy,
   CSP). All reads/actions are written to a D1 audit log (queryable at
   `/api/audit`).
2. **Cloudflare secrets** (set via `wrangler secret put`):
   - `DASHBOARD_TOKEN` — gates the `/api/*` endpoints and dashboard data
3. **Email Routing** — create a rule on your zone routing the security address
   (e.g. `secops@yourdomain`) to the worker. The action value MUST be the array
   `["tambosec-bot"]` (a string 422s).
4. **Threat-intel cache** — run the refresh scripts from a trusted machine to
   populate D1 (the worker can't fetch external hosts at runtime):
   - `node scripts/refresh-kev.mjs`
   - `node scripts/refresh-threatintel.mjs`
5. **Deploy** — `cd cloudflare/tambosec-bot && npx wrangler deploy`, then
   `npx wrangler pages deploy dashboard --project-name tambosec-dashboard`.

## Dashboard (primary interface)

Open **https://tambosec.insights.autos**, enter the tenant id (`tnt_real`) and
the DASHBOARD_TOKEN. The dashboard exposes every capability:

| Tab | What it does |
|-----|--------------|
| Overview | Posture cards, findings table, unread alerts |
| Threat Intel | CISA KEV / EPSS / ATT&CK exposure for your stack (Refresh) |
| Email Desk | Recent mail verdicts + a "classify a message" tester |
| Actions | Run a scan, set tech stack, set scan schedule, view remediation queue |
| Copilot | Ask plain-language questions grounded in your data |

## Verification status

All four paths verified live against the deployed worker:

- Posture scan: 200, findings + AI summary, persisted to D1.
- Email desk: legit → delivered/forwarded; phishing → quarantined (fail-closed).
  Verified across 6 live `/api/mailtest` round-trips.
- Threat-intel: **live bound KV** (intel_source=`live-kv`), KEV 1670 / EPSS 1670 /
  ATT&CK 222; correlation findings produced for `tnt_real` (0 duplicate IDs).
- Copilot: grounded answers (`grounded=true`).
- Dashboard: Worker `/api/dashboard` 403 without token, 200 with token; Pages site
  **https://tambosec.insights.autos** serves 200 with CORS-enabled API calls.
- Cron `7 * * * *` active; `tnt_real` scheduled (24h) and scanning.
- Email Routing: `secops@insights.autos` → `tambosec-bot` worker, rule enabled,
  zone status `ready`.
- Telegram bot removed (website is now the interface).

## Notes / gotchas

- **Dashboard** — the standalone Cloudflare Pages site
  **https://tambosec.insights.autos** (enter tenant id + DASHBOARD_TOKEN in the
  UI; both persist in localStorage). The Pages site calls the Worker API
  cross-origin (CORS enabled, still token-gated).
- **Fail-closed email** — anything the model does not explicitly classify as
  `legitimate` is quarantined, so a misclassification never delivers a phish.
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
