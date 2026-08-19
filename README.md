# TamboSec

AI-native security operations on Cloudflare (https://tambosec.insights.autos)**.

## What it does
- **Posture scan** — HTTPS headers, DNS/email auth (SPF/DKIM/DMARC via DoH), CISA KEV exposure
- **Email desk** — Cloudflare Email Routing → AI classify (phish quarantined, fail-closed)
- **Threat intel** — CISA KEV + FIRST EPSS + MITRE ATT&CK correlation against your stack
- **Copilot** — grounded Q&A from your tenant data only
- **Dashboard** — SOC view: Overview, Threat Intel, Email Desk, Operations, API Tokens, Copilot, Audit

All data in Cloudflare D1 + Workers AI. Rate-limited, audit-logged, token-gated.

## Auth
- **Owner** — `DASHBOARD_TOKEN` secret: full access + can mint/revoke per-tenant tokens.
- **Per-tenant tokens** — created in the dashboard (API Tokens tab), scoped to one tenant.

## Run it
```
cd cloudflare/tambosec-bot
wrangler secret put DASHBOARD_TOKEN      # set owner token
wrangler deploy                          # deploy Worker
wrangler pages deploy dashboard --project-name tambosec-dashboard
```
Open the dashboard, log in with tenant `tnt_waly` + your token.

## Layout
```
cloudflare/tambosec-bot/
  wrangler.toml        # D1 + AI + Email + KV + cron bindings
  schema.sql           # D1 schema
  dashboard/index.html # Static SPA (Pages)
  src/                 # Worker: index.js, scanner.js, threatintel.js, mail.js, copilot.js, dashboard.js, storage.js
  scripts/             # KEV/EPSS refresh + smoke tester
```
