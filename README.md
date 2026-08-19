# TamboSec

AI-native security operations on Cloudflare — $0 infra, zero servers. Web dashboard at [tambosec.insights.autos](https://tambosec.insights.autos).

## What it does

| Path | Capability |
|------|-----------|
| Posture scan | HTTPS headers, DNS/email auth (SPF/DKIM/DMARC via DoH), CISA KEV exposure |
| Email desk | Cloudflare Email Routing → AI classify (fail-closed; phish quarantined) |
| Threat intel | CISA KEV + FIRST EPSS + MITRE ATT&CK correlation against your stack |
| Copilot | Grounded Q&A — answers only from your tenant data, never invents facts |
| Dashboard | 7-tab SOC view: Overview, Threat Intel, Email Desk, Operations, API Tokens, Copilot, Audit |

All data lives in Cloudflare D1 + Workers AI. Rate-limited, audit-logged, token-gated.

## Quick start

1. Set the dashboard token: `cd cloudflare/tambosec-bot && wrangler secret put DASHBOARD_TOKEN`
2. Deploy Worker: `wrangler deploy`
3. Deploy dashboard: `wrangler pages deploy dashboard --project-name tambosec-dashboard`
4. Open [tambosec.insights.autos](https://tambosec.insights.autos), enter tenant `tnt_real` + token

## Token auth

- **Owner** — `DASHBOARD_TOKEN` secret. Full access: scan, configure, generate/revoke API tokens.
- **Per-tenant tokens** — minted by the owner via the dashboard (API Tokens tab). Scoped to one tenant, cannot create/revoke tokens.

Enter the token once in the dashboard connection bar; it persists in localStorage. All API calls pass it via `X-TamboSec-Token` header.

## Project layout

```
cloudflare/tambosec-bot/
  wrangler.toml          # D1 + AI + Email + KV + cron bindings
  schema.sql             # D1 schema
  dashboard/index.html   # Static SPA (Cloudflare Pages)
  src/
    index.js             # Worker: API endpoints + email routing + cron
    scanner.js           # Posture scan
    threatintel.js       # KEV/EPSS/ATT&CK correlation
    mail.js              # Email AI classifier
    copilot.js           # Grounded Q&A
    dashboard.js         # /api/dashboard JSON feed
    storage.js           # D1 access layer
  scripts/               # Offline KEV/EPSS refresh + smoke tester
```

## Testing

1. `curl https://tambosec.insights.autos/health` → `{"ok":true,"service":"tambosec-bot"}`
2. `curl https://tambosec.insights.autos/api/dashboard?tenantId=tnt_real` → 403 without token
3. Set `DASHBOARD_TOKEN`, open the dashboard, run a scan, check findings appear.
4. All four paths verified live: scan (200, findings persisted), email (phish quarantined), threat-intel (live KV), copilot (grounded=true).
