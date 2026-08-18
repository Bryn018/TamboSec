# TamboSec — How to Test & Verify (Step by Step)

This guide walks you through verifying that TamboSec works end-to-end after
any deploy. No internal knowledge required — just follow the steps.

> Everything below is read-only or uses the live system as a normal user would.
> Nothing here changes data except the scans/commands you trigger yourself.

---

## 0. What you need
- Telegram app + the TamboSec bot (message the bot once to become the owner).
- The **DASHBOARD_TOKEN** (a Cloudflare secret). The bot sends you a ready-to-open
  dashboard link via `/dashboard` if you're owner/admin. Otherwise ask the owner.
- A browser to open the dashboard.

---

## A. Telegram bot — the main interface

1. **Open the bot in Telegram** and send `/start`.
   - Expect: a friendly welcome + "your role: owner" + pointers to `/help`.
2. **Send `/help`.**
   - Expect: commands grouped into Monitor & scan / Email / Copilot / Configure /
     Admin, with your role shown. This is your map if you get stuck.
3. **Send `/tenants`.**
   - Expect: a list of monitored organisations (e.g. *InsightsWeb* `tnt_real`).
4. **Send `/tenant tnt_real`.**
   - Expect: domain, tech stack, scan schedule, and open critical/high counts.
5. **Send `/scan tnt_real`.**
   - Expect: a posture scan runs and reports findings by severity (🔴 critical,
     🟠 high, …), plus any new alerts with Acknowledge / Remediate buttons.
6. **Send `/findings tnt_real`.** (optionally `/findings tnt_real critical`)
   - Expect: a list of findings with ids.
7. **Send `/finding <one-finding-id>`** (copy an id from step 6).
   - Expect: full detail — CVE, product, EPSS, ATT&CK technique, description.
8. **Send `/threat tnt_real`.**
   - Expect: actively-exploited vulnerabilities in your stack (KEV/EPSS/ATT&CK).
9. **Send `/ask Which of my findings are actively exploited?`**
   - Expect: a plain-language answer grounded in YOUR data (the Security Copilot).
10. **Send `/me`.** Expect: your role + assigned tenant.
11. **Send `/dashboard`.** (owner/admin) Expect: a link that opens the live
    dashboard with the token pre-filled.

> If a command says "requires *analyst* role" or similar, your account needs a
> higher role — the owner runs `/grant <your-chat-id> <role>`.

---

## B. Web dashboard — live posture view

1. Open **https://tambosec.insights.autos/**.
2. Enter your **tenant id** (`tnt_real`) and **DASHBOARD_TOKEN** (or use the
   link from `/dashboard`). Both are saved in your browser.
3. Expect:
   - Summary cards (Total / Open / Critical / High / Unread alerts / Phishing blocked).
   - A **Top findings** table (severity, finding, source, CVE/EPSS).
   - A **Security Copilot** box — type a question and click *Ask Copilot*.
   - The page auto-refreshes every 60s.
4. If you see "auth error — set token", re-enter the DASHBOARD_TOKEN.

---

## C. Email security (Path 2)

1. Send a test email to **secops@insights.autos** from any mailbox.
   - **Legit mail** (normal text, no urgency/credential requests) → forwarded to
     the verified destination and logged as `delivered`.
   - **Phishing-style** (e.g. "URGENT: verify your password here →
     http://lookalike-domain.com") → **quarantined** (fail-closed) and the owner
     gets a Telegram alert.
2. In Telegram, send `/maillog 10` to see the analysed emails and their verdicts.

> You can't "fail" this test — every message is classified and logged; worst case
> a phish is quarantined (safe) and legit is delivered.

---

## D. Scheduled scans (cron)

- The cron fires at **minute 7 of every hour** and scans any tenant with a
  schedule whose `nextRunAt` is due.
- Verify a schedule exists: Telegram `/schedule tnt_real` → shows "Every 24h, next
  run: …".
- After the next hourly tick, `/findings tnt_real` reflects a fresh scan and
  `/maillog` (and the dashboard) show the new timestamp.
- To change it: `/schedule tnt_real 12` (every 12h).

---

## E. Live health checks (optional, for the curious)

From any shell with `curl` (no auth needed for these):

```
# Worker alive?
curl https://tambosec-bot.walybewillin.workers.dev/health
# -> {"ok":true,"service":"tambosec-bot"}

# Dashboard site alive?
curl -I https://tambosec.insights.autos/ | head -1
# -> HTTP/2 200
```

The admin/verification endpoints (`/api/scan`, `/api/threattest`, `/api/corrtest`,
`/api/classify`, `/api/mailtest`, `/setup`) are gated by the Telegram secret
header and are intended for operators, not end users.

---

## Troubleshooting

| Symptom | Fix |
|--------|-----|
| Bot says "You are not registered" | Owner runs `/grant <chatId> <role>` (get your chat id from `/me` or the error). |
| Dashboard "auth error" | Re-enter the DASHBOARD_TOKEN; it's saved in browser localStorage. |
| `/scan` returns no findings | Set a stack first: `/setstack tnt_real wordpress,nginx,apache`, then re-scan. |
| Email not arriving | Confirm `secops@insights.autos` routes to the worker in Cloudflare Email Routing. |
| Copilot "no tenant associated" | Owner grants you a tenant via `/grant`. |

---

## Architecture recap (so the test results make sense)

- **Worker** (`tambosec-bot`) on Cloudflare: Telegram webhook, Email Routing
  handler, Cron, and the dashboard/API.
- **D1** database: tenants, findings, alerts, mail_log, users, schedules.
- **Threat-Scope KV** (bound namespace): live CISA KEV / FIRST EPSS / MITRE
  ATT&CK, refreshed every 6h by Threat-Scope's own cron. Path 3 reads it
  in-cluster (zero egress).
- **Pages** dashboard on `tambosec.insights.autos` calls the Worker API
  cross-origin (CORS, token-gated).

All data stays on Cloudflare. No Google. No third-party trackers.
