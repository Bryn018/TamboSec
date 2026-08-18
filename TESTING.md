# TamboSec — How to Test & Verify (Step by Step)

This guide walks you through verifying that TamboSec works end-to-end. The
product is a **website** at https://tambosec.insights.autos — no Telegram bot
(removed). Just follow the steps.

> Everything below uses the live system as a normal user would. The only
> data-changing actions are scans/schedule/remediation you trigger yourself.

---

## 0. What you need
- A browser and the **DASHBOARD_TOKEN** (a Cloudflare secret, shared by the
  owner). You paste it once in the dashboard (saved to localStorage).
- (Optional) Cloudflare Access login in front of the site — if enabled, sign in
  first, then enter the tenant id + token.

---

## A. Website — the main interface

1. Open **https://tambosec.insights.autos/**. If Cloudflare Access is on, sign in.
2. Enter **tenant id** (`tnt_real`) and **DASHBOARD_TOKEN**. Both persist.
3. Expect the **Overview** tab:
   - Summary cards (Total / Open / Critical / High / Unread alerts / Phishing blocked).
   - A **Top findings** table (severity, finding, source, CVE/EPSS).
   - An **Unread alerts** list.
4. **Threat Intel** tab → click **Refresh threat-intel**.
   - Expect: actively-exploited vulnerabilities in your stack (CISA KEV / EPSS / ATT&CK).
   - If "set a tech stack first", go to Actions → set stack, then refresh.
5. **Email Desk** tab:
   - Recent mail verdicts (delivered vs quarantined).
   - Paste a message into the tester and click **Classify** — see the verdict.
6. **Actions** tab:
   - **Run scan** → posture scan runs, cards + findings refresh.
   - **Set stack** (e.g. `wordpress,nginx,apache`) and **Save schedule** (hours).
   - **Remediation queue** shows pending approvals.
7. **Copilot** tab → ask a question (e.g. "Summarize our top critical risks") →
   grounded answer.

> If you see "auth error — set token", re-enter the DASHBOARD_TOKEN.

---

## B. Email security (Path 2)

1. Send a test email to **secops@insights.autos** from any mailbox.
   - **Legit mail** → forwarded to the verified destination, logged `delivered`.
   - **Phishing-style** (e.g. "URGENT: verify your password here →
     http://lookalike-domain.com") → **quarantined** (fail-closed).
2. Open the **Email Desk** tab → the message appears with its verdict.

> You can't "fail" this — every message is classified and logged; worst case a
> phish is quarantined (safe) and legit is delivered.

---

## C. Scheduled scans (cron)

- The cron fires at **minute 7 of every hour** and scans any tenant with a
  schedule whose `nextRunAt` is due.
- Verify a schedule exists: Actions → set a schedule (e.g. 24), or the owner can
  POST `/api/schedule` with `everyHours`.
- After the next hourly tick, the Overview cards/findings reflect a fresh scan.

---

## D. Live health checks (optional)

From any shell with `curl` (no auth needed for these):

```
# Worker alive?
curl https://tambosec-bot.walybewillin.workers.dev/health
# -> {"ok":true,"service":"tambosec-bot"}

# Dashboard site alive?
curl -I https://tambosec.insights.autos/ | head -1
# -> HTTP/2 200
```

All `/api/*` endpoints require `?token=<DASHBOARD_TOKEN>` (or the
`X-TamboSec-Token` header). Without it they return 403.

Operator endpoints: `/api/scan`, `/api/threattest`, `/api/corrtest`,
`/api/classify`, `/api/mailtest` (all token-gated).

---

## Troubleshooting

| Symptom | Fix |
|--------|-----|
| Site shows "auth error" | Re-enter the DASHBOARD_TOKEN; saved in localStorage. |
| Threat Intel empty | Set a tech stack first (Actions → Set stack), then Refresh. |
| Scan returns no findings | Set a stack (so KEV exposure is computed) — posture checks still run. |
| Email not arriving | Confirm `secops@insights.autos` routes to the worker in Cloudflare Email Routing. |
| Copilot "no tenant" | Use a valid tenant id (`tnt_real`). |

---

## Architecture recap

- **Worker** (`tambosec-bot`) on Cloudflare: website API endpoints, Email
  Routing handler, Cron.
- **Pages** site `tambosec.insights.autos`: the web app (token in localStorage),
  calls the Worker API cross-origin (CORS, token-gated). Optionally behind
  Cloudflare Access.
- **D1** database: tenants, findings, alerts, mail_log, users, schedules.
- **Threat-Scope KV** (bound namespace): live CISA KEV / FIRST EPSS / MITRE
  ATT&CK, refreshed every 6h. Path 3 reads it in-cluster (zero egress).

All data stays on Cloudflare. No Google. No third-party trackers. The Telegram
bot was removed — the website is the interface.
