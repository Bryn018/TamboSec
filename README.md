# TamboSec

AI-native security operations platform for SMBs — controlled via Telegram, stored on GitHub.

## What It Does

TamboSec is a security posture monitoring tool you operate entirely through Telegram:

- Create tenants (organisations you monitor)
- Run posture scans that detect identity and access misconfigurations
- Get high/critical findings pushed to Telegram with inline Acknowledge / Remediate buttons
- Request remediation actions (force password reset, revoke admin role, revoke sessions)
- Approve or reject remediation requests right from the chat
- Set recurring scan schedules
- Full audit trail of every action

## Architecture

```
Telegram Bot (interface)
    |
    v
bot/index.js (Telegraf, polling mode)
    |
    v
bot/storage.js (GitHub API read/write)
    |
    v
data/*.json (JSON files in this repo = database)
```

**No external servers. No external database. No cost.**

- **Interface**: Telegram Bot (you already have Telegram)
- **Compute**: The bot runs wherever you run it (your machine, free-tier cloud)
- **Database**: JSON files in `data/` synced via GitHub API
- **Scheduled scans**: GitHub Actions cron (free) or node-cron inside the bot

## Data Storage

All data lives as JSON files in the `data/` directory:

| File | Contents |
|------|----------|
| `tenants.json` | Organisations being monitored |
| `findings.json` | Security findings (open/closed) |
| `approvals.json` | Remediation approval requests |
| `alerts.json` | High/critical alerts for dashboard |
| `audit.json` | Immutable audit event log |
| `schedules.json` | Per-tenant scan schedules |

## Setup

### 1. Create a Telegram Bot

- Open Telegram, message @BotFather
- Send `/newbot`, follow the prompts
- Save the token BotFather gives you

### 2. Get Your Chat ID

- Message your new bot with `/start`
- Visit: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
- Find `"chat":{"id": 123456789}` — that number is your chat ID

### 3. Create a GitHub Fine-Grained PAT

- Go to GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens
- Generate new token:
  - Repository: select `Bryn018/tambosec`
  - Permissions: Contents → Read and write
- Save the token (it only shows once)

### 4. Install and Run

```bash
cd bot
npm install
BOT_TOKEN=your_telegram_bot_token node index.js
```

### 5. (Optional) GitHub Actions Scheduled Scans

Add these as GitHub Actions secrets in the repo:

| Secret | Value |
|--------|-------|
| `BOT_TOKEN` | Your Telegram bot token |
| `GITHUB_PAT` | Your GitHub fine-grained PAT |
| `TELEGRAM_CHAT_ID` | Your chat ID |

The workflow runs every hour and auto-scans tenants with active schedules.

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Show all available commands |
| `/newtenant <name> <domain>` | Add an organisation |
| `/tenants` | List all tenants |
| `/scan <tenantId>` | Run posture scan |
| `/findings <tenantId> [severity]` | List findings |
| `/alerts <tenantId>` | View unread high/critical alerts |
| `/remediate <tenantId> <findingId> <action>` | Request remediation |
| `/approvals <tenantId>` | View pending approvals |
| `/audit <tenantId>` | Recent audit events |
| `/schedule <tenantId> <hours>` | Set recurring scan interval |

## Remediation Actions

- `force_password_reset` — Force password reset for a user
- `revoke_admin_role` — Remove admin privileges
- `revoke_active_sessions` — Sign out all active sessions

## Posture Checks (Simulated)

Each scan checks for:

1. Admin account without MFA (high)
2. Dormant privileged account (medium)
3. External collaborator with elevated access (high)
4. Weak password policy (medium)
5. OAuth app with excessive permissions (high)
6. Audit logging disabled on shared drives (low)

## Tech Stack

- **Runtime**: Node.js 20
- **Telegram**: Telegraf library
- **Storage**: GitHub API (JSON files in repo)
- **CI/CD**: GitHub Actions (free tier)
- **Cost**: $0

## Project Structure

```
tambosec/
  bot/
    index.js            # Bot entry point (Telegraf polling)
    commands.js         # All command handlers + inline callbacks
    storage.js          # GitHub API read/write for JSON files
    scanner.js          # Posture scan simulation
    scheduled-scan.js   # Standalone scan runner (GitHub Actions)
    package.json
  data/
    tenants.json
    findings.json
    approvals.json
    alerts.json
    audit.json
    schedules.json
  .github/workflows/
    scheduled-scan.yml
  docs/
  README.md
```
