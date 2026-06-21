# TamboSec

AI-native security operations for SMBs — via Telegram, stored on GitHub. $0 infrastructure.

## How It Works

```
You (Telegram) -> Bot polls GitHub Actions every 5 min
                        |
                        v
              bot/poll.js (command router)
                        |
                        v
              bot/commands-core.js (logic)
                        |
                        v
              bot/storage.js (GitHub API read/write)
                        |
                        v
              data/*.json (JSON files = database)
```

**No servers. No external database. No cost.** Everything runs on GitHub Actions (free) + Telegram (free).

## Setup

### 1. Create a Telegram Bot

- Open Telegram, message @BotFather
- Send `/newbot`, follow prompts
- Save the token

### 2. Get Your Chat ID

- Message your new bot with `/start`
- Visit: `https://api.telegram.org/bot<TOKEN>/getUpdates`
- Find `"chat":{"id": NUMBER}` — that is your chat ID

### 3. Create a GitHub Fine-Grained PAT

- GitHub -> Settings -> Developer settings -> Personal access tokens -> Fine-grained tokens
- Generate: Repository = `Bryn018/tambosec`, Permissions = Contents -> Read and write

### 4. Add GitHub Actions Secrets

Go to `https://github.com/Bryn018/tambosec/settings/secrets/actions` and add:

| Secret | Value |
|--------|-------|
| `BOT_TOKEN` | Telegram bot token |
| `GITHUB_PAT` | GitHub fine-grained PAT |
| `TELEGRAM_CHAT_ID` | Your chat ID |

That's it. The bot starts working immediately.

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Show all commands |
| `/newtenant <name> <domain>` | Add an organisation |
| `/tenants` | List all tenants |
| `/scan <tenantId>` | Run posture scan |
| `/findings <tenantId> [severity]` | List findings |
| `/alerts <tenantId>` | View unread high/critical alerts |
| `/remediate <tenantId> <findingId> <action>` | Request remediation |
| `/approvals <tenantId>` | View pending approvals |
| `/audit <tenantId>` | Recent audit events |
| `/schedule <tenantId> <hours>` | Set recurring scan interval |

## Inline Buttons

- Alert messages have **Acknowledge** and **Remediate** buttons
- Remediation requests have **Approve** and **Reject** buttons
- All actions are logged to the audit trail

## Posture Checks (Simulated)

Each scan checks for 6 issues:

1. Admin account without MFA (high)
2. Dormant privileged account (medium)
3. External collaborator with elevated access (high)
4. Weak password policy (medium)
5. OAuth app with excessive permissions (high)
6. Audit logging disabled on shared drives (low)

## Architecture

```
tambosec/
  bot/
    poll.js             # Polls Telegram via GitHub Actions (every 5 min)
    commands-core.js    # All command handlers (transport-agnostic)
    storage.js          # GitHub API read/write with SHA-based writes
    scanner.js          # Posture scan simulation
    scheduled-scan.js   # Hourly scan runner (GitHub Actions cron)
    package.json
  data/
    tenants.json        # Organisations
    findings.json       # Security findings
    approvals.json      # Remediation approvals
    alerts.json         # High/critical alerts
    audit.json          # Immutable audit log
    schedules.json      # Scan schedules
    _bot-state.json     # Bot polling state (last update_id)
  .github/workflows/
    poll-telegram.yml   # 5-minute polling trigger
    scheduled-scan.yml  # Hourly scheduled scans
```

## Tech Stack

- **Runtime**: Node.js 20 (GitHub Actions)
- **Telegram**: Raw Bot API via fetch
- **Storage**: GitHub API (JSON files in repo)
- **CI/CD**: GitHub Actions (free tier)
- **Cost**: $0
