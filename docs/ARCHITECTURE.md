# TamboSec Architecture (MVP)

## Core Services
1. API Service
   - Tenant auth/session
   - Findings API
   - Policy and approval endpoints
2. Worker Service
   - Scheduled checks
   - Scanner orchestration
   - Connector sync jobs
3. Web App
   - Findings dashboard
   - Approvals queue
   - Weekly posture summaries
4. Data Layer
   - PostgreSQL (source of truth)
   - Redis (queue, lock, dedupe)

## Integrations (Phase 1)
- Google Workspace Admin SDK + Reports API
- Slack notifications + approve/reject actions

## Environments
- local (docker compose)
- staging (GCP)
- production (GCP)

## Security Controls
- strict tenant scoping on every query
- encrypted secrets in cloud secret manager
- immutable audit events
- least-privilege OAuth scopes
- approval gate for critical remediations
