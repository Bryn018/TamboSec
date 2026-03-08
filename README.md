# TamboSec

AI-native security operations platform for SMBs.

## Current Status (MVP in progress)
- ✅ Cloud deployment live on GCP (Cloud Run + Cloud SQL + Artifact Registry)
- ✅ API deployed with Postgres persistence
- ✅ Web dashboard deployed (findings, alerts, remediation queue, audit timeline)
- ✅ Role-based API key auth (owner/admin/analyst/viewer)
- ✅ Persistent scan schedules + recurring execution (dedicated worker service)
- ✅ In-app alert center with acknowledge flow
- 🟡 Google Workspace connector currently runs deterministic simulated checks (live tenant integration pending)

## Live Services
- API: `https://tambosec-api-324509025713.europe-west4.run.app`
- Web: `https://tambosec-web-324509025713.europe-west4.run.app`

## Implemented MVP Capabilities
- Tenant management
- Findings create/list/close
- Remediation request + approve/reject
- Audit event trail
- Alert generation for high/critical findings
- Schedule configuration for recurring scans

## API Security
All `/v1/*` endpoints require:
- `x-api-key`
- `x-tenant-id` for tenant-scoped routes

Role model:
- `viewer` → read-only
- `analyst` → findings, scans, remediation requests, alert ack
- `admin` → approvals + schedule updates + tenant creation
- `owner` → full access

## Monorepo Layout
- `apps/api` - Express API service
- `apps/worker` - recurring scheduler/execution worker
- `apps/web` - dashboard UI service
- `infra/gcp` - deployment and infra notes
- `docs` - architecture, API, security, roadmap

## Runbook Notes
- Production data store: Cloud SQL Postgres
- Runtime secrets: GCP Secret Manager
- Deploy path: GitHub Actions via Workload Identity Federation (keyless CI auth)

## Next Milestones
1. Worker scheduler hardening + retry/dead-letter strategy
2. Expanded test coverage and smoke checks
3. Observability and incident runbooks
4. Live Google Workspace ingestion (when tenant/domain is available)
