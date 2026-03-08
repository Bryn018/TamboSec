# TamboSec API MVP (v0.6)

## Storage mode
- If `DATABASE_URL` is set: Postgres persistence is used.
- If not set: in-memory fallback is used.

## Authentication + RBAC
All `/v1/*` endpoints require:
- `x-api-key: <api-key>`

Configure keys with:
- `TAMBOSEC_API_KEYS=owner:key1,admin:key2,analyst:key3,viewer:key4`

Role rules (minimum):
- Viewer: read data
- Analyst: findings create/close, scan trigger, alerts ack, remediation request
- Admin: approve/reject remediations, update schedules, create tenants
- Owner: highest (inherits all admin+)

## Tenant header
Most tenant-scoped endpoints require:
- `x-tenant-id: <tenantId>`

## Endpoints

### Health
- `GET /health`

### Auth
- `GET /v1/auth/me`

### Tenants
- `POST /v1/tenants` `{ "name": "Acme Agency", "domain": "acme.com" }`
- `GET /v1/tenants`

### Findings
- `POST /v1/findings`
- `GET /v1/findings`
- `POST /v1/findings/:id/close`

### Google Workspace posture collector (MVP simulation)
- `POST /v1/connectors/google-workspace/posture-scan`

Creates deterministic findings for:
- admin account without MFA
- dormant privileged account
- elevated external collaborator

### Alerts (dashboard-first)
- `GET /v1/alerts`
- `POST /v1/alerts/:id/ack`

### Remediation approvals
- `POST /v1/remediations/request`
- `GET /v1/remediations`
- `POST /v1/remediations/:id/approve`
- `POST /v1/remediations/:id/reject`

Allowed action types:
- `force_password_reset`
- `revoke_admin_role`
- `revoke_active_sessions`

### Scheduler
- `GET /v1/scans/schedule`
- `POST /v1/scans/schedule`

### Audit events
- `GET /v1/audit-events`
