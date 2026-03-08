# TamboSec API MVP (v0.4)

## Storage mode
- If `DATABASE_URL` is set: Postgres persistence is used.
- If not set: in-memory fallback is used.

## Tenant header
Most tenant-scoped endpoints require:
- `x-tenant-id: <tenantId>`

## Endpoints

### Health
- `GET /health`

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

### Remediation approvals
- `POST /v1/remediations/request`
- `GET /v1/remediations`
- `POST /v1/remediations/:id/approve`
- `POST /v1/remediations/:id/reject`

Allowed action types:
- `force_password_reset`
- `revoke_admin_role`
- `revoke_active_sessions`

### Audit events
- `GET /v1/audit-events`
