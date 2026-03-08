# TamboSec API MVP (v0.2)

## Tenant header
Most tenant-scoped endpoints require:
- `x-tenant-id: <tenantId>`

## Endpoints

### Health
- `GET /health`

### Tenants
- `POST /v1/tenants` `{ "name": "Acme Agency" }`
- `GET /v1/tenants`

### Findings
- `POST /v1/findings`
- `GET /v1/findings`
- `POST /v1/findings/:id/close`

Finding creation payload example:
```json
{
  "tenantId": "tnt_xxx",
  "title": "Admin account without MFA",
  "severity": "high",
  "source": "google-workspace",
  "category": "identity_hygiene",
  "metadata": {
    "user": "admin@company.com"
  }
}
```

### Remediation Approvals
- `POST /v1/remediations/request`
- `GET /v1/remediations`
- `POST /v1/remediations/:id/approve`
- `POST /v1/remediations/:id/reject`

Allowed action types:
- `force_password_reset`
- `revoke_admin_role`
- `revoke_active_sessions`
