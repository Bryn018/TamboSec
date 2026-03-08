# Security Baseline (MVP)

- Multi-tenant data scoping required on every query
- RBAC for org users (owner, admin, analyst, viewer)
- Secrets only from Secret Manager
- TLS everywhere (public + internal)
- Immutable audit events for detections, approvals, remediations
- High-impact remediations require explicit human approval
- Principle of least privilege for all service accounts and OAuth scopes
- Dependency scanning + SAST in CI before production deploy
