# TamboSec

AI-native security operations platform for SMBs.

## MVP Scope (v0)
- Google Workspace posture checks
- Public asset scanning pipeline
- Risk findings + severity normalization
- Slack alerting with approval-driven remediation
- Tenant-safe audit trail

## Monorepo Layout
- `apps/api` - backend API (NestJS planned)
- `apps/worker` - async jobs/scans (BullMQ planned)
- `apps/web` - admin + customer dashboard (Next.js planned)
- `infra/gcp` - deployment and infra manifests
- `docs` - architecture, security, runbooks

## Build Principles
1. Security-first defaults
2. Human approval for high-impact actions
3. Deterministic detections, AI for explanation only
4. Full auditability for every action
