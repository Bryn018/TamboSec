-- TamboSec PostgreSQL schema v1 (MVP)

create table if not exists tenants (
  id text primary key,
  name text not null,
  domain text,
  created_at timestamptz not null default now()
);

create table if not exists findings (
  id text primary key,
  tenant_id text not null references tenants(id) on delete cascade,
  title text not null,
  severity text not null check (severity in ('critical','high','medium','low')),
  source text not null,
  category text not null,
  status text not null default 'open' check (status in ('open','closed')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists remediation_approvals (
  id text primary key,
  tenant_id text not null references tenants(id) on delete cascade,
  finding_id text not null references findings(id) on delete cascade,
  action_type text not null check (action_type in ('force_password_reset','revoke_admin_role','revoke_active_sessions')),
  reason text,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz,
  decision_by text
);

create table if not exists audit_events (
  id text primary key,
  tenant_id text not null references tenants(id) on delete cascade,
  type text not null,
  actor text,
  finding_id text,
  approval_id text,
  metadata jsonb not null default '{}'::jsonb,
  ts timestamptz not null default now()
);

create index if not exists idx_findings_tenant_status on findings(tenant_id, status);
create index if not exists idx_findings_tenant_severity on findings(tenant_id, severity);
create index if not exists idx_audit_tenant_ts on audit_events(tenant_id, ts desc);
