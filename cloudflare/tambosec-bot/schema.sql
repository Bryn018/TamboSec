CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT,
  domain TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  title TEXT,
  severity TEXT,
  source TEXT,
  category TEXT,
  status TEXT,
  metadata TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  finding_id TEXT,
  severity TEXT,
  status TEXT,
  message TEXT,
  created_at TEXT,
  acknowledged_at TEXT,
  acknowledged_by TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  finding_id TEXT,
  action_type TEXT,
  reason TEXT,
  status TEXT,
  requested_at TEXT,
  decided_at TEXT,
  decision_by TEXT
);

CREATE TABLE IF NOT EXISTS audit (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  type TEXT,
  actor TEXT,
  finding_id TEXT,
  approval_id TEXT,
  metadata TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS schedules (
  tenant_id TEXT PRIMARY KEY,
  every_hours INTEGER,
  enabled INTEGER,
  next_run_at TEXT,
  updated_at TEXT,
  updated_by TEXT
);
