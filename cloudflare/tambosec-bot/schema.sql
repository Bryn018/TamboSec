DROP TABLE IF EXISTS tenants;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS audit;
DROP TABLE IF EXISTS schedules;
DROP TABLE IF EXISTS summaries;

CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT,
  domain TEXT,
  stack TEXT,
  createdAt TEXT
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  tenantId TEXT,
  title TEXT,
  severity TEXT,
  source TEXT,
  category TEXT,
  status TEXT,
  metadata TEXT,
  createdAt TEXT,
  updatedAt TEXT
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  tenantId TEXT,
  findingId TEXT,
  severity TEXT,
  status TEXT,
  message TEXT,
  createdAt TEXT,
  acknowledgedAt TEXT,
  acknowledgedBy TEXT
);

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  tenantId TEXT,
  findingId TEXT,
  actionType TEXT,
  reason TEXT,
  status TEXT,
  requestedAt TEXT,
  decidedAt TEXT,
  decisionBy TEXT
);

CREATE TABLE audit (
  id TEXT PRIMARY KEY,
  tenantId TEXT,
  type TEXT,
  actor TEXT,
  findingId TEXT,
  approvalId TEXT,
  metadata TEXT,
  ts TEXT
);

CREATE TABLE schedules (
  tenantId TEXT PRIMARY KEY,
  everyHours INTEGER,
  enabled INTEGER,
  nextRunAt TEXT,
  updatedAt TEXT,
  updatedBy TEXT
);

CREATE TABLE summaries (
  id TEXT PRIMARY KEY,
  tenantId TEXT,
  text TEXT,
  ts TEXT
);

CREATE TABLE kev (
  cveID TEXT PRIMARY KEY,
  vendorProject TEXT,
  product TEXT,
  vulnerabilityName TEXT,
  shortDescription TEXT,
  knownRansomwareCampaignUse TEXT
);

CREATE TABLE mail_log (
  id TEXT PRIMARY KEY,
  from_addr TEXT,
  to_addr TEXT,
  subject TEXT,
  disposition TEXT,      -- 'delivered' | 'quarantined'
  score REAL,             -- 0..1 phishing confidence
  reason TEXT,
  summary TEXT,
  received_at TEXT,
  tenant_id TEXT
);

CREATE TABLE config (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE epss (
  cve TEXT PRIMARY KEY,
  epss REAL,
  percentile REAL
);

CREATE TABLE attack (
  id INTEGER PRIMARY KEY,
  tid TEXT,
  name TEXT,
  description TEXT
);

-- Path 4: RBAC. Each Telegram user maps to a tenant + role.
-- role ∈ owner | admin | analyst | viewer  (owner = global superuser)
CREATE TABLE users (
  id TEXT PRIMARY KEY,          -- Telegram chat id
  tenantId TEXT,
  role TEXT,
  name TEXT,
  createdAt TEXT
);

-- Per-tenant API tokens minted/revoked from the website. The shared
-- DASHBOARD_TOKEN secret is the OWNER and can create/revoke these. A token is
-- scoped to a single tenant (enforced at the API layer) and cannot manage tokens.
-- `token` holds the raw secret (shown once on creation); `prefix` is for display.
CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL,
  prefix TEXT,
  label TEXT,
  tenantId TEXT,
  role TEXT,                    -- admin | analyst | viewer
  active INTEGER DEFAULT 1,
  createdAt TEXT,
  lastUsedAt TEXT
);
