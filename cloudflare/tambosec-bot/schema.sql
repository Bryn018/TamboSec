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
