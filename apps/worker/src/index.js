import { Pool } from 'pg';
import http from 'node:http';

const DATABASE_URL = process.env.DATABASE_URL;
const API_BASE = process.env.API_BASE || 'https://tambosec-api-324509025713.europe-west4.run.app';
const ANALYST_API_KEY = process.env.TAMBOSEC_ANALYST_KEY || '';
const SCHEDULER_ENABLED = process.env.SCHEDULER_ENABLED !== '0';
const TICK_MS = Number(process.env.SCHEDULER_TICK_MS || 60000);

if (!DATABASE_URL) {
  console.error('[worker] DATABASE_URL missing');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === '1' ? { rejectUnauthorized: false } : undefined,
});

async function runTick() {
  if (!SCHEDULER_ENABLED) return;
  if (!ANALYST_API_KEY) {
    console.warn('[worker] TAMBOSEC_ANALYST_KEY missing, scheduler tick skipped');
    return;
  }

  const lock = await pool.query('select pg_try_advisory_lock(90442002) as locked');
  if (!lock.rows[0]?.locked) return;

  try {
    const due = await pool.query(
      `select s.tenant_id as "tenantId", s.every_hours as "everyHours", t.domain
       from scan_schedules s
       join tenants t on t.id = s.tenant_id
       where s.enabled=true and s.next_run_at <= now()
       order by s.next_run_at asc
       limit 30`
    );

    for (const row of due.rows) {
      if (!row.domain) continue;

      const res = await fetch(`${API_BASE}/v1/connectors/google-workspace/posture-scan`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-tenant-id': row.tenantId,
          'x-api-key': ANALYST_API_KEY,
        },
        body: JSON.stringify({ tenantId: row.tenantId, domain: row.domain }),
      });

      if (!res.ok) {
        const body = await res.text();
        console.error('[worker] scan failed', row.tenantId, body);
        continue;
      }

      await pool.query(
        `update scan_schedules
         set next_run_at = now() + make_interval(hours => every_hours), updated_at = now()
         where tenant_id = $1`,
        [row.tenantId]
      );

      console.log('[worker] scan executed', { tenantId: row.tenantId, everyHours: row.everyHours });
    }
  } finally {
    await pool.query('select pg_advisory_unlock(90442002)');
  }
}

setInterval(() => {
  runTick().catch((e) => console.error('[worker] tick error', e.message));
}, TICK_MS);

runTick().catch((e) => console.error('[worker] initial tick error', e.message));

const port = Number(process.env.PORT || 8080);
http
  .createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'tambosec-worker', scheduler: SCHEDULER_ENABLED }));
  })
  .listen(port, () => {
    console.log('[worker] running', { API_BASE, SCHEDULER_ENABLED, TICK_MS, port });
  });
