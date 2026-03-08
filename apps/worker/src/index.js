import { Queue, Worker } from 'bullmq';
import IORedis from 'ioredis';

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
const apiBase = process.env.API_BASE || 'http://localhost:8080';
const connection = new IORedis(redisUrl, { maxRetriesPerRequest: null });

const queueName = 'tambosec-scan-jobs';
const queue = new Queue(queueName, { connection });

const worker = new Worker(
  queueName,
  async (job) => {
    const { tenantId, domain } = job.data;
    const res = await fetch(`${apiBase}/v1/connectors/google-workspace/posture-scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-tenant-id': tenantId },
      body: JSON.stringify({ tenantId, domain })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(`scan failed: ${JSON.stringify(data)}`);
    return data;
  },
  { connection, concurrency: 3 }
);

worker.on('completed', (job, result) => {
  console.log(`[worker] job ${job.id} completed`, { createdFindings: result?.createdFindings });
});

worker.on('failed', (job, err) => {
  console.error(`[worker] job ${job?.id} failed`, err.message);
});

async function seedExample() {
  if (process.env.SEED_EXAMPLE !== '1') return;
  await queue.add('gw-posture', { tenantId: process.env.SEED_TENANT_ID, domain: process.env.SEED_DOMAIN || 'example.com' });
  console.log('[worker] seeded example job');
}

await seedExample();
console.log('[worker] running', { redisUrl, apiBase, queueName });
