const express = require('express');
const app = express();
const port = process.env.PORT || 8080;

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'tambosec-api', ts: new Date().toISOString() });
});

app.get('/', (_req, res) => {
  res.json({ name: 'TamboSec API', status: 'bootstrap-live' });
});

app.listen(port, () => {
  console.log(`TamboSec API listening on ${port}`);
});
