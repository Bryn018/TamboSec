const express = require('express');
const path = require('path');

const app = express();
const port = process.env.PORT || 8080;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/config.js', (_req, res) => {
  const apiBase = process.env.API_BASE_URL || 'https://tambosec-api-324509025713.europe-west4.run.app';
  res.type('application/javascript').send(`window.TAMBOSEC_CONFIG={API_BASE:${JSON.stringify(apiBase)}};`);
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'tambosec-web' });
});

app.listen(port, () => console.log(`TamboSec Web listening on ${port}`));
