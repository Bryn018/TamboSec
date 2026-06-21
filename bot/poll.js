import { handleCommand, handleCallback } from './commands-core.js';

// Token loaded from environment
const BOT_TOKEN = process.env.BOT_TOKEN;
const GH_PAT = process.env.GITHUB_PAT;
const OWNER = 'Bryn018';
const REPO = 'tambosec';
const STATE_FILE = 'data/_bot-state.json';

async function tg(method, body = {}) {
  const url = 'https://api.telegram.org/bot' + BOT_TOKEN + '/' + method;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!json.ok) throw new Error('telegram ' + method + ' failed: ' + json.description);
  return json.result;
}

async function ghApi(method, path, body = null) {
  const https = require('https');
  const options = {
    hostname: 'api.github.com',
    path: path,
    method: method,
    headers: {
      'User-Agent': 'tambosec-bot',
      Authorization: 'Bearer ' + GH_PAT,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  };
  if (body) options.headers['Content-Type'] = 'application/json';

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(json);
          else reject(new Error(json.message || 'HTTP ' + res.statusCode));
        } catch {
          reject(new Error(data || 'HTTP ' + res.statusCode));
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function ghRead(fileName) {
  try {
    const res = await ghApi('GET', '/repos/' + OWNER + '/' + REPO + '/contents/' + fileName);
    return { data: JSON.parse(Buffer.from(res.content, 'base64').toString()), sha: res.sha };
  } catch (e) {
    if (e.message.includes('404')) return { data: {}, sha: null };
    throw e;
  }
}

async function ghWrite(fileName, data, sha = null) {
  const content = Buffer.from(JSON.stringify(data)).toString('base64');
  const body = { message: 'bot: update ' + fileName, content: content };
  if (sha) body.sha = sha;
  await ghApi('PUT', '/repos/' + OWNER + '/' + REPO + '/contents/' + fileName, body);
}

async function getState() {
  const { data } = await ghRead(STATE_FILE);
  return data;
}

async function setState(state) {
  const { sha } = await ghRead(STATE_FILE);
  await ghWrite(STATE_FILE, state, sha);
}

function makeReply(chatId) {
  return async (text, extra) => {
    extra = extra || {};
    return tg('sendMessage', Object.assign({ chat_id: chatId, text: text, parse_mode: 'Markdown' }, extra));
  };
}

async function poll() {
  const state = await getState();
  let lastUpdateId = state.lastUpdateId || 0;

  const updates = await tg('getUpdates', {
    offset: lastUpdateId + 1,
    timeout: 25,
    allowed_updates: ['message', 'callback_query'],
  });

  if (!updates || updates.length === 0) {
    console.log('[poll] no new messages');
    return;
  }

  console.log('[poll] ' + updates.length + ' update(s)');

  for (const update of updates) {
    const updateId = update.update_id;
    lastUpdateId = Math.max(lastUpdateId, updateId);

    try {
      if (update.callback_query) {
        const cq = update.callback_query;
        const chatId = cq.message.chat.id;
        const reply = makeReply(chatId);

        await handleCallback({
          reply: reply,
          editMessage: async (suffix) => {
            await tg('editMessageText', {
              chat_id: chatId,
              message_id: cq.message.message_id,
              text: cq.message.text + '\n\n_' + suffix + '_',
              parse_mode: 'Markdown',
            });
          },
          answerCallback: async (text) => {
            await tg('answerCallbackQuery', { callback_query_id: cq.id, text: text });
          },
          callbackData: cq.data,
          chatId: chatId,
        });
        continue;
      }

      if (update.message && update.message.text) {
        const msg = update.message;
        const chatId = msg.chat.id;
        const text = msg.text;
        const reply = makeReply(chatId);

        if (text.startsWith('/')) {
          const parts = text.slice(1).split(/\s+/);
          const command = parts[0].toLowerCase();
          const args = parts.slice(1);
          console.log('[poll] command: /' + command, args);
          await handleCommand({ command: command, args: args, reply: reply, chatId: chatId });
        } else {
          await reply('Send /start to see available commands.');
        }
      }
    } catch (err) {
      console.error('[poll] error processing update ' + updateId + ': ' + err.message);
    }
  }

  var newState = Object.assign({}, state, { lastUpdateId: lastUpdateId });
  await setState(newState);
  console.log('[poll] done, lastUpdateId=' + lastUpdateId);
}

var mode = process.argv[2] || 'single';

if (mode === 'single') {
  poll().catch(function(e) { console.error('[poll] fatal:', e.message); process.exit(1); });
} else {
  console.log('[poll] continuous mode');
  setInterval(function() {
    poll().catch(function(e) { console.error('[poll] error:', e.message); });
  }, 30000);
  poll().catch(function(e) { console.error('[poll] initial error:', e.message); });
}
