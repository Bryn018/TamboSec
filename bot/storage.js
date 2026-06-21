import https from 'node:https';

const OWNER = 'Bryn018';
const REPO = 'tambosec';
const DATA_DIR = 'data';
const TOKEN = process.env.GITHUB_PAT;

function apiCall(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        'User-Agent': 'tambosec-bot',
        Authorization: `Bearer ${TOKEN}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    };
    if (body) {
      options.headers['Content-Type'] = 'application/json';
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(json);
          } else {
            reject(new Error(json.message || `HTTP ${res.statusCode}`));
          }
        } catch {
          reject(new Error(data || `HTTP ${res.statusCode}`));
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

export async function readJSON(fileName) {
  try {
    const res = await apiCall('GET', `/repos/${OWNER}/${REPO}/contents/${DATA_DIR}/${fileName}`);
    const content = Buffer.from(res.content, 'base64').toString('utf8');
    return { data: JSON.parse(content), sha: res.sha };
  } catch (e) {
    if (e.message.includes('404')) return { data: [], sha: null };
    throw e;
  }
}

export async function writeJSON(fileName, data, sha = null) {
  const content = Buffer.from(JSON.stringify(data, null, 2)).toString('base64');
  const body = {
    message: `auto: update ${fileName}`,
    content,
  };
  if (sha) body.sha = sha;

  await apiCall('PUT', `/repos/${OWNER}/${REPO}/contents/${DATA_DIR}/${fileName}`, body);
}

export async function appendJSON(fileName, item) {
  const { data, sha } = await readJSON(fileName);
  data.push(item);
  await writeJSON(fileName, data, sha);
  return data;
}

export async function updateJSON(fileName, predicate, updater) {
  const { data, sha } = await readJSON(fileName);
  const idx = data.findIndex(predicate);
  if (idx === -1) return null;
  data[idx] = updater(data[idx]);
  await writeJSON(fileName, data, sha);
  return data[idx];
}

export async function queryJSON(fileName, predicate) {
  const { data } = await readJSON(fileName);
  return data.filter(predicate);
}
