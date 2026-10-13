'use strict';
// Blackbull account server: phone verification by SMS, sign-up, login, sessions.
// Uses only Node.js built-in modules, so there is nothing to install.
const http = require('http');
const { createKv } = require('./kv.js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MIN = 60e3, HOUR = 36e5, DAY = 864e5;

function emptyDb() {
  return { users: {}, codes: {}, signups: {}, sessions: {}, limits: {} };
}

// Refuse to start on a damaged file, so existing accounts are never silently wiped.
function loadDb(file) {
  if (!fs.existsSync(file)) return emptyDb();
  try {
    return Object.assign(emptyDb(), JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch (e) {
    throw new Error('Database file is damaged: ' + file + '. Not starting, so no data is lost.');
  }
}

function saveDb(file, db) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, file); // atomic replace: a crash never leaves half a file
}

// Real SMS through Twilio when configured; otherwise the code is only printed locally.
async function defaultSms(toDigits, text, twilio) {
  if (!twilio) {
    console.log('[dev SMS] to +' + toDigits + ': ' + text);
    return;
  }
  const auth = Buffer.from(twilio.sid + ':' + twilio.token).toString('base64');
  const r = await fetch('https://api.twilio.com/2010-04-01/Accounts/' + twilio.sid + '/Messages.json', {
    method: 'POST',
    headers: { Authorization: 'Basic ' + auth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: '+' + toDigits, From: twilio.from, Body: text })
  });
  if (!r.ok) throw new Error('SMS provider answered ' + r.status);
}

function phoneDigits(v) { return String(v || '').replace(/\D/g, ''); }

// Same rules as the app, enforced again here because the app can be edited.
function phoneProblem(d) {
  if (d.startsWith('850')) return 'Numbers from this country are not supported.';
  if (d.length < 8 || d.length > 15) return 'Enter a valid phone number with its country code.';
  if (/(\d)\1{4,}/.test(d)) return "This doesn't look like a real phone number.";
  for (let i = 0; i + 5 < d.length; i++) {
    let up = true, down = true;
    for (let k = 1; k < 6; k++) {
      const x = +d[i + k] - +d[i + k - 1];
      if (x !== 1) up = false;
      if (x !== -1) down = false;
    }
    if (up || down) return "This doesn't look like a real phone number.";
  }
  return '';
}

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');
const hashCode = (salt, code) => sha(salt + ':' + code);
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, h: crypto.scryptSync(pw, salt, 32).toString('hex') };
}
function checkPw(pw, rec) {
  if (!rec || !rec.salt) return false;
  const got = crypto.scryptSync(String(pw), rec.salt, 32);
  const want = Buffer.from(rec.h, 'hex');
  return want.length === got.length && crypto.timingSafeEqual(got, want);
}
function sameText(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function createApp(opts) {
  opts = opts || {};
  const twilio = opts.twilio || null;
  const kvToken = opts.kvToken || process.env.BB_KV_TOKEN || '';
  const cfg = {
    file: opts.dataFile || path.join(opts.dataDir || path.join(__dirname, '..', 'data'), 'db.json'),
    ownerDigits: phoneDigits(opts.ownerPhone || process.env.OWNER_PHONE || '15488830049'),
    corsOrigin: opts.corsOrigin || process.env.CORS_ORIGIN || '*',
    devExposeCodes: !!opts.devExposeCodes,
    cooldownMs: opts.cooldownMs !== undefined ? opts.cooldownMs : 60 * 1000,
    smsPerPhone: opts.smsPerPhone || 5,
    ipLimit: opts.ipLimit || 20,
    sendSms: opts.sendSms || ((d, t) => defaultSms(d, t, twilio))
  };
  fs.mkdirSync(path.dirname(cfg.file), { recursive: true });
  const db = loadDb(cfg.file);
  const now = () => Date.now();
  const save = () => saveDb(cfg.file, db);

  function allow(key, max, windowMs) {
    const t = now();
    const arr = (db.limits[key] || []).filter((x) => t - x < windowMs);
    if (arr.length >= max) { db.limits[key] = arr; return false; }
    arr.push(t);
    db.limits[key] = arr;
    return true;
  }
  function prune() {
    const t = now();
    for (const k of Object.keys(db.codes)) if (db.codes[k].exp < t) delete db.codes[k];
    for (const k of Object.keys(db.signups)) if (db.signups[k].exp < t) delete db.signups[k];
    for (const k of Object.keys(db.sessions)) if (db.sessions[k].exp < t) delete db.sessions[k];
    for (const k of Object.keys(db.limits)) {
      const a = db.limits[k];
      if (!a.length || t - a[a.length - 1] > DAY) delete db.limits[k];
    }
  }
  const usernameTaken = (u) => Object.values(db.users).some((x) => x.username === u);
  const userByPhone = (d) => Object.values(db.users).find((x) => x.phone === d) || null;
  const userByName = (u) => Object.values(db.users).find((x) => x.username === u) || null;
  function createSession(uid) {
    const t = token();
    db.sessions[sha(t)] = { uid, exp: now() + 30 * DAY };
    return t;
  }
  function currentUser(req) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!m) return null;
    const s = db.sessions[sha(m[1])];
    if (!s || s.exp < now()) return null;
    return db.users[s.uid] || null;
  }
  const publicUser = (u, self) => Object.assign({
    id: u.id, username: u.username, name: u.name, owner: !!u.owner, created: u.created
  }, self ? { phone: u.phone } : {});
  const ok = (data, status) => ({ status: status || 200, data });
  const fail = (status, msg, extra) => ({ status, data: Object.assign({ error: msg }, extra || {}) });

  // POST /api/auth/request-code  {phone}
  async function requestCode({ body, ip }) {
    if (!allow('ip:' + ip, cfg.ipLimit, HOUR)) return fail(429, 'Too many requests. Try again later.');
    const d = phoneDigits(body.phone);
    const problem = phoneProblem(d);
    if (problem) return fail(400, problem);
    const prev = db.codes[d];
    if (prev && now() - prev.sentAt < cfg.cooldownMs) {
      const wait = Math.ceil((cfg.cooldownMs - (now() - prev.sentAt)) / 1000);
      return fail(429, 'Wait a minute before asking for a new code.', { retryIn: wait });
    }
    if (!allow('sms:' + d, cfg.smsPerPhone, HOUR)) return fail(429, 'Too many codes for this number. Try again later.');
    const code = String(crypto.randomInt(100000, 1000000));
    const salt = crypto.randomBytes(8).toString('hex');
    try {
      await cfg.sendSms(d, 'Your Blackbull code is ' + code + '. Never share it with anyone.');
    } catch (e) {
      console.error('SMS failed:', e.message);
      return fail(502, 'Could not send the SMS. Try again in a moment.');
    }
    db.codes[d] = { salt, hash: hashCode(salt, code), exp: now() + 5 * MIN, tries: 0, sentAt: now() };
    save();
    return ok(Object.assign({ ok: true, retryIn: Math.ceil(cfg.cooldownMs / 1000) },
      cfg.devExposeCodes ? { devCode: code } : {}));
  }

  // POST /api/auth/verify-code  {phone, code}  -> signupToken (only for numbers with no account yet)
  async function verifyCode({ body }) {
    const d = phoneDigits(body.phone);
    const c = db.codes[d];
    if (!c || c.exp < now()) return fail(400, 'That code has expired. Ask for a new one.');
    if (c.tries >= 5) { delete db.codes[d]; save(); return fail(429, 'Too many wrong codes. Ask for a new one.'); }
    if (!sameText(hashCode(c.salt, String(body.code || '').trim()), c.hash)) {
      c.tries++; save();
      return fail(400, 'Wrong code.', { left: 5 - c.tries });
    }
    delete db.codes[d];
    if (userByPhone(d)) { save(); return fail(409, 'This number already has an account. Log in instead.'); }
    const st = token();
    db.signups[sha(st)] = { phone: d, exp: now() + 10 * MIN };
    save();
    return ok({ signupToken: st });
  }

  // POST /api/auth/signup  {signupToken, username, name, password}
  async function signup({ body }) {
    const key = sha(String(body.signupToken || ''));
    const s = db.signups[key];
    if (!s || s.exp < now()) return fail(400, 'Verification expired. Start again.');
    const uname = String(body.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(uname)) return fail(400, 'Use 3 to 24 letters, numbers or underscores.');
    if (usernameTaken(uname)) return fail(409, 'This username already exists!');
    const name = String(body.name || '').trim().slice(0, 24);
    if (name.length < 2) return fail(400, 'Enter your name.');
    const pass = String(body.password || '');
    if (pass.length < 6) return fail(400, 'Password needs at least 6 characters.');
    if (userByPhone(s.phone)) return fail(409, 'This number already has an account. Log in instead.');
    const id = 'u' + crypto.randomBytes(6).toString('hex');
    db.users[id] = {
      id, username: uname, name, phone: s.phone, owner: s.phone === cfg.ownerDigits,
      pass: hashPw(pass), created: now(), fails: { n: 0, until: 0 }
    };
    delete db.signups[key];
    const t = createSession(id);
    save();
    return ok({ token: t, user: publicUser(db.users[id], true) }, 201);
  }

  // POST /api/auth/login  {username, password}
  async function login({ body }) {
    const uname = String(body.username || '').trim().toLowerCase();
    const u = userByName(uname);
    const generic = 'Incorrect username or password.';
    if (!u) return fail(401, generic);
    if (u.fails.until > now()) {
      return fail(429, 'Too many wrong passwords. Try again in ' + Math.ceil((u.fails.until - now()) / MIN) + ' min.');
    }
    if (!checkPw(body.password, u.pass)) {
      u.fails.n++;
      if (u.fails.n >= 5) u.fails = { n: 0, until: now() + 5 * MIN };
      save();
      return fail(401, generic);
    }
    u.fails = { n: 0, until: 0 };
    const t = createSession(u.id);
    save();
    return ok({ token: t, user: publicUser(u, true) });
  }

  async function logout({ req }) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (m) { delete db.sessions[sha(m[1])]; save(); }
    return ok({ ok: true });
  }

  async function me({ req }) {
    const u = currentUser(req);
    if (!u) return fail(401, 'Please log in.');
    return ok({ user: publicUser(u, true) });
  }

  const routes = {
    'POST /api/auth/request-code': requestCode,
    'POST /api/auth/verify-code': verifyCode,
    'POST /api/auth/signup': signup,
    'POST /api/auth/login': login,
    'POST /api/auth/logout': logout,
    'GET /api/me': me
  };

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0; const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > 16 * 1024) { reject(new Error('too big')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (!raw) return resolve({});
        try { resolve(JSON.parse(raw)); } catch (e) { reject(e); }
      });
      req.on('error', reject);
    });
  }

  function send(res, status, data) {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(JSON.stringify(data));
  }

  const aiKey = opts.anthropicKey || process.env.ANTHROPIC_API_KEY || '';
  async function aiHandle(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-BB-Token');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    const a = Buffer.from(String(req.headers['x-bb-token'] || ''));
    const b = Buffer.from(String(kvToken || ''));
    if (!b.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return send(res, 401, { error: 'unauthorized' });
    if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
    if (!aiKey) return send(res, 503, { error: 'AI is not set up on this server' });
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: 'bad request' }); }
    const message = String((body && body.message) || '').slice(0, 2000);
    if (!message) return send(res, 400, { error: 'empty message' });
    try {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': aiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({
          model: 'claude-haiku-5-5',
          max_tokens: 400,
          system: 'You are Jarvis, the friendly AI assistant inside the Blackbull messenger app. Answer briefly and helpfully. Blackbull features: chats, gifts and collectibles, Blackbull Premium, followers, usernames, calls, voice messages, blocking, wallpapers, and admin tools for the owner.',
          messages: [{ role: 'user', content: message }]
        })
      });
      if (!r.ok) return send(res, 502, { error: 'AI request failed' });
      const j = await r.json();
      const text = (j.content || []).map((c) => c.text || '').join('').trim();
      return send(res, 200, { reply: text || 'I have no answer for that yet.' });
    } catch (e) {
      return send(res, 502, { error: 'AI is unreachable' });
    }
  }
  const kvHandle = createKv(path.dirname(cfg.file), kvToken);
  const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', cfg.corsOrigin);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    const url = new URL(req.url, 'http://local');
    if (url.pathname === '/kv' || url.pathname.startsWith('/kv/')) return kvHandle(req, res, url);
    if (url.pathname === '/ai') return aiHandle(req, res);
    const route = routes[req.method + ' ' + url.pathname];
    if (!route) return send(res, 404, { error: 'Not found' });
    let body = {};
    if (req.method === 'POST') {
      try { body = await readBody(req); } catch (e) { return send(res, 400, { error: 'Bad request' }); }
    }
    try {
      prune();
      const r = await route({ body, req, ip: req.socket.remoteAddress || '?' });
      send(res, r.status, r.data);
    } catch (e) {
      console.error(e);
      send(res, 500, { error: 'Server error' });
    }
  });

  return { server, db, cfg, prune };
}

module.exports = { createApp, phoneProblem };

if (require.main === module) {
  const port = +process.env.PORT || 8080;
  const twilio = process.env.TWILIO_ACCOUNT_SID ? {
    sid: process.env.TWILIO_ACCOUNT_SID,
    token: process.env.TWILIO_AUTH_TOKEN,
    from: process.env.TWILIO_FROM
  } : null;
  if (!twilio && process.env.NODE_ENV === 'production') {
    console.error('No SMS provider configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM.');
    process.exit(1);
  }
  const app = createApp({
    dataDir: process.env.DATA_DIR,
    corsOrigin: process.env.CORS_ORIGIN,
    devExposeCodes: process.env.DEV_EXPOSE_CODES === '1',
    twilio
  });
  app.server.listen(port, () => console.log('Blackbull account server on port ' + port));
}
