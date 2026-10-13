'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createApp } = require('../src/server.js');

function tempDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'bb-')); }

async function start(opts) {
  const sent = [];
  const dir = (opts && opts.dir) || tempDir();
  const app = createApp(Object.assign({
    dataDir: dir, cooldownMs: 0, ipLimit: 1000, smsPerPhone: 50,
    sendSms: async (to, text) => { sent.push({ to, text }); },
    ownerPhone: '15488830049'
  }, opts || {}));
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + app.server.address().port;
  const call = async (method, p, body, token) => {
    const r = await fetch(base + p, {
      method,
      headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}),
      body: body ? JSON.stringify(body) : undefined
    });
    return { status: r.status, data: await r.json() };
  };
  const code = () => sent[sent.length - 1].text.match(/\d{6}/)[0];
  return { app, sent, call, dir, close: () => new Promise((r) => app.server.close(r)) };
}

test('fake phone numbers never get an SMS', async () => {
  const s = await start();
  try {
    const r = await s.call('POST', '/api/auth/request-code', { phone: '+1 5555555555' });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(s.sent.length, 0);
    const r2 = await s.call('POST', '/api/auth/request-code', { phone: '+1 1234567890' });
    assert.strictEqual(r2.status, 400);
  } finally { await s.close(); }
});

test('full sign-up: code, username, password, then a session', async () => {
  const s = await start();
  const code = () => s.sent[s.sent.length - 1].text.match(/\d{6}/)[0];
  try {
    assert.strictEqual((await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0101' })).status, 200);
    assert.strictEqual(s.sent.length, 1);
    assert.strictEqual((await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0101', code: '000000' })).status, 400);
    const v = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0101', code: code() });
    assert.strictEqual(v.status, 200);
    const su = await s.call('POST', '/api/auth/signup', { signupToken: v.data.signupToken, username: 'Alice_1', name: 'Alice', password: 'secret1' });
    assert.strictEqual(su.status, 201);
    assert.strictEqual(su.data.user.username, 'alice_1');
    assert.strictEqual(su.data.user.phone, '16045550101');
    assert.strictEqual(su.data.user.owner, false);
    const me = await s.call('GET', '/api/me', null, su.data.token);
    assert.strictEqual(me.status, 200);
    assert.strictEqual((await s.call('GET', '/api/me')).status, 401);
    // the same signup token can not be used twice
    const again = await s.call('POST', '/api/auth/signup', { signupToken: v.data.signupToken, username: 'alice_2', name: 'Alice', password: 'secret1' });
    assert.strictEqual(again.status, 400);
  } finally { await s.close(); }
});

test('one phone number, one account; usernames are unique', async () => {
  const s = await start();
  try {
    const verify = async (phone) => {
      await s.call('POST', '/api/auth/request-code', { phone });
      return (await s.call('POST', '/api/auth/verify-code', { phone, code: code() })).data;
    };
    const code = () => s.sent[s.sent.length - 1].text.match(/\d{6}/)[0];
    let v = await verify('+1 604 555 0201');
    await s.call('POST', '/api/auth/signup', { signupToken: v.signupToken, username: 'bob_one', name: 'Bob', password: 'secret1' });
    // same number again: refused at verification
    await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0201' });
    const again = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0201', code: code() });
    assert.strictEqual(again.status, 409);
    // another number, same username
    v = await verify('+1 604 555 0202');
    const dup = await s.call('POST', '/api/auth/signup', { signupToken: v.signupToken, username: 'BOB_ONE', name: 'Carl', password: 'secret1' });
    assert.strictEqual(dup.status, 409);
    assert.match(dup.data.error, /already exists/);
  } finally { await s.close(); }
});

test('wrong codes: five tries, then the code is burned', async () => {
  const s = await start();
  try {
    await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0301' });
    const real = s.sent[0].text.match(/\d{6}/)[0];
    const wrong = real === '999999' ? '888888' : '999999';
    for (let i = 0; i < 5; i++) {
      const r = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0301', code: wrong });
      assert.strictEqual(r.status, 400, 'wrong attempt ' + (i + 1) + ' is refused');
    }
    const sixth = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0301', code: wrong });
    assert.strictEqual(sixth.status, 429, 'the sixth attempt is locked out');
    const after = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0301', code: real });
    assert.strictEqual(after.status, 400, 'the old code no longer works');
  } finally { await s.close(); }
});

test('codes expire, and asking again needs a cooldown', async () => {
  const s = await start({ cooldownMs: 60000 });
  try {
    assert.strictEqual((await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0401' })).status, 200);
    const again = await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0401' });
    assert.strictEqual(again.status, 429);
    assert.ok(again.data.retryIn > 0);
    s.app.db.codes['16045550401'].exp = Date.now() - 1;
    const r = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0401', code: '123456' });
    assert.match(r.data.error, /expired/);
  } finally { await s.close(); }
});

test('login: right password, then lockout after five wrong ones', async () => {
  const s = await start();
  try {
    await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0501' });
    const v = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0501', code: s.sent[0].text.match(/\d{6}/)[0] });
    await s.call('POST', '/api/auth/signup', { signupToken: v.data.signupToken, username: 'carol', name: 'Carol', password: 'secret1' });
    assert.strictEqual((await s.call('POST', '/api/auth/login', { username: 'carol', password: 'secret1' })).status, 200);
    for (let i = 0; i < 5; i++) {
      assert.strictEqual((await s.call('POST', '/api/auth/login', { username: 'carol', password: 'nope' })).status, 401);
    }
    const locked = await s.call('POST', '/api/auth/login', { username: 'carol', password: 'secret1' });
    assert.strictEqual(locked.status, 429, 'even the right password is refused during the lock');
    // unknown names get the same message as wrong passwords (no account hints)
    const unknown = await s.call('POST', '/api/auth/login', { username: 'nobody', password: 'x' });
    assert.strictEqual(unknown.status, 401);
  } finally { await s.close(); }
});

test('logout ends the session', async () => {
  const s = await start();
  try {
    await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0601' });
    const v = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0601', code: s.sent[0].text.match(/\d{6}/)[0] });
    const su = await s.call('POST', '/api/auth/signup', { signupToken: v.data.signupToken, username: 'dan_x', name: 'Dan', password: 'secret1' });
    await s.call('POST', '/api/auth/logout', null, su.data.token);
    assert.strictEqual((await s.call('GET', '/api/me', null, su.data.token)).status, 401);
  } finally { await s.close(); }
});

test('the owner number is marked as owner at sign-up', async () => {
  const s = await start();
  try {
    await s.call('POST', '/api/auth/request-code', { phone: '+1 548 883 0049' });
    const v = await s.call('POST', '/api/auth/verify-code', { phone: '+1 548 883 0049', code: s.sent[0].text.match(/\d{6}/)[0] });
    const su = await s.call('POST', '/api/auth/signup', { signupToken: v.data.signupToken, username: 'blackbull', name: 'Owner', password: 'secret1' });
    assert.strictEqual(su.data.user.owner, true);
  } finally { await s.close(); }
});

test('accounts survive a restart, and a damaged file stops the server', async () => {
  const dir = tempDir();
  let s = await start({ dir });
  await s.call('POST', '/api/auth/request-code', { phone: '+1 604 555 0701' });
  const v = await s.call('POST', '/api/auth/verify-code', { phone: '+1 604 555 0701', code: s.sent[0].text.match(/\d{6}/)[0] });
  await s.call('POST', '/api/auth/signup', { signupToken: v.data.signupToken, username: 'erin', name: 'Erin', password: 'secret1' });
  await s.close();
  s = await start({ dir });
  assert.strictEqual((await s.call('POST', '/api/auth/login', { username: 'erin', password: 'secret1' })).status, 200);
  await s.close();
  fs.writeFileSync(path.join(dir, 'db.json'), '{broken');
  assert.throws(() => createApp({ dataDir: dir }), /damaged/);
});

test('oversized and malformed requests are rejected', async () => {
  const s = await start();
  try {
    const bad = await fetch(s.dir ? 'http://127.0.0.1:' + s.app.server.address().port + '/api/auth/login' : '', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json'
    });
    assert.strictEqual(bad.status, 400);
    const big = await fetch('http://127.0.0.1:' + s.app.server.address().port + '/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ x: 'a'.repeat(40000) })
    }).then((r) => r.status).catch(() => 413);
    assert.ok(big === 400 || big === 413);
  } finally { await s.close(); }
});

test('North Korea (+850) is refused by the server', () => {
  const { phoneProblem } = require('../src/server.js');
  assert.match(phoneProblem('8501234567'), /not supported/);
  assert.strictEqual(phoneProblem('16045550101'), '');
});
