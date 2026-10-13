'use strict';
// Data store for the Blackbull app: saves and loads named values, one file per value.
// Every request must carry the secret token in the X-BB-Token header.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function createKv(dataDir, token) {
  const root = path.join(dataDir, 'kv');
  fs.mkdirSync(root, { recursive: true });
  const fileFor = (k) => path.join(root, Buffer.from(String(k), 'utf8').toString('base64url'));
  const keyOf = (f) => Buffer.from(f, 'base64url').toString('utf8');
  const tokenOk = (req) => {
    const a = Buffer.from(String(req.headers['x-bb-token'] || ''));
    const b = Buffer.from(String(token || ''));
    return b.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
  };
  const readBody = (req, max) => new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > max) { reject(new Error('too big')); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
  return async function handle(req, res, url) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-BB-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (!tokenOk(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end('{"error":"unauthorized"}'); }
    if (req.method === 'GET' && (url.pathname === '/kv' || url.pathname === '/kv/') && url.searchParams.has('prefix')) {
      const pre = url.searchParams.get('prefix') || '';
      const keys = fs.readdirSync(root).filter((f) => !f.endsWith('.tmp')).map(keyOf).filter((k) => k.startsWith(pre));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(keys));
    }
    const key = decodeURIComponent(url.pathname.replace(/^\/kv\/?/, ''));
    if (!key) { res.writeHead(400); return res.end(); }
    const f = fileFor(key);
    if (req.method === 'GET') {
      if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(fs.readFileSync(f, 'utf8'));
    }
    if (req.method === 'PUT' || req.method === 'POST') {
      let body;
      try { body = await readBody(req, 50 * 1024 * 1024); } catch (e) { res.writeHead(413); return res.end(); }
      const tmp = f + '.tmp';
      fs.writeFileSync(tmp, body);
      fs.renameSync(tmp, f); // a crash never leaves half a value
      res.writeHead(200); return res.end();
    }
    if (req.method === 'DELETE') {
      try { fs.unlinkSync(f); } catch (e) {}
      res.writeHead(200); return res.end();
    }
    res.writeHead(405); return res.end();
  };
}
module.exports = { createKv };
