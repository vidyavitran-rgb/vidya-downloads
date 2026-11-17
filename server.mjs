import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, realpath, open } from 'node:fs/promises';
import { resolve, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';

export function proxySignature(params, secret) {
  const grouped = new Map();
  for (const [key, value] of params) {
    if (key === 'signature') continue;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(value);
  }
  const message = [...grouped.keys()].sort().map(key => `${key}=${grouped.get(key).join(',')}`).join('');
  return createHmac('sha256', secret).update(message).digest('hex');
}

export function authenticate(params, secret, shop, now = Date.now()) {
  for (const key of ['signature', 'shop', 'timestamp', 'logged_in_customer_id', 'resource', 'path_prefix']) {
    if (params.getAll(key).length !== 1) return 403;
  }
  const signature = params.get('signature');
  if (!/^[a-f0-9]{64}$/.test(signature)) return 403;
  const expected = proxySignature(params, secret);
  if (!timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'))) return 403;
  if (params.get('shop') !== shop) return 403;
  const timestamp = params.get('timestamp');
  if (!/^\d+$/.test(timestamp) || Math.abs(now / 1000 - Number(timestamp)) > 300) return 403;
  const customer = params.get('logged_in_customer_id');
  if (!customer) return 401;
  return /^[1-9]\d*$/.test(customer) ? 200 : 403;
}

export function createHandler({ secret, shop, root = dirname(fileURLToPath(import.meta.url)) }) {
  if (!secret || secret.startsWith('replace-') || !/^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/.test(shop || '')) throw new Error('Configure SHOPIFY_API_SECRET and SHOPIFY_SHOP before starting.');
  return async (req, res) => {
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (code, message) => {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
    };
    let file;
    try {
      const url = new URL(req.url, 'http://backend.local');
      if (url.pathname === '/health' && req.method === 'GET') { res.writeHead(200, {'Content-Type':'text/plain'}); res.end('ok'); return; }
      if (url.pathname !== '/proxy/download') return fail(404, 'Not found');
      if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return fail(405, 'Method not allowed'); }
      const code = authenticate(url.searchParams, secret, shop);
      if (code !== 200) return fail(code, code === 401 ? 'Sign in required' : 'Invalid request');
      const id = url.searchParams.get('resource');
      if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id)) return fail(404, 'Resource unavailable');
      const catalog = JSON.parse(await readFile(resolve(root, 'resources.json'), 'utf8'));
      const resource = Object.hasOwn(catalog, id) ? catalog[id] : null;
      if (!resource || resource.active !== true || typeof resource.file !== 'string') return fail(404, 'Resource unavailable');
      const privateRoot = await realpath(resolve(root, 'private'));
      const target = await realpath(resolve(privateRoot, resource.file));
      if (!target.startsWith(privateRoot + sep) || !target.toLowerCase().endsWith('.pdf')) return fail(404, 'Resource unavailable');
      file = await open(target, 'r');
      const stat = await file.stat();
      if (!stat.isFile() || stat.size > 50 * 1024 * 1024) return fail(404, 'Resource unavailable');
      const magic = Buffer.alloc(5);
      await file.read(magic, 0, 5, 0);
      if (magic.toString() !== '%PDF-') return fail(404, 'Resource unavailable');
      res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Length': stat.size, 'Content-Disposition': `attachment; filename="${id}.pdf"` });
      await pipeline(file.createReadStream({ start: 0, autoClose: false }), res);
    } catch (error) {
      if (!res.headersSent) fail(error.code === 'ENOENT' ? 404 : 503, 'Resource unavailable');
      else res.destroy();
    } finally { await file?.close().catch(() => {}); }
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const handler = createHandler({ secret: process.env.SHOPIFY_API_SECRET, shop: process.env.SHOPIFY_SHOP });
  createServer(handler).listen(Number(process.env.PORT || 3000), '0.0.0.0', () => console.log('Resource download service started'));
}
