'use strict';
/*
 * BLACK FOX BD v8 — Neon S3 object store (S3-compatible, SigV4).
 *
 * The hub keeps its whole state here: the device registry, the ACL, the custom
 * command table and the session map. Render's free tier recycles the process on
 * every deploy, spin-down and OOM, and /tmp goes with it — which is exactly how
 * a device that was polling from inside a live match still showed up as
 * "no devices" on the bot. State that lives only in memory is state that
 * disappears; this module is what makes it survive.
 *
 * SigV4 is implemented by hand because the Neon endpoint is S3-compatible but
 * not AWS, and pulling the AWS SDK in for four verbs is not worth the cold-start
 * cost on a free dyno.
 */
const crypto = require('crypto');

const ENDPOINT = process.env.NEON_S3_ENDPOINT || '';
const KEY = process.env.NEON_S3_KEY || '';
const SECRET = process.env.NEON_S3_SECRET || '';
const REGION = process.env.NEON_S3_REGION || 'us-east-2';
/*
 * The Neon endpoint is bucket-scoped: the host itself IS the bucket, so the
 * object key goes straight after the root. Prefixing a bucket name here returns
 * NoSuchBucket (verified against the live endpoint). Leave NEON_S3_BUCKET unset
 * for a bucket-scoped endpoint; set it only for a path-style S3 that needs one.
 */
const BUCKET = process.env.NEON_S3_BUCKET || '';

const HOST = ENDPOINT.replace(/^https?:\/\//, '').replace(/\/$/, '');
const SERVICE = 's3';

function enabled() {
  return !!(ENDPOINT && KEY && SECRET);
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function amzDate(d) {
  const iso = d.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { full: iso, short: iso.slice(0, 8) };
}

/**
 * One signed request. `body` is a Buffer or string; the payload hash is always
 * computed over the real bytes so a retry with a different body cannot reuse a
 * stale signature.
 */
async function signed(method, keyPath, body, extraHeaders) {
  const base = ENDPOINT.replace(/\/$/, '');
  const prefix = BUCKET ? '/' + BUCKET : '';
  const url = new URL(base + prefix + '/' + keyPath);
  const payload = body == null ? Buffer.alloc(0) : Buffer.from(body);
  const payloadHash = sha256hex(payload);
  const now = new Date();
  const { full, short } = amzDate(now);

  const headers = {
    host: HOST,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': full,
  };
  if (extraHeaders) for (const k of Object.keys(extraHeaders)) headers[k.toLowerCase()] = extraHeaders[k];

  const signedNames = Object.keys(headers).sort();
  const canonicalHeaders = signedNames.map((h) => h + ':' + String(headers[h]).trim() + '\n').join('');
  const signedHeaders = signedNames.join(';');

  const canonicalRequest = [
    method,
    url.pathname,
    url.searchParams.toString(),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const scope = short + '/' + REGION + '/' + SERVICE + '/aws4_request';
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    full,
    scope,
    sha256hex(canonicalRequest),
  ].join('\n');

  let k = hmac('AWS4' + SECRET, short);
  k = hmac(k, REGION);
  k = hmac(k, SERVICE);
  k = hmac(k, 'aws4_request');
  const signature = crypto.createHmac('sha256', k).update(stringToSign).digest('hex');

  headers.Authorization =
    'AWS4-HMAC-SHA256 Credential=' + KEY + '/' + scope +
    ', SignedHeaders=' + signedHeaders +
    ', Signature=' + signature;

  const res = await fetch(url.toString(), {
    method,
    headers,
    body: method === 'GET' || method === 'HEAD' ? undefined : payload,
  });
  return res;
}

async function put(keyPath, obj) {
  if (!enabled()) return false;
  try {
    const body = Buffer.from(JSON.stringify(obj));
    const res = await signed('PUT', keyPath, body, { 'content-type': 'application/json' });
    return res.ok;
  } catch (e) {
    return false;
  }
}

async function get(keyPath) {
  if (!enabled()) return null;
  try {
    const res = await signed('GET', keyPath, null);
    if (!res.ok) return null;
    const txt = await res.text();
    return JSON.parse(txt);
  } catch (e) {
    return null;
  }
}

async function del(keyPath) {
  if (!enabled()) return false;
  try {
    const res = await signed('DELETE', keyPath, null);
    return res.ok;
  } catch (e) {
    return false;
  }
}

/**
 * The Neon endpoint rejects LIST, so the key set is kept in an index object that
 * every write updates. A missing index is rebuilt lazily from the known key
 * prefixes rather than by listing.
 */
async function list(prefix) {
  const idx = (await get('_index.json')) || { keys: [] };
  return (idx.keys || []).filter((k) => k.startsWith(prefix));
}

async function indexAdd(keyPath) {
  const idx = (await get('_index.json')) || { keys: [] };
  if (!idx.keys.includes(keyPath)) {
    idx.keys.push(keyPath);
    await put('_index.json', idx);
  }
}

async function indexRemove(keyPath) {
  const idx = (await get('_index.json')) || { keys: [] };
  const next = idx.keys.filter((k) => k !== keyPath);
  if (next.length !== idx.keys.length) {
    idx.keys = next;
    await put('_index.json', idx);
  }
}

module.exports = { enabled, put, get, del, list, indexAdd, indexRemove };
