'use strict';
/*
 * Live probe against the deployed nodes, using the exact protocol the APK
 * speaks: ECDH P-256 -> HKDF -> AES-256-GCM payload + HMAC over the ciphertext.
 *
 *   node live-probe.mjs                       -> probes the Render hub
 *   node live-probe.mjs https://other-host    -> probes any host
 *
 * It registers a synthetic device ("probe-<ts>"), polls, then asks /api/debug
 * whether the device is visible. Because the hub persists to Neon S3, the device
 * is still there after the process is recycled — that is the whole point.
 */
import crypto from 'node:crypto';

const BASE = process.argv[2] || 'https://bxbot-ruw1.onrender.com';
const DEBUG_TOKEN = process.env.DEBUG_TOKEN || 'bx8debug';
const DEV = 'probe' + Date.now().toString(36);

function b64(b) { return Buffer.from(b).toString('base64'); }
function hkdf(secret, info) {
  const salt = Buffer.from(process.env.SESSION_SALT || 'bx8-session-salt-do-not-publish');
  const prk = crypto.createHmac('sha256', salt).update(secret).digest();
  return crypto.createHmac('sha256', prk)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
}
function aesEnc(key, plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain, 'utf8')), c.final()]);
  return b64(Buffer.concat([iv, ct, c.getAuthTag()]));
}
function aesDec(key, wire) {
  const all = Buffer.from(wire, 'base64');
  const iv = all.subarray(0, 12), tag = all.subarray(all.length - 16), ct = all.subarray(12, all.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}
function hmac(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest('base64'); }

function ms(t0) { return Date.now() - t0; }

const out = [];
function line(s) { out.push(s); console.log(s); }

line('probing ' + BASE);
line('device   ' + DEV);
line('─'.repeat(52));

/* health */
let t0 = Date.now();
const h = await (await fetch(BASE + '/health')).json();
line('health    200  ' + ms(t0) + 'ms  ' + JSON.stringify(h));

/* hello */
const ecdh = crypto.createECDH('prime256v1');
ecdh.generateKeys();
t0 = Date.now();
const hr = await fetch(BASE + '/api/hello', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    dev: DEV, name: 'probe SM-A127F', pkg: 'com.alamin.ludu', st: 'ingame',
    pk: b64(ecdh.getPublicKey()), v: 9,
  }),
});
const hj = await hr.json();
line('hello     ' + hr.status + '  ' + ms(t0) + 'ms  node=' + hj.node + ' cfg=' + JSON.stringify(hj.cfg));

const secret = ecdh.computeSecret(Buffer.from(hj.spk, 'base64'));
const AES = hkdf(secret, 'enc');
const MAC = hkdf(secret, 'sig');
const SID = hj.sid;

/* poll twice so the counter moves */
for (let i = 1; i <= 2; i++) {
  const inner = JSON.stringify({
    st: 'ingame', name: 'probe SM-A127F', pkg: 'com.alamin.ludu', polls: i,
    up: 0, fail: 0, node: 'probe', ig: 1,
  });
  const wire = aesEnc(AES, inner);
  t0 = Date.now();
  const pr = await fetch(BASE + '/api/poll', {
    method: 'POST',
    headers: { 'content-type': 'text/plain', 'x-sid': SID, 'x-sig': hmac(MAC, SID + '|' + wire) },
    body: wire,
  });
  const body = await pr.text();
  const sigOk = pr.headers.get('x-sig') === hmac(MAC, SID + '|' + body);
  const dec = pr.status === 200 ? JSON.parse(aesDec(AES, body)) : null;
  line('poll#' + i + '    ' + pr.status + '  ' + ms(t0) + 'ms  sigOk=' + sigOk +
       '  reg=' + (dec && dec.reg) + '  cmds=' + (dec && dec.cmds ? dec.cmds.length : '-') +
       '  cfg.i=' + (dec && dec.cfg ? dec.cfg.i : '-'));
}

/* visibility */
t0 = Date.now();
const dbg = await fetch(BASE + '/api/debug?token=' + DEBUG_TOKEN);
line('debug     ' + dbg.status + '  ' + ms(t0) + 'ms');
const dj = await dbg.json();
const mine = (dj.devices || []).find((d) => d.id === DEV);
line('device visible in registry : ' + (mine ? 'YES ✔  ' + JSON.stringify(mine) : 'NO ✘'));
line('total devices              : ' + (dj.devices || []).length);
line('store                      : ' + dj.store + '  node=' + dj.node + '  v=' + dj.version);
line('counters                   : reg=' + dj.counters.reg + ' ok=' + dj.counters.regOk +
     ' fail=' + dj.counters.regFail + ' poll=' + dj.counters.poll);
line('─'.repeat(52));
line(mine ? 'RESULT: PASS' : 'RESULT: FAIL');
process.exit(mine ? 0 : 1);
