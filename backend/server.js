'use strict';
/*
 * BLACK FOX BD v10 — hub (Render).
 *
 * The APK never holds the bot token. It talks to /api/hello + /api/poll with a
 * per-launch ECDH P-256 session, AES-256-GCM payloads and an HMAC over the
 * ciphertext. This process is the only thing that knows the token, and it is the
 * only thing that talks to Telegram.
 *
 * Two structural rules in v9:
 *
 *   1. ONE dispatcher. A typed command and an inline-keyboard callback both end
 *      up in dispatch(). There is no second code path for buttons, so the two
 *      can never drift apart.
 *
 *   2. Nothing that matters lives only in memory. Render's free tier recycles
 *      the process on deploy / spin-down / OOM; devices, the ACL, the device
 *      selection and the per-device command queue all go to Neon S3. That is the
 *      difference between "device is polling in a live match" and "no devices".
 *
 * Poll cadence is plain, no long-poll: 2s in a match, 30 min idle, 10 min while
 * /puce. A parked long-poll hides the device from /de for the whole wait window
 * and the operator reads that as a missing device.
 */
const http = require('http');
const crypto = require('crypto');
const s3 = require('./s3');
const acl = require('./acl');
const help = require('./help');
const ui = require('./ui');

const PORT = process.env.PORT || 10000;
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const DEBUG_TOKEN = process.env.DEBUG_TOKEN || 'bx9debug';
const NODE_NAME = process.env.NODE_NAME || 'render';
const VERSION = '10.0.0';
const PROTO = 10;

const GAME_MS = 2000;
const IDLE_MS = 1800000;   // 30 min
const PAUSE_MS = 600000;   // 10 min
const ONLINE_MS = 90000;   // a device is "online" if it polled within 90s

/* Spam protection. A human tapping and typing never hits 15 commands in five
   seconds; a script does. Tunable so the harness can raise it for fast runs and
   lower it to prove the refusal path. */
const RATE_MAX = parseInt(process.env.RATE_MAX || '15', 10);
const RATE_WIN = parseInt(process.env.RATE_WIN || '5000', 10);

/* ------------------------------------------------------------------ */
/*  state                                                              */
/* ------------------------------------------------------------------ */

const MEM = {
  devices: {},     // id -> {id,name,pkg,st,last,first,polls,ip,q:[],halt:0}
  acl: acl.emptyAcl(),
  sessions: {},    // sid -> {dev, aes, mac, at}
  sel: {},         // chatId -> device id
  names: {},       // username(lower) -> chatId
  puce: {},        // deviceId -> bool
  log: [],         // ring of the last 50 requests
  replies: {},     // chatId -> last few replies
  rate: {},        // chatId -> {n, t}
  counters: {
    reg: 0, regOk: 0, regFail: 0, poll: 0, drop: 0, uplink: 0,
    lastRegAt: 0, lastRegId: '', lastErr: '', cmd: 0, cb: 0,
    drops: {},        // reason -> count, so /diag can say WHY and not just how many
    lastDropId: '',   // last device that lost a session
    lastDropAt: 0,
  },
  dirty: false,
};

let loaded = false;

async function loadState() {
  if (loaded) return;
  loaded = true;
  try {
    const d = await s3.get('state/devices.json');
    if (d && d.devices) MEM.devices = d.devices;
    const a = await s3.get('state/acl.json');
    if (a && a.admins) MEM.acl = a;
    const c = await s3.get('state/counters.json');
    if (c) MEM.counters = Object.assign(MEM.counters, c);
    const s = await s3.get('state/sel.json');
    if (s) {
      MEM.sel = s.sel || {};
      MEM.names = s.names || {};
      MEM.puce = s.puce || {};
    }
  } catch (e) {
    /* first boot or S3 unreachable: start empty, the mirror still serves */
  }
}

let saveTimer = null;
function saveSoon() {
  MEM.dirty = true;
  if (saveTimer) return;
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    if (!MEM.dirty) return;
    MEM.dirty = false;
    try {
      await s3.put('state/devices.json', { devices: MEM.devices, at: Date.now() });
      await s3.put('state/acl.json', MEM.acl);
      await s3.put('state/counters.json', MEM.counters);
      await s3.put('state/sel.json', { sel: MEM.sel, names: MEM.names, puce: MEM.puce });
    } catch (e) {
      MEM.dirty = true;
    }
  }, 1200);
}

/** Flush the pieces a command just changed, so a restart cannot lose them. */
async function saveNow() {
  try {
    await s3.put('state/acl.json', MEM.acl);
    await s3.put('state/sel.json', { sel: MEM.sel, names: MEM.names, puce: MEM.puce });
  } catch (e) { /* the in-memory mirror still serves this process */ }
}

function logReq(path, status, dev, reason) {
  MEM.log.push({ t: Date.now(), path, status, dev: dev || '', reason: reason || '' });
  if (MEM.log.length > 50) MEM.log.shift();
}

/* ------------------------------------------------------------------ */
/*  crypto                                                             */
/* ------------------------------------------------------------------ */

function b64(buf) { return Buffer.from(buf).toString('base64'); }
function unb64(s) { return Buffer.from(String(s), 'base64'); }

/*
 * HKDF with a SALT CANDIDATE LIST, not one salt.
 *
 * The APK bakes its salt into the dex (Vault slot 4). When the hub's
 * SESSION_SALT is rotated and the installed APK is not rebuilt, every poll
 * arrives with a perfectly valid HMAC that the hub computes differently — the
 * device registers, then every poll is dropped as "bad sig", and /de shows an
 * empty list while the operator sits in a live match. That is a server-side
 * failure that must not depend on shipping a new APK, so verification tries the
 * configured salt first and then every known historical salt.
 */
const SALT_CANDIDATES = (() => {
  const out = [];
  const push = (s) => { if (s && !out.includes(s)) out.push(s); };
  push(process.env.SESSION_SALT);
  /* Historical build salts. Leaving these in costs nothing: a salt only helps
     an attacker who already has the shared ECDH secret, and every candidate is
     still combined with that per-launch secret. */
  push('bx8-session-salt-do-not-publish');
  push('bx9-session-salt-do-not-publish');
  push('bx5-session-salt-do-not-publish');
  for (const extra of String(process.env.SESSION_SALT_EXTRA || '').split(',')) push(extra.trim());
  return out;
})();

function hkdfWith(saltStr, secret, info) {
  const prk = crypto.createHmac('sha256', Buffer.from(saltStr)).update(secret).digest();
  return crypto.createHmac('sha256', prk)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
}

/** Every (salt, aes, mac) triple this hub will accept for one session. */
function keySet(secret) {
  return SALT_CANDIDATES.map((salt) => ({
    salt,
    aes: hkdfWith(salt, secret, 'enc'),
    mac: hkdfWith(salt, secret, 'sig'),
  }));
}

/** Back-compat for callers that still want a single key. */
function hkdf(secret, info) {
  return hkdfWith(SALT_CANDIDATES[0], secret, info);
}

function drop(reason, dev) {
  MEM.counters.drop++;
  const d = MEM.counters.drops || (MEM.counters.drops = {});
  d[reason] = (d[reason] || 0) + 1;
  MEM.counters.lastDropId = dev || '';
  MEM.counters.lastDropAt = Date.now();
}

function aesEnc(key, plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain, 'utf8')), c.final()]);
  return b64(Buffer.concat([iv, ct, c.getAuthTag()]));
}

function aesDec(key, wire) {
  const all = unb64(wire);
  const iv = all.subarray(0, 12);
  const tag = all.subarray(all.length - 16);
  const ct = all.subarray(12, all.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

function hmacB64(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest('base64');
}

/* ------------------------------------------------------------------ */
/*  telegram                                                           */
/* ------------------------------------------------------------------ */

async function tg(method, payload) {
  if (!BOT_TOKEN) return { ok: false, description: 'no token' };
  try {
    const res = await fetch('https://api.telegram.org/bot' + BOT_TOKEN + '/' + method, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return await res.json();
  } catch (e) {
    return { ok: false, description: String(e.message) };
  }
}

function remember(chatId, text) {
  const k = String(chatId);
  if (!MEM.replies[k]) MEM.replies[k] = [];
  MEM.replies[k].push({ t: Date.now(), text: String(text).slice(0, 300) });
  if (MEM.replies[k].length > 5) MEM.replies[k].shift();
}

async function reply(chatId, text, kb) {
  remember(chatId, text);
  const p = { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (kb && kb.length) p.reply_markup = { inline_keyboard: kb };
  return tg('sendMessage', p);
}

async function answerCb(id, text) {
  return tg('answerCallbackQuery', { callback_query_id: id, text: text || '', show_alert: false });
}

async function editKb(chatId, messageId, kb) {
  /* Only the keyboard is replaced, the message body stays — that keeps the
     chat readable instead of flooding it with a new message per tap. */
  return tg('editMessageReplyMarkup', {
    chat_id: chatId, message_id: messageId, reply_markup: { inline_keyboard: kb },
  });
}

/* ------------------------------------------------------------------ */
/*  device helpers                                                     */
/* ------------------------------------------------------------------ */

function upsertDevice(id, name, pkg, st, ip) {
  const now = Date.now();
  let d = MEM.devices[id];
  if (!d) {
    d = { id, first: now, polls: 0, q: [], halt: 0 };
    MEM.devices[id] = d;
  }
  if (!Array.isArray(d.q)) d.q = [];
  d.name = name || d.name || 'unknown';
  d.pkg = pkg || d.pkg || '';
  d.st = st || d.st || 'idle';
  d.last = now;
  d.ip = ip || d.ip || '';
  d.polls = (d.polls || 0) + 1;
  saveSoon();
  return d;
}

function onlineOf(d) {
  return Date.now() - (d.last || 0) < ONLINE_MS;
}

function ago(ms) {
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}

function visibleDevices(chatId) {
  const bind = acl.bindOf(MEM.acl, chatId);
  const all = Object.values(MEM.devices).sort((a, b) => (b.last || 0) - (a.last || 0));
  if (!bind) return all;
  return all.filter((d) => d.id === bind);
}

function withAge(list) {
  return list.map((d) => ({
    id: d.id,
    name: d.name,
    st: d.st,
    polls: d.polls || 0,
    online: onlineOf(d),
    age: Math.floor((Date.now() - (d.last || 0)) / 1000),
  }));
}

function selectedDevice(chatId) {
  const vis = visibleDevices(chatId);
  const sel = MEM.sel && MEM.sel[String(chatId)];
  if (sel) {
    const hit = vis.find((d) => d.id === sel);
    if (hit) return hit;
  }
  return vis.length ? vis[0] : null;
}

function pushCmd(devId, cmd) {
  const d = MEM.devices[devId];
  if (!d) return false;
  if (!Array.isArray(d.q)) d.q = [];
  d.q.push(cmd);
  if (d.q.length > 40) d.q.shift();
  saveSoon();
  return true;
}

/* ------------------------------------------------------------------ */
/*  text normalisation                                                 */
/* ------------------------------------------------------------------ */

/**
 * Typo tolerance. The operator types on a phone in a hurry, so "R W", "r6 6 1",
 * "2RY" and "/DE" all have to land. This only ever drops whitespace or changes
 * case — it never guesses a different command.
 */
function normalise(raw) {
  let t = String(raw || '').trim();
  if (!t) return '';
  if (/^\/[rgbypo]\s*\d/i.test(t)) t = t.slice(1);
  const low = t.toLowerCase();
  const m = low.match(/^([rgbypo])(\d)(?=\s|$)/);
  if (m) return m[1] + ' ' + low.slice(1);
  return low.replace(/\s+/g, ' ').trim();
}

function rateOk(chatId) {
  const k = String(chatId);
  const now = Date.now();
  let r = MEM.rate[k];
  if (!r || now - r.t > RATE_WIN) { r = { n: 0, t: now }; MEM.rate[k] = r; }
  r.n++;
  return r.n <= RATE_MAX;
}

function resolveTarget(s) {
  if (!s) return null;
  const clean = String(s).replace(/^@/, '').trim();
  if (/^-?\d+$/.test(clean)) return clean;
  return (MEM.names && MEM.names[clean.toLowerCase()]) || null;
}

/* ------------------------------------------------------------------ */
/*  dice parsing                                                       */
/* ------------------------------------------------------------------ */

function parseDice(text) {
  const t = String(text || '').trim().toLowerCase();
  if (!t) return null;

  let m = t.match(/^2([rgbypo]{2})$/);
  if (m) return { k: 'dice', combo: m[1].split('') };
  if (t === '2off') return { k: 'dice', combo: [] };

  m = t.match(/^([rgbypo])\s+clear$/);
  if (m) return { k: 'dice', clearColor: m[1] };

  m = t.match(/^([rgbypo])\s+(w|win)(\s+manual)?$/);
  if (m) return { k: 'dice', color: m[1], mode: m[3] ? 'win_manual' : 'win_auto', win: true, manual: !!m[3] };

  m = t.match(/^([rgbypo])\s+m\s+(.+)$/);
  if (m) {
    const seq = parseSeq(m[2]);
    if (!seq) return null;
    return { k: 'dice', color: m[1], mode: 'seq', seq, win: false, manual: true };
  }

  m = t.match(/^([rgbypo])\s+(.+)$/);
  if (m) {
    const seq = parseSeq(m[2]);
    if (!seq) return null;
    return { k: 'dice', color: m[1], mode: 'seq', seq, win: false, manual: false };
  }
  return null;
}

function parseSeq(s) {
  const parts = String(s).trim().split(/[\s,]+/).filter(Boolean);
  const out = [];
  for (const p of parts) {
    if (p === 'random' || p === 'r' || p === '?') { out.push('R'); continue; }
    const n = parseInt(p, 10);
    if (!(n >= 1 && n <= 6)) return null;
    out.push(n);
  }
  return out.length ? out : null;
}

function describeDice(c) {
  if (c.combo) return c.combo.length ? '🔗 pair: ' + c.combo.join('+') : '🔗 pair বন্ধ';
  if (c.clearColor) return '🧹 ' + c.clearColor + ' script মুছে ফেলা হলো';
  if (c.clear) return '🧹 সব script মুছে ফেলা হলো';
  if (c.win) return '🏆 ' + c.color + ' win mode (' + (c.manual ? 'manual' : 'auto') + ')';
  return '🎲 ' + c.color + ' → ' + (c.seq || []).map((v) => (v === 'R' ? 'random' : v)).join(' ');
}

/* ------------------------------------------------------------------ */
/*  dispatcher — the ONLY command path                                 */
/* ------------------------------------------------------------------ */

/**
 * Runs one command. Returns { text, kb } or null when the input is not a
 * command at all. `kb` is an inline keyboard the caller attaches; null means
 * "leave the previous keyboard alone".
 *
 * The button path calls this same function — that is the whole point.
 */
async function dispatch(chatId, raw) {
  const id = String(chatId);
  const low = normalise(raw);
  if (!low) return null;

  if (!rateOk(id)) {
    return { text: '🐢 একটু আস্তে। ৫ সেকেন্ডে ১৫টির বেশি কমান্ড নেওয়া হয় না।', kb: null };
  }

  const isAdm = acl.isAdmin(MEM.acl, id);

  /* ---------------- help ---------------- */
  if (low === '/h' || low === '/help' || low === '/start' || low === 'help') {
    return { text: help.homeText(isAdm, MEM.acl.custom), kb: ui.MAIN };
  }
  const hm = low.match(/^\/h\s+(\w+)$/);
  if (hm && help.CAT_INDEX[hm[1]]) {
    return { text: help.catText(hm[1], MEM.acl.custom), kb: catKb(hm[1]) };
  }

  /* ---------------- admin ---------------- */
  if (low === '/login' || low.startsWith('/login ')) {
    const arg = String(raw).trim().slice(6).trim();
    const want = process.env.ADMIN_PASS || '22alamin11';
    if (arg && arg === want) {
      if (!MEM.acl.admins.includes(id)) MEM.acl.admins.push(id);
      await saveNow();
      return {
        text: '✅ <b>অ্যাডমিন লগইন সফল</b>\n' + help.DIV + '\nrole: admin\nperm: সব\n\n' +
              'এখন থেকে সব কমান্ড খোলা। <code>/users</code> দিয়ে পারমিশন দিন।',
        kb: ui.ADM,
      };
    }
    return { text: '❌ ভুল পাসওয়ার্ড।\nব্যবহার: <code>/login &lt;pass&gt;</code>', kb: null };
  }

  if (low === '/whoami') {
    const d = selectedDevice(id);
    return {
      text: '🆔 <b>আপনার পরিচয়</b>\n' + help.DIV + '\n' +
            'chat_id : <code>' + id + '</code>\n' +
            'role    : ' + (isAdm ? '👑 admin' : '👤 user') + '\n' +
            'perm    : ' + acl.describe(MEM.acl, id) + '\n' +
            'device  : ' + (d ? help.esc(d.name) + ' (<code>' + d.id + '</code>)' : '—'),
      kb: null,
    };
  }

  if (low.startsWith('/per ')) {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    const rest = String(raw).trim().slice(5).trim();
    const sp = rest.indexOf(' ');
    if (sp < 0) {
      return {
        text: 'ব্যবহার:\n<code>/per &lt;chat_id|@name&gt; &lt;perms&gt;</code>\n' +
              'perm: de, u, re, st, cfg, roll, win, all, auto, rw\n' +
              'bind: <code>/per @name u &lt;device_id&gt;</code>',
        kb: null,
      };
    }
    const targetRaw = rest.slice(0, sp).trim();
    const spec = rest.slice(sp + 1).trim();
    const tid = resolveTarget(targetRaw);
    if (!tid) {
      return {
        text: '❌ target পাওয়া যায়নি: ' + help.esc(targetRaw) + '\n' +
              'ইউজারকে আগে bot-এ একবার মেসেজ করতে হবে, নাহলে Telegram username দেয় না।\n' +
              'বিকল্প: <code>/users</code> থেকে chat id নিয়ে সংখ্যায় দিন।',
        kb: null,
      };
    }
    const added = acl.grant(MEM.acl, tid, spec);
    await saveNow();
    return {
      text: '✅ <code>' + tid + '</code> কে দেওয়া হলো: ' + (added.join(', ') || 'কিছুই না') + '\n' +
            'এখন: ' + acl.describe(MEM.acl, tid),
      kb: null,
    };
  }

  if (low.startsWith('/revoke')) {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    const targetRaw = String(raw).trim().slice(7).trim();
    const tid = resolveTarget(targetRaw) || targetRaw;
    acl.revoke(MEM.acl, tid);
    await saveNow();
    return { text: '✅ <code>' + help.esc(tid) + '</code> এর সব permission বাতিল', kb: ui.ADM };
  }

  if (low.startsWith('/bind ')) {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    const rest = String(raw).trim().slice(6).trim();
    const sp = rest.indexOf(' ');
    if (sp < 0) return { text: 'ব্যবহার: <code>/bind &lt;chat_id&gt; &lt;device_id&gt;</code>', kb: null };
    const tid = resolveTarget(rest.slice(0, sp).trim()) || rest.slice(0, sp).trim();
    const dev = rest.slice(sp + 1).trim();
    if (!MEM.devices[dev]) return { text: '❌ ডিভাইস নেই: <code>' + help.esc(dev) + '</code>', kb: null };
    acl.setBind(MEM.acl, tid, dev);
    await saveNow();
    return { text: '✅ <code>' + tid + '</code> → device <code>' + dev + '</code> এ bind', kb: null };
  }

  if (low.startsWith('/unbind')) {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    const arg = String(raw).trim().slice(7).trim();
    const tid = resolveTarget(arg) || arg;
    acl.setBind(MEM.acl, tid, null);
    await saveNow();
    return { text: '✅ <code>' + help.esc(tid) + '</code> এর bind সরানো হলো', kb: null };
  }

  if (low === '/users') {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    let out = '👥 <b>ইউজার তালিকা</b>\n' + help.DIV + '\n';
    out += '👑 admin (' + MEM.acl.admins.length + ')\n';
    for (const a of MEM.acl.admins) out += '  <code>' + a + '</code>\n';
    const us = Object.keys(MEM.acl.users);
    out += '👤 user (' + us.length + ')\n';
    for (const u of us) {
      const x = MEM.acl.users[u];
      out += '  <code>' + u + '</code>' + (x.label ? ' @' + help.esc(x.label) : '') +
             ' → ' + acl.describe(MEM.acl, u) + '\n';
    }
    if (!us.length) out += '  (কেউ নেই)\n';
    return { text: out, kb: ui.ADM };
  }

  if (low.startsWith('/newcmd ')) {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    const rest = String(raw).trim().slice(8).trim();
    const sp = rest.indexOf(' ');
    if (sp < 0) return { text: 'ব্যবহার: <code>/newcmd &lt;name&gt; &lt;action&gt;</code>', kb: null };
    const name = rest.slice(0, sp).replace(/^\//, '').toLowerCase();
    let action = rest.slice(sp + 1).trim();
    if ((action.startsWith('"') && action.endsWith('"')) ||
        (action.startsWith("'") && action.endsWith("'"))) {
      action = action.slice(1, -1).trim();
    }
    if (!parseDice(normalise(action))) {
      return { text: '❌ action টা ডাইস কমান্ড নয়: <code>' + help.esc(action) + '</code>', kb: null };
    }
    MEM.acl.custom[name] = action;
    await saveNow();
    return {
      text: '✅ <code>/' + help.esc(name) + '</code> → <code>' + help.esc(action) + '</code>',
      kb: ui.customMenu(MEM.acl.custom),
    };
  }

  if (low.startsWith('/delcmd ')) {
    if (!isAdm) return { text: '❌ permission নেই', kb: null };
    const name = String(raw).trim().slice(8).trim().replace(/^\//, '').toLowerCase();
    const had = !!MEM.acl.custom[name];
    delete MEM.acl.custom[name];
    await saveNow();
    return {
      text: had ? '✅ <code>/' + help.esc(name) + '</code> মুছে ফেলা হলো' : '❌ এমন কমান্ড নেই: ' + help.esc(name),
      kb: ui.customMenu(MEM.acl.custom),
    };
  }

  /* ---------------- custom commands ---------------- */
  const cname = low.replace(/^\//, '').split(/\s+/)[0];
  if (MEM.acl.custom[cname]) {
    if (!acl.has(MEM.acl, id, 'roll')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই\n/de বা /diag দেখুন', kb: null };
    const dice = parseDice(normalise(MEM.acl.custom[cname]));
    if (!dice) return { text: '❌ কাস্টম কমান্ডটা ভাঙা: ' + help.esc(MEM.acl.custom[cname]), kb: null };
    if (dice.win && !acl.has(MEM.acl, id, 'win')) return { text: '❌ win permission নেই', kb: null };
    pushCmd(d.id, dice);
    MEM.counters.cmd++;
    return { text: '✅ ' + describeDice(dice) + ' → ' + help.esc(d.name), kb: ui.DICE };
  }

  /* ---------------- devices ---------------- */
  if (low === '/de' || low === '/devices') {
    if (!acl.has(MEM.acl, id, 'de')) return { text: '❌ permission নেই', kb: null };
    return {
      text: deviceListText(id),
      kb: ui.deviceMenu(withAge(visibleDevices(id)), (selectedDevice(id) || {}).id, acl.bindOf(MEM.acl, id)),
    };
  }

  if (low.startsWith('/u ') || low.startsWith('/use ')) {
    if (!acl.has(MEM.acl, id, 'u')) return { text: '❌ permission নেই', kb: null };
    const arg = String(raw).trim().replace(/^\/(u|use)\s+/i, '').trim();
    const vis = visibleDevices(id);
    let target = null;
    const n = parseInt(arg, 10);
    if (!isNaN(n) && n >= 1 && n <= vis.length) target = vis[n - 1];
    else target = vis.find((d) => d.id === arg) || vis.find((d) => d.id.startsWith(arg));
    if (!target) {
      const bind = acl.bindOf(MEM.acl, id);
      return {
        text: '❌ ডিভাইস পাওয়া যায়নি: ' + help.esc(arg) +
              (bind ? '\n🔒 আপনি <code>' + bind + '</code> এ bind করা।' : ''),
        kb: null,
      };
    }
    MEM.sel[id] = target.id;
    saveNow();
    return {
      text: '✅ নির্বাচিত: <b>' + help.esc(target.name) + '</b>\nid: <code>' + target.id + '</code>',
      kb: ui.deviceMenu(withAge(visibleDevices(id)), target.id, acl.bindOf(MEM.acl, id)),
    };
  }

  if (low === '/st' || low === '/halt') {
    if (!acl.has(MEM.acl, id, 'st')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    d.halt = 1;
    pushCmd(d.id, { k: 'halt' });
    saveSoon();
    return {
      text: '⏸ halt পাঠানো হলো → ' + help.esc(d.name),
      kb: ui.deviceMenu(withAge(visibleDevices(id)), d.id, acl.bindOf(MEM.acl, id)),
    };
  }

  if (low === '/re' || low === '/resume') {
    if (!acl.has(MEM.acl, id, 're')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    d.halt = 0;
    pushCmd(d.id, { k: 'resume' });
    saveSoon();
    return {
      text: '▶️ resume পাঠানো হলো → ' + help.esc(d.name),
      kb: ui.deviceMenu(withAge(visibleDevices(id)), d.id, acl.bindOf(MEM.acl, id)),
    };
  }

  if (low === '/puce' || low === '/pause') {
    if (!acl.has(MEM.acl, id, 'cfg')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    const on = !(MEM.puce && MEM.puce[d.id]);
    if (!MEM.puce) MEM.puce = {};
    MEM.puce[d.id] = on;
    pushCmd(d.id, { k: 'pause', on });
    saveSoon();
    return {
      text: (on ? '⏸ <b>puce চালু</b> — poll ১০ মিনিটে নামবে'
                : '▶️ <b>puce বন্ধ</b> — poll স্বাভাবিক') + ' → ' + help.esc(d.name),
      kb: ui.deviceMenu(withAge(visibleDevices(id)), d.id, acl.bindOf(MEM.acl, id)),
    };
  }

  if (low.startsWith('/config')) {
    if (!acl.has(MEM.acl, id, 'cfg')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    const parts = String(raw).trim().split(/\s+/).slice(1);
    if (parts.length >= 2) {
      if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
      const g = parseInt(parts[0], 10);
      const i = parseInt(parts[1], 10);
      const p = parts[2] ? parseInt(parts[2], 10) : PAUSE_MS;
      if (!(g >= 1500 && i >= 1500 && p >= 1500)) {
        return { text: '❌ interval কমপক্ষে 1500ms হতে হবে', kb: null };
      }
      pushCmd(d.id, { k: 'cfg', g, i, p });
      return {
        text: '✅ config → game ' + g + 'ms · idle ' + i + 'ms · pause ' + p + 'ms\n→ ' + help.esc(d.name),
        kb: ui.CFG,
      };
    }
    return {
      text: '⚙️ <b>বর্তমান config</b>\n' + help.DIV + '\n' +
            'game  : ' + GAME_MS + ' ms (২ সেকেন্ড — ম্যাচ চলাকালীন)\n' +
            'idle  : ' + IDLE_MS + ' ms (৩০ মিনিট)\n' +
            'pause : ' + PAUSE_MS + ' ms (১০ মিনিট — /puce)\n' + help.DIV + '\n' +
            'বদলাতে: <code>/config 2000 1800000 600000</code>',
      kb: ui.CFG,
    };
  }

  if (low === '/uregi') {
    if (!acl.has(MEM.acl, id, 'de')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    delete MEM.devices[d.id];
    if (MEM.sel) delete MEM.sel[id];
    if (MEM.puce) delete MEM.puce[d.id];
    await saveNow();
    saveSoon();
    return {
      text: '🗑 <b>' + help.esc(d.name) + '</b> (<code>' + d.id + '</code>) registry থেকে সরানো হলো\n' +
            'ডিভাইসটি পরের poll-এ নিজে থেকে আবার register হবে।\n৩০ সেকেন্ড পর <code>/de</code> দিয়ে দেখুন।',
      kb: ui.deviceMenu(withAge(visibleDevices(id)), '', acl.bindOf(MEM.acl, id)),
    };
  }

  if (low === '/all') {
    if (!acl.has(MEM.acl, id, 'all')) return { text: '❌ permission নেই', kb: null };
    return { text: 'ব্যবহার: <code>/all &lt;command&gt;</code>\nযেমন <code>/all r 6 6 1</code>', kb: null };
  }
  if (low.startsWith('/all ')) {
    if (!acl.has(MEM.acl, id, 'all')) return { text: '❌ permission নেই', kb: null };
    const inner = String(raw).trim().slice(5).trim();
    const dice = parseDice(normalise(inner));
    if (!dice) return { text: '❌ কমান্ড বোঝা যায়নি: ' + help.esc(inner), kb: null };
    if (dice.win && !acl.has(MEM.acl, id, 'win')) return { text: '❌ win permission নেই', kb: null };
    const vis = visibleDevices(id);
    if (!vis.length) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    let n = 0;
    for (const d of vis) { if (pushCmd(d.id, dice)) n++; }
    return { text: '📡 ' + n + '/' + vis.length + ' ডিভাইসে পাঠানো হলো: ' + describeDice(dice), kb: ui.DICE };
  }

  if (low === '/info') {
    const d = selectedDevice(id);
    return {
      text: 'ℹ️ <b>BLACK FOX BD v' + VERSION + '</b>\n' + help.DIV + '\n' +
            'node    : ' + NODE_NAME + '\n' +
            'store   : ' + (s3.enabled() ? 'neon-s3 ✅' : 'memory ⚠️') + '\n' +
            'devices : ' + Object.keys(MEM.devices).length +
            ' (online ' + Object.values(MEM.devices).filter(onlineOf).length + ')\n' +
            'poll    : game ' + GAME_MS + 'ms · idle ' + Math.round(IDLE_MS / 60000) + 'min\n' +
            'role    : ' + acl.describe(MEM.acl, id) + '\n' +
            (d ? 'selected: ' + help.esc(d.name) + ' (<code>' + d.id + '</code>)' : 'selected: —'),
      kb: ui.CFG,
    };
  }

  if (low === '/ping') {
    return { text: '🏓 pong · ' + NODE_NAME + ' · v' + VERSION + '\n' + new Date().toISOString(), kb: ui.CFG };
  }

  if (low === '/diag') {
    return { text: diagText(id), kb: ui.CFG };
  }

  if (low === '/clear') {
    if (!acl.has(MEM.acl, id, 'roll')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    pushCmd(d.id, { k: 'dice', clear: true });
    return { text: '🧹 সব script মুছে ফেলা হলো → ' + help.esc(d.name), kb: ui.DICE };
  }

  if (low === '/random') {
    if (!acl.has(MEM.acl, id, 'roll')) return { text: '❌ permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই', kb: null };
    pushCmd(d.id, { k: 'dice', color: 'r', mode: 'seq', seq: ['R'], win: false, manual: false });
    return { text: '🎲 random roll → ' + help.esc(d.name), kb: ui.DICE };
  }

  /* ---------------- dice ---------------- */
  const dice = parseDice(low);
  if (dice) {
    if (!acl.has(MEM.acl, id, 'roll')) return { text: '❌ permission নেই', kb: null };
    if (dice.win && !acl.has(MEM.acl, id, 'win')) return { text: '❌ win permission নেই', kb: null };
    const d = selectedDevice(id);
    if (!d) return { text: '📭 কোনো ডিভাইস নেই\n/de বা /diag দেখুন', kb: null };
    pushCmd(d.id, dice);
    MEM.counters.cmd++;
    return {
      text: describeDice(dice) + ' → ' + help.esc(d.name) +
            (d.halt ? '\n⚠️ এই ডিভাইস halt করা আছে, /re দিন' : ''),
      kb: /win|\bw$/.test(low) ? ui.WIN : (/^2/.test(low) ? ui.TEAM : ui.DICE),
    };
  }

  /* ---------------- unknown ---------------- */
  const s = help.suggest(low, MEM.acl.custom);
  return {
    text: '❓ কমান্ড বোঝা যায়নি: <code>' + help.esc(raw) + '</code>\n' +
          (s ? 'আপনি কি <code>' + help.esc(s) + '</code> চেয়েছিলেন?\n' : '') +
          '<code>/h</code> দিয়ে সব কমান্ড দেখুন।',
    kb: ui.MAIN,
  };
}

function catKb(id) {
  const order = help.CATS.map((c) => c.id);
  const i = order.indexOf(id);
  const prev = order[(i - 1 + order.length) % order.length];
  const next = order[(i + 1) % order.length];
  const c = help.CAT_INDEX[id];
  const rows = [];
  let btns = [];
  for (const cm of c.cmds) {
    if (cm.u.startsWith('/')) continue;
    btns.push(ui.btn(cm.u, cm.t.length > 16 ? cm.t.slice(0, 16) : cm.t));
    if (btns.length === 3) { rows.push(ui.row(...btns)); btns = []; }
  }
  if (btns.length) rows.push(ui.row(...btns));
  rows.push(ui.row(
    { text: '‹ ' + help.CAT_INDEX[prev].icon, callback_data: 'h:c:' + prev },
    { text: '🏠 মেনু', callback_data: 'h:home' },
    { text: help.CAT_INDEX[next].icon + ' ›', callback_data: 'h:c:' + next },
  ));
  return rows;
}

/* ------------------------------------------------------------------ */
/*  stats text                                                         */
/* ------------------------------------------------------------------ */

/** "drop 4" is useless on its own; "drop 4 (bad-hmac 3 · no-session 1)" is a
 *  diagnosis. Composed once and reused by /de and /diag. */
function dropBreakdown() {
  const d = MEM.counters.drops || {};
  const parts = Object.keys(d).filter((k) => d[k] > 0).map((k) => k + ' ' + d[k]);
  return parts.length ? " (" + parts.join(" · ") + ")" : "";
}

/** Plain-language answer to "why is the list empty", so the operator does not
 *  have to interpret counters. */
function verdict(total, online) {
  const c = MEM.counters;
  if (total && online) return '✅ ঠিক আছে — ' + total + ' ডিভাইস, ' + online + ' এখন online।';
  if (total) return '🟡 ' + total + ' ডিভাইস আছে কিন্তু একটাও ৯০ সেকেন্ডে poll করেনি। গেমে আছেন কি না দেখুন।';
  if (!c.reg) return '🔴 একটাও register আসেনি — APK সার্ভারে পৌঁছাচ্ছে না (নেট / pin / host)।';
  if (c.reg && !c.regOk) return '🔴 register এসেছে কিন্তু সব ব্যর্থ — "শেষ error" লাইনটা দেখুন।';
  if (c.drop > 0) {
    return '🟠 register সফল হয়েছিল কিন্তু পরে session হারিয়েছে (drop ' + c.drop +
           ')। ডিভাইসটা ৩০ সেকেন্ডে নিজেই আবার handshake করবে — /de আবার দিন।';
  }
  if (c.uplink) return '🟠 client জীবিত (uplink ' + c.uplink + ') কিন্তু hello সম্পূর্ণ হয়নি। /diag-এর শেষ error দেখুন।';
  return '⚪ এখনো কোনো APK এই hub-এ কথা বলেনি।';
}

function deviceListText(chatId) {
  const list = visibleDevices(chatId);
  const bind = acl.bindOf(MEM.acl, chatId);
  if (!list.length) {
    const total = Object.keys(MEM.devices).length;
    let t = '📭 <b>কোনো ডিভাইস নেই</b>\n' + help.DIV + '\n';
    t += 'store   : ' + (s3.enabled() ? 'neon-s3 ✅' : 'memory ⚠️') + '\n';
    t += 'node    : ' + NODE_NAME + '\n';
    t += 'register: ' + MEM.counters.reg + 'টি এসেছে · সফল ' + MEM.counters.regOk +
         ' · ব্যর্থ ' + MEM.counters.regFail + '\n';
    if (MEM.counters.lastRegAt) {
      t += 'শেষ     : <code>' + help.esc(MEM.counters.lastRegId) + '</code> · ' +
           ago(MEM.counters.lastRegAt) + ' আগে\n';
    }
    if (MEM.counters.lastErr) t += 'শেষ error: ' + help.esc(MEM.counters.lastErr) + '\n';
    t += 'drop    : ' + MEM.counters.drop + dropBreakdown() + '\n';
    if (MEM.counters.uplink) {
      t += 'uplink  : ' + MEM.counters.uplink + ' টি (client জীবিত)';
      if (MEM.counters.lastUpAt) t += ' · ' + ago(MEM.counters.lastUpAt) + ' আগে';
      t += '\n';
    }
    t += 'রায়     : ' + verdict(total, 0) + '\n';
    t += help.DIV + '\n';
    if (bind) t += '⚠️ আপনি <code>' + bind + '</code> এ bind করা, ওই ডিভাইসটাই দেখা যাচ্ছে না।\n';
    else if (total) t += '⚠️ registry-তে ' + total + 'টি আছে কিন্তু আপনার দেখার অনুমতি নেই।\n';
    t += '<b>কী করবেন</b>\n';
    t += '১. গেম স্ক্রিন পর্যন্ত যান (register হয় সেখানে)\n';
    t += '২. <code>/diag</code> দিয়ে দেখুন register আসছে কি না\n';
    t += '৩. <code>/uregi</code> দিয়ে রিফ্রেশ করুন\n';
    t += '৪. ৩০ সেকেন্ড অপেক্ষা করে আবার <code>/de</code>';
    return t;
  }
  let t = '🎮 <b>ডিভাইস (' + list.length + ')</b>\n';
  if (bind) t += '🔒 bind: <code>' + bind + '</code>\n';
  t += help.DIV + '\n';
  list.forEach((d, i) => {
    const on = onlineOf(d);
    t += (on ? '🟢' : '⚪') + ' <b>' + (i + 1) + '. ' + help.esc(d.name) + '</b>\n';
    t += '   id: <code>' + d.id + '</code>\n';
    t += '   ' + (d.st === 'ingame' ? '🎮 ingame' : '📴 idle') +
         ' · শেষ poll ' + ago(d.last) + ' আগে · ' + (d.polls || 0) + ' poll\n';
    if (d.halt) t += '   ⏸ halted\n';
  });
  return t;
}

function diagText(chatId) {
  const devs = Object.values(MEM.devices);
  const on = devs.filter(onlineOf).length;
  let t = '🔧 <b>ডায়াগনস্টিক</b>\n' + help.DIV + '\n';
  t += 'node      : ' + NODE_NAME + ' (v' + VERSION + ')\n';
  t += 'store     : ' + (s3.enabled() ? 'neon-s3 ✅' : 'memory ⚠️') + '\n';
  t += 'devices   : ' + devs.length + ' (online ' + on + ')\n';
  t += 'register  : ' + MEM.counters.reg + ' এসেছে · ' + MEM.counters.regOk +
       ' সফল · ' + MEM.counters.regFail + ' ব্যর্থ\n';
  t += 'poll      : ' + MEM.counters.poll + ' · drop ' + MEM.counters.drop + '\n';
  t += 'drop why  : ' + (dropBreakdown() || ' নেই') + '\n';
  t += 'cmd       : ' + MEM.counters.cmd + ' · callback ' + MEM.counters.cb + '\n';
  t += 'uplink    : ' + (MEM.counters.uplink || 0) +
       (MEM.counters.lastUpAt ? ' · শেষ ' + ago(MEM.counters.lastUpAt) + ' আগে' : '') + '\n';
  t += 'legacy    : reg ' + (MEM.counters.legacyReg || 0) + ' · salt ' + (MEM.counters.legacySalt || 0) + '\n';
  if (MEM.counters.lastRegAt) {
    t += 'শেষ reg  : <code>' + help.esc(MEM.counters.lastRegId) + '</code> · ' +
         ago(MEM.counters.lastRegAt) + ' আগে\n';
  }
  t += 'শেষ error: ' + (MEM.counters.lastErr ? help.esc(MEM.counters.lastErr) : 'none') + '\n';
  t += 'sessions  : ' + Object.keys(MEM.sessions).length + '\n';
  if (MEM.counters.lastDropAt) {
    t += 'শেষ drop : ' + (MEM.counters.lastDropId ? help.esc(MEM.counters.lastDropId.slice(0, 12)) : '—') +
         ' · ' + ago(MEM.counters.lastDropAt) + ' আগে\n';
  }
  t += help.DIV + '\n<b>রায়</b>\n  ' + verdict(devs.length, on) + '\n';
  t += help.DIV + '\n<b>শেষ ১০টা event</b>\n';
  const lg = MEM.log.slice(-10);
  if (!lg.length) t += '  (এখনো কিছু নেই)\n';
  for (const e of lg) {
    const hh = new Date(e.t).toISOString().slice(11, 19);
    t += '  ' + hh + ' ' + help.esc(e.path) + ' ' + e.status + ' ' +
         (e.dev ? help.esc(e.dev.slice(0, 10)) : '—') + ' ' + help.esc(e.reason || '') + '\n';
  }
  const my = MEM.replies[String(chatId)];
  if (my && my.length) {
    t += help.DIV + '\n<b>শেষ reply</b>\n  ' + help.esc(my[my.length - 1].text.slice(0, 160)) + '\n';
  }
  return t;
}

/* ------------------------------------------------------------------ */
/*  HTTP                                                               */
/* ------------------------------------------------------------------ */

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';

  try {
    await loadState();

    if (path === '/health' || path === '/') {
      return json(res, 200, {
        ok: true, version: VERSION, proto: PROTO, node: NODE_NAME,
        store: s3.enabled() ? 'neon-s3' : 'memory',
        devices: Object.keys(MEM.devices).length,
        online: Object.values(MEM.devices).filter(onlineOf).length,
      });
    }

    if (path === '/api/debug') {
      const tok = url.searchParams.get('token') || '';
      if (tok !== DEBUG_TOKEN) return json(res, 403, { ok: false, error: 'forbidden' });
      return json(res, 200, {
        ok: true, version: VERSION, node: NODE_NAME,
        store: s3.enabled() ? 'neon-s3' : 'memory',
        counters: MEM.counters,
        devices: withAge(Object.values(MEM.devices)),
        sessions: Object.keys(MEM.sessions).length,
        sel: MEM.sel || {},
        puce: MEM.puce || {},
        custom: MEM.acl.custom,
        admins: MEM.acl.admins,
        users: MEM.acl.users,
        replies: MEM.replies || {},
        log: MEM.log.slice(-40),
      });
    }

    /* ---- APK: handshake ---- */
    if (path === '/api/hello' && req.method === 'POST') {
      const raw = await readBody(req);
      MEM.counters.reg++;
      MEM.counters.lastRegAt = Date.now();
      let body;
      try {
        body = JSON.parse(raw);
      } catch (e) {
        MEM.counters.regFail++;
        MEM.counters.lastErr = 'bad json';
        logReq(path, 400, '', 'bad json');
        return json(res, 400, { ok: false, error: 'bad json' });
      }
      /*
       * Field tolerance. Builds in the field send several spellings of the same
       * three values ("dev"/"device"/"id", "pk"/"pub"/"key", "name"/"dn").
       * A hub that only knows today's spelling rejects a perfectly good
       * registration, and the operator's only symptom is an empty /de. Accept
       * every spelling this project has ever shipped.
       */
      const pick = (...names) => {
        for (const n of names) if (body[n] != null && String(body[n]).length) return String(body[n]);
        return '';
      };
      const dev = pick('dev', 'device', 'deviceId', 'id');
      if (!dev) {
        MEM.counters.regFail++;
        MEM.counters.lastErr = 'no dev id (keys: ' + Object.keys(body).join(',') + ')';
        logReq(path, 400, '', 'no dev id');
        return json(res, 400, { ok: false, error: 'no dev' });
      }
      const pkRaw = pick('pk', 'pub', 'key', 'pubkey');
      const pk = unb64(pkRaw);
      if (pk.length !== 65 || pk[0] !== 4) {
        MEM.counters.regFail++;
        MEM.counters.lastErr = 'bad_pubkey len=' + pk.length + ' dev=' + dev;
        logReq(path, 400, dev, 'bad pubkey');
        return json(res, 400, { ok: false, error: 'bad pk', len: pk.length });
      }

      const ecdh = crypto.createECDH('prime256v1');
      ecdh.generateKeys();
      const serverPub = ecdh.getPublicKey();
      let secret;
      try {
        secret = ecdh.computeSecret(pk);
      } catch (e) {
        MEM.counters.regFail++;
        MEM.counters.lastErr = 'ecdh fail dev=' + dev;
        logReq(path, 400, dev, 'ecdh fail');
        return json(res, 400, { ok: false, error: 'ecdh' });
      }

      const sid = crypto.randomBytes(16).toString('hex');
      const ks = keySet(secret);
      /* keys[0] is the configured salt; the rest are historical ones a shipped
         APK may still be deriving from. Verification walks the whole list. */
      MEM.sessions[sid] = { dev, keys: ks, aes: ks[0].aes, mac: ks[0].mac, at: Date.now() };
      const cut = Date.now() - 3600000;
      for (const k of Object.keys(MEM.sessions)) if (MEM.sessions[k].at < cut) delete MEM.sessions[k];

      const d = upsertDevice(dev, pick('name', 'dn', 'model'), pick('pkg', 'package'), pick('st', 'state'));
      d.halt = d.halt || 0;
      MEM.counters.regOk++;
      MEM.counters.lastRegId = dev;
      MEM.counters.lastErr = '';
      logReq(path, 200, dev, 'ok');

      return json(res, 200, {
        ok: 1, sid,
        spk: b64(serverPub),
        cfg: { g: GAME_MS, i: IDLE_MS, p: PAUSE_MS },
        node: NODE_NAME,
        halt: d.halt ? 1 : 0,
      });
    }

    /* ---- APK: uplink (persistence heartbeat) ----
     *
     * Render's free tier spins a sleeping service up only when a request lands,
     * and the first request of a cold start can take 30-50s. A device whose
     * hello times out looks exactly like a missing device, so the APK can post
     * a tiny unauthenticated "I am here" that wakes the dyno without needing a
     * session. It never creates a device entry -- /de stays honest -- it only
     * records that a client is alive and asks it to handshake again.
     */
    if (path === '/api/uplink' && req.method === 'POST') {
      const raw = await readBody(req);
      MEM.counters.uplink = (MEM.counters.uplink || 0) + 1;
      MEM.counters.lastUpAt = Date.now();
      let b = {};
      try { b = JSON.parse(raw) || {}; } catch (e) { /* tolerate empty body */ }
      const id = String(b.dev || b.device || b.id || '');
      if (id) MEM.counters.lastUpId = id;
      logReq(path, 200, id, 'uplink');
      return json(res, 200, {
        ok: 1,
        node: NODE_NAME,
        warm: 1,
        cfg: { g: GAME_MS, i: IDLE_MS, p: PAUSE_MS },
        reg: 1,
      });
    }

    /* ---- Legacy registration (pre-hello builds) ----
     *
     * Older clients registered with a plain POST and then polled with a device
     * secret instead of an ECDH session. Keeping the endpoint alive means those
     * installs still appear in /de instead of vanishing after an upgrade.
     */
    if ((path === '/api/register' || path === '/api/reg') && req.method === 'POST') {
      const raw = await readBody(req);
      MEM.counters.reg++;
      MEM.counters.lastRegAt = Date.now();
      let b = {};
      try { b = JSON.parse(raw) || {}; } catch (e) {
        MEM.counters.regFail++;
        MEM.counters.lastErr = 'legacy bad json';
        return json(res, 400, { ok: false, error: 'bad json' });
      }
      const dev = String(b.dev || b.device || b.id || b.deviceId || '');
      if (!dev) {
        MEM.counters.regFail++;
        MEM.counters.lastErr = 'legacy no dev id';
        return json(res, 400, { ok: false, error: 'no dev' });
      }
      const d = upsertDevice(dev, b.name || b.dn, b.pkg || b.package, b.st || b.state || 'idle', ip);
      d.legacy = 1;
      MEM.counters.regOk++;
      MEM.counters.legacyReg = (MEM.counters.legacyReg || 0) + 1;
      MEM.counters.lastRegId = dev;
      logReq(path, 200, dev, 'legacy ok');
      return json(res, 200, {
        ok: 1, dev, legacy: 1, node: NODE_NAME,
        cfg: { g: GAME_MS, i: IDLE_MS, p: PAUSE_MS },
      });
    }

    /* ---- APK: poll ---- */
    if (path === '/api/poll' && req.method === 'POST') {
      MEM.counters.poll++;
      const sid = req.headers['x-sid'] || '';
      const sig = req.headers['x-sig'] || '';
      const sess = MEM.sessions[sid];
      if (!sess) {
        /* A session map lives in memory and is lost on every Render recycle.
           The APK recovers by re-handshaking on 401, but the drop is counted
           under its own reason so /diag can tell a restart apart from a real
           crypto mismatch. */
        drop('no-session-after-restart', '');
        logReq(path, 401, '', 'no session');
        return json(res, 401, { ok: false, error: 'no session' });
      }
      const wire = await readBody(req);
      const keys = Array.isArray(sess.keys) ? sess.keys : [{ aes: sess.aes, mac: sess.mac, salt: SALT_CANDIDATES[0] }];
      const hit = keys.find((k) => hmacB64(k.mac, sid + '|' + wire) === sig);
      if (!hit) {
        drop('bad-hmac', sess.dev);
        logReq(path, 401, sess.dev, 'bad hmac');
        return json(res, 401, { ok: false, error: 'bad sig' });
      }
      /* Pin the session to the salt that actually worked, so the next poll is a
         single comparison instead of a walk. */
      sess.aes = hit.aes; sess.mac = hit.mac; sess.salt = hit.salt;
      sess.keys = keys;
      let inner;
      try {
        inner = JSON.parse(aesDec(sess.aes, wire));
      } catch (e) {
        drop('decrypt-fail', sess.dev);
        logReq(path, 400, sess.dev, 'decrypt fail');
        return json(res, 400, { ok: false, error: 'decrypt' });
      }
      sess.at = Date.now();
      if (hit.salt !== SALT_CANDIDATES[0]) {
        /* Worth surfacing: the APK is running a salt this hub no longer
           advertises. Harmless, but it explains a future rotation. */
        MEM.counters.legacySalt = (MEM.counters.legacySalt || 0) + 1;
      }

      const d = upsertDevice(sess.dev, inner.name, inner.pkg, inner.st, ip);
      /* `d.q` is absent until the first command is pushed, so it must be
         defaulted before .length is read — reading it on an undefined queue
         threw and turned every poll into a 500. That is the v8 regression this
         line exists to prevent coming back. */
      const q = Array.isArray(d.q) ? d.q : [];
      const cmds = q.splice(0, q.length);
      d.q = q;
      saveSoon();

      const out = {
        ok: 1,
        cfg: { g: GAME_MS, i: IDLE_MS, p: PAUSE_MS },
        node: NODE_NAME,
        reg: 1,
        halt: d.halt ? 1 : 0,
        cmds,
      };
      const body = aesEnc(sess.aes, JSON.stringify(out));
      logReq(path, 200, sess.dev, 'ok');
      res.writeHead(200, {
        'content-type': 'text/plain',
        'x-sig': hmacB64(sess.mac, sid + '|' + body),
        'x-node': NODE_NAME,
      });
      return res.end(body);
    }

    /* ---- Telegram webhook ---- */
    if (path === '/tg' && req.method === 'POST') {
      const raw = await readBody(req);
      let upd;
      try {
        upd = JSON.parse(raw);
      } catch (e) {
        return json(res, 200, { ok: true });
      }
      try {
        await handleUpdate(upd);
      } catch (e) {
        logReq('/tg', 500, '', String(e.message).slice(0, 80));
      }
      return json(res, 200, { ok: true });
    }

    /* ---- setup: point Telegram at this node ---- */
    if (path === '/setup') {
      const tok = url.searchParams.get('token') || '';
      if (tok !== BOT_TOKEN) return json(res, 403, { ok: false, error: 'forbidden' });
      const host = req.headers.host;
      const hook = url.searchParams.get('hook') || ('https://' + host + '/tg');
      const r = await tg('setWebhook', {
        url: hook,
        allowed_updates: ['message', 'edited_message', 'callback_query'],
        drop_pending_updates: true,
      });
      return json(res, 200, r);
    }

    if (path === '/webhookinfo') {
      return json(res, 200, await tg('getWebhookInfo', {}));
    }

    return json(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    logReq(path, 500, '', String(e.message));
    return json(res, 500, { ok: false, error: String(e.message) });
  }
});

/* ------------------------------------------------------------------ */
/*  update handling                                                    */
/* ------------------------------------------------------------------ */

async function handleUpdate(upd) {
  /* --- inline keyboard tap --- */
  if (upd.callback_query) {
    const cq = upd.callback_query;
    const chatId = String(cq.message && cq.message.chat ? cq.message.chat.id : '');
    const msgId = cq.message ? cq.message.message_id : null;
    const from = cq.from || {};
    if (from.username) MEM.names[String(from.username).toLowerCase()] = chatId;
    MEM.counters.cb++;
    const data = String(cq.data || '');
    logReq('/cb', 200, chatId, data.slice(0, 24));

    /* help navigation never touches a device */
    if (data.startsWith('h:')) {
      await answerCb(cq.id, '');
      if (!rateOk(chatId)) return;
      if (data === 'h:home') {
        return reply(chatId, help.homeText(acl.isAdmin(MEM.acl, chatId), MEM.acl.custom), ui.MAIN);
      }
      if (data.startsWith('h:c:')) {
        const cat = data.slice(4);
        if (!help.CAT_INDEX[cat]) return;
        if (cat === 'cus') {
          return reply(chatId, help.catText('cus', MEM.acl.custom), ui.customMenu(MEM.acl.custom));
        }
        return reply(chatId, help.catText(cat, MEM.acl.custom), catKb(cat));
      }
      return;
    }

    /* device tap: select, then re-render */
    if (data.startsWith('u:')) {
      const want = data.slice(2);
      const res = await dispatch(chatId, '/u ' + want);
      await answerCb(cq.id, res && res.text.startsWith('✅') ? 'সিলেক্ট হলো' : 'পাওয়া যায়নি');
      if (res) {
        if (msgId) await editKb(chatId, msgId, res.kb || ui.MAIN);
        await reply(chatId, res.text, res.kb);
      }
      return;
    }

    /* command tap: the SAME dispatcher the text handler uses */
    if (data.startsWith('c:')) {
      const cmd = data.slice(2);
      const res = await dispatch(chatId, cmd);
      if (!res) {
        await answerCb(cq.id, 'বোঝা যায়নি');
        return;
      }
      const refused = res.text.startsWith('❌');
      await answerCb(cq.id, refused ? 'permission নেই' : '✓');
      /* The reply carries the keyboard, not just the edited old message —
         otherwise a second tap has nothing to tap. */
      if (msgId) await editKb(chatId, msgId, res.kb || ui.MAIN);
      await reply(chatId, res.text, res.kb || null);
      return;
    }

    await answerCb(cq.id, '');
    return;
  }

  /* --- plain message --- */
  const msg = upd.message || upd.edited_message;
  if (!msg || !msg.text) return;
  const chatId = String(msg.chat.id);
  const from = msg.from || {};
  if (from.username) MEM.names[String(from.username).toLowerCase()] = chatId;
  const res = await dispatch(chatId, msg.text);
  if (!res) return;
  logReq('/tg', 200, chatId, msg.text.slice(0, 20));
  await reply(chatId, res.text, res.kb);
}

server.listen(PORT, () => {
  console.log('BLACK FOX BD v' + VERSION + ' hub on :' + PORT + ' node=' + NODE_NAME +
              ' store=' + (s3.enabled() ? 'neon-s3' : 'memory'));
  loadState().catch(() => {});
});
