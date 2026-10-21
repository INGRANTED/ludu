'use strict';
/*
 * BLACK FOX BD v10 — Bengali command guide.
 *
 * Every command the bot accepts lives here exactly once: the help page, the
 * inline keyboard and the dispatcher all read from this table, so a command can
 * never exist in one place and be missing from another.
 */

const CATS = [
  {
    id: 'dice',
    icon: '🎲',
    title: 'ডাইস কমান্ড',
    intro: 'গুতির ডাইস নিয়ন্ত্রণ। রঙ লিখে তারপর মান।',
    cmds: [
      {
        u: 'r 5', t: 'একবার ডাইস', d: 'লাল রঙের জন্য একবার ৫ পড়বে। রঙ: r লাল · g সবুজ · y হলুদ · b নীল · p বেগুনি · o কমলা',
        ex: ['r 5', 'g 6', 'b 1'], note: 'শুধু পরের একবার ডাইসে কাজ করবে',
      },
      {
        u: 'r 6 6 1', t: 'টানা তিনবার', d: 'এই তিনটি মান পরপর বসিয়ে দেবে — ৬, ৬, ১। এরপর আবার স্বাভাবিক',
        ex: ['r 6 6 1', 'y 6 6 2', 'g 6 6 random'], note: 'তিনের বেশি মান দিলে প্রথম তিনটাই নেবে',
      },
      {
        u: 'r 6 random', t: 'প্রথমটা ফিক্স, বাকি র‍্যান্ডম', d: 'প্রথম ডাইস নিশ্চিত ৬, পরেরগুলো স্বাভাবিক র‍্যান্ডম',
        ex: ['r 6 random', 'g 5 random'], note: 'হিউম্যান-লাইক distribution বজায় থাকে',
      },
      { u: 'random', t: 'একবার র‍্যান্ডম', d: 'কোনো ফিক্স ছাড়া স্বাভাবিক ডাইস', ex: ['random'] },
      {
        u: 'clear', t: 'সব স্ক্রিপ্ট মুছে ফেলা', d: 'সব রঙের জমানো ডাইস স্ক্রিপ্ট একসাথে মুছে দেবে',
        ex: ['clear', 'r clear'], note: 'r clear দিলে শুধু লালেরটা মুছবে',
      },
    ],
  },
  {
    id: 'win',
    icon: '🎯',
    title: 'Win মোড',
    intro: 'শেষ ঘরে পৌঁছাতে যতটা লাগে ঠিক ততটাই পড়বে — বেশি না, কম না।',
    cmds: [
      {
        u: 'r w', t: 'লাল জিতবে (অটো)', d: 'লালের গুতি শেষ ঘরে পৌঁছাতে যে মান দরকার, সেটাই আসবে। বট নিজে খেলবে',
        ex: ['r w', 'y w', 'g w', 'b w'], note: 'শেষ ঘরে ৫ লাগলে ৫-ই পড়বে, ৬ পড়বে না',
      },
      {
        u: 'r w manual', t: 'লাল জিতবে (নিজে খেলবেন)', d: 'একই win নিশ্চয়তা, কিন্তু গুতি সরানোর কাজ আপনি নিজে করবেন',
        ex: ['r w manual'], note: 'অটো-প্লে বন্ধ থাকবে',
      },
      {
        u: 'off', t: 'win মোড বন্ধ', d: 'সব রঙের win নিশ্চয়তা বন্ধ করে স্বাভাবিক ডাইসে ফিরবে',
        ex: ['off'], note: 'স্ক্রিপ্ট মুছবে না, শুধু win বন্ধ',
      },
    ],
  },
  {
    id: 'team',
    icon: '👥',
    title: 'টিম মোড',
    intro: 'দুই রঙ একসাথে চালানো — cut priority সহ।',
    cmds: [
      { u: '2ry', t: 'লাল + হলুদ', d: 'দুই রঙের গুতি একসাথে চালাবে, কাটার সুযোগ আগে দেখবে', ex: ['2ry', '2gb', '2rb'] },
      { u: '2gb', t: 'সবুজ + নীল', d: 'একইভাবে সবুজ আর নীল জোড়া', ex: ['2gb'] },
      { u: '2off', t: 'টিম মোড বন্ধ', d: 'জোড়া ভেঙে দেবে', ex: ['2off'] },
    ],
  },
  {
    id: 'dev',
    icon: '📱',
    title: 'ডিভাইস',
    intro: 'কোন ফোনে কমান্ড যাবে সেটা এখান থেকে ঠিক করুন।',
    cmds: [
      { u: '/de', t: 'ডিভাইস লিস্ট', d: 'সব ডিভাইস — 🟢 online, ⚪ offline, কতক্ষণ আগে শেষ poll', ex: ['/de'], note: 'খালি হলে কারণও দেখাবে' },
      { u: '/u 1', t: 'ডিভাইস সিলেক্ট', d: 'নম্বর বা id দিয়ে ডিভাইস বাছুন', ex: ['/u 1', '/u a1b2c3'], note: 'bind করা থাকলে শুধু নিজের ডিভাইস দেখবেন' },
      { u: '/all r 6 6 1', t: 'সব ডিভাইসে একসাথে', d: 'একই কমান্ড সব ডিভাইসে পাঠাবে', ex: ['/all r w', '/all 2gb'] },
      { u: '/st', t: 'থামানো', d: 'ডিভাইসের সব কমান্ড বন্ধ (halt)', ex: ['/st'] },
      { u: '/re', t: 'আবার চালু', d: 'halt করা ডিভাইস আবার চালু', ex: ['/re'] },
      { u: '/puce', t: 'pause টগল', d: 'বিরতিতে poll ১০ মিনিটে নামবে', ex: ['/puce'], note: 'আবার /puce দিলে বন্ধ' },
      { u: '/uregi', t: 'রেজিস্ট্রেশন রিফ্রেশ', d: 'ডিভাইস registry থেকে মুছে দেয়, পরে নিজেই আবার register হবে', ex: ['/uregi'], note: 'ডিভাইস দেখা না গেলে এটা দিয়ে দেখুন' },
    ],
  },
  {
    id: 'cfg',
    icon: '⚙️',
    title: 'সেটিংস',
    intro: 'poll গতি আর সিস্টেমের অবস্থা।',
    cmds: [
      { u: '/config', t: 'বর্তমান সেটিং', d: 'গেমে ২s · idle ৩০ মিনিট · pause ১০ মিনিট', ex: ['/config'] },
      { u: '/config 2000 1800000 600000', t: 'সেটিং বদলানো', d: 'ক্রম: গেম(millisecond) · idle · pause', ex: ['/config 2000 1800000 600000'], note: 'সর্বনিম্ন ১৫০০ms' },
      { u: '/info', t: 'সিস্টেম তথ্য', d: 'node, store, ডিভাইস সংখ্যা, আপনার role', ex: ['/info'] },
      { u: '/ping', t: 'জীবিত কিনা', d: 'কোন node উত্তর দিচ্ছে দেখাবে', ex: ['/ping'] },
      { u: '/diag', t: 'ডায়াগনস্টিক', d: 'register কতগুলো এসেছে, শেষ error, শেষ ১০টা event', ex: ['/diag'], note: 'ডিভাইস না এলে প্রথমে এটাই দেখুন' },
    ],
  },
  {
    id: 'adm',
    icon: '🔐',
    title: 'অ্যাডমিন',
    intro: 'শুধু লগইন করা অ্যাডমিন এই কমান্ডগুলো চালাতে পারবেন।',
    cmds: [
      { u: '/login <pass>', t: 'অ্যাডমিন লগইন', d: 'পাসওয়ার্ড দিয়ে নিজের chat কে অ্যাডমিন বানান', ex: ['/login ****'], note: 'একবারই লাগবে, Neon-এ সেভ থাকে' },
      { u: '/per @name /de,/re,/auto', t: 'পারমিশন দেওয়া', d: 'নির্দিষ্ট ইউজারকে ঠিক যতটা দরকার ততটাই দিন', ex: ['/per @blacktest /de,/re', '/per @blacktest win', '/per @blacktest rw'], note: 'auto = roll + win' },
      { u: '/per @name u <device_id>', t: 'ডিভাইসে bind', d: 'ইউজারকে এক ডিভাইসে আটকে দেয় — অন্য ডিভাইস দেখতেও পাবে না', ex: ['/per @blacktest u a1b2c3'], note: 'bind করা ইউজার শুধু ওই ডিভাইসই দেখে' },
      { u: '/bind <chat_id> <device_id>', t: 'bind (আলাদা)', d: 'একই কাজ, তবে chat_id বা নাম দিয়ে', ex: ['/bind 990077 a1b2c3'] },
      { u: '/unbind <chat_id>', t: 'bind সরানো', d: 'ইউজার আবার সব ডিভাইস দেখবে', ex: ['/unbind @blacktest'] },
      { u: '/revoke <chat_id>', t: 'সব পারমিশন বাতিল', d: 'ইউজারকে আবার শূন্য থেকে শুরু করতে দেয়', ex: ['/revoke @blacktest'] },
      { u: '/users', t: 'সব ইউজার', d: 'কোন ইউজারের কী পারমিশন আছে', ex: ['/users'] },
      { u: '/newcmd mywin "r w"', t: 'নতুন কমান্ড', d: 'নিজের শর্টকাট বানান', ex: ['/newcmd mywin "r w"', '/newcmd cut "2ry"'], note: 'কোটেশন দিলে ভালো' },
      { u: '/delcmd mywin', t: 'কমান্ড মুছে ফেলা', d: 'বানানো শর্টকাট সরাবে', ex: ['/delcmd mywin'] },
    ],
  },
  {
    id: 'cus',
    icon: '🛠️',
    title: 'কাস্টম কমান্ড',
    intro: 'অ্যাডমিন /newcmd দিয়ে যেগুলো বানিয়েছেন, সেগুলো এখানে দেখাবে।',
    cmds: [
      { u: '/newcmd <name> <action>', t: 'বানানো', d: 'যেকোনো কমান্ডের শর্টকাট', ex: ['/newcmd fast "r 6 6 1"'] },
      { u: '/<name>', t: 'চালানো', d: 'বানানো শর্টকাট সিলেক্ট করা ডিভাইসে যাবে', ex: ['/fast'] },
    ],
  },
  {
    id: 'link',
    icon: '🔌',
    title: 'সংযোগ',
    intro: 'APK আর বট কীভাবে কথা বলে, আর কোথায় আটকাচ্ছে।',
    cmds: [
      { u: '/de', t: 'ডিভাইস দেখা যাচ্ছে না?', d: '১) গেম স্ক্রিন পর্যন্ত যান · ২) /diag দেখুন · ৩) /uregi দিন · ৪) ৩০ সেকেন্ড অপেক্ষা', ex: ['/diag', '/uregi', '/de'] },
      { u: '/whoami', t: 'নিজের পরিচয়', d: 'আপনার chat_id, role, permission, সিলেক্ট করা ডিভাইস', ex: ['/whoami'] },
    ],
  },
];

const CAT_INDEX = {};
for (const c of CATS) CAT_INDEX[c.id] = c;

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const DIV = '━━━━━━━━━━━━━━━━';

function homeText(admin, custom) {
  const n = CATS.reduce((a, c) => a + c.cmds.length, 0) + Object.keys(custom || {}).length;
  let t = '📖 <b>BLACK FOX BD v10 — কমান্ড গাইড</b>\n' + DIV + '\n';
  t += 'মোট ' + n + 'টি কমান্ড, ' + CATS.length + 'টি বিভাগ।\n';
  t += 'নিচের বাটনে চাপুন, অথবা সরাসরি কমান্ড লিখুন — দুটোর ফল একই।\n' + DIV + '\n';
  for (const c of CATS) {
    t += c.icon + ' <b>' + esc(c.title) + '</b> — ' + c.cmds.length + 'টি কমান্ড\n';
  }
  if (Object.keys(custom || {}).length) {
    t += '🛠️ <b>কাস্টম</b> — ' + Object.keys(custom).length + 'টি\n';
  }
  t += DIV + '\n';
  t += admin ? '👑 আপনি অ্যাডমিন — সব কমান্ড খোলা আছে।' : '🔒 শুধু অনুমতি পাওয়া কমান্ডগুলো চলবে।';
  return t;
}

function catText(id, custom) {
  const c = CAT_INDEX[id];
  if (!c) return homeText(false, custom);
  let t = c.icon + ' <b>' + esc(c.title) + '</b>\n' + DIV + '\n' + esc(c.intro) + '\n' + DIV + '\n';
  for (const cm of c.cmds) {
    t += '\n<code>' + esc(cm.u) + '</code>\n';
    t += '  <b>' + esc(cm.t) + '</b>\n';
    t += '  ' + esc(cm.d) + '\n';
    if (cm.ex && cm.ex.length) t += '  ▸ ' + cm.ex.map((e) => '<code>' + esc(e) + '</code>').join('  ▸ ') + '\n';
    if (cm.note) t += '  ⓘ ' + esc(cm.note) + '\n';
  }
  if (id === 'cus') {
    const keys = Object.keys(custom || {});
    t += '\n' + DIV + '\n';
    t += keys.length ? 'এখন আছে: ' + keys.map((k) => '<code>/' + esc(k) + '</code>').join(' ') : 'এখনো কোনো কাস্টম কমান্ড নেই।';
  }
  return t;
}

/** Flat list of every command string, for the unknown-command suggestion. */
function allCommands(custom) {
  const out = [];
  for (const c of CATS) for (const cm of c.cmds) out.push(cm.u.split(' ')[0]);
  for (const k of Object.keys(custom || {})) out.push('/' + k);
  return Array.from(new Set(out));
}

function suggest(text, custom) {
  const t = String(text || '').toLowerCase().replace(/^\//, '');
  if (!t) return null;
  let best = null;
  let bestD = Infinity;
  for (const c of allCommands(custom)) {
    const cand = c.replace(/^\//, '').toLowerCase().split(' ')[0];
    const d = lev(t, cand);
    if (d < bestD) { bestD = d; best = c; }
  }
  return bestD <= Math.max(2, Math.floor(t.length / 2)) ? best : null;
}

function lev(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = new Array(n + 1);
  let cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    const tmp = prev; prev = cur; cur = tmp;
  }
  return prev[n];
}

module.exports = { CATS, CAT_INDEX, homeText, catText, allCommands, suggest, esc, DIV };
