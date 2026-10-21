'use strict';
/*
 * BLACK FOX BD v9 — inline keyboard.
 *
 * The single rule that keeps this correct: a button does not own any logic. It
 * carries a command string as callback data, the callback handler feeds that
 * string to the exact same dispatch() the text handler uses, and the only thing
 * this module adds is a re-render of the keyboard afterwards. If a button and a
 * typed command ever disagreed, there would be a second implementation to keep
 * in sync — there is not.
 *
 * callback_data budget is 64 bytes, so device ids are truncated to 12 hex chars
 * (a collision needs two devices sharing 48 bits, and /u accepts a prefix).
 */

const help = require('./help');

const MAX_CB = 64;

function cb(data) {
  return data.length > MAX_CB ? data.slice(0, MAX_CB) : data;
}

function btn(cmd, label) {
  return { text: label, callback_data: cb('c:' + cmd) };
}

function row(...b) {
  return b;
}

/* ------------------------------------------------------------------ */
/*  menus                                                              */
/* ------------------------------------------------------------------ */

const MAIN = [
  row({ text: '🎲 ডাইস', callback_data: 'h:c:dice' }, { text: '🎯 Win', callback_data: 'h:c:win' }, { text: '👥 টিম', callback_data: 'h:c:team' }),
  row({ text: '📱 ডিভাইস', callback_data: 'h:c:dev' }, { text: '⚙️ সেটিংস', callback_data: 'h:c:cfg' }),
  row({ text: '🔐 অ্যাডমিন', callback_data: 'h:c:adm' }, { text: '🛠️ কাস্টম', callback_data: 'h:c:cus' }),
  row({ text: '🔌 সংযোগ', callback_data: 'h:c:link' }, { text: '❓ হেল্প', callback_data: 'h:home' }),
  row(btn('/de', '📋 ডিভাইস লিস্ট'), btn('/diag', '🔧 ডায়াগনস্টিক')),
];

const DICE = [
  row(btn('r 6 6 1', 'r 6 6 1'), btn('r 6 6 2', 'r 6 6 2'), btn('r 6 6 random', 'r 6 6 rand')),
  row(btn('r 6 random', 'r 6 random'), btn('r 5', 'r 5'), btn('r 1', 'r 1')),
  row(btn('random', '🎲 random'), btn('clear', '🧹 clear')),
  row(btn('g 6 6 1', 'g 6 6 1'), btn('y 6 6 1', 'y 6 6 1'), btn('b 6 6 1', 'b 6 6 1')),
  row({ text: '‹ ডাইস গাইড', callback_data: 'h:c:dice' }, { text: '🏠 মেনু', callback_data: 'h:home' }),
];

const WIN = [
  row(btn('r w', '🎯 r w'), btn('y w', '🎯 y w')),
  row(btn('g w', '🎯 g w'), btn('b w', '🎯 b w')),
  row(btn('r w manual', 'r w manual'), btn('off', '⛔ off')),
  row({ text: '‹ Win গাইড', callback_data: 'h:c:win' }, { text: '🏠 মেনু', callback_data: 'h:home' }),
];

const TEAM = [
  row(btn('2ry', '2ry'), btn('2gb', '2gb'), btn('2rb', '2rb')),
  row(btn('2gy', '2gy'), btn('2off', '2off')),
  row({ text: '‹ টিম গাইড', callback_data: 'h:c:team' }, { text: '🏠 মেনু', callback_data: 'h:home' }),
];

const CFG = [
  row(btn('/config', '⚙️ config'), btn('/info', 'ℹ️ info'), btn('/ping', '🏓 ping')),
  row(btn('/diag', '🔧 diag'), btn('/puce', '⏸ puce'), btn('/uregi', '🔄 uregi')),
  row({ text: '‹ সেটিংস গাইড', callback_data: 'h:c:cfg' }, { text: '🏠 মেনু', callback_data: 'h:home' }),
];

const ADM = [
  row(btn('/users', '👥 users'), btn('/diag', '🔧 diag')),
  row({ text: '‹ অ্যাডমিন গাইড', callback_data: 'h:c:adm' }, { text: '🏠 মেনু', callback_data: 'h:home' }),
];

function deviceMenu(devices, selId, bound) {
  const rows = [];
  for (const d of devices.slice(0, 8)) {
    const dot = d.online ? '🟢' : '⚪';
    const mark = d.id === selId ? '✅ ' : '';
    const age = d.age < 60 ? d.age + 's' : Math.floor(d.age / 60) + 'm';
    rows.push(row({
      text: mark + dot + ' ' + String(d.name || d.id).slice(0, 22) + ' · ' + age,
      callback_data: cb('u:' + String(d.id).slice(0, 12)),
    }));
  }
  if (!rows.length) rows.push(row({ text: '📭 কোনো ডিভাইস নেই', callback_data: 'h:c:dev' }));
  rows.push(row(btn('/de', '🔄 রিফ্রেশ'), btn('/all r 6 6 1', '📡 all'), btn('/uregi', '🔄 uregi')));
  rows.push(row(btn('/st', '⏸ st'), btn('/re', '▶️ re'), btn('/puce', '⏸ puce')));
  rows.push(row({ text: '‹ ডিভাইস গাইড', callback_data: 'h:c:dev' }, { text: '🏠 মেনু', callback_data: 'h:home' }));
  return rows;
}

function customMenu(custom) {
  const keys = Object.keys(custom || {});
  const rows = [];
  let cur = [];
  for (const k of keys) {
    cur.push(btn('/' + k, '/' + k));
    if (cur.length === 3) { rows.push(row(...cur)); cur = []; }
  }
  if (cur.length) rows.push(row(...cur));
  rows.push(row({ text: '‹ কাস্টম গাইড', callback_data: 'h:c:cus' }, { text: '🏠 মেনু', callback_data: 'h:home' }));
  return rows;
}

/* ------------------------------------------------------------------ */
/*  wiring                                                             */
/* ------------------------------------------------------------------ */

/**
 * Which keyboard belongs with a given text. The dispatcher calls this after
 * every successful command so the operator always sees a keyboard matching the
 * state they just changed — never a stale one.
 */
function keyboardFor(cmd, ctx) {
  const t = String(cmd || '').trim().toLowerCase();
  if (t === '/de' || t === '/devices' || t.startsWith('/uregi') || t === '/st' || t === '/re' || t === '/puce') {
    return deviceMenu(ctx.devices || [], ctx.sel || '', ctx.bound || null);
  }
  if (t === '/h' || t === '/help' || t === '/start') return MAIN;
  if (t === '/config' || t === '/info' || t === '/ping' || t === '/diag') return CFG;
  if (t === '/users' || t === '/revoke' || t === '/newcmd' || t === '/delcmd') return ADM;
  if (/^[rgbypo]\s+(w|win)\b/.test(t) || t === 'off') return WIN;
  if (/^2/.test(t)) return TEAM;
  if (/^[rgbypo]\s+/.test(t) || t === 'random' || t === 'clear') return DICE;
  return null;
}

module.exports = {
  MAIN, DICE, WIN, TEAM, CFG, ADM,
  deviceMenu, customMenu, keyboardFor, btn, row, cb,
  helpHome: help.homeText,
  helpCat: help.catText,
};
