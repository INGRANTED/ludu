'use strict';
/*
 * BLACK FOX BD v8 — access control.
 *
 * The rule the operator asked for: nobody but a logged-in admin can touch a
 * device. A plain user sees "permission নেই" until an admin grants something,
 * and a user who has been *bound* to one device cannot even see the others.
 *
 * Permissions are a set of tokens:
 *   de      device list
 *   u       select a device
 *   re      resume
 *   st      halt
 *   cfg     change poll intervals
 *   roll    send dice scripts
 *   win     win mode (r w / y w / ...)
 *   all     broadcast to every device
 *   admin   everything, plus /per /newcmd /delcmd /bind /unbind /users
 *
 * A grant may also carry a device binding: the user is then locked to that one
 * device id and every other device is filtered out of /de and refused by /u.
 */

const ALL = ['de', 'u', 're', 'st', 'cfg', 'roll', 'win', 'all'];

function emptyAcl() {
  return {
    admins: [],          // chat ids
    users: {},           // chatId -> { perms: [], bind: null, label: '' }
    custom: {},          // name -> action string
    v: 1,
  };
}

function isAdmin(acl, chatId) {
  return acl.admins.includes(String(chatId));
}

function permsOf(acl, chatId) {
  const id = String(chatId);
  if (isAdmin(acl, id)) return ALL.concat(['admin']);
  const u = acl.users[id];
  return u ? (u.perms || []) : [];
}

function has(acl, chatId, perm) {
  const p = permsOf(acl, chatId);
  return p.includes('admin') || p.includes(perm);
}

function bindOf(acl, chatId) {
  const u = acl.users[String(chatId)];
  return u && u.bind ? u.bind : null;
}

/**
 * Grant. `spec` is the raw argument tail, e.g. "/de,/re,/auto" or "win" or "u".
 * A bare device id (or "u <id>") sets the binding.
 */
function grant(acl, chatId, spec) {
  const id = String(chatId);
  if (!acl.users[id]) acl.users[id] = { perms: [], bind: null, label: '' };
  const u = acl.users[id];
  const parts = String(spec || '').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  const added = [];
  for (const raw of parts) {
    const p = raw.replace(/^\//, '').toLowerCase();
    if (p === 'auto') {
      if (!u.perms.includes('roll')) { u.perms.push('roll'); added.push('roll'); }
      if (!u.perms.includes('win')) { u.perms.push('win'); added.push('win'); }
      continue;
    }
    if (p === 'rw' || p === 'win') {
      if (!u.perms.includes('win')) { u.perms.push('win'); added.push('win'); }
      continue;
    }
    if (p === 'admin') {
      if (!acl.admins.includes(id)) { acl.admins.push(id); added.push('admin'); }
      continue;
    }
    if (ALL.includes(p)) {
      if (!u.perms.includes(p)) { u.perms.push(p); added.push(p); }
      continue;
    }
    /* anything else is treated as a device binding */
    u.bind = raw;
    added.push('bind:' + raw);
  }
  return added;
}

function revoke(acl, chatId) {
  const id = String(chatId);
  acl.admins = acl.admins.filter((a) => a !== id);
  delete acl.users[id];
}

function setBind(acl, chatId, deviceId) {
  const id = String(chatId);
  if (!acl.users[id]) acl.users[id] = { perms: [], bind: null, label: '' };
  acl.users[id].bind = deviceId || null;
}

function label(acl, chatId, name) {
  const id = String(chatId);
  if (!acl.users[id]) acl.users[id] = { perms: [], bind: null, label: '' };
  acl.users[id].label = name || '';
}

function describe(acl, chatId) {
  const id = String(chatId);
  if (isAdmin(acl, id)) return 'admin';
  const u = acl.users[id];
  if (!u) return 'none';
  const p = (u.perms || []).join(',') || 'none';
  return u.bind ? p + ' · bind ' + u.bind : p;
}

module.exports = {
  ALL, emptyAcl, isAdmin, permsOf, has, bindOf, grant, revoke, setBind, label, describe,
};
