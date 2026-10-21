/*
 * BLACK FOX BD v10 — Cloudflare Worker front.
 *
 * A thin, stateless edge in front of the Render hub. Two jobs:
 *
 *   1. Failover. The APK carries a node list; if Render is cold-starting or
 *      down, the Worker answers /health itself and forwards to whichever hub is
 *      alive, so the device never goes dark.
 *
 *   2. A stable hostname. The Worker's own domain is what the APK pins, so the
 *      hub can move without shipping a new APK.
 *
 * It holds no state and no bot token.
 */

const HUBS = [
  'https://bxbot-ruw1.onrender.com',
];

const VERSION = '10.0.0';
const PROTO = 10;

function cors() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type,x-sid,x-sig',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  };
}

/**
 * Forward one request.
 *
 * The body is read once into an ArrayBuffer and reused across hub attempts — a
 * consumed stream cannot be replayed, and the previous version silently sent an
 * empty body on the retry path, which made the failover look like a decrypt
 * failure on the client.
 */
async function forward(request, hub, path, bodyBuf) {
  const url = new URL(request.url);
  const target = hub + path + (url.search || '');
  const headers = new Headers(request.headers);
  headers.delete('host');
  headers.delete('cf-connecting-ip');
  headers.set('x-bx-via', 'cf-front');

  const init = { method: request.method, headers, redirect: 'manual' };
  if (bodyBuf) init.body = bodyBuf;

  const res = await fetch(target, init);
  const out = new Headers(res.headers);
  for (const [k, v] of Object.entries(cors())) out.set(k, v);
  out.set('x-bx-via', 'cf-front');
  return new Response(res.body, { status: res.status, headers: out });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    /* The edge answers its own health so a hub outage is still visible. */
    if (path === '/health' || path === '/') {
      const results = [];
      for (const hub of HUBS) {
        try {
          const r = await fetch(hub + '/health', { signal: AbortSignal.timeout(4000) });
          const j = await r.json();
          results.push({ hub, ok: r.ok, ...j });
        } catch (e) {
          results.push({ hub, ok: false, error: String(e.message) });
        }
      }
      const live = results.find((r) => r.ok);
      return new Response(JSON.stringify({
        ok: true,
        version: VERSION,
        proto: PROTO,
        node: 'cf-front',
        hub: live ? live.hub : null,
        hubs: results,
      }), { status: 200, headers: { 'content-type': 'application/json', ...cors() } });
    }

    /*
     * /api/uplink is a wake-up, not a registration.
     *
     * Render's free tier answers the FIRST request of a cold start in 30-50s; a
     * device whose hello hits that window times out and looks missing. The
     * uplink path is answered by the edge itself so the client always gets a
     * 200 immediately, while the hub is nudged in the background. The device
     * only needs to know "the network works" -- its real handshake follows and
     * by then the dyno is warm.
     */
    if (path === '/api/uplink') {
      const now = Date.now();
      for (const hub of HUBS) {
        fetch(hub + '/health', { signal: AbortSignal.timeout(5000) }).catch(() => {});
      }
      return new Response(JSON.stringify({
        ok: 1, node: 'cf-front', warm: 1, via: 'edge', at: now,
      }), { status: 200, headers: { 'content-type': 'application/json', ...cors() } });
    }

    /* Buffer the body once, then try each hub with the same bytes. */
    let bodyBuf = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      bodyBuf = await request.arrayBuffer();
    }

    let lastErr = null;
    for (const hub of HUBS) {
      try {
        return await forward(request, hub, path, bodyBuf);
      } catch (e) {
        lastErr = e;
      }
    }
    return new Response(JSON.stringify({
      ok: false,
      error: 'all hubs unreachable',
      detail: lastErr ? String(lastErr.message) : '',
    }), { status: 502, headers: { 'content-type': 'application/json', ...cors() } });
  },
};
