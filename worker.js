/**
 * PiLink Sentinel — a pre-armed dead man's switch.
 *
 * WHAT PROBLEM THIS SOLVES
 *
 * A device cannot report its own death. If the Pi loses power, crashes, or the
 * house internet drops, nothing on the Pi can tell you — it's gone. Detection
 * fundamentally requires a third party that expects a signal and notices its
 * absence. Apple solves this for HomePods by being that third party themselves;
 * they just don't expose it as an API.
 *
 * This Worker is that third party, running free on Cloudflare, owned by you.
 *
 * WHY IT ISN'T JUST A HEARTBEAT SERVICE
 *
 * A normal uptime monitor needs your credentials so it can alert you, and it
 * composes the message itself — so it can't tell a crash apart from a reboot you
 * scheduled. Both are bad.
 *
 * Instead, the Pi hands over a fully-formed notification and a deadline:
 *
 *   "If you don't hear from me by 14:32, send exactly this, using this token."
 *
 * The Pi keeps pushing the deadline forward. Consequences:
 *
 *   - This Worker never sees the APNs signing key (.p8). It only ever gets a
 *     provider token valid for at most an hour. A total compromise of this
 *     Worker lets an attacker replay YOUR notification to YOUR phone for under
 *     an hour, and mint nothing.
 *   - This Worker has no message templates and no logic about what happened. It
 *     is a relay with a stopwatch. The Pi authors the text, so it can say
 *     "your Daily reboot didn't come back" versus "nothing was scheduled".
 *   - Nothing is ever pre-fired. Before a scheduled reboot the Pi arms a
 *     different payload with a longer deadline; if the reboot works the Pi
 *     returns and re-arms, and no notification is ever sent.
 *
 * FREE TIER BUDGET (verified against Cloudflare's published limits)
 *
 *   KV writes    720/day of 1,000   <- the binding constraint; hence a 2-minute
 *                                      heartbeat rather than 1-minute
 *   KV reads   1,440/day of 100,000
 *   Requests   2,160/day of 100,000
 *   Cron           1 of 3 triggers, 1-minute minimum
 *
 * Worst-case detection latency: 3 missed beats + one cron tick = 7 minutes.
 */

const MAX_SKEW_SEC = 300;        // reject heartbeats this far out of step
const MAX_BODY = 8192;           // a heartbeat is ~1KB; refuse anything absurd

/** Constant-time compare, so a bad HMAC can't be brute-forced by timing. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify the heartbeat really came from your Pi.
 *
 * Without this, anyone who learned your Worker URL could push the deadline
 * forward forever and permanently silence your alerts — the failure mode where
 * you believe you're monitored and aren't.
 */
async function verifyHmac(secret, rawBody, providedHex) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawBody));
  return timingSafeEqual(toHex(sig), (providedHex || '').toLowerCase());
}

/** POST a pre-armed payload to Apple. The token was minted on the Pi. */
async function sendToApns(entry) {
  const results = [];
  for (const host of ['api.push.apple.com', 'api.sandbox.push.apple.com']) {
    let anyOk = false;
    for (const deviceToken of entry.deviceTokens || []) {
      try {
        const r = await fetch(`https://${host}/3/device/${deviceToken}`, {
          method: 'POST',
          headers: {
            authorization: `bearer ${entry.apnsJwt}`,
            'apns-topic': entry.topic,
            'apns-push-type': 'alert',
            'apns-priority': '10',
          },
          body: JSON.stringify(entry.payload),
        });
        const ok = r.status === 200;
        anyOk = anyOk || ok;
        let reason = '';
        if (!ok) { try { reason = (await r.json()).reason || ''; } catch { /* empty body */ } }
        results.push({ host, status: r.status, reason });
      } catch (e) {
        results.push({ host, error: String(e) });
      }
    }
    // A development build's token only exists in sandbox and a TestFlight one
    // only in production, and we can't tell which we were given -- so try the
    // other host only if production rejected everything.
    if (anyOk) break;
  }
  return results;
}

export default {
  /** Heartbeat intake. The Pi calls this every 2 minutes. */
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return new Response('sentinel up', { status: 200 });
    }

    if (url.pathname !== '/beat' || request.method !== 'POST') {
      return new Response('not found', { status: 404 });
    }

    const raw = await request.text();
    if (raw.length > MAX_BODY) return new Response('too large', { status: 413 });

    let body;
    try { body = JSON.parse(raw); } catch { return new Response('bad json', { status: 400 }); }

    if (!(await verifyHmac(env.SENTINEL_SECRET, raw, request.headers.get('x-sentinel-hmac')))) {
      return new Response('bad signature', { status: 401 });
    }

    const now = Math.floor(Date.now() / 1000);
    // Reject stale replays: an old heartbeat captured off the wire must not be
    // replayable later to push the deadline forward while the Pi is actually down.
    if (Math.abs((body.sentAt || 0) - now) > MAX_SKEW_SEC) {
      return new Response('stale', { status: 400 });
    }
    if (!body.id) return new Response('missing id', { status: 400 });

    // `disarm` is how a DELIBERATE shutdown stays silent: the Pi says "I'm
    // going away on purpose, don't alert."
    if (body.disarm) {
      await env.SENTINEL.delete(`beat:${body.id}`);
      return new Response(JSON.stringify({ ok: true, disarmed: true }), {
        headers: { 'content-type': 'application/json' },
      });
    }

    await env.SENTINEL.put(`beat:${body.id}`, JSON.stringify({
      deadline:     body.deadline,       // epoch seconds; fire if we pass this
      apnsJwt:      body.apnsJwt,        // short-lived, minted on the Pi
      topic:        body.topic,
      deviceTokens: body.deviceTokens,
      payload:      body.payload,        // the exact notification, authored by the Pi
      label:        body.label || '',    // e.g. "scheduled-reboot" (for logs only)
      firedAt:      0,                   // reset on every beat, so recovery re-arms
      updatedAt:    now,
    }));

    return new Response(JSON.stringify({ ok: true, deadline: body.deadline }), {
      headers: { 'content-type': 'application/json' },
    });
  },

  /** Cron tick, once a minute. The only thing that ever fires an alert. */
  async scheduled(event, env, ctx) {
    const now = Math.floor(Date.now() / 1000);
    const list = await env.SENTINEL.list({ prefix: 'beat:' });

    for (const key of list.keys) {
      const rec = await env.SENTINEL.get(key.name, 'json');
      if (!rec || !rec.deadline) continue;
      if (now < rec.deadline) continue;    // still within its window
      if (rec.firedAt) continue;           // already alerted; don't nag

      const results = await sendToApns(rec);
      console.log(`[sentinel] ${key.name} lapsed (${rec.label || 'unlabelled'}) ->`,
                  JSON.stringify(results));

      // Mark fired rather than deleting: the record documents what happened, and
      // the Pi's next heartbeat clears it automatically on recovery.
      rec.firedAt = now;
      await env.SENTINEL.put(key.name, JSON.stringify(rec));
    }
  },
};
