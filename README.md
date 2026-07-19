# PiLink Sentinel

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/spencermoya-byte/pilink-sentinel)

A free, self-owned dead man's switch that tells you when your Pi goes offline —
including a total power cut, a crash, or your whole house losing internet.

## Why this has to exist

**A device cannot report its own death.** If the Pi loses power, nothing running
on the Pi can tell you: it's gone. Detecting that fundamentally requires a third
party that expects a signal and notices its absence.

This is not a limitation of PiLink. It's the same constraint Apple has. When your
HomePod loses power and your iPhone tells you "a home hub is not responding",
that notification came from **Apple's servers** — the only party still alive to
notice. Apple solved it by being the third party. They just never exposed that as
an API, so no app can rent it.

Sentinel is that third party, running free on Cloudflare, owned entirely by you.

## What makes it different from an uptime monitor

A normal monitoring service needs your credentials so it can alert you, and it
composes the alert itself — so it cannot tell a crash apart from a reboot you
scheduled. Both of those are bad.

Sentinel inverts it. The Pi doesn't say "I'm alive". It hands over a
**fully-formed notification and a deadline**:

> *"If you don't hear from me by 14:32, send exactly this, using this token."*

and then keeps pushing the deadline forward. That gives four properties an
off-the-shelf monitor can't:

| | |
| --- | --- |
| **No lasting secret leaves the Pi** | The watcher receives an APNs provider token valid for at most an hour, never `apns_key.p8`. Fully compromised, an attacker can replay *your* message to *your* phone briefly, and mint nothing. |
| **The watcher composes nothing** | It has no templates and no idea what happened. It's a relay with a stopwatch. |
| **The message knows the cause** | Only the Pi knows if a disappearance was expected, so only the Pi can write *"your Daily reboot didn't come back"* versus *"nothing was scheduled"*. |
| **Nothing is ever pre-fired** | Before a scheduled reboot the Pi arms a *different* payload with a longer window. Reboot works → Pi returns, re-arms → **nothing is sent**. Reboot hangs → you're told, and told why. |

A scheduled **shutdown** disarms the switch completely, because staying off is
the point and alerting on it would be noise.

## Cost

Free, permanently, on Cloudflare's free tier. Verified against their published
limits:

| Resource | Sentinel uses | Free limit | Spare |
| --- | --- | --- | --- |
| KV writes | 720/day | 1,000/day | 28% |
| KV reads | 1,440/day | 100,000/day | 98.6% |
| Worker requests | 2,160/day | 100,000/day | 97.8% |
| Cron triggers | 1 | 3 | — |

KV writes are the binding constraint, and they're why the heartbeat is **two
minutes rather than one** — a 1-minute beat would be 1,440 writes/day and blow
the free tier. Worst-case detection latency is **7 minutes** (3 missed beats plus
one cron tick).

## Setup

**Do this from the PiLink app**, not from here: **Settings → Offline alerts → Set up**.
The app generates your setup code, walks you through the deploy, and configures the Pi
for you. You never touch a terminal.

The button above is the same thing, if you'd rather start from GitHub. Cloudflare will:

1. Copy this repo into **your** GitHub account
2. Create the KV namespace on **your** Cloudflare account automatically
3. Ask you for `SENTINEL_SECRET` — paste the setup code from the PiLink app
4. Deploy, and hand you an address ending in `workers.dev`

Paste that address back into PiLink and you're done.

Everything lives on your own free Cloudflare account. Nobody else — including whoever
wrote PiLink — can see your Pi's name, your notifications, or your device tokens,
because there is no shared server for that data to sit on.

<details>
<summary>Manual setup with the CLI (you almost certainly don't need this)</summary>

```bash
npx wrangler login
npx wrangler kv namespace create SENTINEL     # paste the id into wrangler.toml
openssl rand -hex 32                          # your setup code
npx wrangler secret put SENTINEL_SECRET
npx wrangler deploy
```

Then on the Pi:

```bash
cat > ~/.pilink/sentinel.json <<'JSON'
{ "url": "https://<your-worker>.workers.dev/beat", "secret": "<setup code>", "id": "my-pi" }
JSON
chmod 600 ~/.pilink/sentinel.json
sudo systemctl restart pilink-server
```

</details>

## Testing it for real

The honest test is to actually kill the Pi:

```bash
sudo poweroff        # or physically pull the power
```

Within ~7 minutes you should get:

> **Streaming-Pi stopped responding**
> No response for several minutes, and nothing was scheduled — it may have lost
> power or dropped off the network.

Power it back on and the heartbeat re-arms automatically.

To confirm the *other* half — that a scheduled reboot stays silent — just let
your Daily reboot run. You should get the normal "restarted" notification and
**no** offline alert, because the Pi came back and re-armed before the widened
deadline lapsed.

## What it still can't do

Worth stating plainly:

- **If your home internet dies but the Pi is fine**, Sentinel fires. The alert
  says "lost power or dropped off the network", which is accurate — it genuinely
  cannot distinguish those from outside.
- **Detection isn't instant.** Seven minutes worst case, by design: a shorter
  window either costs money or produces false alarms on brief network blips.
- **If Cloudflare is down**, there's no alert. That's the same trade Apple makes
  with iCloud, and there is no way to remove it — something outside the Pi has to
  be alive to notice the Pi isn't.
