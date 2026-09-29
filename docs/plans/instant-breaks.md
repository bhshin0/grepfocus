# Instant breaks — a loopback passthrough proxy

Status: **implemented and live-verified** (2026-07-28). The core behaviour —
an already-open tab on a blocked site becomes reachable the instant a break
starts, with the proxy bound and active — was confirmed on the owner's machine.
Adversarial security audit passed (findings low/theoretical, all fixed). Owner
approved: build it, **default-on**, fail-soft with a GUI notice when a port is
taken.

## The problem

When a break starts, the daemon removes the domain from `/etc/hosts` and flushes
the *system* resolver — both work instantly. But the browser keeps its **own**
in-process DNS cache (~60 s Firefox/Chrome, up to ~120 s with Firefox's grace
period), which no external process can flush. So an already-open tab keeps
hitting the old dead address for up to a minute. Per-browser config (Firefox
`network.dnsCacheExpiration`) can fix it, but Chrome ignores DNS TTLs entirely,
so nothing DNS-level generalises. The only browser-agnostic fix is to make the
address the browser *already cached* lead somewhere that works during a break.

## Mechanism

Point blocked domains at **`127.0.0.1`** instead of `0.0.0.0`, and run a
root-owned loopback listener on `:80`/`:443` (the daemon is already root). Per
connection, read the requested host — `Host:` header on `:80`, TLS **SNI** on
`:443` — then decide from live daemon state:

- **domain blocked right now** → close (on `:80`, first return the fixed
  `403 no-store` page). Site stays blocked.
- **domain on a break right now** → resolve its real IP, open a TCP connection
  to it, and **splice raw bytes** both ways (`tokio::io::copy_bidirectional`).
  No TLS termination, so **no certificate** — the browser completes its own
  handshake straight through to the real server. The stale cached `127.0.0.1`
  now forwards to the real site → instant, on any browser, zero user config.
- **anything else** → close.

### The elegant part (verified)

`enforce::union_domains` already **drops an on-break domain from `/etc/hosts`**
for the break's duration. So during a break a normal `lookup_host(host)` returns
the **real** IP — the proxy needs no custom DNS client, because our own block is
lifted for that domain while it's on break. Fresh browser lookups during the
break also get the real IP and connect directly, bypassing the proxy entirely;
the proxy only ever serves the *stale-cache* connections, which is exactly the
gap being closed.

## What is reused vs new

Reused from `visit-detection-shelf` (already fuzzed: 594M cases, 0 panics;
injection impossible by construction):
- `listener.rs` — `parse_sni` / `parse_host_header` and the `Cursor`, the bind
  lifecycle (`bind_loopback`, all-or-nothing `bind_all`, `Drop`, async
  `release`), `MAX_CONNECTIONS` semaphore, read/write timeouts, `403` page.
- `enforce.rs` / `hosts.rs` — the sink-IP-as-parameter mechanism (`Ipv4Addr`
  through `apply_block`, `sink_ip`, `Applied.sink` in the memo).

NOT reused (that was the shelved *detection* feature): visit recording,
`BlockAttempt`, `Status.attempts`, coalescing, detection notifications,
`Settings.detect_attempts`.

New:
- The per-connection **decision + forward/splice** path in `handle()`.
- The **decision callback**: `Arc<dyn Fn(&str) -> ProxyVerdict + Send + Sync>`
  the daemon supplies, closing over its state — returns `Forward`/`Refuse` by
  checking whether the host exactly matches a domain of an active block whose
  `break_until_unix > now`. Evaluated fresh per connection so a just-ended break
  refuses.
- Real-IP resolve with a **loopback guard**: if the host resolves to `127/8` or
  `::1`, refuse (prevents a self-loop; the on-break scoping already prevents
  arbitrary-target SSRF, since only a domain the user themselves blocked and is
  on break from can ever be forwarded).

## Key design decisions

1. **Bind condition changes.** The shelf bound the listener only while the hosts
   union was non-empty. But a *solo* break empties the union (the one block's
   domain is removed) exactly when the proxy is needed. So bind the listener
   whenever `instant_breaks` is on **and any block is active** (on-break or not);
   unbind only when no block is active. The sink written to `/etc/hosts` is
   `127.0.0.1` while the listener is bound, `0.0.0.0` otherwise.
2. **Default-on.** `Settings.instant_breaks: bool`, **default `true`**.
   `Settings::default` is hand-written (`true`), and the container keeps
   `#[serde(default)]` so an old 0.3.0 state (`settings` without the field) fills
   `instant_breaks` from that struct default — NOT the bool zero. A compat test
   pins that an old state loads with `instant_breaks == true`.
3. **Fail-soft + notice.** A failed bind never touches enforcement (`127.0.0.1`
   with nothing listening still refuses — site blocked). It degrades instant
   breaks only. Surface it: `Status` gains an instant-breaks state
   (`Off` | `Active` | `Degraded`); the GUI shows a small notice when
   `Degraded` (enabled but a port is in use) so a lagging break isn't a mystery.
4. **Scoping is the security boundary.** Forward **only** a domain that is
   on-break-blocked *at connection time*. Never a general proxy. Re-audit this.

## Stages (each gated on `./scripts/check.sh`)

Branch `instant-breaks` off `master`.

1. **Port the listener + sink, refuse-only.** Bring `listener.rs` (handler
   refuses/serves 403 for every connection — no forwarding yet), port the sink
   threading, add `Settings.instant_breaks` (default true) gating sink+bind,
   change the bind condition to "any active block". Result: blocking works via
   `127.0.0.1` instead of `0.0.0.0`; breaks not yet instant. Behaviour-preserving
   for enforcement. Verify a block still blocks.
2. **Forward during break.** Add the decision callback, real-IP resolve with the
   loopback guard, and `copy_bidirectional` splice with the existing cap +
   timeouts. Breaks become instant. The core value.
3. **GUI.** `Status` instant-breaks state + the `Degraded` notice; a Settings
   toggle (default on) to disable it. Wire `set_settings` (already exists).
4. **Adversarial security review** of the forwarding path specifically —
   scoping, the loopback/SSRF guard, connection-cap behaviour under forwarded
   long-lived streams, teardown — then the milestone doc.

Stages 1–2 are daemon-only, verifiable over the IPC socket + `curl`/browser.

## What shipped (all gated on `./scripts/check.sh`)

- `bca81fe` docs: this plan.
- `0f3a72e` stage 1 — the loopback listener ported refuse-only behind
  `instant_breaks` (default on), sink threaded through `hosts`/`enforce`, bind
  keyed on "any active block". Parsers byte-identical to the fuzzed shelf.
- `293b4fd` stage 2 — forward on-break connections: byte-exact head replay +
  `copy_bidirectional`, the `forwardable` set (on-break minus union) updated each
  tick and read by the per-connection `Decide` hook, loopback/unspecified guard.
- `b949af4` stage 3 — GUI: `instant_breaks` settings toggle (default on) and a
  `instant_breaks_degraded` status flag driving a "port in use" notice; both
  preference toggles send the full `Settings` object.
- `61cacf5` — dial guard also rejects IPv4 link-local (`169.254/16`, the cloud
  metadata range), defence in depth.

Deviations from the plan above: the fail-soft status is a single
`instant_breaks_degraded: bool` on `Status` rather than an `Off|Active|Degraded`
enum — the GUI only needs "wanted-but-couldn't-bind", and `settings.instant_breaks`
already carries on/off. The SSRF guard was extended past the planned loopback/`::1`
to also cover IPv4 link-local. Since `hardening-health` WP3, `health.proxy`
now carries the `Holding|Degraded|Off` enum; the bool is kept on the wire,
derived (`docs/plans/hardening-health-updates.md`).

## Verification (live, after deploy)

| # | Check |
|---|---|
| 1 | Block active: site blocked; `:80` returns the 403, `:443` connection closes |
| 2 | Take a break with a tab already open on the blocked site → it loads **immediately**, no ~60 s wait, in both Firefox and a Chromium-based browser |
| 3 | A fresh tab opened during the break also loads (direct real-IP path) |
| 4 | Break ends → site blocks again (reverse ~60 s browser-cache lag still exists and is accepted) |
| 5 | A domain NOT on break is never forwarded (try to reach another blocked block's domain — refused) |
| 6 | Occupy :80 with a local server → blocking still works, breaks lag, GUI shows the "instant breaks unavailable — port in use" notice |
| 7 | `instant_breaks` toggle off → sink reverts to `0.0.0.0`, ports never bound, behaves like 0.3.0 |
| 8 | Upgrade from 0.3.0 state → `instant_breaks` defaults ON, blocks/licence intact |
| 9 | Multi-block same domain, one on break: domain stays in hosts (other block enforces) → resolve returns loopback → forward refused (not instant, but no self-loop or crash) |

## Out of scope
Making the *re-block* after a break instant (the reverse cache lag — accepted).
A real HTTPS block page (needs a cert). IPv6 sink (`::1`) — v1 is IPv4 loopback;
note it. Reviving detection/notifications (stays shelved).
