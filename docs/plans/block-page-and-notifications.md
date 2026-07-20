# Block page + block notifications (design note, not scheduled)

Status: **design note only** — not planned into a milestone, no code.

## The want

When a blocked site fails to load, the browser shows "This site can't be
reached." That is indistinguishable from a network fault, a DNS problem, or the
site being down. The user wants to know the block was **intentional** — ideally a
page saying so, otherwise some other signal.

## The constraint that shapes everything

GrepFocus blocks a domain by writing `0.0.0.0` into `/etc/hosts`. The browser
therefore fails the connection **locally**, and **the daemon never observes the
attempt**. This is the same wall that killed per-domain counters in
[premium-usage-stats](premium-usage-stats.md): there is nothing to count, and
nothing to notify about, because nothing reaches us.

So "just send a desktop notification when a blocked site is visited" is **not
implementable** on the current architecture. Observability has to come first,
and every option below is really a choice about *how to observe the attempt*.

By contrast, **app blocks are already observable** — procwatch does the killing,
so "GrepFocus closed Steam" could be notified today with no new machinery. That
asymmetry is worth exploiting even if the domain side is never built.

## Options

### A. Point blocked domains at `127.0.0.1` and listen (recommended shape)

Replace `0.0.0.0` with `127.0.0.1` in the hosts block and run a small local
listener:

- **:80** — serve the block page. No certificate involved; this is the clean,
  real version of what the user asked for.
- **:443** — the browser opens TLS; read the requested hostname from the
  **ClientHello SNI**, then close the connection without completing the
  handshake. The browser still shows an error, but GrepFocus now *knows* which
  site was attempted and can notify. No certificate is presented, so there is no
  "your connection is not private" theatre and no trust decision forced on the
  user.

This is the only option that yields both a genuine page (HTTP) and a genuine
signal (HTTPS), and it makes **per-domain stats possible for the first time** —
recovering the capability deliberately given up in the usage-stats milestone.

**The real cost is ports, not cryptography.** Binding 80 and 443 on the author's
own machine — a developer box that runs local web servers — will collide.
Mitigations to think through before committing:

- bind only while a block is active, and release the ports the moment it ends;
- fail soft: if the bind fails (port in use), fall back to `0.0.0.0` hosts
  entries for that run and log it — enforcement must never depend on the
  listener succeeding;
- make the whole listener opt-in per install, off by default.

Also note this weakens nothing about enforcement, but it does mean a blocked
domain now resolves to a live local socket rather than a black hole — worth a
security think-through (the listener must serve exactly one static page, parse
no request body, and never proxy).

### B. Local CA so HTTPS certs validate

Generate a root CA, install it in the system/browser trust stores, and mint
per-domain certs on the fly so the block page renders cleanly over HTTPS.

**Rejected.** Installing a root CA is a serious, machine-wide security posture
change, is exactly the behaviour that gets software flagged as malware, and is
wildly disproportionate for an akrasia tool whose threat model explicitly
assumes the user has root and could bypass it anyway. The failure mode if the CA
key leaks is catastrophic and permanent.

### C. Browser extension

Gives a real block page in all cases with no port or certificate problems.
**Rejected**: it contradicts the "why not a browser extension" positioning on the
marketing site, multiplies per-browser work and store-review surface, and only
covers browsers — while GrepFocus blocks system-wide.

### D. Notification only, driven by app kills

Ship notifications for the *observable* half only: "GrepFocus closed Steam."
Cheap, no new privileged surface, no ports. Does not address the browser-error
confusion at all, but it is genuinely useful on its own and is a strict subset
of what A would eventually emit.

## Recommendation

Sequence it: **D first, A later if the confusion still bites.** D is small,
carries no architectural risk, and is independently valuable. A is the real
answer to the original want but drags in a privileged listener, port conflicts
on the author's own machine, and a security review — none of which should be
rushed for a comfort feature.

Do not build B. Do not build C.

## Notifications must be optional and rate-limited (explicit requirement)

The owner's requirement: **an off switch**, to avoid notification spam.

Design points:

- A global setting (notifications on/off), not per block — the spam concern is
  about volume, and a per-block toggle multiplies configuration for no gain.
  Free, not premium; it is a comfort feature, not enforcement.
- **Coalesce aggressively.** With option A, a single page load fires many
  requests to the same host, and background tabs retry forever. Notify at most
  once per (domain, block-run), or once per domain per N minutes — never once
  per connection. The same discipline as procwatch's PID dedup
  (`recently_killed`), which already exists as a precedent.
- Coalesce app kills the same way: one notification per process name per run,
  not per PID and not per sweep tick.
- Notifications are cosmetic and must **never** gate or delay enforcement. A
  failed or unavailable notification daemon is a `debug!`, not an error.
- Respect the desktop's own do-not-disturb; do not attempt to bypass it.

## Open questions

- Does the block page need to say *which block* caught the domain, and how long
  is left? That is genuinely useful, but it means the listener talks to the
  daemon over IPC on every request — more surface, more failure modes.
- If the listener is opt-in, what does the GUI show when it is off — does the
  domain silently revert to `0.0.0.0`, and is that legible to the user?
- Does a live local socket on a blocked domain create any new bypass? (e.g. a
  page on `127.0.0.1` that the browser now treats as same-origin for something.)
  Needs a proper think before any of this ships.
