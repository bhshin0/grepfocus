# Un-brickable milestone — teardown, recovery, enforcement robustness

Status: **implemented, reviewed, and live-verified** (2026-07-07).

Goal: removing or breaking Frostbite must never leave the machine
semi-bricked. Before this milestone there was no uninstaller, and removing
the binaries after any block had run stranded a `chattr +i` /etc/hosts with
blocks still in it plus an nftables table — with the only tool that could
undo them deleted.

Decisions baked in (see README Recovery + Known limits):

1. Uninstall/cleanup works even mid-block — never-brick beats fighting root,
   who is out of the threat model anyway.
2. Uninstall keeps data by default; `--purge` deletes state, secret, group.
3. The DoT (853) drop is scoped to the known-resolver IP sets, same friction
   line as DoH — an unscoped drop could kill ALL DNS for a system resolver.
4. `chattr +i` failure degrades to a warning; the hosts write stays fatal.

## What shipped

- `bfcab46` hosts: chattr degrades gracefully; strip_managed edge tests
- `ff33447` `frostbited cleanup [--purge] [--force]`: idempotent,
  state-independent offline teardown
- `e989f99` packaging: uninstall.sh (teardown-first ordering, inline
  fallback) + full-product install.sh
- `dd95b8c` enforce: 30s liveness re-verify catches firewall/hosts drift
- `1890f41` nftables: DoT drops daddr-scoped
- `ffcf623` README Recovery runbook + BACKLOG bookmarks

Post-review fix wave (adversarial review, 17 findings adjudicated, all
mechanically confirmed against the code):

- `f109108` enforce: clock-step-immune probe (`abs_diff`); per-half memo —
  nft-only drift heals without rewriting /etc/hosts; broken-nft hosts no
  longer churn every 30s
- `a62d8fd` nftables: every exec bounded by coreutils `timeout` (a hung nft
  under the applied mutex would wedge the scheduler); port-set-aware
  plain-DNS test
- `79ba9c0` cleanup: systemd-aware daemon guard (Restart=always respawn
  race); `--purge` keeps the recovery copy after a failed strip; non-UTF-8 /
  CRLF hosts handled byte-exactly; step (f) genuinely tested
- `24e7d2c` packaging: delegation timeout (pre-milestone binaries ignore
  argv and boot the daemon); fallback restores a missing /etc/hosts;
  chroot-safe unit removal; install.sh restarts on re-run, probes cargo
- `1740d88` README runbook corrections (`install -m 644`, cleanup --purge
  scope)
- `e699eaa` uninstall.sh: drain buffered keystrokes before the purge prompt
  and echo the keep/purge decision (defect caught live during the matrix)

## Live failure-mode matrix (Fedora 43, 2026-07-07)

| # | Scenario | Result |
|---|----------|--------|
| 1 | `kill -9` mid-block | PASS — systemd respawn ~1s; enforcement re-applied; markers + immutable bit intact |
| 2 | corrupt state.json → start | PASS — HMAC failure logged "starting fresh"; markers, bit, and nft table all cleared (fails open) |
| 3 | `systemctl stop` mid-block | PASS — enforcement persists (stop ≠ bypass): markers, bit, DoH drop all live |
| 4a | uninstall mid-block (keep) | Teardown PASS (live ×3); keep-gates verified by inspection — the purge prompt was answered `y` in every live run, so the keep skip-paths (3 one-line gates) were not exercised live |
| 4b | uninstall `--purge`, run again | PASS — second run takes the inline-fallback branch (binary gone), exits clean, hosts untouched |
| 5 | nft table flushed mid-block | PASS — drift warn + nft-only re-install ≤30s, `/etc/hosts` NOT rewritten (per-half heal). Note: `firewall-cmd --reload` on Fedora 43 does NOT flush foreign tables (firewalld rebuilds only its own), so the table survives a plain reload; the drift path matters for `nft flush ruleset` / other firewall managers |
| 6 | torn apply healed on start | PASS — chattr -i + dropped table + planted tmp orphan while stopped → re-hardened seconds after start; orphan consumed by the atomic write |
| 7 | chattr denied (bind-mounted /usr/bin/false) | PASS — block applies, "active but NOT tamper-protected" warning, no error; re-hardens once chattr works again |
| 8 | port 53 during block | PASS — `dig @1.1.1.1` answers; only 443/853 to listed resolver IPs are dropped |
| 9 | cleanup with daemon running | PASS — refuses via the systemd-aware guard ("unit is active — stop it first or pass --force") |

Extra finding from the matrix: the purge prompt could be answered by a stale
keystroke buffered in the tty during an earlier sudo/fingerprint exchange
(observed: prompt "answered" in under 2 seconds). Fixed in `e699eaa`.

Operational note: uninstall `--purge` + reinstall recreates the `frostbite`
group with a new GID, so already-logged-in sessions can't reach the socket
until re-login (`sg frostbite -c ...` works in the interim).
