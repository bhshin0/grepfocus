# Frostbite — daily-driver hardening: implementation handoff

Status: approved plan, not yet implemented. Written 2026-07-04 against
commit `b84db7f` (master). Line references are as of that commit and may
shift — treat symbols as authoritative, lines as hints.

## 1. Current MVP baseline

Frostbite is a Cold Turkey-style website/app blocker for Linux, for defeating
in-the-moment akrasia by the machine's owner. Root bypass is explicitly out of
threat model.

- **Architecture**: root daemon `frostbited` (crates/daemon) enforces blocks
  via `/etc/hosts` (+ `chattr +i`), an nftables DoH/DoT drop table
  (`frostbite_doh`), and SIGKILL of matching processes (500 ms `/proc` sweep).
  A Tauri 2 GUI (crates/gui) talks to it over `/run/frostbite/sock`
  (length-prefixed JSON, u32-BE + payload, 1 MiB cap — `crates/core/src/wire.rs`;
  group `frostbite`, mode 0660). Shared types in crates/core. State persisted
  as HMAC-signed JSON (`state.json` + separate `state.json.mac`, key in
  `/etc/frostbite/secret`).
- **Working, live-E2E-verified (2026-07-04)**: multi-block domain enforcement
  with `www.` aliasing; app killing; weekly schedules (no midnight wrap, by
  design); strict mode (no cancel while active); daily break allowance with
  cap/exhaustion/auto-resume; Argon2id settings password with 300 s in-memory
  unlock window; DoH damping; tray + D-Bus notifications; single instance;
  state survival across restarts; self-healing enforcement retried each
  scheduler tick.
- **Deployment skew**: the installed daemon (`/usr/local/bin/frostbited`) is
  the `d1748b3` build; the `b84db7f` fixes (enforcement race, break edge
  cases) are built but not installed. The running GUI is the fixed build.
  First run of the new `packaging/upgrade.sh` (Phase 3) closes this skew.
- **Quality baseline**: 24-agent adversarial review found 19 real bugs;
  the 9 high/medium fixed in `b84db7f`; 6 lows tracked in `BACKLOG.md`
  (the single known-issues ledger — repo has no TODO/FIXME comments).
  12 unit tests total; no integration tests; no CI.

## 2. Milestone goal and non-goals

**Goal**: harden the MVP into a personal daily driver on the author's
machine. Four phases, one commit each, in order: durability, backlog lows,
launcher + deploy loop, test floor.

**Non-goals (explicitly out of scope)**:
- The frostbite→Timely rename is **deferred** (user decision 2026-07-04).
  Everything keeps current names: crates `frostbite-core`/`frostbited`/
  `frostbite-gui`, group `frostbite`, socket `/run/frostbite/sock`, nft table
  `frostbite_doh`, hosts markers `# frostbite-begin`/`# frostbite-end`,
  paths `/var/lib/frostbite`, `/etc/frostbite`. Track the open rename
  decision in BACKLOG.md.
- No new features: no GUI wiring of `update_block`/`cancel_block` (protocol
  arms exist in `crates/core/src/lib.rs` but the GUI works via
  delete+recreate); no stats/pomodoro/extension work.
- No distribution packaging (RPM/Flatpak), no portability work, no CI
  service — the test floor is local scripts only.
- No adversarial hardening beyond the akrasia threat model.
- Wontfix: TakeBreak ledger residual under *persistent* enforce failure
  (see BACKLOG.md rationale).

## 3. Phase 1 — Durability fixes

### 3.1 `/etc/hosts` fsync + recovery copy — `crates/daemon/src/hosts.rs`

- `write_atomic` (hosts.rs:80-85) currently does `fs::write` + `fs::rename`
  with no fsync. Rewrite: `OpenOptions` create/truncate → `write_all` →
  `sync_all()` → `rename` — mirror the existing pattern in
  `crates/daemon/src/state.rs:56-67`.
- In `apply_block` (hosts.rs:16) and `clear_block` (hosts.rs:31), after
  computing `stripped = strip_managed(&original)`, write `stripped` to a new
  constant `paths::HOSTS_ORIG` = `/var/lib/frostbite/hosts.orig` (mode 0600,
  reuse `write_atomic`) *before* modifying `/etc/hosts`. This is a recovery
  copy of the unmanaged hosts content. Add the constant to
  `crates/daemon/src/paths.rs` next to `STATE_FILE`.

### 3.2 Single-file state format — `crates/daemon/src/state.rs`

Kills the crash window between the two renames in `save` (state.rs:52-84),
which can wipe blocks/schedules/password on the next boot.

- **New format**: `state.json` = 32-byte HMAC-SHA256 prefix
  (`frostbite_core::hmac_sig::sign` returns `[u8; 32]`) followed by the JSON
  body. Single tmp + `sync_all` + rename.
- **`load`**: read `state.json`; if len ≥ 32, split MAC = bytes 0..32, body =
  rest, verify with `hmac_sig::verify`. If verification or JSON parse fails,
  fall back to the legacy two-file scheme (whole file as body,
  `state.json.mac` as MAC — the current load, state.rs:40-48). A legacy
  pure-JSON file fails the new-format MAC check and falls through cleanly, so
  migration is automatic and needs no version flag.
- **`save`**: write new format, then best-effort
  `fs::remove_file(paths::STATE_MAC)` (ignore NotFound).
- **Testability**: implement as `save_in(dir: &Path, state, key)` /
  `load_in(dir: &Path, key)`; keep existing `save(state, key)` /
  `load(key)` signatures as thin wrappers passing `paths::STATE_DIR`, so the
  call sites in `ipc.rs` (many), `scheduler.rs:128`, and `main.rs:56/85`
  do not change.
- Keep `main.rs:56-73` corrupt-vs-missing handling as is (fail-open fresh
  start is by design).

## 4. Phase 2 — BACKLOG.md lows (all six)

All in `crates/daemon/src/ipc.rs` unless noted. Reference patterns: rollback
already exists in StartBlock (ipc.rs:177-180), TakeBreak (ipc.rs:266-272),
SetPassword (ipc.rs:397-403).

1. **Rollback in the six config arms** — AddBlock (:104), UpdateBlock (:119),
   DeleteBlock (:137), AddSchedule (:284), UpdateSchedule (:308),
   DeleteSchedule (:336). Before mutating, clone the affected collection plus
   its counter (`st.blocks` + `st.next_id`, or `st.schedules` +
   `st.next_schedule_id`); restore both on `state::save` failure. Collections
   are tiny; clones are fine.
2. **Argon2 off the state mutex** (currently `auth::verify`/`auth::hash` run
   while holding `daemon.state`, stalling scheduler/procwatch/IPC):
   - `Unlock` (:359-375): clone the PHC string, drop the lock, run
     `auth::verify` in `tokio::task::spawn_blocking`, then set
     `daemon.unlocked_until` on success.
   - `SetPassword` (:377-410): snapshot `st.password_hash` clone, drop the
     lock, run verify(old)/hash(new) in `spawn_blocking`; re-acquire the
     lock and return an error if `password_hash` no longer equals the
     snapshot (concurrent change guard); otherwise proceed with the existing
     replace + save + rollback logic.
3. **Wire frames** — `crates/core/src/wire.rs:7`: raise `MAX_FRAME` from
   1 MiB to 16 MiB (`1 << 24`). Both daemon and GUI share this constant via
   `frostbite-core`, so read/write stay symmetric. Additionally, in
   `ipc.rs::handle` (:60-70): when `write_json` fails with
   `io::ErrorKind::InvalidData`, send
   `Response::Error { message: "response too large" }` on the same stream and
   continue the loop instead of returning `Err`. Safe because `write_json`
   serializes and size-checks before writing any bytes, so the stream is not
   corrupted.
4. **GUI `ensureUnlocked` race** — `crates/gui/ui/src/main.ts` (module-level
   `unlockResolver` at :528, `promptUnlock` :531, `finishUnlock` :541,
   `ensureUnlocked` :570). Two concurrent gated actions clobber
   `unlockResolver`, leaking the first promise. Fix: add
   `let unlockPromise: Promise<boolean> | null = null`; `promptUnlock`
   returns the in-flight promise when set; `finishUnlock` resolves and clears
   both `unlockPromise` and `unlockResolver`.
5. **Stale tray tooltip** — `crates/gui/src/main.rs`, `spawn_status_watcher`
   (:154-195). On poll failure the `_ => continue` arm (:164) leaves the last
   "N active" tooltip. Fix: before `continue`, set the tooltip on tray id
   `"frostbite-tray"` to `"Frostbite — daemon unreachable"`. Do NOT touch the
   `prev` map (notification baseline) on failure.
6. **BACKLOG.md**: mark items 1-5 fixed (with commit hash), keep the
   TakeBreak ledger-residual entry marked wontfix with its existing
   rationale, and add the deferred-rename decision as a tracked entry.

## 5. Phase 3 — Launcher + one-command deploy loop

No installable artifact exists today (`bundle.active: false` in
`crates/gui/tauri.conf.json`; nothing on PATH; no .desktop file).

- **`packaging/frostbite.desktop`**:
  `Type=Application`, `Name=Frostbite`, `Comment=Website and app blocker`,
  `Exec=/usr/local/bin/frostbite-gui`, `Icon=frostbite`,
  `Categories=Utility;`, `StartupNotify=false`. Icon source is
  `crates/gui/icons/icon.png` (single icon in the repo; check its dimensions
  at implementation time and install under
  `~/.local/share/icons/hicolor/<size>x<size>/apps/frostbite.png`).
- **`packaging/upgrade.sh`** — the one command run after every change.
  Mirror the style/guards of `packaging/install.sh` (set -euo pipefail;
  build as invoking user). Order matters — the tauri build embeds `ui/dist`
  at compile time, so the UI build must precede cargo:
  1. `pnpm --dir crates/gui/ui install && pnpm --dir crates/gui/ui build`
  2. `cargo build --release`
  3. `sudo install -m0755 target/release/frostbited /usr/local/bin/frostbited`
     then `sudo systemctl restart frostbited`
  4. `sudo install -m0755 target/release/frostbite-gui /usr/local/bin/frostbite-gui`
  5. Install `frostbite.desktop` to `~/.local/share/applications/`, the icon
     to the hicolor path above, and an autostart copy of the .desktop file to
     `~/.config/autostart/` (steps under $HOME need no sudo).

## 6. Phase 4 — Test floor

New unit tests (crates/daemon already has `tempfile = "3"` as a
dev-dependency; crates/core needs a `tokio` dev-dependency with
`macros` + `rt` features added — its normal dep is io-util only):

- **state** (`crates/daemon/src/state.rs`): round-trip via
  `save_in`/`load_in` in a tempdir; legacy two-file → single-file migration
  (write old format by hand, load, save, assert `.mac` removed and reload
  works); corrupt/truncated file rejected.
- **wire** (`crates/core/src/wire.rs`): round-trip over `tokio::io::duplex`;
  oversize rejected in both directions.
- **TakeBreak accounting** (`crates/daemon/src/ipc.rs:202-273`): extract two
  pure helpers — grant computation (inputs: allowance, used-today, ends_at,
  now, requested secs → Result<u64, error>; behavior: cap by remaining
  allowance AND remaining block time; errors on zero allowance, exhausted,
  block ended, zero grant) and ledger upsert (retain today + add/update
  entry). The IPC arm calls them; tests cover cap/exhaustion/edge cases.
- **Scheduler reconcile** (`crates/daemon/src/scheduler.rs:34-132`): extract
  the tick body (steps 1-4 + ledger prune) into
  `fn reconcile(st: &mut State, now_unix: u64, now_local: &DateTime<Local>, today: i64) -> bool`
  (returns "changed"); `tick` calls it under the lock, then saves + calls
  `enforce::sync` exactly as now. Tests: wall-clock expiry;
  schedule-driven end on disable/delete/window-slide; auto-start; dedupe
  against an existing manual active for the same block; break resume;
  ledger prune. Reuse the existing test helpers `s()`/`t()`
  (scheduler.rs:183-202).
- **Procwatch matcher** (`crates/daemon/src/procwatch.rs:65-99`): extract the
  loop body of `matches_any` into a pure predicate over
  `(exe: Option<&Path>, cmdline: Option<&[String]>, comm: Option<&str>)`;
  test all three `AppMatcher` kinds incl. basename-vs-comm fallback.
- **`scripts/check.sh`** (new): `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `pnpm --dir crates/gui/ui build` (runs
  `tsc -noEmit` per ui/package.json). If the tree is not already fmt-clean,
  run `cargo fmt` in this phase's commit. Document in README under a
  Development section; mention optional use as a pre-commit hook but do not
  auto-install one.

## 7. Validation commands (per phase)

In a full dev environment (the author's machine):
```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm --dir crates/gui/ui build
cargo build --release
```
In an environment without webkit2gtk-4.1/gtk3 dev libs (e.g. a remote
container), the GUI crate cannot compile; scope Rust checks to
`-p frostbite-core -p frostbited` and rely on the pnpm build to type-check
`main.ts`. The Phase 2 tray change (`crates/gui/src/main.rs`) then needs
compile verification on the author's machine (`cargo check -p frostbite-gui`).

## 8. Manual verification (author's machine, after merge)

1. `./packaging/upgrade.sh` — first run also closes the deployment skew
   (replaces the installed `d1748b3` daemon with the fixed build).
2. Durability: `kill -9` the daemon mid-save (loop config mutations while
   killing), restart, confirm blocks/schedules/password survive; confirm
   `/var/lib/frostbite/hosts.orig` exists and matches the unmanaged hosts
   content; confirm `state.json.mac` is gone after first save.
3. Launcher: launch Frostbite from the GNOME app grid; log out/in → tray
   icon present without manual start.
4. Live-verify the `b84db7f` daemon fixes now that they're installed:
   already-on-break rejected; break grant capped by remaining block time;
   manual+schedule dedupe (manual start, then overlapping schedule window
   opens → still one ActiveBlock).
5. Re-run the full E2E suite from 2026-07-04: domain enforcement + immutable
   hosts, procwatch kill (~0.5 s), break lift/resume/cap/exhaust, password
   gating (mutations gated, StartBlock never gated), tray tooltip states,
   D-Bus notifications on block start/end.
6. Backlog spot-checks: unlock prompt no longer double-fires under two
   concurrent gated actions; stopping the daemon flips the tooltip to
   "daemon unreachable" within ~5 s.

## 9. Rollback boundaries

- One commit per phase; each phase is independently revertable in git.
  Phase 4 depends on Phase 1's `save_in`/`load_in` and Phase 2's extracted
  helpers; reverting those requires reverting Phase 4 first (or fixing tests).
- **State-format caveat (only real migration)**: once the Phase 1 daemon has
  saved, `state.json` is in the new single-file format and `state.json.mac`
  is deleted. Old daemon builds cannot read it — reverting the binary past
  Phase 1 on a live machine causes a (by-design fail-open) fresh start.
  Acceptable for this machine; note it before any live rollback.
- `hosts.orig`, the .desktop files, and `upgrade.sh` are additive; removing
  them has no runtime effect.
- The wire `MAX_FRAME` bump is compatible in both directions for mixed
  old/new GUI-daemon pairs as long as actual frames stay under 1 MiB (true
  for current data sizes).

## 10. Risks and unresolved blockers

- **Legacy-state fallback ordering**: the new-format parse must be tried
  first and fall through to legacy on MAC failure; get the migration test in
  place before installing the Phase 1 daemon over real state.
- **SetPassword concurrent-change guard** introduces a new user-visible
  error ("password changed concurrently") — extremely unlikely single-user,
  but the GUI surfaces it as an inline string; no GUI change needed.
- **icon.png dimensions unknown** — check before choosing the hicolor size
  directory.
- **rustfmt cleanliness of the existing tree unverified** — `cargo fmt` may
  produce a noisy diff; keep any reformat inside the Phase 4 commit.
- **webkit2gtk 4.1 localhost workaround** (`crates/gui/src/main.rs:198-202`,
  `remote.urls` in `crates/gui/capabilities/default.json`) is untouched by
  this milestone; any Tauri dependency bumps risk disturbing it — avoid
  upgrading GUI deps here.
- **Rename decision** remains open; cost grows with each new artifact
  (this milestone adds `frostbite.desktop`, `hosts.orig`, `upgrade.sh`).

## 11. Privileged actions requiring user approval/participation

Everything below needs the user's sudo (fingerprint) or their live session;
the implementation itself needs none of it until deploy time:

- Running `packaging/upgrade.sh` (installs `/usr/local/bin/frostbited`,
  restarts the `frostbited` systemd unit, installs
  `/usr/local/bin/frostbite-gui`).
- The kill-9-mid-save durability test against the live daemon (root to kill
  a root process) and any manual `systemctl stop/start frostbited`.
- Log out/in for the autostart check.
- If verifying in a container: `apt-get install libwebkit2gtk-4.1-dev
  libgtk-3-dev` (best-effort, may be unavailable).

## 12. Implementation status (2026-07-04)

All four repository-level phases are implemented and committed on `master`, one
commit per phase, in order:

- Phase 1 — `818b8c4` (durability: hosts fsync + `hosts.orig`, single-file
  state)
- Phase 2 — `b252b69` (backlog lows: config-arm rollback, off-lock Argon2,
  wire cap, GUI races)
- Phase 3 — `1070199` (launcher `.desktop` + `upgrade.sh`)
- Phase 4 — `b01c35a` (test floor, extracted helpers, `scripts/check.sh`,
  tree-wide `cargo fmt`)

Repository acceptance criteria all pass on the author's machine:
`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, `cargo test --workspace` (45 tests, up from 12), the pnpm UI
build (`tsc -noEmit` + vite), and `cargo build --release` (both binaries).

### Deviations from the plan as written

- **State-format tests moved from Phase 4 to Phase 1.** They cover the
  riskiest change (the state rewrite), so they were co-located with it for
  revertability and to test the risky change as it landed. All other tests
  stayed in Phase 4 as planned.
- **`write_atomic` gained a `mode` parameter** (hosts.rs) instead of a single
  hardcoded mode. The plan said "reuse `write_atomic`" with mode 0600 for
  `hosts.orig`; a single hardcoded 0600 would have regressed `/etc/hosts` from
  its required 0644 (world-readable, needed by the libc resolver). `/etc/hosts`
  is written 0644, the recovery copy 0600, both re-asserted via
  `set_permissions` after rename.
- **`load_in` corruption classification made explicit.** A present-but-
  unverifiable `state.json` now returns a non-`NotFound` error (→ "corrupted"),
  while only an absent file yields `NotFound` (→ "first run"), realizing the
  plan's stated intent precisely.
- **`paths::STATE_FILE`/`STATE_MAC` removed** (dead after the dir-based
  `save_in`/`load_in`); filenames now live in `state.rs`. Required to pass
  `clippy -D warnings`.
- **Pre-existing clippy lints fixed in Phase 4** (`procwatch` `is_none_or`,
  `gate_config` `?`), alongside the tree-wide `cargo fmt`, so the new
  `check.sh` gate passes.
- **`.desktop` includes `Terminal=false`** (standard for GUI entries) beyond
  the plan's literal field list.
- **BACKLOG "fixed" markers** reference the fixing phase (and the real Phase 1
  hash for the crash-window item); a commit cannot embed its own hash, so the
  Phase 2 items cite the phase rather than a literal SHA.
- **rustfmt + clippy components were installed** into the user's `~/.rustup`
  (`rustup component add`) — a per-user toolchain change, not a system/sudo
  modification — because `check.sh` requires them.

### Adversarial review

A multi-agent adversarial review of the full diff (`1603b2b..HEAD`, 8
dimensions, each finding double-verified) surfaced four real low/medium issues,
all fixed:

- `28c8927` — fsync the parent directory after rename in `state::save_in` /
  `hosts::write_atomic` (power-loss lost-update window); make the `hosts.orig`
  recovery-copy write best-effort so a full/RO `/var/lib` can't block an
  `/etc/hosts` enforcement change.
- `b84f8c5` — `check.sh` now finds the repo root via `git rev-parse
  --show-toplevel` (the old `$0`-based path broke the documented pre-commit
  hook) and runs `pnpm install` before the UI build (broke on a fresh clone).

One finding was investigated and dismissed as not a defect: `Unlock` verifying
against a password-hash snapshot without a re-check is intentional (only
`SetPassword`, which persists, needs the concurrent-change guard; `Unlock` only
opens a time-limited window, and the single-user race is benign).

### Pending live-system steps (need the machine owner's sudo/session)

Unchanged from §8/§11 — none were run by the implementation:

1. `./packaging/upgrade.sh` (first run also closes the `d1748b3` deployment
   skew). Validated with `bash -n` + `desktop-file-validate`; not executed.
2. `kill -9`-mid-save durability test against the live daemon; confirm
   blocks/schedules/password survive and `state.json.mac` is gone after the
   first save; confirm `/var/lib/frostbite/hosts.orig` exists and matches the
   unmanaged hosts content.
3. Launcher + autostart check (app grid; log out/in).
4. Live-verify the `b84db7f` daemon fixes and re-run the 2026-07-04 E2E suite.
