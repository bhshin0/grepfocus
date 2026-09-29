# Hardening, health signals, browser DoH policies and update paths — implementation plan

Status: **designed, implementation pending** (2026-09-28). Written against commit
`3dff97e` on branch `hardening-health` (same HEAD as `release-0.5.1`, clean tree).
Line references are as of that commit — treat symbols as authoritative, lines as
hints. Five item designs (browser DoH policies, input hardening, health signals,
version display + AppImage self-update, update-available check) were each
critiqued, revised and then reconciled into this one record. Where two items
disagreed, the resolution is stated inline and collected in *Resolved
disagreements* below. Extends `docs/plans/appimage-dist.md` (its "Upgrades"
bullet) and `docs/plans/instant-breaks.md` (the degraded flag).

Progress (fill in the commit hash as each work package lands; every package
leaves `./scripts/check.sh` green and is shippable on its own):

| WP | Scope | Commit |
|---|---|---|
| 1 | core: `validate` module, `State::sanitize`, health wire types | — |
| 2 | daemon + GUI input hardening, procwatch guards | — |
| 3 | daemon health state, `GetStatus.health`, `--version`, GUI pass-through | — |
| 4 | daemon `browser_policy` module, unit comment, cleanup parity | — |
| 5 | GUI health banner, tray RED notification, about/diagnostics line, error-state fixes | — |
| 6 | GUI/daemon skew advice + AppImage "Update system service" | — |
| 7 | daily update check, Settings toggle, `open_url`, website hand-off | — |

## Context

Three things went wrong at once in the 0.5.x line, and each was only visible to
someone reading the journal:

- **DoH bypasses blocks, and the fix for it broke Mullvad Browser.** Firefox
  self-enrols in Mozilla's DoH rollout and Mullvad Browser ships TRR-only DoH
  (`network.trr.mode=3`), so both skip `/etc/hosts`. 0.5.1 answered with an
  nftables table that drops traffic to known resolver IPs (`nftables.rs`). That
  is anycast whack-a-mole for Firefox and, for Mullvad Browser, kills *all* DNS
  during a block — documented as an accepted limit, but the wrong trade-off
  when the browsers themselves offer an enterprise-policy switch that turns DoH
  off at the source.
- **Enforcement failures are journal-only.** A failed `chattr +i`, a failed
  `nft` install, a DoH table left behind after a block, a proxy that could not
  bind, a stale `/etc/hosts` region after a failed teardown: all `warn!`, none
  reach the GUI. Nothing validates what a socket client sends either — a domain
  string carrying `\n` becomes arbitrary root-written `/etc/hosts` lines, an
  empty `cmdline:` matcher matches every process, and `procwatch` has no guard
  against killing pid 1, itself, or root services.
- **AppImage users cannot get daemon fixes.** The AppImage installs the daemon
  once via pkexec and never again; replacing the AppImage updates the GUI only.
  There is no version anywhere (no crate reads `CARGO_PKG_VERSION`, `GetStatus`
  has none, the GUI shows none), so a skew is invisible, and the installer
  itself is bash executed by `/bin/sh` — it dies under dash, i.e. on every
  Debian/Ubuntu host, which is the AppImage's audience.

Outcome after all seven packages: the daemon writes standard enterprise-policy
files that switch DoH off in Firefox, Mullvad Browser, Chromium (rpm/deb/snap),
Chrome and Brave, and reports per-browser state; every enforcement outcome and
the daemon's version/location ride on `GetStatus.health`; the GUI shows a
Status-tab banner (RED/YELLOW/INFO), a tray notification on the RED edge, and a
Settings about/diagnostics line; input is validated once (core) and used by the
daemon, the GUI and the loopback proxy; `procwatch` never signals root, itself,
pid 0/1 or kernel threads; an AppImage GUI newer than its daemon offers a
guarded pkexec re-install; and the GUI checks grepfocus.com once a day (opt-out,
disclosed) for a newer release. No version bump in any package — the release
commit owns that.

## Shared contracts

Everything below is the one definition every package builds against. A later
package never redefines a type or a DOM id introduced by an earlier one.

### 1. Core wire types (`crates/core/src/lib.rs`)

Placed after `impl Default for Settings` (lib.rs:956-969) and before
`pub struct State` (lib.rs:973). All derive
`Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize`; enums that carry
no payload are additionally `Copy`.

```rust
#[serde(rename_all = "snake_case")]
pub enum InstallKind { Package, Local, #[default] #[serde(other)] Unknown }

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NftStatus {
    Ok,
    Failed     { #[serde(default)] reason: String },   // nft could not install the table; hosts block live, DoH open
    StaleTable { #[serde(default)] reason: String },   // block ended but `nft delete` failed; retried every REVERIFY_SECS
    #[default] NotApplicable,                           // nothing enforced, no table left behind
    #[serde(other)] Unknown,                            // last apply failed before the nft half ran, or a newer tag
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostsLockStatus {
    Locked,
    Unlocked { #[serde(default)] reason: String },      // licensed for tamper_protection but chattr +i failed
    #[default] NotApplicable,                           // nothing enforced, or not licensed (no lock attempted)
    #[serde(other)] Unknown,
}

#[serde(rename_all = "snake_case")]
pub enum ProxyStatus { Holding, Degraded, #[default] Off, #[serde(other)] Unknown }

#[serde(rename_all = "snake_case")]
pub enum BrowserPolicyFailKind { Unsupported, ReadOnlyFs, NotJson, Symlink, Io, #[default] #[serde(other)] Unknown }

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserPolicyState {
    NotInstalled,                                       // browser not detected; any leftover of ours removed
    Written,                                            // we created the file (possibly seeded from distribution/policies.json)
    Merged,                                             // pre-existing admin file; only DNSOverHTTPS added, recovery copy kept
    Failed { #[serde(rename = "fail_kind", default)] kind: BrowserPolicyFailKind, #[serde(default)] reason: String },
    #[default] #[serde(other)] Unknown,
}

#[serde(default)]
pub struct BrowserPolicyStatus {
    pub browser: String,      // slug, see §3: firefox | firefox-flatpak | mullvad-browser | chromium | chromium-snap | chrome | brave
    pub path: String,         // the policy file we manage (or would manage)
    pub state: BrowserPolicyState,
    pub since_unix: u64,      // Written/Merged: mtime of the file (survives daemon restarts); else when this daemon first saw the state
}

#[serde(default)]
pub struct Health {
    pub daemon_version: String,                  // env!("CARGO_PKG_VERSION"); "" = daemon older than this field
    pub daemon_exe: String,                      // current_exe() at startup, "" if unavailable
    pub install_kind: InstallKind,
    pub nft: NftStatus,
    pub hosts: HostsLockStatus,
    pub hosts_reapplies: u32,                    // re-probe found the hosts region missing and re-applied (tamper signal); saturating
    pub nft_reinstalls: u32,                     // re-probe found the table gone while nft worked and re-installed it (firewall reload); saturating
    pub proxy: ProxyStatus,
    pub browser_policies: Vec<BrowserPolicyStatus>,  // fixed slug order, 7 entries after the first pass; [] before it / old daemon
    pub startup_notes: Vec<String>,              // what State::sanitize changed or flagged at startup (≤200 lines, last line "… and N more")
    pub last_error: Option<String>,              // last enforce::apply Err (hosts read/write, install OR teardown); cleared by the next Ok
    pub last_error_unix: Option<u64>,
}
```

Rules: every `reason` is `#[serde(default)]` (the daemon always emits it; a
missing one must never fail the `Status` parse). Every enum accepts any other
tag as `Unknown`; clients say nothing for `unknown`. `Health` and
`BrowserPolicyStatus` are `#[serde(default)]` containers so a future field never
breaks an older client. serde_derive 1.0.228 (`Cargo.lock`) accepts
`#[serde(other)]` on a unit variant of an internally tagged enum and on a plain
string enum — both shapes were probed during design. The `Failed` payload field
is *renamed* to `fail_kind` because the internal tag already uses `kind`.

Exact JSON the daemon emits (the contract; pinned by a core test):

```json
"health": {
  "daemon_version": "0.5.1",
  "daemon_exe": "/usr/local/bin/grepfocusd",
  "install_kind": "local",
  "nft":   {"kind": "ok"},
  "hosts": {"kind": "locked"},
  "hosts_reapplies": 0,
  "nft_reinstalls": 0,
  "proxy": "holding",
  "browser_policies": [
    {"browser": "firefox",         "path": "/etc/firefox/policies/policies.json",              "state": {"kind": "written"},      "since_unix": 1790000000},
    {"browser": "firefox-flatpak", "path": "/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/x86_64/stable/policies/policies.json", "state": {"kind": "not_installed"}, "since_unix": 1790000000},
    {"browser": "mullvad-browser", "path": "/usr/lib/mullvad-browser/distribution/policies.json", "state": {"kind": "failed", "fail_kind": "read_only_fs", "reason": "opening …grepfocus.tmp: Read-only file system (os error 30)"}, "since_unix": 1790000000}
  ],
  "startup_notes": [],
  "last_error": null,
  "last_error_unix": null
}
```

Other variants on the wire: `{"kind":"failed","reason":"…"}`,
`{"kind":"stale_table","reason":"…"}`, `{"kind":"not_applicable"}`,
`{"kind":"unlocked","reason":"…"}`, `"proxy":"degraded"|"off"`,
`"install_kind":"package"|"local"|"unknown"`.

### 2. `GetStatus` additions

`Response::Status` (lib.rs:1172-1241) gains exactly one field, after
`instant_breaks_degraded` (lib.rs:1234-1240):

```rust
/// Enforcement health + daemon identity (see `Health`). `#[serde(default)]`:
/// an old daemon never emits it and the client reads `Health::default()`,
/// whose empty `daemon_version` is the tell.
#[serde(default)]
health: Health,
```

`instant_breaks_degraded` stays on the wire, doc changed to "DEPRECATED, still
emitted: always equal to `health.proxy == Degraded`". Nothing else on `Status`
changes. Exhaustive constructions/patterns that must change with it:
`crates/daemon/src/ipc.rs:214-232`, `crates/gui/src/main.rs:137-169` (compile
error if missed — the deploy-skew safety net), and the test literal at
`crates/core/src/lib.rs:2613-2634`.

**Resolved:** the browser-policy design put `browser_policies` at the top level
of `Status` and the self-update design used `health: Option<DaemonHealth>`
with two fields. One `health: Health` object carries everything;
`health.daemon_version == ""` replaces `health == None` as the
"pre-reporting daemon" signal.

### 3. Daemon-side API

**`crates/daemon/src/health.rs`** (WP3) — pure state + transitions behind a leaf
`std::sync::Mutex` on `Daemon` (`pub health: std::sync::Mutex<health::HealthState>`,
helper `Daemon::health() -> MutexGuard`), replacing
`Daemon.instant_breaks_degraded: AtomicBool` (main.rs:78-82, :254; ipc.rs:229-231,
:1417; enforce.rs:157-160). Held for microseconds, never across an await, so it
may be taken under `applied` (enforce) or under `state` (ipc) without extending
the lock order — the `forwardable` discipline at main.rs:57-62.

```rust
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
impl HealthState {
    pub fn new(daemon_exe: String, install_kind: InstallKind, startup_notes: Vec<String>) -> Self;
    pub fn set_proxy(&mut self, proxy: ProxyStatus);                                   // every tick (live, not memo)
    pub fn apply_succeeded(&mut self, nft: NftStatus, hosts: HostsLockStatus);         // clears last_error; StaleTable kept only after Ok/StaleTable/Unknown
    pub fn apply_failed(&mut self, err: &anyhow::Error, now: u64);                     // both halves → Unknown (pre-write chattr -i already ran)
    pub fn nft_reprobed(&mut self, prev_ok: bool, result: Result<(), &anyhow::Error>); // prev_ok && Ok → nft_reinstalls += 1; Err → Failed, never counted
    pub fn teardown_retried(&mut self, result: Result<(), &anyhow::Error>);            // Ok → NotApplicable; Err → StaleTable
    pub fn hosts_drift_detected(&mut self);                                            // hosts_reapplies saturating += 1
    pub fn set_browser_policies(&mut self, list: Vec<BrowserPolicyStatus>);            // whole-list replace; called by browser_policy::run after every pass
    pub fn snapshot(&self) -> Health;                                                  // stamps DAEMON_VERSION, caps startup_notes at 200
}
pub fn reason(err: &anyhow::Error) -> String;            // `{err:#}`, trimmed, ≤500 chars + "…"
pub fn install_kind_for(exe: &Path) -> InstallKind;      // strips " (deleted)", then parent dir: /usr/bin → Package, /usr/local/bin → Local, else Unknown
```

**`crates/daemon/src/browser_policy.rs`** (WP4) —
`targets(root, state_dir) -> Vec<Target>` in fixed slug order,
`reconcile(&[Target], now) -> Vec<BrowserPolicyStatus>`,
`remove_all(&[Target]) -> Vec<(Browser, RemoveOutcome)>`,
`fold_cleanup(..) -> (cleanup::Outcome, Vec<String>)`,
`managed_paths(root, state_dir) -> Vec<String>`, task `run(Arc<Daemon>)` with
`RECHECK = 60 s`. **Resolved:** the policy design's separate
`Daemon.browser_policies` mutex is dropped; the task publishes each pass with
`daemon.health().set_browser_policies(statuses.clone())`. The health design's
`label`, `reason: Option<String>`, plain-string `state` and `Skipped` variant are
dropped in favour of the policy design's tagged state with `fail_kind` and
`since_unix` (the health copy needs both); the GUI maps slugs to display names.

**`crates/core/src/validate.rs`** (WP1) — `hostname_shape`, `normalize_domain`,
`normalize_matcher`, `matcher_kind_label`, `matcher_text`, `validate_block`,
`is_self_target`, the two error enums and the constants; `State::sanitize` next
to `absorb_legacy_allowance` (lib.rs:1031-1050). Consumers (WP2): ipc
AddBlock/UpdateBlock, main.rs startup, enforce `union_domains`/`forwardable_set`,
procwatch `enforced_groups`, listener `plausible_hostname`, GUI
`add_block`/`update_block`.

`startup_notes`: `State::sanitize` runs in `run_daemon` before `Daemon` is built
(WP2 logs them; WP3 hands the same `Vec<String>` to `HealthState::new`). No
`Daemon.startup_notes` field — in a `[[bin]]` crate under `-D warnings` a field
nothing reads is a clippy failure.

### 4. GUI: `AppEnv`, `StatusOut`, Tauri commands

`AppEnv` (crates/gui/src/main.rs:314-328) becomes:

```rust
struct AppEnv {
    appimage: bool,          // $APPIMAGE set by AppRun
    gui_version: String,     // GUI_VERSION (WP5)
    packaged_daemon: bool,   // /usr/bin/grepfocusd exists (WP6)
    local_daemon: bool,      // /usr/local/bin/grepfocusd exists (WP6)
}
```

`const GUI_VERSION: &str = env!("CARGO_PKG_VERSION")`,
`PACKAGED_DAEMON_BIN = "/usr/bin/grepfocusd"`, `LOCAL_DAEMON_BIN = "/usr/local/bin/grepfocusd"`;
a unit test pins `crates/gui/tauri.conf.json`'s `version` to `GUI_VERSION`.
**Resolved:** the health design's `AppEnv.version` and the self-update design's
`gui_version` are one field, `gui_version`; the update-check design's
`app.package_info().version` is replaced by `GUI_VERSION` (one source, the
workspace version).

`StatusOut` (main.rs:106-132) gains `health: Health` (WP3, pass-through) and
`update: version::UpdateAdvice` (WP6, computed in `get_status`, not license-gated).

New Tauri commands — only WP7 adds any; each must be registered in ALL THREE
sync points (`main.rs` `generate_handler!` :737-760, `build.rs` `.commands([...])`
:4-25, `capabilities/default.json` `allow-*` :10-33):

| Command | Returns | ACL name |
|---|---|---|
| `get_update_info()` | `UpdateInfo` | `allow-get-update-info` |
| `acknowledge_update_check()` | `UpdateInfo` | `allow-acknowledge-update-check` |
| `check_for_update()` | `UpdateInfo` (Err only when disabled) | `allow-check-for-update` |
| `set_update_check_enabled(enabled: bool)` | `UpdateInfo` | `allow-set-update-check-enabled` |
| `dismiss_update()` | `UpdateInfo` (no argument) | `allow-dismiss-update` |
| `open_url(url: String)` | `()` (allowlisted to `https://grepfocus.com/`, `https://www.grepfocus.com/`, ≤2048 bytes) | `allow-open-url` |

`install_service` (existing) is reused by the WP6 skew banner and the first-run
dialog; `installServiceAndWait()` is its only frontend caller. `tauri-plugin-shell`
(declared, never initialised) is removed in WP7.

### 5. Settings

No change to core `Settings` or `SetSettings` in any package. The update-check
preference is GUI-local, per user: `$XDG_CONFIG_HOME/grepfocus/update-check.json`
(fallback `~/.config/grepfocus/update-check.json`; dir 0700, file 0600,
`<file>.<pid>.tmp` + rename; keys `schema, enabled (default true), disclosed
(default false), last_check_unix, latest, dismissed_version, check_error`;
`schema` ignored on read; not removed by uninstall or `cleanup --purge`). No
browser-policy toggle in v1 (open question 2). No password gate on the
update-check toggle.

### 6. systemd unit

No directive changes. `packaging/systemd/grepfocusd.service:15-17` comment is
extended to list the policy paths (`/etc/firefox/policies`,
`/etc/chromium|/etc/opt/chrome|/etc/brave/policies/managed`,
`/var/snap/chromium/current/policies/managed`,
`/usr/lib/mullvad-browser/distribution`) so a future hardening pass adds
`ReadWritePaths=` for each. Verified: the unit has no `ProtectSystem`,
`ProtectHome`, `ReadOnlyPaths`, `ReadWritePaths`; `UMask=0022`; the daemon runs
`unconfined_service_t`, so inherited SELinux labels match `matchpathcon` and no
policy module is needed.

### 7. `install_kind` semantics

Classified once at daemon startup from `current_exe()` (never re-read: after an
in-place update `/proc/self/exe` gains a " (deleted)" suffix, which
`install_kind_for` strips anyway). `package` = `/usr/bin/grepfocusd` (rpm/deb/AUR;
also hardcoded in `debian/grepfocus.prerm` and the installer's `PACKAGED_BIN`).
`local` = `/usr/local/bin/grepfocusd`: the AppImage's pkexec installer
(`packaging/appimage/appimage-install.sh:26`) **or** the dev scripts
(`packaging/install.sh`, `upgrade.sh`) — *not* evidence of an AppImage install;
the self-update advice keys off `$APPIMAGE` plus the two binary probes, never
off `install_kind` alone. `unknown` = anything else (cargo run, `/opt`) — the
conservative branch, never an install offer. The dev box is `local`
(`ExecStart=/usr/local/bin/grepfocusd`, no rpm installed).

### 8. Version compare — one implementation

`crates/gui/src/version.rs` (WP6), on the `semver` crate (already compiled into
the GUI via tauri-utils, so `semver = "1"` adds no crate — only a lock-file edge):

```rust
pub fn parse_version(s: &str) -> Option<semver::Version>;   // trim; strip one leading 'v'/'V'
pub fn compare(a: &str, b: &str) -> Option<Ordering>;       // None when either side does not parse
pub fn newer_than(latest: &Version, current: &Version) -> bool;   // strict >
pub fn advise(p: Probe) -> UpdateAdvice;                    // the skew decision table (§WP6)
```

Both the skew advice (WP6) and the release check (WP7, `notice_for`) call these.
**Resolved:** the self-update design's hand-rolled triple parser is dropped
(prerelease ordering is semver's; `Less` never offers an install, so an `-rc`
tag can never trigger one). The daemon never compares versions. The single
deliberate exception is the installer script's `sort -V` downgrade guard
(§WP6), which must work as root without the GUI; releases are plain
`MAJOR.MINOR.PATCH` so both agree.

### 9. Website `latest.json` contract

`GET https://grepfocus.com/downloads/latest.json`, `application/json`, < 64 KiB,
HTTP 200 only, `Access-Control-Allow-Origin: *`, `Cache-Control: public,
max-age=300, s-maxage=3600`:

```json
{
  "schema": 1,
  "version": "0.6.0",
  "published": "2026-10-01",
  "notes_url": "https://grepfocus.com/changelog",
  "downloads": {
    "rpm":      {"url": "https://grepfocus.com/downloads/grepfocus-0.6.0-1.fc44.x86_64.rpm", "sha256": "<64 lowercase hex>", "built_for": "fc44"},
    "deb":      {"url": "https://grepfocus.com/downloads/grepfocus_0.6.0-1_amd64.deb",       "sha256": "<64 lowercase hex>", "built_for": "ubuntu-24.04"},
    "appimage": {"url": "https://grepfocus.com/downloads/GrepFocus_0.6.0_amd64.AppImage",    "sha256": "<64 lowercase hex>"}
  }
}
```

Only `version` is required (newest **stable** release, plain semver, no `v`, no
prerelease). Every URL must start with `https://grepfocus.com/` or
`https://www.grepfocus.com/` (the client refuses anything else); `url`s are the
versioned files, not the redirect aliases, so `sha256` stays stable; unknown
fields and extra `downloads` keys (e.g. `rpm-fc45`) are ignored. The `/download`
route must stay: the GUI opens `https://grepfocus.com/download` from the skew
banner. Client behaviour: UA `GrepFocus/<ver> (linux)`, no query string, no
cookies, redirects only over https, one GET per running GUI per 24 h in steady
state (404/5xx/unusable bodies count as a completed check; only DNS/connect/
timeout failures retry hourly, and those never reach the origin).

### 10. CLI

`grepfocusd --version` / `-V` → stdout `grepfocusd <ver>`, exit 0 (WP3; the
installer's downgrade guard parses it). `grepfocus-gui --version` / `-V` →
`grepfocus-gui <ver>`, exit 0, before any Tauri init so it never surfaces an
existing window (WP5).

### 11. Status-tab surfaces, top to bottom (all siblings ABOVE `#status-content`, which `refreshStatus` rewrites every poll)

1. `#health-banner` (WP5, `role="status" aria-live="polite"`) — enforcement
   notices, one `.health-notice.{error|warn|info}` element each.
2. `#update-banner` (WP6, `.lock-state` card; children `#update-text`,
   `#update-action`, `#update-msg`) — GUI/daemon skew; the only banner with a
   pkexec button.
3. `#update-disclosure` then `#update-notice` (WP7, `.update-strip`) — the
   release check.

Precedence: `#update-notice` is hidden while a block is active **and** while
`#update-banner` shows a non-`up_to_date` advice (fix what is on disk first; the
Settings row still reports the newer release). `renderUpdateBanner` is skipped
while `installBusy`. The global rule `[hidden] { display: none !important; }`
lands in WP5 (author `display: flex/grid` rules beat the UA `[hidden]` rule;
`#old-pw-label` at index.html:109 is a grid label carrying `hidden` — eyeball it
once after WP5).

Settings tab: `#prefs` (index.html:95-105) gains the update-check toggle, row and
persist line (WP7); after `#password-form`'s `</form>` comes
`<div id="about"><p id="about-line" class="hint"></p><p id="health-diag" class="hint"></p></div>`
(WP5). **Resolved:** the update-check design's Settings "Reinstall system
service" row (`#service-row`) is dropped — the WP6 banner and the first-run
dialog's `stopped` mode are the two guarded paths to the installer, and a third
unguarded button at the same version added nothing. First-run dialog
(index.html:240-249): modes `install | relogin | packaged | stopped` (WP6), a
ghost `#firstrun-secondary` "Reinstall service" button for `stopped`, and the
one-sentence DoH-policy disclosure appended to the `install` body (WP4; the WP6
refactor keeps it).

### 12. Deploy-skew rule

`Response::Status` gains a field the GUI pattern-matches exhaustively, so daemon
and GUI must ship together (`packaging/upgrade.sh` rebuilds both; packages
carry both). Runtime mixes still work: old GUI ignores `health` (no
`deny_unknown_fields` anywhere in core), new GUI on an old daemon reads
`Health::default()` and says nothing.

### Resolved disagreements

| Topic | Items | Resolution |
|---|---|---|
| Where `browser_policies` rides | policy: top-level `Status` field; health: inside `Health` | Inside `Health`; policy task calls `HealthState::set_browser_policies` |
| `BrowserPolicyStatus` shape | policy: tagged `state` + `fail_kind` + `since_unix`; health: `label`, plain `state`, `reason`, `Skipped` | Policy shape; GUI maps slugs to names; no `Skipped` (writes are unconditional) |
| Daemon identity on the wire | health: `Health{daemon_version,…}`; self-update: `Option<DaemonHealth>` | `health: Health`, `daemon_version == ""` means pre-reporting daemon |
| `install_kind_for` | health: parent-dir match after stripping " (deleted)"; self-update: prefix match | Parent-dir match, in `health.rs` |
| `--version` arms | health and self-update both add the daemon arm | Once, in WP3; GUI arm in WP5 |
| `AppEnv` version field | health: `version`; self-update: `gui_version` | `gui_version` |
| Version parsing | self-update: hand-rolled; update-check: `semver` | `semver` in `crates/gui/src/version.rs`, used by both |
| Current GUI version | update-check: `package_info()`; self-update: `CARGO_PKG_VERSION` | `GUI_VERSION = env!("CARGO_PKG_VERSION")`, test pins tauri.conf.json |
| `Daemon.startup_notes` field | hardening: unlocked field on `Daemon` | No field (dead code under `-D warnings`); notes go into `HealthState::new` in WP3 |
| Reinstall-service button in Settings | update-check adds one | Dropped; WP6 banner + `stopped` first-run mode are the paths |
| Download link | self-update: plain text; update-check: `open_url` | WP6 ships text; WP7 turns it into a "Download" button via `open_url` |
| `tauri-plugin-shell` | self-update: leave; update-check: drop | Dropped in WP7 (touches `Cargo.lock` there anyway) |
| Browser-policy failures in the banner | health: YELLOW for every `failed` | YELLOW for `not_json`/`symlink`/`io` (fixable), INFO for `unsupported`/`read_only_fs` (not fixable), nothing for `unknown` |
| WP order | task sketch: policy before health | Health state before policy, so the policy task has somewhere to report |

## Implementation order

Each package: files, concrete changes with hook points, tests, and a
"done when" that includes `./scripts/check.sh` (fmt, clippy `--workspace
--all-targets -D warnings`, `cargo test --workspace`, `pnpm build`). Commit
messages never mention AI tooling.

### WP1 — core: validators + health wire types

Depends on: nothing. Touches only `crates/core`.

**Files**

| Action | Path |
|---|---|
| ADD | `crates/core/src/validate.rs` |
| EDIT | `crates/core/src/lib.rs` — `pub mod validate;` next to lib.rs:11-13; health types after :969; `State::sanitize` inside `impl State` (:1031-1050); tests |

**`validate.rs`** (pure, no I/O, no tracing):

```rust
pub const MAX_HOSTNAME_LEN: usize = 253;   pub const MAX_LABEL_LEN: usize = 63;
pub const WWW_ALIAS_RESERVE: usize = 4;    // render_block adds "www." and the alias must fit the DNS limit
pub const MAX_DOMAINS_PER_BLOCK: usize = 5000; pub const MAX_APPS_PER_BLOCK: usize = 500;
pub const MAX_BLOCK_NAME_CHARS: usize = 200;   pub const MIN_CMDLINE_CHARS: usize = 3;
pub const MAX_MATCHER_BYTES: usize = 4096;     pub const MAX_BASENAME_BYTES: usize = 255;
pub const SELF_MARKER: &str = "grepfocus";     // case-insensitive substring: grepfocusd, grepfocus-gui, GrepFocus-*.AppImage
pub fn is_self_target(s: &str) -> bool;
pub enum DomainError  { Empty, NotAscii, TooLong, EmptyLabel, LabelTooLong, BadChar, HyphenEdge, SingleLabel, LooksLikeIp, Wildcard }
pub enum MatcherError { Empty, ControlChar, TooLong, NotAbsolute, BadComponent, TrailingSlash, ContainsSlash, TooShort, SelfMatch }
// both Copy + PartialEq + Eq, with message(self) -> &'static str and Display
pub fn hostname_shape(host: &str) -> Result<(), DomainError>;          // RFC 1123 SHAPE only; no lowercasing, no policy (the proxy wraps this)
pub fn normalize_domain(raw: &str) -> Result<String, DomainError>;     // canonical stored form; idempotent
pub fn normalize_matcher(m: &AppMatcher) -> Result<AppMatcher, MatcherError>;   // idempotent
pub fn matcher_kind_label(m: &AppMatcher) -> &'static str;             // "exe path" | "basename" | "cmdline pattern"
pub fn matcher_text(m: &AppMatcher) -> &str;
pub fn validate_block(block: &mut Block) -> Result<(), String>;        // normalizes in place; Err = exact user-facing text; does NOT call validate_policy
```

`normalize_domain`, in order: trim; strip `http://`/`https://` (ASCII
case-insensitive via `get(..n)` + `eq_ignore_ascii_case`); cut at first `/`,
`?`, `#`; strip a trailing `:<digits>`; strip one trailing `.`; `*` →
`Wildcard`; `hostname_shape` (this is where `\n`, space, `#`, `_`, `@`, `[`,
non-ASCII and bad lengths land — ASCII is checked on the host part only, so
`https://reddit.com/r/ünicode` → `reddit.com`); lowercase; non-`www.` names
longer than 249 bytes → `TooLong`; fewer than 2 labels → `SingleLabel`; last
label all digits → `LooksLikeIp`. The `www.` prefix is kept as typed
(`render_block` and `forwardable_set` own the alias).

`normalize_matcher`: trim; empty → `Empty`; any `char::is_control()` →
`ControlChar`; > 4096 bytes → `TooLong`. `ExePath`: must start with `/`
(`NotAbsolute`), not end with `/` (`TrailingSlash`), no `""`/`.`/`..` component
(`BadComponent` — `/usr//bin/steam` can never equal a resolved `/proc/<pid>/exe`),
`is_self_target(file_name)` → `SelfMatch`. `Basename`: no `/` (`ContainsSlash`),
≤255 bytes, self-target. `Cmdline`: `chars().count() >= 3` (`TooShort`),
self-target.

`validate_block` order and exact messages (tests pin them): `name is required`
/ `name cannot contain control characters` / `name is too long (max 200
characters)`; `a block can hold at most 5000 domains`; per domain
`domain {raw:?}: {DomainError}` (Debug-quoted, first 40 chars + `…`), dedupe
after normalization keeping first occurrence; `a block can hold at most 500 app
matchers`; per matcher `{kind} {raw:?}: {MatcherError}`; dedupe; finally
`a block needs at least one domain or app to block`. Domain messages:
`hostname is empty` · `international domain names must be entered in punycode
(xn--…) form` · `hostname is too long (max 253 characters including its www.
alias)` · `hostname has an empty label (two dots in a row, or a leading dot)` ·
`a hostname label is too long (max 63 characters between dots)` · `hostname
contains an invalid character — only letters, digits, dots and hyphens, one
hostname per entry` · `a hostname label cannot start or end with a hyphen` ·
`enter a full hostname with a dot, e.g. reddit.com` · `IP addresses cannot be
blocked — enter a hostname, e.g. reddit.com` · `wildcards are not supported —
reddit.com also blocks www.reddit.com; list other subdomains explicitly`.
Matcher messages: `must not be empty` · `cannot contain control characters` ·
`is too long` · `must be absolute (start with /), e.g. /usr/bin/steam` · `cannot
contain ., .. or empty (//) components — use the resolved path` · `must name a
file, not a directory` · `cannot contain / — use an exe path for a full path` ·
`must be at least 3 characters — a shorter pattern would match nearly every
process` · `would match GrepFocus itself, which cannot block itself`.

**`State::sanitize(&mut self) -> Vec<String>`**: applies to `blocks` (ctx
`saved`) and `active[*].block` (ctx `active` — enforcement reads the active
copies, enforce.rs:385 / procwatch.rs:78); normalizes or drops each domain and
matcher with one note per change (`block {id} ({ctx}) {name:?}: domain {raw:?}
normalized to {n:?}` / `dropped domain {raw:?}: {e}` / same for matchers /
`removed duplicate …`); never drops a block, never edits a name, never
truncates; note-only entries for over-cap lists and invalid names (`… exceeds
the 5000 limit — edits will be refused until it is trimmed`). Mutating part is
idempotent; over-cap notes repeat every start on purpose.

**Health types**: exactly §1.

**Tests** (core): `validate.rs` in-module — `hostname_shape_accepts_wire_shapes`
(incl. `localhost`, `1.2.3.4`, exactly 253) and each rejection kind;
`normalize_domain_canonical_forms_pass_through`, `_normalizes` (scheme/path/
port/trailing dot/uppercase/`ünicode` path), `_is_idempotent`,
`_rejects_injection` (`"reddit.com\n0.0.0.0 evil.example"`, space, tab+`#`,
NUL, CRLF → `BadChar`), `_rejects_unicode`, `_rejects_shape`, `_length_limits`
(249 vs 250 non-www; `www.`+249 = 253 passes); `normalize_matcher_exe_path`
(incl. `/tmp/.mount_x/usr/bin/grepfocus-gui`, `/home/u/GrepFocus-0.5.1-x86_64.AppImage`
→ `SelfMatch`), `_basename`, `_cmdline`, `_is_idempotent`;
`validate_block_normalizes_and_dedupes`, `_error_text_names_the_entry` (exact
strings incl. the 40-char truncation), `_rejects_name_counts_and_empty` (201
chars via a multibyte char), `_leaves_policy_alone`. lib.rs —
`sanitize_normalizes_saved_and_active_copies`, `sanitize_notes_over_cap_without_truncating`;
`health_round_trips_with_payload_variants` (Failed/Unlocked/StaleTable/Local/
Degraded/browser `failed{read_only_fs}`/last_error), `health_wire_field_names_are_pinned`
(`serde_json::to_value` equals the §1 literal, including `"fail_kind"`),
`health_unknown_variants_degrade_to_unknown` (`{"nft":{"kind":"quantum"},
"hosts":{"kind":"welded"},"proxy":"warp","install_kind":"snap","browser_policies":
[{"state":{"kind":"something_new"}},{"state":{"kind":"failed","fail_kind":"x"}}]}`),
`health_payload_without_reason_still_parses`, `health_partial_object_fills_defaults`,
`browser_policy_status_missing_since_unix_is_zero`.

**Done when**: `./scripts/check.sh` green; `git diff --stat` shows only
`crates/core`; no wire change yet (`Response::Status` untouched).

### WP2 — daemon + GUI input hardening, procwatch guards

Depends on: WP1.

**Files**

| Action | Path | Change |
|---|---|---|
| EDIT | `crates/daemon/src/ipc.rs` | AddBlock (:235-277), UpdateBlock (:279-333), tests |
| EDIT | `crates/daemon/src/main.rs` | startup sanitize + save before the "Drop any active blocks" comment (:222), merged with the `dropped` save (:229-235) |
| EDIT | `crates/daemon/src/enforce.rs` | `union_domains` (:379-392), `forwardable_set` (:407-437), tests |
| EDIT | `crates/daemon/src/hosts.rs` | `render_block` belt (:156-169), tests |
| EDIT | `crates/daemon/src/procwatch.rs` | module doc, `run` (:19-62), `enforced_groups` (:71-80), `sweep` (:95-119), delete `matches_any` (:121-131), tests |
| EDIT | `crates/daemon/src/listener.rs` | `MAX_HOSTNAME` (:199), `plausible_hostname` (:881-901), one test |
| EDIT | `crates/gui/src/main.rs` | `add_block` (:27-34), `update_block` (:42-49) |
| EDIT | `crates/gui/ui/src/main.ts` | `parseAppLines` (:160-168), `readBlockForm` split (:232-235), edit-form labels (:461-465) |
| EDIT | `crates/gui/ui/index.html` | labels/placeholders (:33-37) |
| EDIT | `README.md`, `BACKLOG.md` | see *Docs* |

**Changes**

- ipc.rs AddBlock: after `gate_config` (:237-239) and before the
  `{ let lic = daemon.license.lock().await;` block (:239-240):
  `if let Err(msg) = validate_block(&mut block) { return err(msg); }` — before
  `gate_add_block` so a typo gets the typo error, not a premium gate, and the
  app-count gate sees the deduped list. UpdateBlock: after the active check
  (:284-286), before the saved/`update_needs_app_license` block (:287-306), so a
  retyped-but-equal app list compares equal to the canonical saved one and is
  not gated after a downgrade. `validate_policy`/`set_policy` unchanged.
- main.rs: `let notes = initial.sanitize(); for n in &notes { warn!(%n,
  "sanitized stored block content"); }` and
  `if dropped > 0 || !notes.is_empty() { state::save(..) }`. `notes` is kept in
  scope — WP3 passes it to `HealthState::new`.
- enforce.rs `union_domains`: `match validate::normalize_domain(d) { Ok(n) =>
  set.insert(n), Err(e) => debug!(domain = ?d, block = a.block.id, %e,
  "skipping invalid stored domain") }` — `debug!`, it runs on every 1 s tick.
  `forwardable_set`: `normalize_domain(d).ok()` in place of
  `trim()/to_ascii_lowercase()` (:421-429); `www.` aliasing and the union
  subtraction unchanged.
- hosts.rs `render_block`: `fn line_safe(d) -> bool` (bytes in `0x21..0x7f`,
  not `#`); `if !line_safe(d) { warn!(domain = ?d, "refusing to write unsafe
  hosts entry"); continue; }`. The last belt before root writes `/etc/hosts`,
  deliberately independent of core.
- procwatch.rs: `fn is_protected(pid: i32, uid: u32, kthread: bool, self_pid:
  i32) -> bool { pid <= 1 || pid == self_pid || kthread || uid == 0 }`;
  `fn sweep(groups, self_pid)`, per process: pid check → `proc.uid()` (one
  fstat; the *effective* uid — `task_dump_owner` exempts the top-level pid dir
  from the dumpable→root rule) → `is_protected` → `proc.stat()` once →
  `stat.flags & StatFlags::PF_KTHREAD.bits() != 0` belt → only then `exe()`/
  `cmdline()` → `proc_matches(.., Some(&stat.comm), ..)`. `self_pid =
  std::process::id() as i32` once in `run`, moved into the `spawn_blocking`
  closure (:44). `enforced_groups` maps apps through `normalize_matcher(m).ok()`
  and drops empty groups. Decision: uid 0 is skipped outright (systemd,
  logind, our own `nft`/`chattr` children; `sudo`/`pkexec`-launched apps are
  euid 0 and survive — documented). Not `uid < 1000`: `UID_MIN` is
  distro-configurable and a wrong boundary silently stops blocking the user's
  own apps.
- listener.rs: `use grepfocus_core::validate;`; `const MAX_HOSTNAME: usize =
  validate::MAX_HOSTNAME_LEN;`; `plausible_hostname` body becomes
  `validate::hostname_shape(host).is_ok()` (identical rule set; the 41
  listener tests stand). `hostname_from_str` keeps lowercasing, so wire names
  and stored names compare equal.
- GUI main.rs: `let mut block = block; grepfocus_core::validate::validate_block
  (&mut block)?;` before `client::call` in both commands (same text as the
  daemon, no round trip; the daemon stays authoritative). main.ts:
  `readBlockForm` splits domains on `/[\s,]+/`; `parseAppLines` gains a
  `cmdline:` prefix branch (`CMDLINE_PREFIX = "cmdline:"`, matching the card
  renderer at :499-503 — today an edit silently turns a cmdline matcher into a
  basename). index.html:33-37 labels: `Domains (one per line — hostnames only,
  e.g. reddit.com; the www. form is blocked too)`, `App exe paths, basenames,
  or cmdline:<substring> (one per line)`; placeholder
  `/usr/bin/steam&#10;discord&#10;cmdline:com.discordapp.Discord`; same on the
  edit-form clone (main.ts:461-465).

**Tests**: ipc.rs (dispatch style of `add_block_refuses_an_invalid_policy`
:1725; fixtures `blk` :1901, `steam`/`discord` :1932-1942, `err_msg` :1956,
`assert_not_premium_gated` :1965) — `add_block_refuses_injection_domain`,
`_refuses_empty_cmdline_matcher`, `_refuses_self_matcher`, `_refuses_empty_block`,
`update_block_refuses_bad_domain_without_mutation`,
`add_block_validation_precedes_premium_gate`,
`update_block_refuses_over_cap_legacy_block` (seed 5001 domains directly),
`update_block_retyped_apps_not_gated_after_downgrade`,
`update_block_changed_apps_still_gated_after_downgrade`. procwatch.rs —
`is_protected_matrix`, `enforced_groups_drops_invalid_matchers`. hosts.rs —
`render_block_never_emits_an_unsafe_line` (output exactly `"\n"`),
`render_block_line_count_is_bounded`. enforce.rs —
`union_domains_canonicalizes_and_drops_invalid`; extend
`forwardable_is_on_break_minus_union` (:504) with trailing-dot and uppercase.
listener.rs — `canonical_domains_round_trip_through_the_wire_parser`.

**Done when**: `./scripts/check.sh` green; the injection frame from *Live
verification* step 2.2 is refused with the exact `domain "reddit.com\n0.0.0.0
evil.example": hostname contains an invalid character …` text; a `sleeper`
block kills `sleep` as the user and never `sudo sleep`.

### WP3 — daemon health state, `GetStatus.health`, `--version`, GUI pass-through

Depends on: WP1 (types), WP2 (the `notes` vec).

**Files**

| Action | Path | Change |
|---|---|---|
| EDIT | `crates/core/src/lib.rs` | `Response::Status.health` (§2); doc on `instant_breaks_degraded`; test literal :2613-2634 gets `health: Health::default()`; test `status_without_health_still_deserializes` |
| ADD | `crates/daemon/src/health.rs` | §3 |
| EDIT | `crates/daemon/src/main.rs` | `mod health;` (:16-27); `Daemon.health` replaces `instant_breaks_degraded` (:78-82, :254); `--version` arm before `Some(other)` (:133) + usage line (:137-149); startup `info!` gains `version`, `exe`, `install_kind` (:237-242); `HealthState::new(exe, install_kind, notes)` |
| EDIT | `crates/daemon/src/hosts.rs` | `apply_block(..) -> anyhow::Result<HostsLockStatus>` (:54; match at :73-91 returns `Locked` / `Unlocked{reason}` / `NotApplicable`) |
| EDIT | `crates/daemon/src/nftables.rs` | `clear()` (:167-181) returns `Err(anyhow!("nft delete failed (status {}): {}", ..))` on any non-zero exit other than "absent" (the `warn!` at :178 goes) |
| EDIT | `crates/daemon/src/enforce.rs` | `ApplyOutcome`, `proxy_status`, `install_nft_status`, `teardown_nft_status`, `apply(..) -> Result<ApplyOutcome>` (:455-475), five `sync` hooks, module doc |
| EDIT | `crates/daemon/src/ipc.rs` | GetStatus (:214-232): `let health = daemon.health().snapshot(); let instant_breaks_degraded = health.proxy == ProxyStatus::Degraded;`; `test_daemon` (:1417) → `health: std::sync::Mutex::new(HealthState::default())` |
| EDIT | `crates/gui/src/main.rs` | import `Health`; `StatusOut.health` (:106-132); destructure + init in `get_status` (:137-169) |
| EDIT | `crates/gui/ui/src/main.ts` | TS types `InstallKind`, `NftStatus`, `HostsLockStatus`, `ProxyStatus`, `BrowserPolicyFailKind`, `BrowserPolicyStatus`, `Health` after `Settings` (:97-102); `Status.health: Health` (:104-125). Types only — no rendering. |
| EDIT | `README.md` wire table row :157 + Health paragraph; `docs/plans/instant-breaks.md:130-133` | see *Docs* |

**`sync` hooks** (enforce.rs:120-232), none inside an `.await`:

1. :157-160 — replace the atomic store with `daemon.health().set_proxy(proxy_status(detection));`.
2. New, first thing inside `if prev.matches(&domains, sink) {` (:162): on an
   empty union, if `!prev.nft_ok && now.abs_diff(prev.verified_at) >=
   REVERIFY_SECS` → `let res = nftables::clear(); daemon.health().teardown_retried
   (res.as_ref().map(|_| ())); prev.nft_ok = res.is_ok(); prev.verified_at =
   now;` then `return Ok(())`. A teardown that left the DoH table behind now
   self-heals at the probe cadence (log at `debug!`).
3. :177-190 — `let prev_ok = prev.nft_ok; let res = nftables::apply();
   daemon.health().nft_reprobed(prev_ok, res.as_ref().map(|_| ()));` then the
   existing match. (The `warn!` at :174-176 stays; no counter there.)
4. :195 — after `warn!("enforcement drift detected — re-applying")`:
   `daemon.health().hosts_drift_detected();`.
5. :208-231 — `Ok(outcome) => { if changed { dns::flush_caches(); } let nft_ok =
   outcome.nft_ok(); daemon.health().apply_succeeded(outcome.nft,
   outcome.hosts); *applied = Some(Applied { .., nft_ok }); }` /
   `Err(e) => { *applied = None; daemon.health().apply_failed(&e, now); Err(e) }`.

`ApplyOutcome::nft_ok()` is true for `Ok | NotApplicable` (false for `Failed`
and `StaleTable`, so both re-probe paths key off the memo). `apply` on an empty
union: `hosts::clear_block()?; let nft = nftables::clear(); Ok(ApplyOutcome {
nft: teardown_nft_status(..), hosts: NotApplicable })`; on a non-empty union the
hosts failure is still the only `Err`. `apply_succeeded` downgrades `StaleTable`
to `NotApplicable` when the previous state was `NotApplicable` or `Failed` (no
table can exist). `cleanup.rs:169-171` already handles `Err` from `clear()`; the
13 cleanup tests are pure and pin nothing about it (verified).

**Tests**: health.rs — `fresh_state_is_quiet`,
`apply_succeeded_records_halves_and_clears_last_error`,
`apply_failed_sets_last_error_and_resets_halves_to_unknown`,
`nft_reprobe_heals_breaks_and_counts_only_real_drift`,
`stale_table_is_downgraded_when_no_table_can_exist`,
`teardown_retry_heals_or_keeps_stale`, `hosts_drift_counter_increments_and_saturates`,
`install_kind_for_paths` (`/usr/bin/grepfocusd`, `/usr/local/bin/grepfocusd`,
`/usr/bin/grepfocusd (deleted)`, `target/debug/grepfocusd`, `""`),
`reason_trims_and_caps`, `set_browser_policies_replaces_list`,
`snapshot_caps_startup_notes`. enforce.rs — `proxy_status_maps_detection`,
`nft_status_mappings_and_memo_flag`. ipc.rs —
`get_status_carries_health_and_derives_legacy_degraded_flag`
(`daemon.health().set_proxy(Degraded)` → `instant_breaks_degraded == true`,
`health.daemon_version == env!("CARGO_PKG_VERSION")`). `set_browser_policies`
carries `#[cfg_attr(not(test), allow(dead_code))]` until WP4 calls it.

**Done when**: `./scripts/check.sh` green; `grepfocusd --version` prints
`grepfocusd 0.5.1`; the raw socket read (*Live verification* 3.1) shows the §1
JSON with `install_kind: local`, `nft/hosts: not_applicable`, `proxy: off`,
`browser_policies: []`; the GUI still renders every tab.

### WP4 — daemon `browser_policy` module, unit comment, cleanup parity

Depends on: WP3 (`HealthState::set_browser_policies`, `hosts::write_atomic`).

**Files**

| Action | Path | Change |
|---|---|---|
| ADD | `crates/daemon/src/browser_policy.rs` | module (below) |
| EDIT | `crates/daemon/Cargo.toml` | `sha2 = "0.10"` (already in `Cargo.lock` via core) |
| EDIT | `crates/daemon/src/main.rs` | `mod browser_policy;`; `let policy_handle = tokio::spawn(browser_policy::run(daemon.clone()));` after :264; `select!` arm `r = policy_handle => { error!(?r, "browser policy task exited"); }`; crate doc :1-8 |
| EDIT | `crates/daemon/src/health.rs` | remove the `cfg_attr` on `set_browser_policies` |
| EDIT | `crates/daemon/src/paths.rs` | `pub const POLICY_ORIG_DIR: &str = "/var/lib/grepfocus/policies";` |
| EDIT | `crates/daemon/src/cleanup.rs` | step (d) loop at :150 also sweeps `browser_policy::managed_paths(..)`; new step `"browser DoH policies"` after (e) (:166-173), before (f); purge gate (:182-191) also skips when a policy restore failed and its `.orig` exists; module doc :1-10; comment :63 |
| EDIT | `crates/daemon/src/nftables.rs` | module doc :1-34 reframed as second line of defence (see *Docs*) |
| EDIT | `packaging/uninstall.sh` | `inline_teardown()` (:59-82) shell mirror of `remove_all`, marker-gated; "Removed:" summary (:155) |
| EDIT | `packaging/systemd/grepfocusd.service` | comment :15-17 (§6) |
| EDIT | `crates/gui/ui/src/main.ts` | `showFirstRun` `install` body (:2368-2371) gains one sentence: ` It also switches DNS-over-HTTPS off in Firefox, Chromium and similar browsers through a system policy so blocks apply there — those browsers will say they are "managed by your organization"; restart them once after installing.` |
| EDIT | `README.md`, `BACKLOG.md` | see *Docs* |

**Module** — decisions: policies are written from daemon start, unconditionally
(free tier, no toggle), and reconciled every `RECHECK = 60 s` by a dedicated
task in the `procwatch::run` shape (`interval` + `MissedTickBehavior::Skip` +
`spawn_blocking`), not on the 1 s `enforce::sync` tick (independent of
`state.active`; Firefox reads policies only at its own start, so writing at
block start is too late). Every outcome is a status; nothing here can fail the
daemon. The nft table stays as the backstop for browsers not restarted or not
covered.

Targets, fixed slug order, probes are install trees (never `/usr/bin` launchers,
except Firefox whose every layout reads the same `/etc` file; a wrapper-only
Mullvad tarball must not make us create `/usr/lib/mullvad-browser/distribution/`):

| Slug | Probes (any exists = installed) | Path written |
|---|---|---|
| `firefox` | `usr/bin/firefox`, `usr/bin/firefox-esr`, `usr/lib64/firefox/firefox`, `usr/lib/firefox/firefox`, `usr/lib/firefox-esr/firefox-esr`, `opt/firefox/firefox`, `snap/bin/firefox` | `etc/firefox/policies/policies.json` (seeded from the first existing `…/distribution/policies.json`, which it shadows while it exists) |
| `firefox-flatpak` | `var/lib/flatpak/app/org.mozilla.firefox` | never written; reported `failed{unsupported}` |
| `mullvad-browser` | `usr/lib/mullvad-browser/application.ini`, `usr/lib/mullvad-browser/mullvadbrowser` | `usr/lib/mullvad-browser/distribution/policies.json` (its only policy source: `MOZ_SYSTEM_POLICIES=false`) |
| `chromium` | `usr/lib64/chromium-browser/chromium-browser`, `usr/lib/chromium/chromium`, `usr/lib/chromium-browser/chromium-browser` | `etc/chromium/policies/managed/grepfocus.json` |
| `chromium-snap` | `var/snap/chromium/current` | `var/snap/chromium/current/policies/managed/grepfocus.json` (not live-verified) |
| `chrome` | `opt/google/chrome/chrome` | `etc/opt/chrome/policies/managed/grepfocus.json` |
| `brave` | `opt/brave.com/brave/brave` | `etc/brave/policies/managed/grepfocus.json` |

File contents: Chromium family exactly `{\n  "DnsOverHttpsMode": "off"\n}\n`
(the filename is the ownership marker). Firefox family: parse with
`serde_json`, set `policies.DNSOverHTTPS = {"Enabled": false, "Locked": true}`,
keep every other key, add a top-level `"grepfocus"` marker (Firefox ignores
non-`policies` keys) with `created`, `managed: ["DNSOverHTTPS"]`, `note`, and
when seeded `seeded_from` + `seeded_sha256` (sha256 of the canonical render of
the seed's `policies`); canonical render = `to_string_pretty` + `\n` (sorted
keys), written only when bytes differ, via `hosts::write_atomic(path, content,
0o644)` after `create_dir_all(parent)`. On the first touch of a foreign
(marker-less) file, its exact bytes go to
`/var/lib/grepfocus/policies/<path with '/'→'_'>.orig` (0600, dir 0700). Refuse
symlinks (`failed{symlink}`) and invalid JSON (`failed{not_json}`); on an
unchanged file re-assert 0644 root:root; never chmod vendor dirs.
`classify_io`: root-cause `ErrorKind::ReadOnlyFilesystem` → `read_only_fs`,
else `io`.

Removal (`remove_all`, used by cleanup and by the not-installed path):
Chromium family → delete our file. Firefox family → no marker → not ours;
marker + `created:true` and nothing left but what we created or seeded →
**delete** (so the distribution file applies again); otherwise strip our key +
marker and restore the `.orig` byte-exact if the live bytes still equal the
re-rendered merge of it, else write the stripped JSON. After removing on the
not-installed path, best-effort non-recursive `rmdir` up the vendor chain (never
`/etc/opt`). Stopping the daemon does not remove the files; `grepfocusd
cleanup` does (rpm `%preun`, deb `prerm`, AppImage `do_uninstall` inherit it).
`cleanup --purge` is skipped, like the hosts rule, while a policy restore failed
and its `.orig` exists, naming the surviving copies. `cleanup --force` under a
live daemon gets the files recreated within 60 s (documented at cleanup.rs:63
and README:182).

Pure, unit-tested core: `build_firefox_policy(existing, seed) -> Value`,
`strip_firefox_policy(current) -> Strip {NotOurs, Delete, Rewrite(Value)}`,
`render`, `has_marker`, `plan(format, installed, current, seed) -> Result<Plan,
Fail>` (`Remove` / `Unchanged{merged}` / `Write{content, merged,
first_touch_of_foreign_file}`), `transitions(prev, next) -> (info, warn)`,
`carry_since`, `orig_path_for`, `classify_io`, `fold_cleanup`. Thin IO:
`reconcile`, `reconcile_one`, `remove_one`, all parametrised by `root` so tests
run in a tempdir.

Task loop: `interval(RECHECK)` (first tick immediate) → `spawn_blocking(reconcile)`
→ `carry_since` → `transitions` logged → `daemon.health().set_browser_policies
(statuses.clone())`. Journal: first pass `browser DoH policies: firefox=written
(/etc/firefox/policies/policies.json) firefox-flatpak=not_installed
mullvad-browser=written(…) chromium=written(…) chromium-snap=not_installed
chrome=not_installed brave=not_installed` (a failure renders as
`failed:<fail_kind>(<path>)`); writes `wrote browser DoH policy` with fields
`browser`, `path`, `merged`; transitions `browser DoH policy for <slug>: <old>
-> <new> (<path>)`; into Failed (once) `browser DoH policy for <slug> failed
(<fail_kind>): <reason> — DoH may bypass blocks in that browser until this is
fixed`; unchanged passes at `debug!`.

`uninstall.sh` mirror: `rm -f` the four Chromium-family files; for the two
Firefox-family files, skip when the marker is absent (keep any `.orig` and say
so), `install -m 0644 "$orig" "$f" && rm -f "$orig"` when an `.orig` exists,
`rm -f` when `"created": true`, else print the manual-removal note; then
`rm -f` every `<path>.grepfocus.tmp`. A daemon test reads the script via
`include_str!("../../../packaging/uninstall.sh")` and asserts every
`managed_paths` entry and its `.grepfocus.tmp` twin appears in it.

**Tests**: the pure set (build/merge/strip incl. seed→build→strip = `Delete`,
seeded-then-edited = `Rewrite`, idempotence, older render with a different
`note` → one write then `Unchanged`, `plan` for all three formats, `CHROMIUM_CONTENT`
parses to exactly `{"DnsOverHttpsMode":"off"}`, `orig_path_for` pins
`/var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig`,
`managed_paths` pins 6 policy paths + 2 origs and the `uninstall.sh` parity,
`targets` order = slug order with 7 entries, `transitions`, `carry_since`,
`classify_io`, `fold_cleanup`); the tempdir IO set (not-installed writes
nothing and creates no dirs; fresh write creates 0644 files; second pass is a
byte/mtime no-op with no `.grepfocus.tmp`; 0600 drift re-asserted to 0644;
merge keeps `.orig` 0600 in a 0700 dir and reports `merged`; seeding; invalid
JSON untouched; symlink refused; a regular file where the policy dir should be
fails only that target; removal cases incl. rmdir of empty chain dirs only;
wrapper-only Mullvad → `not_installed`; flatpak probe → `failed{unsupported}`).
cleanup.rs: `managed_paths` in the stale-tmp sweep; purge gate with a
non-empty surviving list → `Skipped`.

**Done when**: `./scripts/check.sh` green; `bash -n packaging/uninstall.sh`;
after `sudo ./packaging/upgrade.sh` the journal shows the first-pass line with
`firefox=written`, `mullvad-browser=written`, `chromium=written`, the three
files exist 0644 root:root with the expected labels (`etc_t`/`lib_t`), and
`GetStatus.health.browser_policies` has 7 entries in slug order.

### WP5 — GUI health banner, tray RED notification, about/diagnostics line, error-state fixes

Depends on: WP3 (`Status.health`). Renders WP4's browser rows when present.

**Files**

| Action | Path | Change |
|---|---|---|
| EDIT | `crates/gui/src/main.rs` | `GUI_VERSION`; `--version` first in `main()` (:628, before `configure_appimage_webview_env()`); `AppEnv.gui_version`; `fn enforcement_red(&Health, domain_block_active: bool) -> Option<&'static str>`; `spawn_status_watcher` (:518-591) destructures `health`, keeps `prev_red: Option<bool>`, fires ONE `notify(&app, "GrepFocus: blocking problem", body)` on the false→true edge inside the existing `if settings.notifications` (:570), baseline on the first successful poll, untouched while unreachable; tooltip strings unchanged; first `#[cfg(test)] mod tests` |
| EDIT | `crates/gui/ui/index.html` | `<div id="health-banner" role="status" aria-live="polite" hidden></div>` between `<h2>Status</h2>` and `#status-content` (:24-27); `#about` div at the end of `#settings` (after :121) |
| EDIT | `crates/gui/ui/src/style.css` | `--warn: #b7791f` (dark `#d69e2e`) in `:root` (:1-19); `[hidden] { display: none !important; }`; `.health-notice`, `.health-notice.error/.warn/.info` after `.msg.warn` (:300) |
| EDIT | `crates/gui/ui/src/main.ts` | `AppEnv.gui_version`; pure `healthNotices(s)`, `healthSummary(s)`, `aboutLine(gui, h)`; `renderHealthBanner` (change-keyed, no flicker); `renderAboutLine`; hooks; Week + block-list fixes |

**Severity rules** (`healthNotices`, with `domainBlockActive = s.active.some(a
=> a.block.domains.length > 0)`; silent when `daemon_version === ""` or a value
is `"unknown"`; order RED → YELLOW → INFO):

- RED `last_error` **always** (text varies: with a domain block active
  "Website blocking may not be enforced: the /etc/hosts change could not be
  applied (…). The daemon retries every second; see journalctl -u grepfocusd";
  without one "The last /etc/hosts change could not be applied (…) —
  previously blocked sites may still be blocked. …").
- RED `nft.kind === "failed"` only while `domainBlockActive`: "Active blocks
  can be bypassed: DoH protection (nftables) failed — {reason}. Browsers using
  DNS-over-HTTPS (Firefox, Mullvad Browser) may still reach blocked sites."
- YELLOW `hosts.kind === "unlocked"`: "Tamper protection off: /etc/hosts is
  not locked ({reason}). Blocking still works, but the file can be edited
  while a block is active."
- YELLOW `nft.kind === "stale_table"`: "The DoH block table could not be
  removed after the last block ({reason}) — DNS-over-HTTPS resolvers stay
  blocked (Mullvad Browser loses DNS). The daemon retries every 30 s; to
  remove it now: sudo nft delete table inet grepfocus_doh".
- YELLOW per `browser_policies[]` with `state.kind === "failed"` and
  `fail_kind` ∈ `not_json | symlink | io`: "{Name}: DoH policy not installed
  ({reason}). {Name} may bypass blocks via DNS-over-HTTPS." + remedy
  (`not_json`: "Fix or remove {path}; GrepFocus retries every minute." ·
  `symlink`: "Replace {path} with a real file or add DNSOverHTTPS there
  yourself." · `io`: "GrepFocus retries every minute.").
- YELLOW `startup_notes.length > 0`: "{n} stored block entries were changed or
  dropped when the daemon started (invalid domains or app matchers from an
  older version). Details: journalctl -u grepfocusd | grep sanitized".
- INFO per browser `failed` with `unsupported` / `read_only_fs`: "{Name} is
  present but not covered ({reason}). DoH may bypass blocks in it — see README
  → Known limits." / "Cannot write {path}: read-only filesystem. DoH may
  bypass blocks in {Name}; not fixable on this system layout."
- INFO "restart once": any `written`/`merged` entry with `s.now_unix -
  since_unix < 900`: "GrepFocus switched DNS-over-HTTPS off in {names} through
  a system policy so blocks apply there (they will say 'managed by your
  organization'). Restart Firefox-based browsers once if they were open before
  {time}."
- INFO `proxy === "degraded" && settings.instant_breaks`: "Instant breaks
  unavailable — port 80 or 443 is in use, so breaks may take up to a minute to
  show in an already-open tab. Blocking is unaffected." (The Settings note at
  main.ts:1582-1588 keeps reading the legacy bool.)

Slug → name map: Firefox, Firefox (Flatpak), Mullvad Browser, Chromium,
Chromium (snap), Google Chrome, Brave; unknown slug shown raw.
`enforcement_red` mirrors exactly the two RED rules (comment both sides
"change together"). Counters are diagnostics only: `healthSummary` renders
`Enforcement — DoH block (nft): {ok|FAILED|stale table (…)|not applicable} ·
/etc/hosts lock: {locked|NOT locked|off (premium feature)|not applicable} ·
instant-break proxy: {holding|degraded|off} · re-applies since daemon start:
hosts {n}, nft {n}` ("off (premium feature)" only when a domain block is active
and `tamper_protection` is not licensed; the daemon stays the only source of
"unlocked"). `aboutLine`: `GrepFocus {gui} · daemon {ver} ({exe or
install_kind})`, or `· daemon: older version (no health reporting)`, or `·
daemon unreachable` from the catch branch.

Hooks: `refreshStatus` (:646-685) — after `hideFirstRun()` (:650):
`renderAboutLine(s); renderHealthBanner(healthNotices(s));`, **before** the
`s.active.length === 0` early return (:660-664) so a teardown failure shows
above "No active block"; in the catch (:675-684) `renderAboutLine(null);
renderHealthBanner([]);` before the error paragraph. `refreshSettings`
(:1568-1609) — after the instant-breaks note: `healthDiagEl.textContent =
s.health.daemon_version === "" ? "" : healthSummary(s)`. Week tab (:1448-1470):
replace the two `.catch(() => [])` with a try/catch that renders `String(e)` as
`.msg.error` (a dead daemon must never read as "No schedules yet"). Block list
(:307-357): the `get_status` `.catch(() => null)` at :332 records the error and
`listMsg` says `Live status could not be read ({err}) — which blocks are active
and their remaining allowance are unknown; cards show saved configuration
only.` with class `warn`; every `listMsg.classList.remove("error")` (:308, :510,
:521, :1138, :1152) becomes `remove("error", "warn")`.

**Tests**: gui main.rs `enforcement_red_mirrors_frontend_rules` (empty
version → None even with `last_error`; `last_error` → Some regardless of
`domain_block_active`; nft `Failed` → Some only with `true`; `StaleTable` →
None); `tauri_conf_version_matches_cargo`; `gui_version_parses`. Frontend: no
runner — `pnpm build` (tsc `strict`, `noUnusedLocals`, `noUnusedParameters`)
is the gate; keep `healthNotices`/`healthSummary`/`aboutLine` pure.

**Done when**: `./scripts/check.sh` green; `grepfocus-gui --version` prints
`grepfocus-gui 0.5.1` and exits without a window; the banner states in *Live
verification* 5.x render and clear; Week tab and block list show the error
when the daemon is stopped.

### WP6 — GUI/daemon skew advice + AppImage "Update system service"

Depends on: WP3 (`health.daemon_version`, `install_kind`, `grepfocusd --version`), WP5 (`GUI_VERSION`, about line, `[hidden]` rule).

**Files**

| Action | Path | Change |
|---|---|---|
| ADD | `crates/gui/src/version.rs` | §8 + `Probe`, `UpdateAdvice`, `advise` |
| EDIT | `crates/gui/Cargo.toml`, `Cargo.lock` | `semver = "1"` (no new crate; commit the lock) |
| EDIT | `crates/gui/src/main.rs` | `mod version;`; `PACKAGED_DAEMON_BIN`/`LOCAL_DAEMON_BIN`; `AppEnv.packaged_daemon/local_daemon` via `probe_app_env()`; `StatusOut.update`; `get_status` builds `Probe { gui: GUI_VERSION, daemon: (!health.daemon_version.is_empty()).then_some(..), install_kind: health.install_kind, appimage, packaged_binary, local_binary }`; BOOTSTRAP last line (:374) `/bin/sh "$tmp/appimage-install.sh" …` → `bash "$tmp/appimage-install.sh" "$action" "$tgt_user"` (no `exec`: the `trap … EXIT` at :367 must still remove `$tmp`; BOOTSTRAP itself stays POSIX under `pkexec /bin/sh -c`); `installer_error(code, stderr) -> String` extracted from :462-483 with 97/98/99 mappings; tests |
| EDIT | `packaging/appimage/appimage-install.sh` | header (:2-19) documents re-run = update, `[--force]`, exit codes; `PACKAGED_BIN=/usr/bin/grepfocusd`, `FORCE="${3:-}"`; `do_install` starts with the package guard (exit 98) and the downgrade guard (`chmod 0755 "$PAYLOAD/grepfocusd"`; `new=$("$PAYLOAD/grepfocusd" --version)`, `cur=$("$BIN" --version 2>/dev/null || true)`, strip the `grepfocusd ` prefix; refuse with exit 99 when `cur` is non-empty, differs, `--force` absent and `sort -V` puts `cur` last); before `install -D … "$UNIT"` (:41) save a differing existing unit as `$UNIT.bak`; `do_uninstall` refuses with 98 whenever `$PACKAGED_BIN` exists; `case` usage `install <user> [--force] | uninstall` |
| EDIT | `crates/gui/ui/index.html` | `#update-banner` card with `#update-text`, `#update-action` (hidden), `#update-msg` between `#health-banner` and `#status-content`; `#firstrun-secondary` ghost button after `#firstrun-action` (:245) |
| EDIT | `crates/gui/ui/src/style.css` | `.update-banner .row`, `.about-line` (append after :223) |
| EDIT | `crates/gui/ui/src/main.ts` | types `UpdateAdvice`, `Status.update`, `AppEnv` fields; `DOWNLOAD_URL = "https://grepfocus.com/download"` (plain selectable text until WP7); `updateAdviceText(a, appimage, kind)`, `renderUpdateBanner`, `hideUpdateBanner`, `updateHoldUntil` (success text held ~10 s); click handler; `FirstRunMode = "install" | "relogin" | "packaged" | "stopped"`; `firstRunBusy` → `installBusy` everywhere; `installServiceAndWait(report, waitMs): Promise<"ok"|"denied"|"timeout"|"error">` as the only `invoke("install_service")` caller; `runFirstRunInstall()`; `handleDaemonUnreachable` picks a mode only for the connect-class error (`"daemon is not running"` → `packaged` if `appEnv.packaged_daemon`, `stopped` if `appEnv.local_daemon`, else `install`; `"not allowed to talk"` → `relogin`; deserialize/protocol errors never open the dialog); `refreshStatus` catch paints "Restarting service…" while `installBusy` |
| EDIT | `docs/plans/appimage-dist.md`, `README.md` | see *Docs* |

**Decision table** (`advise`; one unit test per row):

| daemon version | gui vs daemon | appimage | install_kind | /usr/bin | /usr/local/bin | advice |
|---|---|---|---|---|---|---|
| none / "" | — | any | — | yes | any | `package_manager{from:null}` |
| none / "" | — | true | — | no | yes | `update_service{from:null}` (migration: every existing AppImage install) |
| none / "" | — | false | — | no | yes | `manual{from:null}` |
| none / "" | — | any | — | no | no | `manual{from:null}` |
| unparseable | — | any | any | any | any | `up_to_date` |
| some | equal | any | any | any | any | `up_to_date` |
| some | gui newer | true | local | no | any | `update_service` (the only variant with a button) |
| some | gui newer | any | package | any | any | `package_manager` |
| some | gui newer | any | local | yes | any | `both_installs` |
| some | gui newer | false | local | no | any | `manual` |
| some | gui newer | any | unknown | any | any | `manual` |
| some | gui older | any | any | any | any | `gui_outdated` — never an install offer |

Wire: `kind`-tagged snake_case, `from` = daemon version (null = predates
reporting), `to` = GUI version, `gui_outdated{gui, daemon}`. Copy per variant
lives in `updateAdviceText` (the `gui_outdated` text branches on `appimage` and
`install_kind`: packaged app installed → launch that; local → "quit and
relaunch; if this notice stays, ./packaging/upgrade.sh"; AppImage → download
from `DOWNLOAD_URL`). Installer exit codes: 0 ok · 2 usage · 97 integrity
(BOOTSTRAP) · 98 package install owns grepfocusd · 99 would downgrade
(`--force` is CLI-only; BOOTSTRAP never forwards it) · 126/127 pkexec only when
stderr is empty. A daemon restart (SIGTERM) loses in-memory-only state — unlock
window, pending break challenges, unflushed kill counts — exactly as
`upgrade.sh` does today; the banner says "settings relock".

**Tests**: version.rs — `parse_plain_triple`, `parse_strips_v`,
`parse_rejects` (`""`, `1.2`, `1.2.3.4`, `a.b.c`), `compare_is_numeric_not_lexical`
(`0.10.0 > 0.9.9`), `compare_unparseable_is_none`, one `advise_*` per row,
`advise_daemon_newer_never_offers_install`, `advise_empty_daemon_version_is_pre_reporting`,
`advice_wire_shape`. main.rs — `installer_error_maps_pkexec_codes` (126/127
empty stderr; 126 with stderr → generic), `_97_integrity`, `_98_package_present`,
`_99_downgrade`, `_other_includes_code_and_stderr`;
`bootstrap_runs_installer_under_bash_and_is_posix` (last non-empty BOOTSTRAP
line starts with `bash "$tmp/appimage-install.sh"`; BOOTSTRAP contains neither
`[[` nor `pipefail`); `payload_files_are_staged` (each `PAYLOAD_FILES` name
appears as `"$DEST/<name>"` in `include_str!("../../../packaging/appimage/stage-payload.sh")`);
`installer_script_agrees_on_paths_and_codes` (script contains
`PACKAGED_BIN=/usr/bin/grepfocusd`, `BIN=/usr/local/bin/grepfocusd`, `exit 98`,
`exit 99`; `debian/grepfocus.prerm` contains `PACKAGED_DAEMON_BIN`). All
`include_str!` only inside `#[cfg(test)]`.

**Done when**: `./scripts/check.sh` green; `bash -n packaging/appimage/appimage-install.sh`;
`podman run --rm -v $PWD/packaging/appimage/appimage-install.sh:/t.sh:ro
ubuntu:24.04 sh -c 'readlink -f /bin/sh; bash /t.sh bogus; echo exit=$?'`
prints `/usr/bin/dash`, the usage line and `exit=2` (never "Illegal option" /
"[[: not found"); the non-bundled error path (`APPIMAGE=1 target/release/grepfocus-gui`
→ button → "installer payload not found …", button re-enabled) works; the
real pkexec update (*Live verification* 6.x) succeeds once.

### WP7 — daily update check, Settings toggle, `open_url`, website hand-off

Depends on: WP5 (`GUI_VERSION`, strips' CSS), WP6 (`version.rs`, `#update-banner` precedence, `DOWNLOAD_URL`).

**Files**

| Action | Path | Change |
|---|---|---|
| ADD | `crates/gui/src/update.rs` | pure logic + `Store` + `fetch_latest` + checker loop + launcher + tests |
| EDIT | `crates/gui/Cargo.toml`, `Cargo.lock` | `ureq = { version = "3", default-features = false, features = ["rustls"] }`; delete `tauri-plugin-shell = "2"` (removes only `open`, `os_pipe`, `shared_child`); the first build needs network (ring/rustls/webpki-roots are not in the registry cache); commit the lock — every packaging builds `--locked` |
| EDIT | `crates/gui/src/main.rs` | `mod update;`; the six commands (§4) after `uninstall_service` (:345-347); `app.manage(update::Store::open(config_path(..), url from `GREPFOCUS_UPDATE_URL` or `DEFAULT_URL`, user_agent(GUI_VERSION)))` in `.setup` (:662) before the window; `update::spawn_checker(app.handle().clone())` after `spawn_status_watcher` (:734); `generate_handler!` (:759) |
| EDIT | `crates/gui/build.rs` (:25), `crates/gui/capabilities/default.json` (:34) | the six names / six `allow-*` |
| EDIT | `crates/gui/ui/index.html` | `#update-disclosure` (`#update-disclosure-ok`, `#update-disclosure-off`) and `#update-notice` (`#update-notice-text`, `#update-notes`, `#update-dismiss`) after `#update-banner`; inside `#prefs` after `#instant-breaks-note` (:104): `#update-check-toggle` checkbox row, `#update-check-row` (`#update-check-now`, `#update-check-status`), `#update-check-persist` |
| EDIT | `crates/gui/ui/src/style.css` | `.update-strip`, `.update-check-row` |
| EDIT | `crates/gui/ui/src/main.ts` | `Release`, `UpdateInfo` types; `refreshUpdateInfo()` polled from `refreshStatus`'s `finally` (every 5 s, daemon up or down) and from `refreshSettings` before its `try`; `renderUpdate` → `renderUpdateNotice` (suppressed while `blockActive` or the skew banner is non-`up_to_date`) + `renderUpdateSettings`; `acknowledge_update_check` invoked **after** the first render; handlers; the `gui_outdated` AppImage copy gains a "Download" ghost button → `invoke("open_url", { url: DOWNLOAD_URL })` |
| EDIT | `packaging/aur/PKGBUILD`, `packaging/grepfocus.spec`, `debian/control` | `optdepends`/`Recommends: xdg-utils` |
| EDIT | `README.md`, `BACKLOG.md` | see *Docs* |

**Behaviour**: fetch in Rust (`ureq`, `https_only` whenever the URL is https,
10 s timeout, 64 KiB body cap, redirects only over https); first check 3 s
after launch when due (short GNOME sessions still check), hourly tick with 0-5
min jitter; "due" = ≥24 h since the last *completed* check and ≥1 h since the
last attempt; a server reply or unusable body (404/5xx/HTML/oversize/TLS
failure) completes a check, only DNS/connect/timeout/io retry hourly. The
one-time disclosure strip renders before the first network contact (`disclosed`
flag; "Got it" / "Turn off"). State file per §5; fail-closed on a corrupt or
unreadable existing file (checks off for the session with a dedicated line;
toggling on rewrites it); persist errors are a separate field and line, never
mixed with fetch errors. `dismiss_update` takes no argument (dismisses the
current `latest`). `open_url`: allowlist + ≤2048 bytes, `xdg-open` spawned with
a per-element `$APPDIR` scrub under an AppImage (`PATH_LIST_VARS` keep the
user's tail entries — Flatpak browsers live in `XDG_DATA_DIRS`; pure overrides
such as `PYTHONHOME`, `GTK_EXE_PREFIX`, `GDK_PIXBUF_MODULE_FILE`,
`WEBKIT_EXEC_PATH` and anything containing `$APPDIR` removed; `APPDIR`,
`APPIMAGE`, `ARGV0`, `OWD`, `GTK_THEME`, `GDK_BACKEND`, `PYTHONDONTWRITEBYTECODE`
removed unconditionally); `xdg-open` resolves against the scrubbed `PATH`
because `PATH` is set on the `Command`. `fetch` is injected into `run_check`
so the cadence/state machine is unit-tested without the network. Exact status
texts: `Not checked yet.` · `Checked {when}: up to date ({ver}).` · `Checked
{when}: GrepFocus {latest} is available.` · `Checked {when}: grepfocus.com has
no update information yet (HTTP 404)` · `Could not reach grepfocus.com ({e}).
Will retry.` · `secure connection to grepfocus.com failed ({e}) — a
TLS-intercepting proxy?`; notice `GrepFocus {latest} is available (released
{date}) — you have {ver}.` (+ under an AppImage: ` After replacing the AppImage,
the Status tab will offer "Update system service".`).

**Tests** (`cargo test -p grepfocus-gui update::`): `parse_latest` (tolerant;
missing/invalid `version` → Err), `classify` per ureq error kind, `https_only_for`,
`due` matrix, `tick_delay`, `apply_outcome` (Unreachable never rewrites the
file), `notice_for`, `info`, `config_path`, `state_from_json` (`schema: 9`
accepted), `load_state` (garbage → off + persist_error), `link_allowed`
(`https://grepfocus.com.evil.com/` ✗, `HTTPS://GREPFOCUS.COM/` ✗, 2049 bytes ✗),
`scrub_env` against the strings extracted from the 0.5.0 AppImage (`PATH` tail
kept, `XDG_DATA_DIRS` tail kept in order, `GSETTINGS_SCHEMA_DIR` removed,
`/tmp/.mount_GrepFoXYZ2/usr` not treated as under `/tmp/.mount_GrepFoXYZ`),
`launcher`, `user_agent`, `Store` persist round-trip (dir 0700, file 0600) and
persist-failure path, `run_check` with injected closures (disabled/undisclosed
skip, force, Ok persisted, NoInfo persisted, Unreachable not persisted).

**Done when**: `./scripts/check.sh` green; `cargo build --release --locked`
green with the committed lock; the stub-server run (*Live verification* 7.x)
shows exactly one GET per launch when due, the strips and Settings row behave,
and `pgrep -n firefox`'s environ after "What's new" from the AppImage contains
neither `mount_` nor `PYTHONHOME`.

## Docs to update

- **`README.md`**
  - *What it does* (:8-20): app blocking kills processes "not running as
    root"; new bullet **Turns browser DNS-over-HTTPS off** via
    enterprise-policy files (Firefox, Mullvad Browser, Chromium incl. the
    Ubuntu snap, Chrome, Brave) so `/etc/hosts` blocks apply — those browsers
    say "managed by your organization"; written at daemon start, re-checked
    every minute; Firefox-based browsers pick it up at their next start,
    Chromium immediately.
  - *Verify it's running* (:78-83): `grepfocusd --version`; the Settings tab
    shows both versions and an enforcement diagnostics line.
  - *Development* (after :141): new **Updating** section — rpm/deb/AUR via the
    package manager; AppImage: download the new file, run it, the Status tab
    offers *Update system service* (pkexec, same installer re-run; never over
    a package install, never a downgrade; a customized unit is saved as
    `.bak`, use a drop-in); source checkout: `./packaging/upgrade.sh`. Side
    effects of any daemon restart (blocks stay enforced, settings relock,
    pending break challenges and unflushed kill counts lost). Dev-mode stub
    for the update check: `GREPFOCUS_UPDATE_URL=http://127.0.0.1:8099/latest.json
    cargo run -p grepfocus-gui`.
  - *Wire protocol* (:157-161): `get_status` row → "…plus `health` (daemon
    version, install kind, nft/hosts/proxy state, browser DoH policies, drift
    counters, last error)"; a Health paragraph with the §1 JSON and the
    `unknown` rule; the `Block` rules (hostnames only, lowercased, scheme/path/
    port stripped, no IP literals/wildcards/single labels, punycode, ≤249
    chars so the `www.` alias fits; `exe_path` absolute and resolved;
    `basename` no slash; `cmdline` ≥3 chars; nothing may target GrepFocus;
    canonicalized on save and at startup — `journalctl -u grepfocusd | grep
    sanitized`).
  - *Recovery* (:178-199): cleanup wording gains "removes or restores the
    browser DoH policy files" and "its 1 s enforcement tick and 60 s
    browser-policy pass"; **Stopping or disabling the daemon does not restore
    browsers**; downgrade note (a pre-policy daemon's cleanup does not know
    the files — run the manual commands first); manual commands for the six
    policy paths and the `.orig` restore rule; the broad-`cmdline:` recovery
    line (`Ctrl+Alt+F3`, `sudo systemctl stop grepfocusd && sudo grepfocusd
    cleanup`, then start — the cleared active state is not re-applied).
  - *Known limits* (:211-256): rewrite the DoH bullet (:222-231, drop the
    "Mullvad loses DNS" text, keep the unlisted-endpoint line); new **Browser
    DoH policies** bullet (covered/not covered list incl. "not live-tested"
    flags for the snaps, Chrome and Brave; merge/restore semantics; a seeded
    `/etc` file shadows `distribution/policies.json` until uninstall; Chromium
    applies managed files alphabetically; **DoH stays off while GrepFocus is
    installed, not only during blocks — Mullvad Browser's DNS goes to the OS
    resolver**; a Firefox already running keeps DoH until restarted; the
    "directory not empty" warning when uninstalling a browser); immutable-flag
    bullet (:237-240): "The Status tab shows a yellow 'Tamper protection off'
    notice and the Settings diagnostics line says so"; Mullvad/DoT bullet: "If
    the DoH table is ever left behind after a block ends, the Status tab says
    so and the daemon retries removing it"; **Root processes are never
    killed** (system services, setuid helpers, `sudo`/`pkexec`-launched apps);
    **Other users' desktop processes ARE killed** on a shared machine; **The
    `www.` alias is one-directional**; the update check trusts the bundled
    Mozilla root store (webpki-roots), so a TLS-intercepting proxy with a
    private CA makes it fail.
  - New **Update notifications** section before *Known limits*: once a day
    the GUI fetches `https://grepfocus.com/downloads/latest.json`; only the
    version number is exchanged, nothing downloaded; UA `GrepFocus/<ver>
    (linux)`, IP visible to the site's host like any request; first launch
    shows a one-line disclosure; opt-out in Settings, per user, stored in
    `~/.config/grepfocus/update-check.json` (not removed by uninstall);
    `GREPFOCUS_UPDATE_URL` for mirrors.
- **`crates/daemon/src/nftables.rs:1-34`**: reframe as the *second* line —
  "The first line is `browser_policy`, which turns DoH off in every detected
  browser via enterprise policy; this table catches browsers that have not
  restarted since the policy was written, browsers we do not policy (Flatpak
  Firefox, Vivaldi/Edge/Opera, per-user installs) and DoT." Replace the
  Mullvad bullets (:18-21) with: "Mullvad Browser: with its policy in place it
  falls back to the native resolver and keeps working; only one started
  before the policy was written, or on a read-only `/usr`, still hits the
  listed-resolver case."
- **Module docs**: `enforce.rs:1-29` (every outcome recorded in `health`;
  teardown retry), `hosts.rs:15-22` (both lock outcomes reported to health),
  `cleanup.rs:1-10` and `:63`, `procwatch.rs:1` (the guard set),
  `crates/daemon/src/main.rs:1-8` (browser policies), `packaging/appimage/appimage-install.sh:2-19`,
  `packaging/systemd/grepfocusd.service:15-17`, `packaging/uninstall.sh`
  inline-teardown comment.
- **`docs/plans/appimage-dist.md`**: status block (:3-21) gains an "Updates"
  paragraph (health.daemon_version/install_kind, version.rs, the bash fix,
  exit codes 98/99, `grepfocusd --version`); `:66` → "Version lives in 5
  hand-synced places (root Cargo.toml, tauri.conf.json, spec, debian/changelog,
  PKGBUILD); the binaries read it via `CARGO_PKG_VERSION` and a gui test pins
  tauri.conf.json to it"; `:108-110` → "DONE — see hardening-health-updates.md
  WP6; note `install_kind` is `local` for BOTH the AppImage installer and the
  dev scripts".
- **`docs/plans/instant-breaks.md:130-133`**: append "`health.proxy` now
  carries the `Holding|Degraded|Off` enum; the bool is kept on the wire,
  derived."
- **`BACKLOG.md`**: new section `## Input hardening, health, DoH policies,
  updates (2026-09-28)` with a `Status:` line and the pending release-note
  bullets below; *Bookmarks* (:76+): Flatpak Firefox `systemconfig` extension
  (v2; needs a flatpak Firefox to verify the mount), Chromium/Firefox snap
  live verification on an Ubuntu VM, Vivaldi/Edge/Opera managed dirs, an
  opt-out `Settings.browser_policies` toggle, `/etc/mullvadbrowser/...` is
  never read (`MOZ_SYSTEM_POLICIES=false`) — do not retry it, multi-user
  procwatch scoping (SO_PEERCRED uid on `ActiveBlock`), save-time breadth
  check for app matchers (count currently matching processes and refuse
  above a threshold), `GREPFOCUS_NO_UPDATE_CHECK` packager kill switch,
  version-mismatch YELLOW when both versions are known but differ (one-line
  rule in `healthNotices`), read-only `~/.config` residual for the
  update-check opt-out, `min_supported`/`security` flag in `latest.json`.
- **This document**: flip the status header to **implemented** with the WP
  table filled in, then to **implemented and live-verified (date)** after the
  checklist below.

### Release hand-off (pending changelog lines — this plan edits no version or changelog file)

For the next `Release x.y.z` commit (`debian/changelog`, `packaging/grepfocus.spec
%changelog`, release notes), in this order:

- Browsers' DNS-over-HTTPS is now switched off through standard
  enterprise-policy files (Firefox, Mullvad Browser, Chromium, Chrome, Brave)
  so blocks apply in them; those browsers show a "managed by your
  organization" notice and must be restarted once. DoH stays off while
  GrepFocus is installed (Mullvad Browser then uses the OS resolver instead
  of Mullvad DNS); `grepfocusd cleanup` or uninstalling restores the files.
  Downgrading: remove the files first (README → Recovery).
- The Status tab now reports enforcement problems (failed `/etc/hosts` write,
  failed or stale DoH table, tamper protection off, browser policy failures,
  instant-break proxy) with a desktop notification on a new failure; the
  Settings tab shows the app and service versions plus a diagnostics line;
  `grepfocusd --version` and `grepfocus-gui --version`.
- Block content is validated: domains must be hostnames (URLs are trimmed to
  the hostname; IP literals, wildcards and single labels are refused), app
  matchers must be well-formed and may not target GrepFocus itself, a block
  needs at least one domain or app; stored entries are canonicalized at
  startup and unusable legacy entries are dropped with a journal warning.
- App blocking never kills root processes (system services, `sudo`/`pkexec`-
  launched apps) or GrepFocus itself.
- AppImage: the Status tab offers "Update system service" when the app is
  newer than the installed service; the installer runs under bash (fixes the
  first-run install on Debian/Ubuntu), refuses to run over a package install
  and refuses downgrades.
- The app checks grepfocus.com once a day for a newer release (version
  number only; one-time disclosure; opt-out in Settings).

## Live verification checklist (dev machine: Fedora 44, Local daemon at /usr/local/bin, Firefox rpm, Mullvad Browser rpm, Chromium rpm)

Steps marked **[user]** need sudo or podman and are run by the owner; the rest
the assistant runs (the user is in group `grepfocus`, the socket is
`/run/grepfocus/sock`).

**After WP2 (hardening)**

1. `./scripts/check.sh`.
2. Seed legacy entries against the OLD daemon before upgrading: via the GUI
   save (do not start) block `legacy` with domains `Reddit.Com`, `localhost`
   and app `grepfocus-gui`; write `scratchpad/gf_inject.py` (4-byte BE length
   + JSON frame) sending `{"method":"add_block","block":{"id":0,"name":"inj",
   "domains":["reddit.com\n0.0.0.0 evil.example"],"apps":[],"allowance_secs_per_day":0,
   "allowance":null,"lock":"normal"}}` (send `unlock` first if a settings
   password is set — ask, do not guess) → succeeds on 0.5.1 (proves the bug).
3. **[user]** `sudo ./packaging/upgrade.sh`; `journalctl -u grepfocusd -b
   --no-pager | grep -i sanitized` → `Reddit.Com`→`reddit.com` normalized,
   `localhost`, `grepfocus-gui` and the injected domain dropped; `grep -c
   evil.example /etc/hosts` → 0.
4. Re-run `gf_inject.py` → `{"result":"error","message":"domain \"reddit.com
   \\n0.0.0.0 evil.example\": hostname contains an invalid character — …"}`.
5. GUI New block: `https://www.Reddit.com/r/rust` → card `www.reddit.com`;
   `1.2.3.4`, `localhost`, `*.reddit.com` → the three messages; `reddit.com
   twitter.com` on one line → two entries; `grepfocus-gui`, `cmdline:GrepFocus`
   → SelfMatch text; `cmdline:ab` → "at least 3 characters"; `cmdline:com.discordapp.Discord`
   → saved, Edit, Save → still `"kind":"cmdline"` in `list_blocks`.
6. procwatch guards: block `sleeper` (basename `sleep`) for 2 min; `sleep 300 &`
   as the user → killed within ~1 s; **[user]** `sudo sleep 300 &` → survives
   the whole block; `systemctl status grepfocusd` shows no restart;
   `ps -o pid,uid,comm -C grepfocus-gui` still alive. Delete the test blocks;
   `/etc/hosts` has no managed region afterwards.

**After WP3 (health)**

1. `./scripts/check.sh`; **[user]** `sudo ./packaging/upgrade.sh`;
   `journalctl -u grepfocusd -n 20` shows `version=0.5.1
   exe=/usr/local/bin/grepfocusd install_kind=Local`; `grepfocusd --version`.
2. Raw status read: `python3 - <<'EOF'` connecting to the socket, sending
   `{"method":"get_status"}`, printing `json.loads(d)["health"]` → §1 shape,
   `nft`/`hosts` `not_applicable`, `proxy off`, counters 0, `last_error null`,
   `browser_policies []`.

**After WP4 (browser policies)**

1. `./scripts/check.sh`; `bash -n packaging/uninstall.sh`; **[user]** `sudo
   ./packaging/upgrade.sh`; `journalctl -u grepfocusd -n 40` → the first-pass
   line (`firefox=written`, `firefox-flatpak=not_installed`,
   `mullvad-browser=written`, `chromium=written`, others `not_installed`).
2. `cat` the three files; `ls -lZ` → `-rw-r--r-- root root`, `etc_t`/`lib_t`/
   `etc_t`; no `*.grepfocus.tmp`; `rpm -qf /usr/lib/mullvad-browser/distribution`
   still owned; **[user]** `sudo ausearch -m AVC -ts recent | grep -i grepfocusd`
   → empty.
3. **Firefox honours it**: quit all windows, start; `about:policies` lists
   `DNSOverHTTPS` active; `about:config` `network.trr.mode` = 5, locked;
   Settings → Privacy → DoH shows off/managed; the menu shows "managed by your
   organization". Block `example.com` → reload fails; `about:networking#dns`
   TRR=false; other sites load.
4. **Mullvad Browser honours it (the uncertain one)**: quit, start;
   `about:policies` must list the policy as active (proves `XREAppDist` =
   `/usr/lib/mullvad-browser/distribution`); `network.trr.mode` = 5 locked.
   With a block active: the blocked site fails and **all other sites keep
   loading** (the 0.5.1 regression fixed). If inactive: check
   `toolkit.policies.perUserDir` and report — there is no alternative path.
5. **Chromium honours it** (no restart): `chrome://policy` → `DnsOverHttpsMode
   = off`, Source Platform, Level Mandatory ("Reload policies" if it lags);
   `chrome://settings/security` → "Use secure DNS" off and managed.
6. Drift: **[user]** `sudo rm /etc/chromium/policies/managed/grepfocus.json`
   → back within 60 s with `wrote browser DoH policy browser=chromium`; `sudo
   chmod 600 …grepfocus.json` → 0644 within 60 s, no rewrite line.
7. Merge/restore: **[user]** `sudo systemctl stop grepfocusd && sudo grepfocusd
   cleanup` (summary `browser DoH policies done`); `printf '{"policies":{"DisableTelemetry":true}}\n'
   | sudo tee /etc/firefox/policies/policies.json; sudo cp … /tmp/ff-admin.json;
   sudo systemctl start grepfocusd` → both keys + marker `created:false`,
   state `merged`, `.orig` present; stop + cleanup → `cmp` identical to
   `/tmp/ff-admin.json`, `.orig` gone; `sudo rm …policies.json; sudo systemctl
   start grepfocusd` → `written`.
8. Seed: **[user]** daemon stopped and cleaned, `printf '{"policies":{"DisableTelemetry":true}}\n'
   | sudo tee /usr/lib64/firefox/distribution/policies.json; sudo systemctl
   start grepfocusd` → the `/etc` file has both keys, marker `created:true` +
   `seeded_from`/`seeded_sha256`; stop + cleanup → `/etc/firefox/policies/policies.json`
   **deleted**; remove the test dist file.
9. Purge gate: **[user]** daemon stopped, redo the merge from 7, corrupt the
   `/etc` file into non-JSON, `sudo grepfocusd cleanup --purge` → `browser DoH
   policies FAILED`, `purge dirs skipped — … pre-grepfocus copies survive`,
   `.orig` still present; restore by hand, finish with a normal cleanup.
10. GetStatus shows 7 `browser_policies` entries in slug order with
    `since_unix` = file mtimes.

**After WP5 (banner)**

1. `./scripts/check.sh`; **[user]** `sudo ./packaging/upgrade.sh`;
   `/usr/local/bin/grepfocus-gui --version` → `grepfocus-gui 0.5.1`.
2. Start a 5-min block with a domain: no RED/YELLOW; the INFO "restart once"
   line appears only if a policy was written in the last 15 min; Settings
   about line `GrepFocus 0.5.1 · daemon 0.5.1 (/usr/local/bin/grepfocusd)`;
   diag line `DoH block (nft): ok · /etc/hosts lock: locked` (licensed) or
   `off (premium feature)` `· instant-break proxy: holding · re-applies since
   daemon start: hosts 0, nft 0`; `lsattr /etc/hosts` shows `i` when licensed.
3. nft drift: **[user]** `sudo nft delete table inet grepfocus_doh` → within
   30 s the diag line shows `nft 1`, the table is back, no banner.
4. nft failure (RED): **[user]** block still active, `sudo chmod 000
   /usr/sbin/nft`, wait ≤30 s → RED "Active blocks can be bypassed: DoH
   protection (nftables) failed — …"; `nft` counter stays 0; with
   notifications on and the window hidden, exactly one desktop notification
   "GrepFocus: blocking problem"; `sudo chmod 755 /usr/sbin/nft` → clears
   within 30 s, journal "installed after earlier failure".
5. Stale table (YELLOW): **[user]** start a 2-min block, `chmod 000` nft, let
   it end → "No active block" plus the yellow "DoH block table could not be
   removed…"; `sudo nft list tables` still lists it; `chmod 755` → within 30 s
   the notice clears and the table is gone.
6. Proxy degraded (INFO): **[user]** no block, `sudo python3 -m http.server 80
   --bind 127.0.0.1 &`, start a block → INFO on Status and the existing
   Settings note; kill the server, toggle Instant breaks off/on → both clear.
7. Daemon down: **[user]** `sudo systemctl stop grepfocusd` → Status shows the
   client.rs error, banner hidden; Week tab shows the error (not "No schedules
   yet"); block list shows the error; about line "daemon unreachable"; tray
   tooltip "daemon unreachable" (unchanged). `sudo systemctl start grepfocusd`
   → all recover on the next poll, no spurious notification.
8. Startup notes (YELLOW): seed one over-cap block through the socket (5001
   domains), **[user]** restart the daemon → the yellow "stored block entries
   were changed or dropped" notice; delete the block.
9. hosts write failure (RED incl. the no-active-block teardown case) is not
   safely reproducible here (needs a read-only `/etc`); covered by unit tests.

**After WP6 (self-update)**

1. `./scripts/check.sh`; `bash -n`; **[user, podman]** the ubuntu:24.04 dash
   check from the WP6 "done when".
2. Migration case: run the freshly built `target/release/grepfocus-gui` against
   the still-running pre-WP3 daemon (if step order allows) → about line
   "daemon: older version (no health reporting)", `manual` banner (not an
   AppImage); `APPIMAGE=1 target/release/grepfocus-gui` → button "Update
   system service to <ver>" → click → "installer payload not found…", button
   re-enabled.
3. Daemon-newer: `cp target/release/grepfocus-gui /tmp/gui-old`; bump the
   workspace + tauri.conf.json temporarily (e.g. 0.6.1); **[user]** `sudo
   ./packaging/upgrade.sh`; run `/tmp/gui-old` → red banner "…newer than this
   app… quit and relaunch; if this notice stays, ./packaging/upgrade.sh";
   `APPIMAGE=1 /tmp/gui-old` → "Download the latest AppImage from
   grepfocus.com/download". No button either way.
4. Real AppImage update: **[user]** bump again (0.6.2), `./packaging/build-appimage.sh`
   (podman). Start a block. Run `dist/grepfocus.AppImage` against the 0.6.1
   daemon → banner + button → click → polkit prompt → "Service installed —
   waiting…" → "Service updated to 0.6.2." for ~10 s → banner gone; about line
   `0.6.2 · 0.6.2`; the block is still active; `/usr/local/bin/grepfocusd
   --version` = 0.6.2; `systemctl show grepfocusd -p ExecMainStartTimestamp`
   new; journal shows a clean start with the previous `block_count`.
5. Auth dismissed: repeat 4 with another bump, cancel the polkit dialog →
   "Authorization was dismissed.", button re-enabled.
6. Downgrade guard: **[user]** stage a payload dir from a checkout whose
   `target/release/grepfocusd` is OLDER than the installed one (0644 copies),
   `sudo bash packaging/appimage/appimage-install.sh install $USER` → refusal,
   `echo $?` = 99; with `--force` → installs.
7. Package guard: **[user]** `sudo touch /usr/bin/grepfocusd` → relaunch the
   AppImage at a higher version → `both_installs`, no button; `sudo bash
   …appimage-install.sh install $USER; echo $?` → 98; `sudo systemctl stop
   grepfocusd` → "Service not running" (packaged) with Retry only; `sudo rm
   /usr/bin/grepfocusd` → relaunch → `stopped` dialog with Retry + Reinstall;
   `sudo systemctl start grepfocusd` → Retry closes it.
8. Fold the temporary bumps into the real release bump (or revert);
   `git status` clean apart from intended changes.

**After WP7 (update check)**

1. `./scripts/check.sh`; `cargo build --release --locked`.
2. Stub: `$SCRATCH/latest/latest.json` with `"version": "9.9.9"`,
   `"notes_url": "https://grepfocus.com/changelog"`; `python3 -m http.server
   8099 --directory $SCRATCH/latest &`.
3. `rm -f ~/.config/grepfocus/update-check.json; GREPFOCUS_UPDATE_URL=http://127.0.0.1:8099/latest.json
   cargo run -p grepfocus-gui` → the disclosure strip renders first; within
   ~3 s one GET with UA `GrepFocus/0.5.1 (linux)`; next poll shows "GrepFocus
   9.9.9 is available — you have 0.5.1."; file has `disclosed:true`, mode
   0600, dir 0700. "Got it" hides the strip; relaunch → no strip.
4. Short session: relaunch and quit after ~5 s → exactly one GET; relaunch
   within 24 h → no GET.
5. Settings: "Check now" → immediate GET, row "Checked just now: GrepFocus
   9.9.9 is available."; toggle off → row and notice hidden, file
   `enabled:false`; relaunch → no GET; toggle on → GET at once.
6. Dismiss → strip gone, `dismissed_version":"9.9.9"`; relaunch → still
   hidden; serve `9.9.10` → Check now → strip returns.
7. Active block → notice disappears while active, returns after; with a
   temporary skew banner showing (step WP6.3 setup) → notice hidden, Settings
   row still says available.
8. Failure paths: 404 → "grepfocus.com has no update information yet (HTTP
   404)", `check_error` persisted and survives relaunch; `{}`, HTML, a 300 KiB
   file → "unexpected reply…"; stop the stub → "Could not reach grepfocus.com
   (connection failed). Will retry.", file NOT rewritten; `nc -l 8099` with no
   reply → 10 s then the timeout text; `nonexistent.invalid` → host-not-found
   text; corrupt the file → toggle unchecked + "preference file could not be
   read…"; toggle on → rewritten.
9. "What's new" (Firefox closed first) → Firefox opens the changelog;
   `ps -ef | grep xdg-open` shows no zombie.
10. AppImage: **[user, podman]** `./packaging/build-appimage.sh`; run
    `dist/grepfocus.AppImage` with the env override → notice carries the
    "Update system service" sentence; "What's new" (Firefox closed) →
    `tr '\0' '\n' < /proc/$(pgrep -n firefox)/environ | grep -cE 'mount_|PYTHONHOME'`
    == 0, `XDG_DATA_DIRS` still starts with the flatpak export dirs, `PATH`
    has no `mount_`; the skew banner's "Download" button opens
    `https://grepfocus.com/download`.
11. Real endpoint, after the website ships `latest.json` = 0.5.1: run without
    the override → "Checked just now: up to date (0.5.1)".
12. **[user]** `sudo ./packaging/upgrade.sh`; relaunch from the desktop entry;
    optionally `./packaging/build-rpm.sh` / `build-deb.sh` to prove ring
    compiles in the containers.

## Open questions (decisions only the owner can make)

1. **Release number.** 0.5.2 or 0.6.0? Recommendation: 0.6.0 — a new wire
   field, three behaviour changes (root processes never killed, block needs
   content, entries canonicalized), a privacy-relevant DoH-off policy and a
   daily network check. It fixes the changelog lines, the live-checklist
   numbers and the AppImage filename the website advertises.
2. **DoH-off privacy stance.** Policies switch DoH off in every covered browser
   for as long as GrepFocus is installed, not only during blocks — Mullvad
   Browser users lose Mullvad DNS. Ship v1 without an opt-out toggle (disclose
   in changelog, README, first-run dialog and the health copy; revisit after
   feedback), or add `Settings.browser_policies: bool` now (core + GUI +
   `set_settings` surface, and a "not attempted" state)? Recommendation: no
   toggle in v1.
3. **Update check default.** Default ON with the one-time disclosure strip
   (designed), or default OFF/opt-in (no strip needed, but almost nobody
   would ever learn about a release)? Recommendation: ON with the strip.

Everything else raised by the five designs is decided above: Chromium/Firefox
snap and Chrome/Brave targets ship unverified and flagged; Flatpak Firefox is
detection-only; the release notice is suppressed during a block and under a
skew banner; the RED tray notification baselines on the first poll; the
`stopped` first-run mode keeps its guarded "Reinstall service" button;
`tauri.conf.json`'s `version` stays and is pinned by a test; the banner is
Status-only; `xdg-utils` becomes a Recommends; the settings password does not
gate the update-check toggle.

## Hand-off note for the website session (`/home/scada/projects/grepfocus-web` — no edits planned here)

1. **Publish `GET https://grepfocus.com/downloads/latest.json`** exactly as in
   *Shared contracts §9* — ship it with `"version": "0.5.1"` **before** the
   0.6 GUI is released so today's clients read "up to date" (until then every
   install shows "grepfocus.com has no update information yet (HTTP 404)" in
   Settings once a day). Static `public/downloads/latest.json` works; a route
   handler fed from one `lib/release.ts` shared with `app/download/page.tsx`'s
   `VERSION` and the `next.config.ts` redirect aliases is recommended so the
   three cannot drift — your call. Headers: `Content-Type: application/json;
   charset=utf-8`, `Access-Control-Allow-Origin: *`, `Cache-Control: public,
   max-age=300, s-maxage=3600`, the existing global `X-Content-Type-Options:
   nosniff`. HTTP 200 only, body < 64 KiB. `notes_url` may gain a per-version
   anchor once `/changelog` sections have `id`s (they have none today).
2. **Keep the `/download` route stable**: the GUI's skew banner opens
   `https://grepfocus.com/download` verbatim.
3. **Release checklist line**: in the same commit that repoints the download
   aliases and the download page, update `version`/`published`/`downloads`
   (versioned filenames, lowercase sha256 of the exact files); smoke with
   `curl -s https://grepfocus.com/downloads/latest.json | jq -r .version` and
   `curl -sI … | grep -i 'cache-control\|access-control\|content-type'`.
4. **`/download` "After installing"** (`app/download/page.tsx:122-139`): add
   "Updating: package installs update through the package manager. AppImage:
   download the new file, run it — the Status tab offers *Update system
   service*; approve the password prompt. Blocks stay enforced." and "Restart
   your browser once after installing."
5. **FAQ entries**: "Why does Firefox/Chromium say it is managed by my
   organization?" (GrepFocus switches DNS-over-HTTPS off through a standard
   policy file so blocks apply); the privacy note (DoH stays off while
   GrepFocus is installed; Mullvad Browser's DNS goes to the OS resolver);
   "How do I undo it?" → `sudo grepfocusd cleanup` or uninstall; "How do I
   tell if blocking is healthy?" → the Status-tab banner, the Settings
   diagnostics line, `grepfocusd --version`; "Does GrepFocus phone home?" →
   one version-number GET a day, disclosed on first launch, opt-out in
   Settings.
