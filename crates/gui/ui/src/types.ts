// Wire types shared by main.ts and the pure modules under logic/. Each one
// mirrors a Rust type (core's in crates/core/src/lib.rs, the GUI's own in
// crates/gui/src/main.rs), snake_case on the wire.

export type AppMatcher =
  | { kind: "exe_path"; path: string }
  | { kind: "basename"; name: string }
  | { kind: "cmdline"; contains: string };

/// Mirrors core's `LockMode` (snake_case on the wire). How taking a break on
/// this block is locked down; every mode but unlocked is premium, enforced by
/// the daemon when the block is SAVED. The unlocked variant is spelled
/// `"normal"` on the wire for compatibility with released daemons — the Rust
/// variant was renamed, the wire value deliberately was not.
export type LockMode = "normal" | "password_breaks" | "challenge_breaks";

/// Mirrors core's `AllowancePolicy`, an internally-tagged enum on `kind`: how
/// much break time a block grants. Either/or by construction — policies never
/// stack. The whole axis is FREE; friction lives on `LockMode` instead.
export type AllowancePolicy =
  | { kind: "none" }
  | { kind: "per_day"; secs: number }
  | { kind: "rolling_window"; secs: number; window_secs: number }
  | { kind: "per_break"; secs: number };

export interface Block {
  id: number;
  name: string;
  domains: string[];
  apps: AppMatcher[];
  /// LEGACY downgrade mirror of `allowance`, kept in step by the daemon on
  /// save. Read `allowance` instead; this only survives so a block written by
  /// this build still means something to an older daemon.
  allowance_secs_per_day: number;
  allowance: AllowancePolicy | null;
  lock: LockMode;
}

export interface AllowanceLedger {
  block_id: number;
  day: number;
  used_secs: number;
}

/// One active block's allowance as reported by `get_status`: the policy plus
/// the daemon's reduction of break history under it. The view's fields are
/// `#[serde(flatten)]`ed in core, so they sit flat here rather than nested.
///
/// The daemon does this arithmetic precisely so raw break history never
/// reaches the frontend and window math is never reimplemented in TypeScript.
export interface AllowanceStatus {
  block_id: number;
  policy: AllowancePolicy;
  budget_secs: number;
  remaining_secs: number;
  /// Absolute unix seconds, or null for the policies where "when does more
  /// appear" has no knowable instant (none, per_day, per_break).
  next_free_unix: number | null;
  /// How much returns at `next_free_unix`, ties summed. 0 when that is null.
  next_free_secs: number;
}

export type Originator = { kind: "manual" } | { kind: "schedule"; schedule_id: number };

export interface ActiveBlock {
  block: Block;
  started_at_unix: number;
  ends_at_unix: number;
  originator: Originator;
  break_until_unix: number | null;
  /// The allowance policy SNAPSHOTTED at activation, for the same reason as
  /// `lock` below. Null on a record written before snapshotting existed, in
  /// which case the embedded block's policy is the fallback.
  allowance: AllowancePolicy | null;
  /// The lock mode SNAPSHOTTED at activation — not `block.lock`, which is the
  /// (editable) saved config. This is the one the daemon enforces, so it is
  /// the one the break UI must branch on.
  lock: LockMode;
  /// Refused-connection attempts against this block's entries during THIS
  /// run (reset on activation). Counted only while the instant-breaks proxy
  /// holds ports 80 and 443, so the card shows it only under
  /// `health.proxy === "holding"`. Absent from an old daemon.
  attempts?: number;
}

/// Mirrors core's `PomodoroPhase` (snake_case on the wire): which half of the
/// pomodoro rhythm the session is in.
export type PomodoroPhase = "focus" | "break";

/// The running-session view carried on `Status` (a projection of the daemon's
/// live `PomodoroSession`). `cycle_index` is 0-based; `phase_ends_unix` is the
/// unix time the current interval ends.
export interface PomodoroStatus {
  block_id: number;
  phase: PomodoroPhase;
  phase_ends_unix: number;
  cycle_index: number;
  cycles_total: number;
}

/// Mirrors core's `Settings`: cross-cutting preferences the daemon persists,
/// echoed on every `Status`. `notifications` defaults ON server-side (a
/// hand-written Default, so an upgrading user is never silently muted).
export interface Settings {
  notifications: boolean;
  /// Instant breaks: run the loopback proxy so a break takes effect at once
  /// even in a tab that is already open. Defaults ON server-side.
  instant_breaks: boolean;
  /// Desktop nudge when a blocked site is attempted — a sub-switch of
  /// `notifications`. Defaults OFF server-side. The GUI's Rust side
  /// deserializes `Settings` through core, whose container-level
  /// `#[serde(default)]` fills a field an old daemon omits, so this always
  /// arrives as a bool (false for such a daemon); `nudgeToggle` still reads
  /// it as `=== true` so a bare object cannot tick the box.
  attempt_nudges: boolean;
}

// ─── Health (mirrors core's wire types, snake_case on the wire) ─────────────
//
// Every enum below can carry a tag this build does not know — a newer daemon
// may add one — which core folds to `"unknown"`; the UI says nothing for it.

/// Where the daemon binary lives, classified once at daemon start.
export type InstallKind = "package" | "local" | "unknown";

/// State of the DoH-blocking nftables table.
export type NftStatus =
  | { kind: "ok" }
  /// `nft` could not install the table: the hosts block is live, DoH is open.
  | { kind: "failed"; reason: string }
  /// The block ended but `nft delete` failed; the daemon keeps retrying.
  | { kind: "stale_table"; reason: string }
  /// Nothing enforced, no table left behind.
  | { kind: "not_applicable" }
  | { kind: "unknown" };

/// State of the immutable flag on `/etc/hosts`.
export type HostsLockStatus =
  | { kind: "locked" }
  /// Licensed for tamper protection but `chattr +i` failed.
  | { kind: "unlocked"; reason: string }
  /// Nothing enforced, or not licensed (no lock attempted).
  | { kind: "not_applicable" }
  | { kind: "unknown" };

/// State of the instant-breaks loopback proxy. `degraded` is what the legacy
/// `Status.instant_breaks_degraded` flag is derived from.
export type ProxyStatus = "holding" | "degraded" | "off" | "unknown";

/// Why a browser's DoH policy file could not be written. `unsupported` and
/// `read_only_fs` are not fixable from inside GrepFocus; the rest are.
export type BrowserPolicyFailKind =
  | "unsupported"
  | "read_only_fs"
  | "not_json"
  | "symlink"
  | "io"
  | "unknown";

/// What the daemon did about one browser's DoH policy file. The failure
/// payload is `fail_kind` on the wire because the tag already owns `kind`.
export type BrowserPolicyState =
  | { kind: "not_installed" }
  | { kind: "written" }
  | { kind: "merged" }
  | { kind: "failed"; fail_kind: BrowserPolicyFailKind; reason: string }
  | { kind: "unknown" };

/// One browser's DoH policy file, as the daemon last saw it. `browser` is a
/// slug (`firefox | firefox-flatpak | mullvad-browser | chromium |
/// chromium-snap | chrome | brave`); the UI maps slugs to display names.
export interface BrowserPolicyStatus {
  browser: string;
  path: string;
  state: BrowserPolicyState;
  /// `written`/`merged`: mtime of the file; otherwise when this daemon first
  /// saw the state.
  since_unix: number;
}

/// Enforcement health plus daemon identity, carried on `Status`. An OLD
/// daemon never emits it and core's default arrives instead — an empty
/// `daemon_version` is the tell, and every other field is then meaningless.
export interface Health {
  daemon_version: string;
  daemon_exe: string;
  install_kind: InstallKind;
  nft: NftStatus;
  hosts: HostsLockStatus;
  /// Times a re-probe found the hosts region missing and re-applied it — a
  /// tamper signal.
  hosts_reapplies: number;
  /// Times a re-probe found the table gone while nft worked and re-installed
  /// it — a firewall reload.
  nft_reinstalls: number;
  proxy: ProxyStatus;
  /// Fixed slug order after the first browser-policy pass; empty before it
  /// and on an old daemon.
  browser_policies: BrowserPolicyStatus[];
  /// What the daemon's startup sanitize changed or flagged (capped at 200
  /// lines, the last one a count of the rest).
  startup_notes: string[];
  /// The last enforcement error (hosts read/write, install or teardown);
  /// cleared by the next success.
  last_error: string | null;
  last_error_unix: number | null;
}

export interface Status {
  active: ActiveBlock[];
  now_unix: number;
  password_set: boolean;
  unlocked: boolean;
  allowance: AllowanceStatus[];
  /// DEPRECATED, still emitted: a bare per-day counter. Only read as a
  /// fallback when `allowance` is absent — see `renderActive`.
  allowance_used: AllowanceLedger[];
  license_present: boolean;
  license_valid: boolean;
  license_kind: string | null;
  license_email: string | null;
  license_expires_at: number | null;
  licensed_features: string[];
  pomodoro: PomodoroStatus | null;
  settings: Settings;
  /// DEPRECATED, still emitted: equal to `health.proxy === "degraded"` —
  /// instant breaks are on and a block is active but the loopback proxy could
  /// not bind a port (something else holds :80 or :443), so breaks lag on
  /// this machine. Drives an explanatory notice.
  instant_breaks_degraded: boolean;
  /// Enforcement health and daemon identity — see `Health`.
  health: Health;
  /// The daemon's recent enforcement events, oldest first; empty from an old
  /// daemon. The Rust status watcher (src/notify.rs) turns these into desktop
  /// notifications off its own poll — this side never decides notifications
  /// from them, it only mirrors the shape.
  recent_events: RecentEvent[];
  /// GUI/daemon version skew advice, computed by the Rust side on every poll
  /// — see `UpdateAdvice`.
  update: UpdateAdvice;
}

/// Mirrors core's `EventKind` (snake_case on the wire). A tag this build does
/// not know folds to `"unknown"` in core; say nothing for it.
export type EventKind = "attempt" | "app_kill" | "unknown";

/// Mirrors core's `RecentEvent`: one enforcement event on `Status`.
export interface RecentEvent {
  /// Monotonic per daemon run, starting at 1; the dedup key. A value below
  /// the last one seen means the daemon restarted.
  seq: number;
  unix: number;
  kind: EventKind;
  block_id: number;
  /// `attempt`: the blocklist entry (canonical hostname). `app_kill`: the
  /// matched app entry's label. Capped at 64 chars by the daemon.
  detail: string;
}

/// Mirrors `version::UpdateAdvice` in src/version.rs: what the GUI/daemon
/// version skew calls for. `from` is the daemon's version (null = it predates
/// version reporting), `to` this app's. Only `update_service` comes with a
/// button; `gui_outdated` is never an install offer.
export type UpdateAdvice =
  | { kind: "up_to_date" }
  | { kind: "update_service"; from: string | null; to: string }
  | { kind: "package_manager"; from: string | null; to: string }
  | { kind: "both_installs"; from: string | null; to: string }
  | { kind: "manual"; from: string | null; to: string }
  | { kind: "gui_outdated"; gui: string; daemon: string };

/// Mirrors `update::Release` in src/update.rs: what the GUI keeps of the
/// site's `latest.json`. `notes_url` arrives only when it is a grepfocus.com
/// link — the Rust side drops anything else before it gets here.
export interface Release {
  version: string;
  published: string | null;
  notes_url: string | null;
}

/// Mirrors `update::UpdateInfo`: the daily release check as the Rust side
/// sees it. `status` and `notice` are finished copy; this side only decides
/// where and when they show.
export interface UpdateInfo {
  enabled: boolean;
  /// The one-time disclosure strip has been rendered (this launch or an
  /// earlier one).
  disclosed: boolean;
  current: string;
  latest: Release | null;
  available: boolean;
  dismissed: boolean;
  checking: boolean;
  last_check_unix: number | null;
  /// The Settings row.
  status: string;
  /// The Status-tab strip; null unless a newer, undismissed release is known
  /// and checks are on.
  notice: string | null;
  /// A preference file that could not be read or saved — its own line,
  /// never mixed into `status`.
  persist_error: string | null;
}

export interface Schedule {
  id: number;
  name: string;
  block_id: number;
  days: number; // bitmask
  start_minute: number;
  duration_minutes: number;
  enabled: boolean;
}

// ─── Stats (premium) ─────────────────────────────────────────────────────────

export interface LifetimeTotals {
  focus_secs: number;
  sessions: number;
  app_kills: number;
  breaks_refused: number;
  /// Refused-connection attempts, lifetime. Absent from an old daemon.
  attempts?: number;
}

/// Mirrors core's `Origin` (snake_case on the wire).
export type Origin = "manual" | "schedule";

export interface FocusSession {
  block_id: number;
  name: string;
  started_at_unix: number;
  ended_at_unix: number;
  origin: Origin;
  duration_secs: number;
}

export interface DayStat {
  /// `num_days_from_ce` (a local-day integer), NOT a unix timestamp — use only
  /// for ordering and labels relative to today, never as a clock time.
  day: number;
  focus_secs: number;
  sessions_completed: number;
  breaks_taken: number;
  break_secs: number;
  breaks_refused: number;
  app_kills: number;
  /// Refused-connection attempts per blocklist entry. Mirrors core's
  /// `DayStat.attempts` with its two caveats: at most 50 entries per day,
  /// FIRST COME (not the top 50 — past the cap a new entry moves only
  /// `attempts_total`), and the map is cleared on rows more than 30 days
  /// before today while the total survives. Both are handled in
  /// logic/attempts.ts; never derive "other" from this directly. Absent from
  /// an old daemon.
  attempts?: Record<string, number>;
  attempts_total?: number;
}

export interface UsageStats {
  totals: LifetimeTotals;
  /// Stored ring, oldest-last — reverse for newest-first display.
  sessions: FocusSession[];
  /// Recent window, sorted ascending (oldest-first), last ~30 rollups.
  days: DayStat[];
  current_streak: number;
  longest_streak: number;
}

// ─── GUI process environment (`app_env`) ─────────────────────────────────────

export interface AppEnv {
  appimage: boolean;
  /// The app's own version, for the Settings about line (`aboutLine`).
  gui_version: string;
  /// `/usr/bin/grepfocusd` exists — a package install owns the daemon.
  packaged_daemon: boolean;
  /// `/usr/local/bin/grepfocusd` exists — the AppImage installer's or the
  /// dev scripts' daemon.
  local_daemon: boolean;
}
