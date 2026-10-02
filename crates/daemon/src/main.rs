//! grepfocusd — privileged blocking daemon.
//!
//! Runs as root via systemd. Owns the persisted block state, edits
//! /etc/hosts (with chattr +i during active blocks), and SIGKILLs blocked
//! processes. Keeps browser DNS-over-HTTPS switched off through enterprise
//! policy files so the hosts block applies there (see `browser_policy`).
//! Talks to the GUI over a Unix socket at /run/grepfocus/sock.
//!
//! Also ships the offline recovery path: `grepfocusd cleanup` tears down all
//! enforcement without needing a working daemon (see `cleanup`).

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

mod attempts;
mod auth;
mod browser_policy;
mod cleanup;
mod clock;
mod dns;
mod enforce;
mod events;
mod health;
mod hosts;
mod ipc;
mod listener;
mod nftables;
mod paths;
mod procwatch;
mod scheduler;
mod state;

use grepfocus_core::license::LicenseClaims;
use grepfocus_core::{now_unix, ActiveBlock, State};

/// Runtime context shared across all daemon tasks.
pub struct Daemon {
    /// Persisted state — blocks, active blocks, schedules.
    pub state: Mutex<State>,
    /// HMAC key loaded from /etc/grepfocus/secret at startup.
    pub key: Vec<u8>,
    /// Unix time until which configuration changes are unlocked. In-memory
    /// only: a daemon restart relocks the settings. `0` means locked.
    pub unlocked_until: Mutex<u64>,
    /// Serializes enforcement writes and memoizes the domain union that was
    /// last applied successfully, plus when it was last verified live.
    /// `None` means unknown/dirty — the next `enforce::sync` re-applies
    /// unconditionally. See `enforce::sync`.
    pub applied: Mutex<Option<enforce::Applied>>,
    /// The loopback proxy while it is running, or `None` when no ports are
    /// held (instant-breaks off, or nothing blocked).
    ///
    /// Taken ONLY by `enforce::sync`, and only with `applied` already held, so
    /// it extends the documented lock order to `applied` → `listener` without
    /// adding a second route to it. Nothing releases it at shutdown: the
    /// kernel closes the sockets when the process exits, and the offline
    /// teardown path (`grepfocusd cleanup`) runs with the daemon stopped, so
    /// there is nothing left bound for it to free.
    pub listener: Mutex<Option<listener::ProxyListener>>,
    /// Domains the loopback proxy may forward RIGHT NOW: those on a break this
    /// instant that are not otherwise enforced (see `enforce::forwardable_set`).
    /// Rewritten by `enforce::sync` each tick under the state lock; read by the
    /// proxy's per-connection decision hook. A `std::sync::Mutex` on purpose —
    /// it is a leaf lock held for microseconds and NEVER across an await, so the
    /// accept path takes no tokio lock and cannot deadlock against the daemon.
    pub forwardable: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Domains the daemon is enforcing RIGHT NOW — the canonical union
    /// `enforce::sync` last wrote to `/etc/hosts` (see `enforce::union_domains`).
    /// Rewritten each tick next to `forwardable`, read by the proxy's
    /// per-connection observe hook: only a refused hostname that folds to one
    /// of these counts as an attempt, so a developer's own `127.0.0.1
    /// myapp.test` hosts line — which lands on our `:80` and is refused too —
    /// never becomes one. Same leaf-lock discipline as `forwardable`.
    pub enforced: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Refused-connection attempts the proxy has observed and the scheduler
    /// has not yet credited (see `attempts`). Written from the accept path by
    /// the observe hook, drained once per scheduler tick under the state lock
    /// — the `app_kills_pending` pattern with a dedup window in front. A leaf
    /// `std::sync::Mutex` for the same reason as `forwardable`; `Arc` because
    /// the hook closure captures a clone. The scheduler goes through
    /// `Daemon::attempts()`; the hook has only its captured clone and locks
    /// that directly, with the same poison recovery (`into_inner`).
    pub attempts: Arc<std::sync::Mutex<attempts::Buffer>>,
    /// Claims from the verified `state.license_token`, or `None` when
    /// unlicensed or the stored token failed verification. Derived and
    /// in-memory only — rebuilt at startup and on `SetLicense`.
    pub license: Mutex<Option<LicenseClaims>>,
    /// Pending break challenges for `ChallengeBreaks` blocks: block_id → the
    /// exact string the daemon issued via `GetBreakChallenge`. In-memory
    /// only, deliberately: a daemon restart invalidating a pending challenge
    /// fails safe — the user just requests a new one.
    pub break_challenges: Mutex<std::collections::HashMap<u64, String>>,
    /// Distinct app kills counted by procwatch since the last stats flush.
    /// In-memory only — folded into today's `DayStat` opportunistically at the
    /// next state save from the scheduler tick, exactly the `high_water_unix`
    /// "accumulate in memory, persist when something else saves" pattern. No
    /// fsync per kill; a crash loses at most the unflushed count.
    pub app_kills_pending: std::sync::atomic::AtomicU64,
    /// Enforcement health and daemon identity, reported on `GetStatus`.
    /// Written by `enforce::sync` (every outcome of an apply, re-probe or
    /// teardown, and the live proxy state each tick), read by `GetStatus`.
    /// In-memory only; enforcement never depends on it. A `std::sync::Mutex`
    /// for the same reason as `forwardable`: a leaf lock held for
    /// microseconds and never across an await, so it can be taken with
    /// `applied` or `state` already held. Go through `Daemon::health()`.
    pub health: std::sync::Mutex<health::HealthState>,
    /// Recent enforcement events — attempts credited by the scheduler, kills
    /// by procwatch — reported on `GetStatus.recent_events` (see `events`).
    /// In-memory only, bounded and sequence-numbered. A leaf
    /// `std::sync::Mutex` like `health`, so the scheduler can push while it
    /// holds `state` and procwatch while it holds nothing. Go through
    /// `Daemon::events()`.
    pub events: std::sync::Mutex<events::Log>,
    /// The trusted block clock (see `clock`): the time base for every
    /// block-timing decision, advanced once per scheduler tick and read
    /// through `Daemon::now()`. A leaf `std::sync::Mutex` like `health`,
    /// held for microseconds and never across an await, so the scheduler
    /// advances it with `state` held and `GetStatus` reads it the same way;
    /// `Arc` because the proxy's observe hook captures a clone to stamp
    /// attempts in the same frame. Go through `Daemon::clock()`.
    pub clock: Arc<std::sync::Mutex<clock::BlockClock>>,
    /// The kernel's `boot_id`, read once at startup (it cannot change within
    /// a boot): what `resume` matched the persisted anchor against, and what
    /// every anchor the scheduler writes carries. Empty when unreadable.
    pub boot_id: String,
}

impl Daemon {
    /// The health leaf lock. Poison is recovered rather than propagated: a
    /// panicked prior holder must not wedge status reporting or enforcement.
    pub fn health(&self) -> std::sync::MutexGuard<'_, health::HealthState> {
        self.health.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The attempt-buffer leaf lock, poison recovered as for `health`.
    pub fn attempts(&self) -> std::sync::MutexGuard<'_, attempts::Buffer> {
        self.attempts.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The event-log leaf lock, poison recovered as for `health`.
    pub fn events(&self) -> std::sync::MutexGuard<'_, events::Log> {
        self.events.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The block-clock leaf lock, poison recovered as for `health`.
    pub fn clock(&self) -> std::sync::MutexGuard<'_, clock::BlockClock> {
        self.clock.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// "Now" on the trusted block clock — what every block-timing decision
    /// reads instead of the wall clock: block, break and pomodoro ends, the
    /// settings unlock window, the status frame's `now_unix` (so the GUI's
    /// countdowns follow this frame too), attempt and kill event stamps.
    /// By design NOT on this clock: license expiry (`effective_now`),
    /// `browser_policy` and the export stamp (`exported_at_unix` is
    /// provenance compared across machines, so it agrees with the file's
    /// wall-clock name) — those read the wall clock.
    pub fn now(&self) -> u64 {
        clock::now_in(&self.clock)
    }
}

/// Drop the active blocks whose end has passed on the block clock (`now`),
/// returning how many. Pure; what `run_daemon` does at startup.
fn drop_expired_active(active: &mut Vec<ActiveBlock>, now: u64) -> usize {
    let before = active.len();
    active.retain(|a| a.ends_at_unix > now);
    before - active.len()
}

/// Wall-clock "now" (unix seconds) for license checks, clamped so a rewound
/// system clock can never travel back before the highest time this daemon has
/// observed (`state.high_water_unix`, bumped by the scheduler tick). Without
/// the clamp, setting the clock to 1999 would resurrect any expired trial.
pub fn effective_now(state: &State) -> i64 {
    (now_unix() as i64).max(state.high_water_unix as i64)
}

/// Whether the cached license grants premium feature `key` right now.
///
/// True iff claims exist, are unexpired against `effective_now(state)`, and
/// list `key` in `features`. The expiry comparison follows the frozen
/// boundary rule shared with the verifier and `license_status_fields`:
/// `expires_at == now` is still valid; `None` means perpetual.
pub fn has_feature(license: Option<&LicenseClaims>, state: &State, key: &str) -> bool {
    license.is_some_and(|c| {
        c.expires_at.is_none_or(|t| t >= effective_now(state))
            && c.features.iter().any(|f| f == key)
    })
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing before dispatching so subcommands log too.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => run_daemon(),
        Some("cleanup") => {
            let mut opts = cleanup::Opts {
                purge: false,
                force: false,
            };
            for arg in args {
                match arg.as_str() {
                    "--purge" => opts.purge = true,
                    "--force" => opts.force = true,
                    other => usage(&format!("unknown cleanup flag: {}", other)),
                }
            }
            cleanup::run(opts)
        }
        // Parsed by the AppImage installer's downgrade guard: keep the
        // `grepfocusd <ver>` shape.
        Some("--version") | Some("-V") => {
            println!("grepfocusd {}", health::DAEMON_VERSION);
            Ok(())
        }
        Some(other) => usage(&format!("unknown subcommand: {}", other)),
    }
}

/// Print an error plus usage to stderr and exit nonzero.
fn usage(err: &str) -> ! {
    eprintln!("error: {}", err);
    eprintln!(
        "usage: grepfocusd                        run the daemon (root; normally via systemd)"
    );
    eprintln!("       grepfocusd cleanup [--force] [--purge]");
    eprintln!(
        "                                          tear down all enforcement (daemon stopped)"
    );
    eprintln!("         --force  skip the running-daemon check");
    eprintln!("         --purge  also delete /var/lib/grepfocus and /etc/grepfocus");
    eprintln!("       grepfocusd --version | -V        print the version and exit");
    std::process::exit(2);
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn run_daemon() -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("grepfocusd must run as root");
    }

    paths::ensure_dirs().context("creating runtime/state directories")?;
    let key = state::load_or_create_secret().context("loading HMAC secret")?;

    let mut initial = match state::load(&key) {
        Ok(s) => s,
        Err(err) => {
            let missing = err.chain().any(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            });
            if missing {
                info!("no state file yet — first run, starting fresh");
            } else if state::is_unparseable(&err) {
                // The HMAC verified, so this file is authentically ours — it
                // just doesn't fit this build's schema (our bug, or state
                // written by a newer daemon). Starting fresh would save over
                // it and destroy every block, schedule, stat and the stored
                // licence token, so refuse to start instead and leave
                // state.json exactly as it is. Note we deliberately do *not*
                // clear the hosts block on this path: we cannot know what was
                // being enforced, and for a blocker leaving enforcement up is
                // the safe failure.
                return Err(err).context(
                    "refusing to start: state.json is authentic but unreadable by this build \
                     (state left untouched — check for a version downgrade)",
                );
            } else {
                error!(
                    ?err,
                    "state file corrupted — starting fresh and clearing any leftover hosts block"
                );
                if let Err(e) = hosts::clear_block() {
                    error!(?e, "failed to clear leftover hosts block");
                }
            }
            State::default()
        }
    };

    // Advance the clock-rollback high-water mark once at startup; the
    // scheduler tick keeps it moving from here. If the stored mark is ahead
    // of the system clock (rolled back while we were down), keep the mark.
    let wall_now = now_unix();
    if wall_now > initial.high_water_unix {
        initial.high_water_unix = wall_now;
    }

    // Verify any stored license token. Failure is never fatal and never
    // strips the token from state: an expired/invalid token stays stored so
    // GetStatus can report "present but invalid" — we just run unlicensed.
    let license = match &initial.license_token {
        None => None,
        Some(token) => {
            match grepfocus_core::license::verify_token(token, effective_now(&initial)) {
                Ok(claims) => {
                    info!(kind = %claims.kind, "stored license verified");
                    Some(claims)
                }
                Err(err) => {
                    warn!(%err, "stored license token failed verification — running unlicensed");
                    None
                }
            }
        }
    };

    // Canonicalize stored block content — the saved blocks and the copies
    // inside active blocks, which is what enforcement reads — before anything
    // enforces it. Entries written by a pre-validation daemon (or a raw
    // socket client) that cannot be normalized are dropped here; each change
    // is one journal line, and the flag-only notes (over-cap lists, invalid
    // names) repeat every start until the user fixes the block.
    let notes = initial.sanitize();
    for n in &notes {
        warn!(note = %n, "sanitized stored block content");
    }

    // Rebuild the trusted block clock before anything judges expiry by it.
    // An anchor from this boot resumes the previous run's time base exactly
    // (a clock stepped while we were down cannot shorten a persisted block);
    // otherwise the clock seeds from the wall clock, no earlier than the
    // high-water mark bumped above.
    let readings = clock::read();
    let boot_id = clock::boot_id();
    let (block_clock, restored) = clock::BlockClock::resume(
        initial.clock_anchor.as_ref(),
        &boot_id,
        readings,
        initial.high_water_unix,
    );
    let now = block_clock.now_at(readings);
    if restored {
        info!(
            trusted_unix = now,
            wall_unix = readings.wall_unix,
            "clock anchor restored"
        );
    }

    // Drop any active blocks that have already expired between shutdown and
    // startup, judged on the block clock. (They will simply never be
    // re-applied.)
    let dropped = drop_expired_active(&mut initial.active, now);
    if dropped > 0 {
        info!(dropped, "discarded expired active blocks on startup");
    }
    if dropped > 0 || !notes.is_empty() {
        if let Err(e) = state::save(&initial, &key) {
            error!(?e, "failed to save state after startup sanitize");
        }
    }

    // Identity for `GetStatus.health`, classified once: after an in-place
    // upgrade `/proc/self/exe` would read differently, and the kind must
    // describe the binary that is running.
    let daemon_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let install_kind = health::install_kind_for(std::path::Path::new(&daemon_exe));

    info!(
        version = health::DAEMON_VERSION,
        exe = %daemon_exe,
        ?install_kind,
        block_count = initial.blocks.len(),
        active_count = initial.active.len(),
        schedule_count = initial.schedules.len(),
        "daemon starting"
    );

    let daemon = Arc::new(Daemon {
        state: Mutex::new(initial),
        key,
        unlocked_until: Mutex::new(0),
        applied: Mutex::new(None),
        listener: Mutex::new(None),
        forwardable: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        enforced: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        attempts: Arc::new(std::sync::Mutex::new(attempts::Buffer::default())),
        license: Mutex::new(license),
        break_challenges: Mutex::new(std::collections::HashMap::new()),
        app_kills_pending: std::sync::atomic::AtomicU64::new(0),
        health: std::sync::Mutex::new(health::HealthState::new(daemon_exe, install_kind, notes)),
        events: std::sync::Mutex::new(events::Log::default()),
        clock: Arc::new(std::sync::Mutex::new(block_clock)),
        boot_id,
    });

    // Catch SIGTERM — what systemd sends on `stop` and on an upgrade — from
    // here on, so the shutdown below runs for it exactly as for a terminal's
    // ^C. Needs the runtime's signal driver, hence not at the top of `main`;
    // until this line the default disposition (terminate) applies, and there
    // is nothing to save before it.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;

    // Re-apply the union of all still-active blocks before accepting clients.
    if let Err(e) = enforce::sync(&daemon).await {
        error!(?e, "failed to re-apply hosts enforcement on startup");
    }

    let ipc_handle = tokio::spawn(ipc::serve(daemon.clone()));
    let watch_handle = tokio::spawn(procwatch::run(daemon.clone()));
    let sched_handle = tokio::spawn(scheduler::run(daemon.clone()));
    let policy_handle = tokio::spawn(browser_policy::run(daemon.clone()));

    // Run until any task fails or we receive SIGTERM/SIGINT.
    tokio::select! {
        r = ipc_handle => { error!(?r, "ipc task exited"); }
        r = watch_handle => { error!(?r, "procwatch task exited"); }
        r = sched_handle => { error!(?r, "scheduler task exited"); }
        r = policy_handle => { error!(?r, "browser policy task exited"); }
        _ = tokio::signal::ctrl_c() => { info!("received SIGINT, shutting down"); }
        _ = sigterm.recv() => { info!("received SIGTERM, shutting down"); }
    }

    // Persist once on the way out, whatever ended the select. The scheduler
    // saves credits (attempts, app kills) at most once a minute, so without
    // this a `systemctl stop` or an upgrade could drop up to a minute of
    // counts; what is still undrained in `attempts`/`app_kills_pending` is at
    // most one tick's worth and is accepted. The lock is free to take: a task
    // that exited through a panic dropped its guard on the way out (a tokio
    // mutex does not poison), and whatever enforcement it left behind is
    // re-applied from this very state at the next start.
    {
        let st = daemon.state.lock().await;
        if let Err(e) = state::save(&st, &daemon.key) {
            error!(?e, "final state save failed");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_now_follows_clock_when_high_water_is_behind() {
        let st = State::default(); // high_water_unix == 0
        let before = now_unix() as i64;
        let eff = effective_now(&st);
        let after = now_unix() as i64;
        assert!((before..=after).contains(&eff));
    }

    #[test]
    fn effective_now_clamps_to_high_water_on_clock_rollback() {
        // A high-water mark ahead of the system clock is exactly what a
        // rewound clock looks like: effective time must not travel back.
        let hw = 4_102_444_800; // 2100-01-01, safely ahead of any test run
        let st = State {
            high_water_unix: hw,
            ..Default::default()
        };
        assert_eq!(effective_now(&st), hw as i64);
    }

    // ── has_feature() ───────────────────────────────────────────────────────

    use grepfocus_core::license::features;

    /// Pins `effective_now` in these tests: a high-water mark of 2100-01-01
    /// dominates the real clock for any plausible test run, making the
    /// expiry comparisons deterministic.
    const HW: u64 = 4_102_444_800;

    fn st_at_hw() -> State {
        State {
            high_water_unix: HW,
            ..Default::default()
        }
    }

    fn claims(feature_keys: &[&str], expires_at: Option<i64>) -> LicenseClaims {
        LicenseClaims {
            license_id: "GF-TEST-0001".into(),
            email: "kat@example.com".into(),
            tier: "premium".into(),
            kind: "trial".into(),
            features: feature_keys.iter().map(|s| s.to_string()).collect(),
            issued_at: 0,
            expires_at,
            max_devices: 3,
        }
    }

    #[test]
    fn has_feature_false_without_license() {
        assert!(!has_feature(None, &st_at_hw(), features::SCHEDULES));
    }

    #[test]
    fn has_feature_false_when_expired() {
        let c = claims(&features::ALL, Some(HW as i64 - 1));
        assert!(!has_feature(Some(&c), &st_at_hw(), features::SCHEDULES));
    }

    #[test]
    fn has_feature_boundary_expiry_equal_to_now_is_still_valid() {
        // Frozen boundary rule (matches the verifier and
        // license_status_fields): expires_at == now grants.
        let c = claims(&features::ALL, Some(HW as i64));
        assert!(has_feature(Some(&c), &st_at_hw(), features::SCHEDULES));
    }

    #[test]
    fn has_feature_false_when_key_not_granted() {
        // Valid license, but the queried key is not in `features`.
        let c = claims(&[features::SCHEDULES], None);
        assert!(!has_feature(Some(&c), &st_at_hw(), features::APP_BLOCKING));
    }

    #[test]
    fn has_feature_true_for_every_granted_key_on_valid_license() {
        let c = claims(&features::ALL, None); // perpetual
        for key in features::ALL {
            assert!(has_feature(Some(&c), &st_at_hw(), key), "key {key}");
        }
    }

    // ── startup: expired-active retain on the resumed clock ────────────────

    use grepfocus_core::{Block, ClockAnchor, LockMode, Originator};

    fn active_ending(id: u64, ends_at_unix: u64) -> ActiveBlock {
        ActiveBlock {
            block: Block {
                id,
                name: format!("block-{id}"),
                domains: vec!["example.com".into()],
                apps: vec![],
                allowance_secs_per_day: 0,
                allowance: None,
                lock: LockMode::Unlocked,
            },
            started_at_unix: 0,
            ends_at_unix,
            originator: Originator::Manual,
            break_until_unix: None,
            apps_enforced: false,
            lock: LockMode::Unlocked,
            allowance: None,
            attempts: 0,
        }
    }

    #[test]
    fn expired_active_retain_uses_the_resumed_clock() {
        // The daemon restarts in the same boot after the clock was stepped
        // back: the wall clock reads 1000, the resumed block clock 5010 (the
        // anchor's 5000 plus 10 s of BOOTTIME). A block due at 5005 is over;
        // one due at 5011 is not — judged on the wall clock, both would have
        // been kept and the first enforced for four thousand seconds more.
        let anchor = ClockAnchor {
            trusted_unix: 5_000,
            boot_secs: 50,
            boot_id: "this-boot".into(),
            absorbed_secs: 0,
        };
        let readings = clock::Readings {
            wall_unix: 1_000,
            boot_secs: 60,
        };
        let (c, restored) = clock::BlockClock::resume(Some(&anchor), "this-boot", readings, 0);
        assert!(restored);
        let now = c.now_at(readings);
        assert_eq!(now, 5_010);

        let mut active = vec![active_ending(1, 5_005), active_ending(2, 5_011)];
        assert_eq!(drop_expired_active(&mut active, now), 1);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].block.id, 2);
        // Nothing to drop is a clean zero, not an underflow.
        assert_eq!(drop_expired_active(&mut active, now), 0);
    }

    #[test]
    fn has_feature_respects_clock_rollback_clamp() {
        // The license expired at HW-1; even though the *system clock* is far
        // before HW, effective_now clamps to the high-water mark, so a
        // rewound clock cannot resurrect the feature.
        let c = claims(&features::ALL, Some(HW as i64 - 1));
        let st = st_at_hw(); // real clock << HW in any test run
        assert!(!has_feature(Some(&c), &st, features::TAMPER_PROTECTION));
    }
}
