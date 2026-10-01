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

mod auth;
mod browser_policy;
mod cleanup;
mod dns;
mod enforce;
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
use grepfocus_core::{now_unix, State};

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
}

impl Daemon {
    /// The health leaf lock. Poison is recovered rather than propagated: a
    /// panicked prior holder must not wedge status reporting or enforcement.
    pub fn health(&self) -> std::sync::MutexGuard<'_, health::HealthState> {
        self.health.lock().unwrap_or_else(|p| p.into_inner())
    }
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
    let now = now_unix();
    if now > initial.high_water_unix {
        initial.high_water_unix = now;
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

    // Drop any active blocks that have already expired between shutdown and
    // startup. (They will simply never be re-applied.)
    let before = initial.active.len();
    initial.active.retain(|a| a.ends_at_unix > now);
    let dropped = before - initial.active.len();
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
        license: Mutex::new(license),
        break_challenges: Mutex::new(std::collections::HashMap::new()),
        app_kills_pending: std::sync::atomic::AtomicU64::new(0),
        health: std::sync::Mutex::new(health::HealthState::new(daemon_exe, install_kind, notes)),
    });

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
