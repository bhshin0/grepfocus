//! Enforcement health and daemon identity, as reported on `GetStatus.health`.
//!
//! Every outcome `enforce::sync` used to log and forget — a failed `nft`
//! install, a `chattr +i` refused by the filesystem, a DoH table left behind
//! after a block ended, a hosts write that failed outright — is recorded here
//! so the GUI can say what only the journal used to say. The state is pure:
//! transitions take results and clocks as arguments and never touch the
//! system, which is what makes them unit-testable without root.
//!
//! Lives behind a leaf `std::sync::Mutex` on `Daemon` (`Daemon::health()`):
//! held for microseconds and never across an await, so it may be taken with
//! `applied` (enforce) or `state` (ipc) already held without extending the
//! documented lock order — the same discipline as `forwardable`.

use std::path::Path;

use grepfocus_core::{
    BrowserPolicyStatus, Health, HostsLockStatus, InstallKind, NftStatus, ProxyStatus,
};

/// The version stamped on every snapshot; `grepfocusd --version` prints it.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Longest `reason` / `last_error` put on the wire, in chars. An `anyhow`
/// chain can carry a whole `nft` stderr dump; the GUI shows one line.
const MAX_REASON_CHARS: usize = 500;
/// Longest `startup_notes` list put on the wire. A legacy state file with
/// thousands of unusable entries produces one note per entry.
const MAX_STARTUP_NOTES: usize = 200;

/// The live health record. Identity fields are set once at startup; the
/// enforcement fields follow `enforce::sync`.
#[derive(Debug, Default)]
pub struct HealthState {
    daemon_exe: String,
    install_kind: InstallKind,
    nft: NftStatus,
    hosts: HostsLockStatus,
    hosts_reapplies: u32,
    nft_reinstalls: u32,
    proxy: ProxyStatus,
    browser_policies: Vec<BrowserPolicyStatus>,
    startup_notes: Vec<String>,
    last_error: Option<String>,
    last_error_unix: Option<u64>,
}

impl HealthState {
    pub fn new(daemon_exe: String, install_kind: InstallKind, startup_notes: Vec<String>) -> Self {
        Self {
            daemon_exe,
            install_kind,
            startup_notes,
            ..Self::default()
        }
    }

    /// Set every tick from the live proxy detection, not from the memo: a
    /// port that frees up is visible on the next tick, not the next apply.
    pub fn set_proxy(&mut self, proxy: ProxyStatus) {
        self.proxy = proxy;
    }

    /// Record a successful `enforce::apply`. Clears `last_error` — the
    /// hosts write is the only fatal step, and it just landed.
    ///
    /// A `StaleTable` (teardown's `nft delete` failed) is only believed when
    /// a table could actually exist: after `Ok`, an earlier `StaleTable`, or
    /// `Unknown`. After `NotApplicable` or `Failed` nothing was installed, so
    /// a failing delete says the nft binary is broken, not that DoH is still
    /// blocked, and the status stays `NotApplicable`.
    pub fn apply_succeeded(&mut self, nft: NftStatus, hosts: HostsLockStatus) {
        self.nft = self.settle_teardown(nft);
        self.hosts = hosts;
        self.last_error = None;
        self.last_error_unix = None;
    }

    /// Record a failed `enforce::apply`. Both halves become `Unknown`: the
    /// pre-write `chattr -i` already ran and the nft half never did, so
    /// neither the previous status nor the intended one describes the file.
    pub fn apply_failed(&mut self, err: &anyhow::Error, now: u64) {
        self.nft = NftStatus::Unknown;
        self.hosts = HostsLockStatus::Unknown;
        self.last_error = Some(reason(err));
        self.last_error_unix = Some(now);
    }

    /// Record an nft-only re-install from the re-verify probe. `prev_ok` is
    /// the memo's view before the probe: a re-install that succeeds after the
    /// table was seen working is real drift (a firewall reload) and is
    /// counted; healing an nft half that was broken since apply time is not.
    /// A failure is never counted — the transition was reported at apply
    /// time and this path repeats every re-verify interval.
    pub fn nft_reprobed(&mut self, prev_ok: bool, result: Result<(), &anyhow::Error>) {
        self.nft = match result {
            Ok(()) => {
                if prev_ok {
                    self.nft_reinstalls = self.nft_reinstalls.saturating_add(1);
                }
                NftStatus::Ok
            }
            Err(e) => NftStatus::Failed { reason: reason(e) },
        };
    }

    /// Record a retried teardown of a table left behind after a block ended.
    /// Subject to the same "could a table exist" rule as `apply_succeeded`,
    /// so a retry cannot resurrect a `StaleTable` the apply already
    /// downgraded.
    pub fn teardown_retried(&mut self, result: Result<(), &anyhow::Error>) {
        let nft = match result {
            Ok(()) => NftStatus::NotApplicable,
            Err(e) => NftStatus::StaleTable { reason: reason(e) },
        };
        self.nft = self.settle_teardown(nft);
    }

    /// The re-verify probe found the hosts region missing and re-applied it.
    pub fn hosts_drift_detected(&mut self) {
        self.hosts_reapplies = self.hosts_reapplies.saturating_add(1);
    }

    /// Whole-list replace after every browser-policy pass.
    pub fn set_browser_policies(&mut self, list: Vec<BrowserPolicyStatus>) {
        self.browser_policies = list;
    }

    /// The wire view: stamps the daemon version and caps `startup_notes`.
    pub fn snapshot(&self) -> Health {
        Health {
            daemon_version: DAEMON_VERSION.to_string(),
            daemon_exe: self.daemon_exe.clone(),
            install_kind: self.install_kind,
            nft: self.nft.clone(),
            hosts: self.hosts.clone(),
            hosts_reapplies: self.hosts_reapplies,
            nft_reinstalls: self.nft_reinstalls,
            proxy: self.proxy,
            browser_policies: self.browser_policies.clone(),
            startup_notes: capped_notes(&self.startup_notes),
            last_error: self.last_error.clone(),
            last_error_unix: self.last_error_unix,
        }
    }

    fn settle_teardown(&self, nft: NftStatus) -> NftStatus {
        let table_possible = matches!(
            self.nft,
            NftStatus::Ok | NftStatus::StaleTable { .. } | NftStatus::Unknown
        );
        match nft {
            NftStatus::StaleTable { .. } if !table_possible => NftStatus::NotApplicable,
            other => other,
        }
    }
}

/// The first `MAX_STARTUP_NOTES` lines, the last one replaced by a count of
/// what was left out.
fn capped_notes(notes: &[String]) -> Vec<String> {
    if notes.len() <= MAX_STARTUP_NOTES {
        return notes.to_vec();
    }
    let keep = MAX_STARTUP_NOTES - 1;
    let mut out = notes[..keep].to_vec();
    out.push(format!("… and {} more", notes.len() - keep));
    out
}

/// One line for the wire: the full `anyhow` chain (`{err:#}`), trimmed and
/// cut at `MAX_REASON_CHARS` with an ellipsis.
pub fn reason(err: &anyhow::Error) -> String {
    let full = format!("{err:#}");
    let full = full.trim();
    match full.char_indices().nth(MAX_REASON_CHARS) {
        Some((cut, _)) => format!("{}…", &full[..cut]),
        None => full.to_string(),
    }
}

/// Classify the daemon binary's location by its parent directory. After an
/// in-place replacement `/proc/self/exe` reads with a ` (deleted)` suffix,
/// which is stripped first so a running daemon keeps its kind across an
/// upgrade. Anything but the two known directories is `Unknown` — the branch
/// that never triggers an install offer.
pub fn install_kind_for(exe: &Path) -> InstallKind {
    let raw = exe.to_string_lossy();
    let path = raw.strip_suffix(" (deleted)").unwrap_or(raw.as_ref());
    match Path::new(path).parent().and_then(Path::to_str) {
        Some("/usr/bin") => InstallKind::Package,
        Some("/usr/local/bin") => InstallKind::Local,
        _ => InstallKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    fn err(msg: &str) -> anyhow::Error {
        anyhow!("{msg}")
    }

    #[test]
    fn fresh_state_is_quiet() {
        let h = HealthState::new(
            "/usr/local/bin/grepfocusd".into(),
            InstallKind::Local,
            vec!["note".into()],
        )
        .snapshot();
        assert_eq!(h.daemon_version, DAEMON_VERSION);
        assert_eq!(h.daemon_exe, "/usr/local/bin/grepfocusd");
        assert_eq!(h.install_kind, InstallKind::Local);
        assert_eq!(h.nft, NftStatus::NotApplicable);
        assert_eq!(h.hosts, HostsLockStatus::NotApplicable);
        assert_eq!(h.proxy, ProxyStatus::Off);
        assert_eq!(h.hosts_reapplies, 0);
        assert_eq!(h.nft_reinstalls, 0);
        assert!(h.browser_policies.is_empty());
        assert_eq!(h.startup_notes, vec!["note".to_string()]);
        assert_eq!(h.last_error, None);
        assert_eq!(h.last_error_unix, None);

        // The test daemon's shape: nothing known, version still stamped.
        let d = HealthState::default().snapshot();
        assert_eq!(d.daemon_version, DAEMON_VERSION);
        assert_eq!(d.daemon_exe, "");
        assert_eq!(d.install_kind, InstallKind::Unknown);
    }

    #[test]
    fn set_proxy_is_live() {
        let mut s = HealthState::default();
        s.set_proxy(ProxyStatus::Degraded);
        assert_eq!(s.snapshot().proxy, ProxyStatus::Degraded);
        s.set_proxy(ProxyStatus::Holding);
        assert_eq!(s.snapshot().proxy, ProxyStatus::Holding);
        s.set_proxy(ProxyStatus::Off);
        assert_eq!(s.snapshot().proxy, ProxyStatus::Off);
    }

    #[test]
    fn apply_succeeded_records_halves_and_clears_last_error() {
        let mut s = HealthState::default();
        s.apply_failed(&err("reading /etc/hosts: boom"), 50);
        assert!(s.snapshot().last_error.is_some());

        s.apply_succeeded(
            NftStatus::Failed {
                reason: "nft -f failed".into(),
            },
            HostsLockStatus::Unlocked {
                reason: "chattr +i failed".into(),
            },
        );
        let h = s.snapshot();
        assert_eq!(
            h.nft,
            NftStatus::Failed {
                reason: "nft -f failed".into()
            }
        );
        assert_eq!(
            h.hosts,
            HostsLockStatus::Unlocked {
                reason: "chattr +i failed".into()
            }
        );
        assert_eq!(h.last_error, None);
        assert_eq!(h.last_error_unix, None);

        s.apply_succeeded(NftStatus::Ok, HostsLockStatus::Locked);
        let h = s.snapshot();
        assert_eq!(h.nft, NftStatus::Ok);
        assert_eq!(h.hosts, HostsLockStatus::Locked);
    }

    #[test]
    fn apply_failed_sets_last_error_and_resets_halves_to_unknown() {
        let mut s = HealthState::default();
        s.apply_succeeded(NftStatus::Ok, HostsLockStatus::Locked);
        let e = err("writing /etc/hosts").context("applying hosts block");
        s.apply_failed(&e, 1234);
        let h = s.snapshot();
        assert_eq!(h.nft, NftStatus::Unknown);
        assert_eq!(h.hosts, HostsLockStatus::Unknown);
        assert_eq!(
            h.last_error.as_deref(),
            Some("applying hosts block: writing /etc/hosts")
        );
        assert_eq!(h.last_error_unix, Some(1234));
    }

    #[test]
    fn nft_reprobe_heals_breaks_and_counts_only_real_drift() {
        let mut s = HealthState::default();
        s.apply_succeeded(NftStatus::Ok, HostsLockStatus::Locked);

        // Table seen working, then gone (firewall reload), re-installed: drift.
        s.nft_reprobed(true, Ok(()));
        let h = s.snapshot();
        assert_eq!(h.nft, NftStatus::Ok);
        assert_eq!(h.nft_reinstalls, 1);

        // Re-install fails: Failed, never counted.
        let e = err("nft -f failed (status 1)");
        s.nft_reprobed(true, Err(&e));
        let h = s.snapshot();
        assert_eq!(
            h.nft,
            NftStatus::Failed {
                reason: "nft -f failed (status 1)".into()
            }
        );
        assert_eq!(h.nft_reinstalls, 1);

        // Healing a half broken since apply time is not drift.
        s.nft_reprobed(false, Ok(()));
        let h = s.snapshot();
        assert_eq!(h.nft, NftStatus::Ok);
        assert_eq!(h.nft_reinstalls, 1);

        // Still broken: stays Failed, still not counted.
        s.nft_reprobed(false, Err(&e));
        let h = s.snapshot();
        assert!(matches!(h.nft, NftStatus::Failed { .. }));
        assert_eq!(h.nft_reinstalls, 1);
    }

    #[test]
    fn stale_table_is_downgraded_when_no_table_can_exist() {
        let stale = || NftStatus::StaleTable {
            reason: "nft delete failed".into(),
        };
        // Fresh daemon (NotApplicable), idle union, broken nft: nothing to
        // leave behind.
        let mut s = HealthState::default();
        s.apply_succeeded(stale(), HostsLockStatus::NotApplicable);
        assert_eq!(s.snapshot().nft, NftStatus::NotApplicable);

        // After a failed install the table was never there either.
        s.apply_succeeded(
            NftStatus::Failed {
                reason: "no nft".into(),
            },
            HostsLockStatus::Locked,
        );
        s.apply_succeeded(stale(), HostsLockStatus::NotApplicable);
        assert_eq!(s.snapshot().nft, NftStatus::NotApplicable);

        // After Ok the table was live, so a failed delete really is stale.
        s.apply_succeeded(NftStatus::Ok, HostsLockStatus::Locked);
        s.apply_succeeded(stale(), HostsLockStatus::NotApplicable);
        assert_eq!(s.snapshot().nft, stale());
        // ... and stays stale across another idle apply.
        s.apply_succeeded(stale(), HostsLockStatus::NotApplicable);
        assert_eq!(s.snapshot().nft, stale());

        // After Unknown (apply failed mid-way) a table may exist: keep it.
        s.apply_failed(&err("hosts"), 1);
        s.apply_succeeded(stale(), HostsLockStatus::NotApplicable);
        assert_eq!(s.snapshot().nft, stale());
    }

    #[test]
    fn teardown_retry_heals_or_keeps_stale() {
        let mut s = HealthState::default();
        s.apply_succeeded(NftStatus::Ok, HostsLockStatus::Locked);
        s.apply_succeeded(
            NftStatus::StaleTable {
                reason: "first".into(),
            },
            HostsLockStatus::NotApplicable,
        );

        let e = err("nft delete failed (status 1): busy");
        s.teardown_retried(Err(&e));
        assert_eq!(
            s.snapshot().nft,
            NftStatus::StaleTable {
                reason: "nft delete failed (status 1): busy".into()
            }
        );

        s.teardown_retried(Ok(()));
        assert_eq!(s.snapshot().nft, NftStatus::NotApplicable);

        // A retry after the apply downgraded the stale table cannot bring it
        // back: the memo keeps retrying, the status stays quiet.
        s.teardown_retried(Err(&e));
        assert_eq!(s.snapshot().nft, NftStatus::NotApplicable);
    }

    #[test]
    fn hosts_drift_counter_increments_and_saturates() {
        let mut s = HealthState::default();
        s.hosts_drift_detected();
        s.hosts_drift_detected();
        assert_eq!(s.snapshot().hosts_reapplies, 2);
        s.hosts_reapplies = u32::MAX - 1;
        s.hosts_drift_detected();
        s.hosts_drift_detected();
        assert_eq!(s.snapshot().hosts_reapplies, u32::MAX);

        s.nft_reinstalls = u32::MAX;
        s.nft_reprobed(true, Ok(()));
        assert_eq!(s.snapshot().nft_reinstalls, u32::MAX);
    }

    #[test]
    fn install_kind_for_paths() {
        let k = |p: &str| install_kind_for(Path::new(p));
        assert_eq!(k("/usr/bin/grepfocusd"), InstallKind::Package);
        assert_eq!(k("/usr/local/bin/grepfocusd"), InstallKind::Local);
        assert_eq!(k("/usr/bin/grepfocusd (deleted)"), InstallKind::Package);
        assert_eq!(k("/usr/local/bin/grepfocusd (deleted)"), InstallKind::Local);
        assert_eq!(k("target/debug/grepfocusd"), InstallKind::Unknown);
        assert_eq!(k("/opt/grepfocus/grepfocusd"), InstallKind::Unknown);
        assert_eq!(k("/usr/local/bin"), InstallKind::Unknown);
        assert_eq!(k(""), InstallKind::Unknown);
    }

    #[test]
    fn reason_trims_and_caps() {
        assert_eq!(reason(&err("  spaced out \n")), "spaced out");
        let e = err("inner").context("middle").context("outer");
        assert_eq!(reason(&e), "outer: middle: inner");

        let long = "é".repeat(MAX_REASON_CHARS + 10);
        let r = reason(&err(&long));
        assert_eq!(r.chars().count(), MAX_REASON_CHARS + 1);
        assert!(r.ends_with('…'));
        assert!(r.starts_with(&"é".repeat(MAX_REASON_CHARS)));

        let exact = "x".repeat(MAX_REASON_CHARS);
        assert_eq!(reason(&err(&exact)), exact);
    }

    #[test]
    fn set_browser_policies_replaces_list() {
        let mut s = HealthState::default();
        let one = |browser: &str| BrowserPolicyStatus {
            browser: browser.into(),
            path: format!("/etc/{browser}/policies/policies.json"),
            state: grepfocus_core::BrowserPolicyState::Written,
            since_unix: 1,
        };
        s.set_browser_policies(vec![one("firefox"), one("chromium")]);
        assert_eq!(s.snapshot().browser_policies.len(), 2);
        s.set_browser_policies(vec![one("brave")]);
        let list = s.snapshot().browser_policies;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].browser, "brave");
        s.set_browser_policies(vec![]);
        assert!(s.snapshot().browser_policies.is_empty());
    }

    #[test]
    fn snapshot_caps_startup_notes() {
        let notes = |n: usize| (0..n).map(|i| format!("note {i}")).collect::<Vec<_>>();

        let exact = HealthState::new(String::new(), InstallKind::Unknown, notes(200)).snapshot();
        assert_eq!(exact.startup_notes.len(), 200);
        assert_eq!(exact.startup_notes[199], "note 199");

        let over = HealthState::new(String::new(), InstallKind::Unknown, notes(1000)).snapshot();
        assert_eq!(over.startup_notes.len(), 200);
        assert_eq!(over.startup_notes[198], "note 198");
        assert_eq!(over.startup_notes[199], "… and 801 more");

        let one_over = HealthState::new(String::new(), InstallKind::Unknown, notes(201)).snapshot();
        assert_eq!(one_over.startup_notes.len(), 200);
        assert_eq!(one_over.startup_notes[199], "… and 2 more");
    }
}
