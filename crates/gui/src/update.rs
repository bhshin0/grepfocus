//! The daily release check: once a day the GUI fetches
//! `https://grepfocus.com/downloads/latest.json` and compares its `version`
//! with `GUI_VERSION`. The version number is the only thing exchanged;
//! nothing is downloaded. The preference is GUI-local, per user
//! (`$XDG_CONFIG_HOME/grepfocus/update-check.json`), so the daemon never
//! sees it and uninstall never removes it.
//!
//! Layout: the pure parts first (parsing, cadence, texts, the link allowlist,
//! the AppImage environment scrub), then the on-disk preference and the
//! `Store` the commands in main.rs talk to, then the fetch, the checker task
//! and the launcher. `run_check` takes the fetch as a closure so the cadence
//! and state machine are tested without the network.
//!
//! Cadence: "due" means at least 24 h since the last *completed* check and
//! at least 1 h since the last attempt. A server reply or an unusable body
//! (404/5xx, HTML, oversize, TLS failure) completes a check and is recorded
//! in the file; only DNS/connect/timeout/io failures are transient — they
//! never touch the file and retry at the next hourly tick.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::version;

/// The website contract (docs/plans/hardening-health-updates.md §9).
/// `GREPFOCUS_UPDATE_URL` overrides it for a local stub.
pub const DEFAULT_URL: &str = "https://grepfocus.com/downloads/latest.json";
/// Links `open_url` will hand to the browser: the site itself, nothing else.
pub const LINK_ALLOWLIST: [&str; 2] = ["https://grepfocus.com/", "https://www.grepfocus.com/"];
pub const MAX_LINK_BYTES: usize = 2048;
/// The reply is a few hundred bytes; anything beyond this is not `latest.json`.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Steady state: one completed check per day per running GUI.
pub const CHECK_INTERVAL_SECS: u64 = 24 * 3600;
/// After a transient failure, or between two attempts of any kind.
pub const RETRY_INTERVAL_SECS: u64 = 3600;
/// Short GNOME sessions still get their check: it runs soon after launch
/// when due, not at the first hourly tick.
pub const FIRST_CHECK_DELAY: Duration = Duration::from_secs(3);
pub const TICK_SECS: u64 = 3600;
/// Spread a fleet's ticks so the origin never sees them on the hour.
pub const TICK_JITTER_SECS: u64 = 300;
/// The on-disk format version, written always and ignored on read.
pub const SCHEMA: u32 = 1;

// ─── Pure: the reply ────────────────────────────────────────────────────────

/// What we keep of `latest.json`. `version` is canonical semver text
/// (a leading `v` stripped); `notes_url` survives only when the allowlist
/// admits it, since it ends up in `xdg-open`'s argv.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Release {
    pub version: String,
    pub published: Option<String>,
    pub notes_url: Option<String>,
}

/// Tolerant of unknown fields and extra `downloads` keys; only `version`
/// is required, and it must parse as semver.
pub fn parse_latest(body: &[u8]) -> Result<Release, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let obj = value.as_object().ok_or("not a JSON object")?;
    let raw = obj
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("no version field")?;
    let version = version::parse_version(raw).ok_or_else(|| format!("bad version {raw:?}"))?;
    let string_field = |key: &str| {
        obj.get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Ok(Release {
        version: version.to_string(),
        published: string_field("published").filter(|s| s.len() <= 64),
        notes_url: string_field("notes_url").filter(|u| link_allowed(u)),
    })
}

/// One fetch, classified. Every variant but `Unreachable` completes a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchOutcome {
    Release(Release),
    /// 404 or 5xx: the site answered, it just has nothing for us (yet).
    NoInfo(u16),
    /// Any other reply we cannot use: HTML, oversize, a redirect off https.
    Unusable(String),
    /// The handshake failed: a wrong certificate, or a middlebox.
    Tls(String),
    /// DNS, connect, timeout, io: nothing reached the origin. Retried hourly.
    Unreachable(String),
}

impl FetchOutcome {
    /// The Settings-row tail after `Checked {when}: ` for a completed
    /// failure; `None` for a release or a transient failure.
    pub fn error_text(&self) -> Option<String> {
        match self {
            FetchOutcome::Release(_) | FetchOutcome::Unreachable(_) => None,
            FetchOutcome::NoInfo(status) => Some(format!(
                "grepfocus.com has no update information yet (HTTP {status})"
            )),
            FetchOutcome::Unusable(e) => Some(format!("unexpected reply from grepfocus.com ({e})")),
            FetchOutcome::Tls(e) => Some(format!(
                "secure connection to grepfocus.com failed ({e}) — a TLS-intercepting proxy?"
            )),
        }
    }
}

/// Which bucket a ureq error falls into. Transient (`Unreachable`) is the
/// narrow set that never reached the origin; a TLS failure did reach
/// something and is worth telling the user about once, not hourly.
pub fn classify(err: &ureq::Error) -> FetchOutcome {
    match err {
        ureq::Error::HostNotFound => FetchOutcome::Unreachable("host not found".to_string()),
        ureq::Error::ConnectionFailed => FetchOutcome::Unreachable("connection failed".to_string()),
        ureq::Error::Io(e) => classify_io(e),
        ureq::Error::Timeout(_) => {
            FetchOutcome::Unreachable(format!("timed out after {} s", FETCH_TIMEOUT.as_secs()))
        }
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => FetchOutcome::Tls(err.to_string()),
        other => FetchOutcome::Unusable(other.to_string()),
    }
}

/// An io error before or during the reply: the socket, not the site.
pub fn classify_io(e: &std::io::Error) -> FetchOutcome {
    use std::io::ErrorKind::*;
    let text = match e.kind() {
        ConnectionRefused | ConnectionReset | ConnectionAborted | NotConnected | BrokenPipe
        | UnexpectedEof | NetworkUnreachable | HostUnreachable | NetworkDown => {
            "connection failed".to_string()
        }
        TimedOut | WouldBlock => format!("timed out after {} s", FETCH_TIMEOUT.as_secs()),
        _ => e.to_string(),
    };
    FetchOutcome::Unreachable(text)
}

/// TLS is enforced (including for redirects) whenever the configured URL is
/// https; an `http://` override is the dev stub and is fetched as given.
pub fn https_only_for(url: &str) -> bool {
    url.get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
}

pub fn user_agent(ver: &str) -> String {
    format!("GrepFocus/{ver} (linux)")
}

// ─── Pure: cadence and texts ────────────────────────────────────────────────

/// A timestamp in the future (clock set back) counts as elapsed, so one
/// extra check happens rather than none until the clock catches up.
fn elapsed(now: u64, then: u64) -> u64 {
    if then > now {
        u64::MAX
    } else {
        now - then
    }
}

pub fn due(last_check: Option<u64>, last_attempt: Option<u64>, now: u64) -> bool {
    last_check.is_none_or(|t| elapsed(now, t) >= CHECK_INTERVAL_SECS)
        && last_attempt.is_none_or(|t| elapsed(now, t) >= RETRY_INTERVAL_SECS)
}

/// One hour plus 0–5 min of jitter drawn from `seed`.
pub fn tick_delay(seed: u64) -> Duration {
    Duration::from_secs(TICK_SECS + seed % (TICK_JITTER_SECS + 1))
}

/// "just now", "5 min ago", "3 h ago", "2 days ago".
pub fn fmt_when(now: u64, then: u64) -> String {
    let secs = now.saturating_sub(then);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => {
            let days = secs / 86_400;
            if days == 1 {
                "1 day ago".to_string()
            } else {
                format!("{days} days ago")
            }
        }
    }
}

/// Strictly newer, on the one version comparison the GUI has.
fn is_newer(latest: &str, current: &str) -> bool {
    match (
        version::parse_version(latest),
        version::parse_version(current),
    ) {
        (Some(l), Some(c)) => version::newer_than(&l, &c),
        _ => false,
    }
}

/// The Status-tab strip text, `None` unless `latest` is newer than
/// `current`. Under an AppImage it says where the service update comes
/// from, since replacing the file updates the GUI only.
pub fn notice_for(current: &str, latest: &Release, appimage: bool) -> Option<String> {
    if !is_newer(&latest.version, current) {
        return None;
    }
    let released = latest
        .published
        .as_deref()
        .map(|d| format!(" (released {d})"))
        .unwrap_or_default();
    let mut text = format!(
        "GrepFocus {} is available{released} — you have {current}.",
        latest.version
    );
    if appimage {
        text.push_str(
            " After replacing the AppImage, the Status tab will offer \"Update system service\".",
        );
    }
    Some(text)
}

// ─── Pure: the link allowlist and the AppImage environment scrub ────────────

/// Only the site, only https, spelled exactly — the value goes to
/// `xdg-open` as one argv element, so no control characters or spaces
/// either. Case-sensitive on purpose: `HTTPS://GREPFOCUS.COM/` is refused
/// rather than normalized.
pub fn link_allowed(url: &str) -> bool {
    url.len() <= MAX_LINK_BYTES
        && url.bytes().all(|b| (0x21..0x7f).contains(&b))
        && LINK_ALLOWLIST.iter().any(|p| url.starts_with(p))
}

/// Exported by AppRun for the bundled process only; no user value to keep.
const DROP_ALWAYS: [&str; 7] = [
    "APPDIR",
    "APPIMAGE",
    "ARGV0",
    "OWD",
    "GTK_THEME",
    "GDK_BACKEND",
    "PYTHONDONTWRITEBYTECODE",
];

/// Colon-separated lists AppRun prepends its own directories to. The user's
/// tail entries are kept in order — Flatpak browsers are found through
/// `XDG_DATA_DIRS`.
const PATH_LIST_VARS: [&str; 12] = [
    "PATH",
    "LD_LIBRARY_PATH",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
    "GTK_PATH",
    "GI_TYPELIB_PATH",
    "GSETTINGS_SCHEMA_DIR",
    "PYTHONPATH",
    "PERLLIB",
    "QT_PLUGIN_PATH",
    "GST_PLUGIN_SYSTEM_PATH",
    "GST_PLUGIN_SYSTEM_PATH_1_0",
];

/// When PATH is scrubbed away entirely (the user had none of their own).
const FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// `entry` is `appdir` itself or below it. A sibling mount such as
/// `/tmp/.mount_GrepFoXYZ2` is not.
fn under_appdir(entry: &[u8], appdir: &[u8]) -> bool {
    entry == appdir || (entry.starts_with(appdir) && entry.get(appdir.len()) == Some(&b'/'))
}

/// `appdir` occurs in `value` as a path (followed by `/`, `:` or the end).
fn mentions_appdir(value: &[u8], appdir: &[u8]) -> bool {
    if appdir.is_empty() || value.len() < appdir.len() {
        return false;
    }
    (0..=value.len() - appdir.len()).any(|i| {
        &value[i..i + appdir.len()] == appdir
            && matches!(value.get(i + appdir.len()), None | Some(b'/') | Some(b':'))
    })
}

/// The environment a browser launched from an AppImage should see: the
/// AppRun exports (bundled GTK, webkit, Python, the mount itself) removed,
/// the user's own values kept. Three rules, in order: `DROP_ALWAYS` is
/// dropped; a `PATH_LIST_VARS` entry keeps only the elements not under
/// `$APPDIR` (dropped when none remain); any other variable whose value
/// names `$APPDIR` is dropped.
pub fn scrub_env(vars: Vec<(OsString, OsString)>, appdir: &Path) -> Vec<(OsString, OsString)> {
    let mut appdir = appdir.as_os_str().as_bytes();
    while appdir.len() > 1 && appdir.ends_with(b"/") {
        appdir = &appdir[..appdir.len() - 1];
    }
    vars.into_iter()
        .filter_map(|(key, value)| {
            let name = key.to_str().unwrap_or("");
            if DROP_ALWAYS.contains(&name) {
                return None;
            }
            if PATH_LIST_VARS.contains(&name) {
                let kept: Vec<&[u8]> = value
                    .as_bytes()
                    .split(|b| *b == b':')
                    .filter(|e| !e.is_empty() && !under_appdir(e, appdir))
                    .collect();
                if kept.is_empty() {
                    return None;
                }
                return Some((key, OsStr::from_bytes(&kept.join(&b':')).to_os_string()));
            }
            if mentions_appdir(value.as_bytes(), appdir) {
                return None;
            }
            Some((key, value))
        })
        .collect()
}

/// `xdg-open <url>` with every stdio detached. Under an AppImage (`appdir`
/// given) the child gets the scrubbed environment instead of ours; setting
/// `PATH` on the `Command` also makes `xdg-open` itself resolve against the
/// scrubbed list rather than the mount's `usr/bin`.
pub fn launcher(url: &str, env: Vec<(OsString, OsString)>, appdir: Option<&Path>) -> Command {
    let mut cmd = Command::new("xdg-open");
    cmd.arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(appdir) = appdir {
        let mut scrubbed = scrub_env(env, appdir);
        if !scrubbed.iter().any(|(k, _)| k == "PATH") {
            scrubbed.push((OsString::from("PATH"), OsString::from(FALLBACK_PATH)));
        }
        cmd.env_clear().envs(scrubbed);
    }
    cmd
}

/// Open an allowlisted link in the user's browser. The child is reaped on
/// a detached thread: `xdg-open` returns as soon as the browser has the URL,
/// and nothing here needs its exit status.
pub fn open_link(url: &str) -> Result<(), String> {
    if !link_allowed(url) {
        return Err("Refused to open a link that is not on grepfocus.com.".to_string());
    }
    let appdir = std::env::var_os("APPIMAGE")
        .and(std::env::var_os("APPDIR"))
        .map(PathBuf::from);
    let mut cmd = launcher(url, std::env::vars_os().collect(), appdir.as_deref());
    let mut child = cmd.spawn().map_err(|e| {
        format!("Could not run xdg-open ({e}) — install xdg-utils, or open {url} yourself.")
    })?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

// ─── The preference file ────────────────────────────────────────────────────

/// What `update-check.json` holds. `#[serde(default)]` on the container:
/// a missing key reads as its default, an unknown one is ignored, and
/// `schema` is written for a future reader but never checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub schema: u32,
    pub enabled: bool,
    /// The disclosure strip has been rendered at least once.
    pub disclosed: bool,
    pub last_check_unix: Option<u64>,
    pub latest: Option<Release>,
    pub dismissed_version: Option<String>,
    /// The tail of the last completed check's Settings line, `None` after a
    /// check that produced a release.
    pub check_error: Option<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            schema: SCHEMA,
            enabled: true,
            disclosed: false,
            last_check_unix: None,
            latest: None,
            dismissed_version: None,
            check_error: None,
        }
    }
}

pub fn prefs_from_json(s: &str) -> Result<Prefs, String> {
    serde_json::from_str(s).map_err(|e| e.to_string())
}

/// `$XDG_CONFIG_HOME/grepfocus/update-check.json`, falling back to
/// `~/.config/…`; `None` with neither variable set.
pub fn config_path(xdg_config_home: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    let base = match xdg_config_home.filter(|v| !v.is_empty()) {
        Some(xdg) => PathBuf::from(xdg),
        None => PathBuf::from(home.filter(|v| !v.is_empty())?).join(".config"),
    };
    Some(base.join("grepfocus").join("update-check.json"))
}

pub struct Loaded {
    pub prefs: Prefs,
    /// The dedicated Settings line for a file that exists but cannot be
    /// used; checks are off for the session until the file is rewritten.
    pub persist_error: Option<String>,
}

/// A missing file is a fresh install (defaults, checks on). An existing
/// file that cannot be read or parsed fails closed rather than silently
/// re-enabling a check the user may have turned off.
pub fn load_prefs(path: &Path) -> Loaded {
    let fail_closed = |why: String| {
        Loaded {
        prefs: Prefs {
            enabled: false,
            ..Prefs::default()
        },
        persist_error: Some(format!(
            "The update-check preference file could not be read ({why}); checks are off for this session — turning them on rewrites it."
        )),
    }
    };
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded {
            prefs: Prefs::default(),
            persist_error: None,
        },
        Err(e) => fail_closed(e.to_string()),
        Ok(text) => match prefs_from_json(&text) {
            Ok(prefs) => Loaded {
                prefs,
                persist_error: None,
            },
            Err(e) => fail_closed(e),
        },
    }
}

/// Atomic write: `<file>.<pid>.tmp` then rename, directory 0700, file 0600
/// — the file records a preference and what the site last said, nothing
/// another user should read or be able to swap.
pub fn persist(path: &Path, prefs: &Prefs) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = path.parent().ok_or("preference path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("restricting {}: {e}", dir.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("preference path has no file name")?;
    let tmp = path.with_file_name(format!("{name}.{}.tmp", std::process::id()));
    let mut body = serde_json::to_string_pretty(&Prefs {
        schema: SCHEMA,
        ..prefs.clone()
    })
    .map_err(|e| e.to_string())?;
    body.push('\n');
    let written = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("writing {}: {e}", path.display()));
    }
    Ok(())
}

// ─── The store: what the Tauri commands and the checker share ───────────────

/// The frontend's view, from `get_update_info` and every mutating command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UpdateInfo {
    pub enabled: bool,
    pub disclosed: bool,
    /// `GUI_VERSION`.
    pub current: String,
    pub latest: Option<Release>,
    /// `latest` is newer than `current`.
    pub available: bool,
    /// `latest` is the version the user dismissed.
    pub dismissed: bool,
    pub checking: bool,
    pub last_check_unix: Option<u64>,
    /// The Settings row: `Not checked yet.` · `Checked {when}: …` ·
    /// `Could not reach grepfocus.com (…). Will retry.` · `Checking…`.
    pub status: String,
    /// The Status-tab strip, `None` unless a newer release is known,
    /// checks are on and it has not been dismissed. The frontend decides
    /// when to show it (never during a block or under the skew banner).
    pub notice: Option<String>,
    /// A separate line for the file, never mixed with fetch errors.
    pub persist_error: Option<String>,
}

struct Inner {
    prefs: Prefs,
    /// `None` when no config directory could be determined; checks are off.
    path: Option<PathBuf>,
    url: String,
    user_agent: String,
    current: String,
    appimage: bool,
    /// In memory only: a transient failure must not rewrite the file, but
    /// it still holds the hourly retry back.
    last_attempt_unix: Option<u64>,
    checking: bool,
    /// The last transient failure's line, cleared by any completed check.
    transient_error: Option<String>,
    persist_error: Option<String>,
}

impl Inner {
    fn persist(&mut self) {
        let Some(path) = &self.path else {
            return;
        };
        self.persist_error = persist(path, &self.prefs).err().map(|e| {
            format!("The update-check preference could not be saved ({e}); it will not survive a restart.")
        });
    }

    fn info(&self, now: u64) -> UpdateInfo {
        let latest = self.prefs.latest.clone();
        let available = latest
            .as_ref()
            .is_some_and(|l| is_newer(&l.version, &self.current));
        let dismissed = matches!(
            (&latest, &self.prefs.dismissed_version),
            (Some(l), Some(d)) if &l.version == d
        );
        let status = if self.checking {
            "Checking…".to_string()
        } else if let Some(e) = &self.transient_error {
            e.clone()
        } else {
            match self.prefs.last_check_unix {
                None => "Not checked yet.".to_string(),
                Some(t) => {
                    let when = fmt_when(now, t);
                    match (&self.prefs.check_error, &latest) {
                        (Some(e), _) => format!("Checked {when}: {e}"),
                        (None, Some(l)) if available => {
                            format!("Checked {when}: GrepFocus {} is available.", l.version)
                        }
                        _ => format!("Checked {when}: up to date ({}).", self.current),
                    }
                }
            }
        };
        let notice = if self.prefs.enabled && available && !dismissed {
            latest
                .as_ref()
                .and_then(|l| notice_for(&self.current, l, self.appimage))
        } else {
            None
        };
        UpdateInfo {
            enabled: self.prefs.enabled,
            disclosed: self.prefs.disclosed,
            current: self.current.clone(),
            latest,
            available,
            dismissed,
            checking: self.checking,
            last_check_unix: self.prefs.last_check_unix,
            status,
            notice,
            persist_error: self.persist_error.clone(),
        }
    }
}

/// Managed by Tauri (`app.manage`), read by the six commands and the
/// checker task. The lock is held for microseconds and never across the
/// fetch.
pub struct Store {
    inner: Mutex<Inner>,
}

impl Store {
    /// `path` is `config_path(..)`; `None` means no config directory, so
    /// the preference cannot be kept and checks stay off.
    pub fn open(path: Option<PathBuf>, url: String, current: &str, appimage: bool) -> Store {
        let (prefs, persist_error) = match &path {
            Some(p) => {
                let l = load_prefs(p);
                (l.prefs, l.persist_error)
            }
            None => (
                Prefs {
                    enabled: false,
                    ..Prefs::default()
                },
                Some(
                    "No config directory ($XDG_CONFIG_HOME or $HOME) — the update-check preference cannot be kept, so checks are off."
                        .to_string(),
                ),
            ),
        };
        Store {
            inner: Mutex::new(Inner {
                prefs,
                path,
                url,
                user_agent: user_agent(current),
                current: current.to_string(),
                appimage,
                last_attempt_unix: None,
                checking: false,
                transient_error: None,
                persist_error,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn info(&self, now: u64) -> UpdateInfo {
        self.lock().info(now)
    }

    /// The disclosure strip has been rendered; the file remembers so a
    /// relaunch shows no strip.
    pub fn acknowledge(&self, now: u64) -> UpdateInfo {
        let mut g = self.lock();
        if !g.prefs.disclosed {
            g.prefs.disclosed = true;
            g.persist();
        }
        g.info(now)
    }

    /// Turning checks on rewrites the file, which is also how a corrupt one
    /// (fail-closed at load) is repaired.
    pub fn set_enabled(&self, enabled: bool, now: u64) -> UpdateInfo {
        let mut g = self.lock();
        g.prefs.enabled = enabled;
        if !enabled {
            g.transient_error = None;
        }
        g.persist();
        g.info(now)
    }

    /// Dismisses the current `latest`; a newer one brings the strip back.
    pub fn dismiss(&self, now: u64) -> UpdateInfo {
        let mut g = self.lock();
        if let Some(v) = g.prefs.latest.as_ref().map(|l| l.version.clone()) {
            g.prefs.dismissed_version = Some(v);
            g.persist();
        }
        g.info(now)
    }
}

// ─── The check ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    Disabled,
    /// The strip has not been rendered yet: no network contact before it.
    Undisclosed,
    NotDue,
    InFlight,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckResult {
    Skipped(Skip),
    /// Recorded in the file (a release, or a completed failure).
    Completed,
    /// Transient; the file is untouched.
    Unreachable,
}

/// Decide and mark the attempt. `force` (the Settings button, or the toggle
/// going on) bypasses the cadence and the disclosure, never the switch.
fn begin_check(i: &mut Inner, now: u64, force: bool) -> Result<(), Skip> {
    if !i.prefs.enabled {
        return Err(Skip::Disabled);
    }
    if i.checking {
        return Err(Skip::InFlight);
    }
    if !force {
        if !i.prefs.disclosed {
            return Err(Skip::Undisclosed);
        }
        if !due(i.prefs.last_check_unix, i.last_attempt_unix, now) {
            return Err(Skip::NotDue);
        }
    }
    i.checking = true;
    i.last_attempt_unix = Some(now);
    Ok(())
}

/// Record the fetch. A completed check stamps `last_check_unix` and is
/// persisted; a transient failure only updates the in-memory line.
fn apply_outcome(i: &mut Inner, outcome: FetchOutcome, now: u64) -> CheckResult {
    i.checking = false;
    if let FetchOutcome::Unreachable(e) = outcome {
        i.transient_error = Some(format!("Could not reach grepfocus.com ({e}). Will retry."));
        return CheckResult::Unreachable;
    }
    i.transient_error = None;
    i.prefs.last_check_unix = Some(now);
    match outcome {
        FetchOutcome::Release(r) => {
            i.prefs.latest = Some(r);
            i.prefs.check_error = None;
        }
        other => i.prefs.check_error = other.error_text(),
    }
    i.persist();
    CheckResult::Completed
}

/// One attempt: decide under the lock, fetch without it, record under it.
/// `fetch` gets the URL and the User-Agent; production passes
/// `fetch_latest`, tests a closure.
pub fn run_check(
    store: &Store,
    now: u64,
    force: bool,
    fetch: impl FnOnce(&str, &str) -> FetchOutcome,
) -> CheckResult {
    let (url, ua) = {
        let mut g = store.lock();
        if let Err(skip) = begin_check(&mut g, now, force) {
            return CheckResult::Skipped(skip);
        }
        (g.url.clone(), g.user_agent.clone())
    };
    let outcome = fetch(&url, &ua);
    apply_outcome(&mut store.lock(), outcome, now)
}

/// The GET: no query string, no cookies (ureq has none without the
/// feature), redirects only over https when the URL is https, 10 s
/// overall, body capped at 64 KiB. 200 is the only status with a body we
/// read; 404 and 5xx are "nothing published", anything else is unusable.
pub fn fetch_latest(url: &str, user_agent: &str) -> FetchOutcome {
    let config = ureq::Agent::config_builder()
        .https_only(https_only_for(url))
        .http_status_as_error(false)
        .timeout_global(Some(FETCH_TIMEOUT))
        .max_redirects(3)
        .user_agent(user_agent)
        .accept("application/json")
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(e) => return classify(&e),
    };
    let status = resp.status().as_u16();
    if status == 404 || (500..600).contains(&status) {
        return FetchOutcome::NoInfo(status);
    }
    if status != 200 {
        return FetchOutcome::Unusable(format!("HTTP {status}"));
    }
    let mut body = Vec::new();
    let read = resp
        .body_mut()
        .as_reader()
        .take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut body);
    if let Err(e) = read {
        return classify_io(&e);
    }
    if body.len() > MAX_BODY_BYTES {
        return FetchOutcome::Unusable(format!("reply larger than {} KiB", MAX_BODY_BYTES / 1024));
    }
    match parse_latest(&body) {
        Ok(r) => FetchOutcome::Release(r),
        Err(e) => FetchOutcome::Unusable(e),
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn jitter_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    nanos ^ u64::from(std::process::id())
}

/// The fetch is blocking (ureq), so it runs off the async runtime.
async fn check_in_background(app: &AppHandle, force: bool) -> CheckResult {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let store = app.state::<Store>();
        run_check(&store, now_unix(), force, fetch_latest)
    })
    .await
    .unwrap_or(CheckResult::Skipped(Skip::InFlight))
}

/// The Settings button: a forced check, then the fresh view. `Err` only
/// when checks are off.
pub async fn check_now(app: &AppHandle) -> Result<UpdateInfo, String> {
    match check_in_background(app, true).await {
        CheckResult::Skipped(Skip::Disabled) => Err("Update checks are turned off.".to_string()),
        _ => Ok(app.state::<Store>().info(now_unix())),
    }
}

/// The disclosure strip has been rendered: record it, then run the check
/// the launch tick had to skip when the page acknowledged later than
/// `FIRST_CHECK_DELAY` — otherwise the first check would wait for the next
/// hourly tick. Not forced, so it is a no-op when the tick already ran or
/// nothing is due.
pub fn acknowledge_then_check(app: &AppHandle) -> UpdateInfo {
    let info = app.state::<Store>().acknowledge(now_unix());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        check_in_background(&app, false).await;
    });
    info
}

/// The background cadence: one due-check shortly after launch, then one
/// per hourly tick (each a no-op unless due).
pub fn spawn_checker(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_DELAY).await;
        loop {
            check_in_background(&app, false).await;
            tokio::time::sleep(tick_delay(jitter_seed())).await;
        }
    });
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Skip::Disabled => "disabled",
            Skip::Undisclosed => "undisclosed",
            Skip::NotDue => "not due",
            Skip::InFlight => "in flight",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const H: u64 = 3600;
    const D: u64 = 24 * H;

    fn release(v: &str) -> Release {
        Release {
            version: v.to_string(),
            published: Some("2026-10-01".to_string()),
            notes_url: Some("https://grepfocus.com/changelog".to_string()),
        }
    }

    fn store_in(dir: &Path, current: &str) -> (Store, PathBuf) {
        let path = dir.join("cfg").join("grepfocus").join("update-check.json");
        let store = Store::open(
            Some(path.clone()),
            "https://example.invalid/latest.json".to_string(),
            current,
            false,
        );
        (store, path)
    }

    fn disclosed(store: &Store) {
        store.lock().prefs.disclosed = true;
    }

    fn on_disk(path: &Path) -> Option<Prefs> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| prefs_from_json(&s).expect("valid file"))
    }

    // ── the reply ──

    #[test]
    fn parse_latest_is_tolerant() {
        let body = br#"{
          "schema": 1, "version": "v0.6.0", "published": "2026-10-01",
          "notes_url": "https://grepfocus.com/changelog",
          "downloads": {"rpm": {"url": "x"}, "rpm-fc45": {}},
          "future": [1, 2, 3]
        }"#;
        assert_eq!(parse_latest(body), Ok(release("0.6.0")));
        // Only version is required; a disallowed notes_url is dropped, not fatal.
        let sparse =
            br#"{"version": "0.6.0", "notes_url": "https://evil.example/x", "published": ""}"#;
        assert_eq!(
            parse_latest(sparse),
            Ok(Release {
                version: "0.6.0".to_string(),
                published: None,
                notes_url: None,
            })
        );
    }

    #[test]
    fn parse_latest_requires_a_version() {
        assert!(parse_latest(b"{}").is_err());
        assert!(parse_latest(br#"{"version": 6}"#).is_err());
        assert!(parse_latest(br#"{"version": "six"}"#).is_err());
        assert!(parse_latest(br#"{"version": "0.6"}"#).is_err());
        assert!(parse_latest(b"<html><body>404</body></html>").is_err());
        assert!(parse_latest(b"[]").is_err());
        assert!(parse_latest(b"").is_err());
    }

    #[test]
    fn classify_maps_ureq_errors() {
        let transient = |e: ureq::Error| matches!(classify(&e), FetchOutcome::Unreachable(_));
        assert!(transient(ureq::Error::HostNotFound));
        assert!(transient(ureq::Error::ConnectionFailed));
        assert!(transient(ureq::Error::Timeout(ureq::Timeout::Connect)));
        assert!(transient(ureq::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        ))));
        assert_eq!(
            classify(&ureq::Error::Io(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused
            ))),
            FetchOutcome::Unreachable("connection failed".to_string())
        );
        assert!(matches!(
            classify(&ureq::Error::Tls("invalid peer certificate")),
            FetchOutcome::Tls(e) if e.contains("invalid peer certificate")
        ));
        // Replies we cannot use complete the check.
        for e in [
            ureq::Error::TooManyRedirects,
            ureq::Error::RedirectFailed,
            ureq::Error::RequireHttpsOnly("http://grepfocus.com/x".to_string()),
            ureq::Error::BadUri("nope".to_string()),
            ureq::Error::StatusCode(500),
        ] {
            assert!(matches!(classify(&e), FetchOutcome::Unusable(_)), "{e}");
        }
        assert_eq!(
            FetchOutcome::NoInfo(404).error_text().as_deref(),
            Some("grepfocus.com has no update information yet (HTTP 404)")
        );
        assert!(FetchOutcome::Tls("x".to_string())
            .error_text()
            .unwrap()
            .ends_with("a TLS-intercepting proxy?"));
        assert_eq!(FetchOutcome::Release(release("1.0.0")).error_text(), None);
        assert_eq!(
            FetchOutcome::Unreachable("x".to_string()).error_text(),
            None
        );
    }

    #[test]
    fn https_only_for_scheme() {
        assert!(https_only_for(DEFAULT_URL));
        assert!(https_only_for("HTTPS://grepfocus.com/x"));
        assert!(!https_only_for("http://127.0.0.1:8099/latest.json"));
        assert!(!https_only_for(""));
        assert!(!https_only_for("https:/"));
    }

    #[test]
    fn user_agent_format() {
        assert_eq!(user_agent("0.5.1"), "GrepFocus/0.5.1 (linux)");
    }

    // ── cadence and texts ──

    #[test]
    fn due_matrix() {
        let now = 10 * D;
        // Never checked, never tried.
        assert!(due(None, None, now));
        // Checked a day ago, no attempt since: due.
        assert!(due(Some(now - D), None, now));
        // Checked an hour ago: not due, whatever the attempt.
        assert!(!due(Some(now - H), None, now));
        assert!(!due(Some(now - H), Some(now - H), now));
        // A day since the check but an attempt 10 min ago (transient
        // failure): hold off.
        assert!(!due(Some(now - D), Some(now - 600), now));
        assert!(due(Some(now - D), Some(now - H), now));
        // Never completed, tried 59 min ago: not yet.
        assert!(!due(None, Some(now - H + 60), now));
        // Timestamps in the future (clock set back) count as elapsed.
        assert!(due(Some(now + D), Some(now + H), now));
    }

    #[test]
    fn tick_delay_is_hourly_with_jitter() {
        for seed in [0, 1, 300, 301, 302, u64::MAX] {
            let d = tick_delay(seed).as_secs();
            assert!((3600..=3900).contains(&d), "seed {seed}: {d}");
        }
        assert_eq!(tick_delay(0).as_secs(), 3600);
        assert_eq!(tick_delay(300).as_secs(), 3900);
        assert_eq!(tick_delay(301).as_secs(), 3600);
    }

    #[test]
    fn fmt_when_buckets() {
        let now = 1_800_000_000;
        assert_eq!(fmt_when(now, now), "just now");
        assert_eq!(fmt_when(now, now + 5), "just now");
        assert_eq!(fmt_when(now, now - 59), "just now");
        assert_eq!(fmt_when(now, now - 60), "1 min ago");
        assert_eq!(fmt_when(now, now - 3599), "59 min ago");
        assert_eq!(fmt_when(now, now - 3600), "1 h ago");
        assert_eq!(fmt_when(now, now - D + 1), "23 h ago");
        assert_eq!(fmt_when(now, now - D), "1 day ago");
        assert_eq!(fmt_when(now, now - 3 * D), "3 days ago");
    }

    #[test]
    fn notice_for_newer_only() {
        assert_eq!(
            notice_for("0.5.1", &release("0.6.0"), false).as_deref(),
            Some("GrepFocus 0.6.0 is available (released 2026-10-01) — you have 0.5.1.")
        );
        let appimage = notice_for("0.5.1", &release("0.6.0"), true).unwrap();
        assert!(appimage.ends_with(
            " After replacing the AppImage, the Status tab will offer \"Update system service\"."
        ));
        let undated = Release {
            published: None,
            ..release("0.6.0")
        };
        assert_eq!(
            notice_for("0.5.1", &undated, false).as_deref(),
            Some("GrepFocus 0.6.0 is available — you have 0.5.1.")
        );
        // Equal, older, or unparseable on either side: nothing.
        assert_eq!(notice_for("0.6.0", &release("0.6.0"), true), None);
        assert_eq!(notice_for("0.7.0", &release("0.6.0"), true), None);
        assert_eq!(notice_for("dev", &release("0.6.0"), true), None);
        assert_eq!(notice_for("0.5.1", &release("latest"), true), None);
        // Numeric, not lexical.
        assert!(notice_for("0.9.9", &release("0.10.0"), false).is_some());
    }

    // ── the allowlist and the environment scrub ──

    #[test]
    fn link_allowed_rules() {
        assert!(link_allowed("https://grepfocus.com/"));
        assert!(link_allowed("https://grepfocus.com/download"));
        assert!(link_allowed("https://www.grepfocus.com/changelog#0.6.0"));
        assert!(!link_allowed("https://grepfocus.com"));
        assert!(!link_allowed("https://grepfocus.com.evil.com/"));
        assert!(!link_allowed("https://evil.com/https://grepfocus.com/"));
        assert!(!link_allowed("HTTPS://GREPFOCUS.COM/"));
        assert!(!link_allowed("http://grepfocus.com/"));
        assert!(!link_allowed("https://grepfocus.com/a b"));
        assert!(!link_allowed("https://grepfocus.com/a\nb"));
        assert!(!link_allowed(""));
        let long = format!("https://grepfocus.com/{}", "a".repeat(2048 - 22));
        assert_eq!(long.len(), 2048);
        assert!(link_allowed(&long));
        assert!(!link_allowed(&format!("{long}a")));
    }

    /// The environment AppRun (linuxdeploy + its GTK hook) and the AppImage
    /// runtime export, as extracted from the 0.5.0 AppImage.
    fn appimage_env() -> Vec<(OsString, OsString)> {
        let m = "/tmp/.mount_GrepFoXYZ";
        [
            ("APPDIR", m.to_string()),
            ("APPIMAGE", "/home/u/Downloads/GrepFocus_0.5.0_amd64.AppImage".to_string()),
            ("ARGV0", "./GrepFocus_0.5.0_amd64.AppImage".to_string()),
            ("OWD", "/home/u".to_string()),
            ("PATH", format!("{m}/usr/bin/:{m}/usr/sbin/:{m}/usr/games/:{m}/bin/:{m}/sbin/:/home/u/.local/bin:/usr/local/bin:/usr/bin")),
            ("LD_LIBRARY_PATH", format!("{m}/usr/lib/:{m}/usr/lib/i386-linux-gnu/:{m}/usr/lib/x86_64-linux-gnu/:{m}/usr/lib32/:{m}/usr/lib64/:{m}/lib/:{m}/lib/i386-linux-gnu/:{m}/lib/x86_64-linux-gnu/:{m}/lib32/:{m}/lib64/:")),
            ("PYTHONHOME", format!("{m}/usr/")),
            ("PYTHONPATH", format!("{m}/usr/share/pyshared/:")),
            ("PYTHONDONTWRITEBYTECODE", "1".to_string()),
            ("XDG_DATA_DIRS", format!("{m}/usr/share/:{m}/usr/share:/usr/share:/var/lib/flatpak/exports/share:/home/u/.local/share/flatpak/exports/share:/usr/local/share/:/usr/share/")),
            ("PERLLIB", format!("{m}/usr/share/perl5/:{m}/usr/lib/perl5/:")),
            ("GSETTINGS_SCHEMA_DIR", format!("{m}/usr/share/glib-2.0/schemas/:{m}//usr/share/glib-2.0/schemas")),
            ("QT_PLUGIN_PATH", format!("{m}/usr/lib/qt4/plugins/:{m}/usr/lib/qt5/plugins/:")),
            ("GST_PLUGIN_SYSTEM_PATH", format!("{m}/usr/lib/gstreamer:")),
            ("GST_PLUGIN_SYSTEM_PATH_1_0", format!("{m}/usr/lib/gstreamer-1.0:")),
            ("GTK_DATA_PREFIX", m.to_string()),
            ("GTK_THEME", "Adwaita:light".to_string()),
            ("GDK_BACKEND", "x11".to_string()),
            ("GTK_EXE_PREFIX", format!("{m}//usr")),
            ("GTK_PATH", format!("{m}//usr/lib/x86_64-linux-gnu/gtk-3.0:/usr/lib64/gtk-3.0:/usr/lib/x86_64-linux-gnu/gtk-3.0")),
            ("GTK_IM_MODULE_FILE", format!("{m}//usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules.cache")),
            ("GDK_PIXBUF_MODULE_FILE", format!("{m}//usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache")),
            ("GIO_EXTRA_MODULES", format!("{m}/usr/lib/x86_64-linux-gnu/gio/modules")),
            // Our own configure_appimage_webview_env.
            ("WEBKIT_EXEC_PATH", format!("{m}/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1")),
            ("WEBKIT_INJECTED_BUNDLE_PATH", format!("{m}/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/injected-bundle")),
            // The user's own session.
            ("HOME", "/home/u".to_string()),
            ("DISPLAY", ":0".to_string()),
            ("WAYLAND_DISPLAY", "wayland-0".to_string()),
            ("XDG_RUNTIME_DIR", "/run/user/1000".to_string()),
            ("LANG", "en_US.UTF-8".to_string()),
            // A sibling mount of another AppImage: not ours.
            ("OTHER_APP_LIB", format!("{m}2/usr/lib")),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
    }

    #[test]
    fn scrub_env_appimage_strings() {
        let out = scrub_env(appimage_env(), Path::new("/tmp/.mount_GrepFoXYZ/"));
        let get = |k: &str| {
            out.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.to_str().unwrap().to_string())
        };
        assert_eq!(
            get("PATH").as_deref(),
            Some("/home/u/.local/bin:/usr/local/bin:/usr/bin")
        );
        assert_eq!(
            get("XDG_DATA_DIRS").as_deref(),
            Some("/usr/share:/var/lib/flatpak/exports/share:/home/u/.local/share/flatpak/exports/share:/usr/local/share/:/usr/share/")
        );
        assert_eq!(
            get("GTK_PATH").as_deref(),
            Some("/usr/lib64/gtk-3.0:/usr/lib/x86_64-linux-gnu/gtk-3.0")
        );
        for gone in [
            "APPDIR",
            "APPIMAGE",
            "ARGV0",
            "OWD",
            "GTK_THEME",
            "GDK_BACKEND",
            "PYTHONDONTWRITEBYTECODE",
            "LD_LIBRARY_PATH",
            "PYTHONHOME",
            "PYTHONPATH",
            "PERLLIB",
            "GSETTINGS_SCHEMA_DIR",
            "QT_PLUGIN_PATH",
            "GST_PLUGIN_SYSTEM_PATH",
            "GST_PLUGIN_SYSTEM_PATH_1_0",
            "GTK_DATA_PREFIX",
            "GTK_EXE_PREFIX",
            "GTK_IM_MODULE_FILE",
            "GDK_PIXBUF_MODULE_FILE",
            "GIO_EXTRA_MODULES",
            "WEBKIT_EXEC_PATH",
            "WEBKIT_INJECTED_BUNDLE_PATH",
        ] {
            assert_eq!(get(gone), None, "{gone} should be scrubbed");
        }
        for kept in [
            "HOME",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "LANG",
        ] {
            assert!(get(kept).is_some(), "{kept} should survive");
        }
        assert_eq!(
            get("OTHER_APP_LIB").as_deref(),
            Some("/tmp/.mount_GrepFoXYZ2/usr/lib")
        );
        assert!(
            out.iter()
                .all(|(_, v)| !v.to_string_lossy().contains("mount_GrepFoXYZ/")),
            "no value may still point into the mount"
        );
        // Order of the kept tail is preserved (checked above by equality);
        // nothing new is invented.
        assert_eq!(out.len(), 3 + 5 + 1);
    }

    #[test]
    fn scrub_env_edge_cases() {
        let appdir = Path::new("/tmp/.mount_X");
        let vars = |pairs: &[(&str, &str)]| -> Vec<(OsString, OsString)> {
            pairs
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect()
        };
        // A PATH made only of mount entries disappears; empty elements go too.
        let out = scrub_env(vars(&[("PATH", "/tmp/.mount_X/usr/bin::")]), appdir);
        assert!(out.is_empty());
        // A pure override under the mount is dropped; elsewhere, kept.
        let out = scrub_env(
            vars(&[
                (
                    "GDK_PIXBUF_MODULE_FILE",
                    "/usr/lib64/gdk-pixbuf-2.0/loaders.cache",
                ),
                ("LD_PRELOAD", "/tmp/.mount_X/usr/lib/libfoo.so"),
                ("SOMETHING", "prefix:/tmp/.mount_X:suffix"),
                ("UNRELATED", "/tmp/.mount_XY/usr"),
            ]),
            appdir,
        );
        let keys: Vec<&str> = out.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert_eq!(keys, ["GDK_PIXBUF_MODULE_FILE", "UNRELATED"]);
    }

    #[test]
    fn launcher_shape() {
        let url = "https://grepfocus.com/changelog";
        // Native install: inherits the environment untouched.
        let cmd = launcher(url, appimage_env(), None);
        assert_eq!(cmd.get_program(), "xdg-open");
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), [url]);
        assert_eq!(cmd.get_envs().count(), 0);
        // AppImage: cleared and re-set from the scrub, PATH among them.
        let cmd = launcher(
            url,
            appimage_env(),
            Some(Path::new("/tmp/.mount_GrepFoXYZ")),
        );
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert!(envs.iter().all(|(k, _)| k != "APPDIR" && k != "PYTHONHOME"));
        let path = envs
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.clone());
        assert_eq!(
            path.as_deref(),
            Some("/home/u/.local/bin:/usr/local/bin:/usr/bin")
        );
        assert!(envs.iter().all(|(_, v)| !v.contains("mount_GrepFoXYZ/")));
        // With no PATH of the user's own, a sane default is supplied.
        let cmd = launcher(
            url,
            vec![(
                OsString::from("PATH"),
                OsString::from("/tmp/.mount_GrepFoXYZ/usr/bin"),
            )],
            Some(Path::new("/tmp/.mount_GrepFoXYZ")),
        );
        let path = cmd
            .get_envs()
            .find(|(k, _)| *k == "PATH")
            .and_then(|(_, v)| v)
            .map(|v| v.to_string_lossy().into_owned());
        assert_eq!(path.as_deref(), Some(FALLBACK_PATH));
    }

    // ── the preference file ──

    #[test]
    fn config_path_resolution() {
        assert_eq!(
            config_path(Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/xdg/grepfocus/update-check.json"))
        );
        assert_eq!(
            config_path(None, Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.config/grepfocus/update-check.json"))
        );
        // An empty XDG_CONFIG_HOME is unset (the spec's rule).
        assert_eq!(
            config_path(Some(OsStr::new("")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.config/grepfocus/update-check.json"))
        );
        assert_eq!(config_path(None, None), None);
        assert_eq!(config_path(None, Some(OsStr::new(""))), None);
    }

    #[test]
    fn prefs_from_json_accepts_any_schema() {
        let p = prefs_from_json(
            r#"{"schema": 9, "enabled": false, "disclosed": true, "last_check_unix": 5,
                "latest": {"version": "0.6.0", "extra": 1}, "dismissed_version": "0.6.0",
                "check_error": null, "unknown_key": {"a": 1}}"#,
        )
        .unwrap();
        assert_eq!(p.schema, 9);
        assert!(!p.enabled);
        assert!(p.disclosed);
        assert_eq!(p.last_check_unix, Some(5));
        assert_eq!(p.latest.as_ref().map(|l| l.version.as_str()), Some("0.6.0"));
        assert_eq!(p.dismissed_version.as_deref(), Some("0.6.0"));
        // Missing keys read as defaults: enabled on, undisclosed.
        let p = prefs_from_json("{}").unwrap();
        assert_eq!(p, Prefs::default());
        assert!(p.enabled && !p.disclosed);
        assert!(prefs_from_json("").is_err());
        assert!(prefs_from_json(r#"{"enabled": "yes"}"#).is_err());
    }

    #[test]
    fn load_prefs_garbage_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        // Missing: a fresh install.
        let l = load_prefs(&path);
        assert_eq!(l.prefs, Prefs::default());
        assert_eq!(l.persist_error, None);
        // Garbage: checks off, a dedicated line.
        std::fs::write(&path, "not json {").unwrap();
        let l = load_prefs(&path);
        assert!(!l.prefs.enabled);
        assert!(l
            .persist_error
            .as_deref()
            .unwrap()
            .starts_with("The update-check preference file could not be read ("));
        // A directory in its place is unreadable in the same way.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let l = load_prefs(&path);
        assert!(!l.prefs.enabled && l.persist_error.is_some());
    }

    #[test]
    fn store_persist_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store_in(dir.path(), "0.5.1");
        let now = 1_800_000_000;
        let info = store.info(now);
        assert!(info.enabled && !info.disclosed);
        assert_eq!(info.status, "Not checked yet.");
        assert_eq!(info.persist_error, None);
        assert!(!path.exists(), "nothing written until something changes");

        let info = store.acknowledge(now);
        assert!(info.disclosed);
        assert_eq!(info.persist_error, None);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let disk = on_disk(&path).unwrap();
        assert_eq!(disk.schema, SCHEMA);
        assert!(disk.disclosed && disk.enabled);
        assert!(std::fs::read_to_string(&path).unwrap().ends_with("}\n"));
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")),
            "no temp file left behind"
        );

        store.set_enabled(false, now);
        assert!(!on_disk(&path).unwrap().enabled);
        // A second store on the same file reads it all back.
        let (again, _) = store_in(dir.path(), "0.5.1");
        let info = again.info(now);
        assert!(!info.enabled && info.disclosed);
    }

    #[test]
    fn store_persist_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        // A file where the directory should be: create_dir_all fails.
        let blocker = dir.path().join("cfg");
        std::fs::write(&blocker, "").unwrap();
        let (store, _) = store_in(dir.path(), "0.5.1");
        let info = store.acknowledge(0);
        assert!(info.disclosed, "the in-memory state still advances");
        assert!(info
            .persist_error
            .as_deref()
            .unwrap()
            .starts_with("The update-check preference could not be saved ("));
        // A fetch failure is never folded into that line.
        assert_eq!(info.status, "Not checked yet.");
        // Repairing the directory clears it on the next write.
        std::fs::remove_file(&blocker).unwrap();
        let info = store.set_enabled(true, 0);
        assert_eq!(info.persist_error, None);
    }

    #[test]
    fn store_without_config_dir_is_off() {
        let store = Store::open(None, DEFAULT_URL.to_string(), "0.5.1", false);
        let info = store.info(0);
        assert!(!info.enabled);
        assert!(info.persist_error.unwrap().contains("No config directory"));
        assert_eq!(
            run_check(&store, 0, true, |_, _| panic!("no fetch")),
            CheckResult::Skipped(Skip::Disabled)
        );
    }

    // ── the check ──

    #[test]
    fn run_check_skips_disabled_and_undisclosed() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store_in(dir.path(), "0.5.1");
        let fetch = |_: &str, _: &str| panic!("must not fetch");
        assert_eq!(
            run_check(&store, D, false, fetch),
            CheckResult::Skipped(Skip::Undisclosed)
        );
        disclosed(&store);
        store.set_enabled(false, D);
        assert_eq!(
            run_check(&store, D, false, fetch),
            CheckResult::Skipped(Skip::Disabled)
        );
        // Force never overrides the switch.
        assert_eq!(
            run_check(&store, D, true, fetch),
            CheckResult::Skipped(Skip::Disabled)
        );
        assert_eq!(on_disk(&path).unwrap().last_check_unix, None);
    }

    #[test]
    fn run_check_force_bypasses_cadence() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store_in(dir.path(), "0.5.1");
        disclosed(&store);
        let ok = |_: &str, _: &str| FetchOutcome::Release(release("0.6.0"));
        assert_eq!(run_check(&store, D, false, ok), CheckResult::Completed);
        // An hour later: not due.
        assert_eq!(
            run_check(&store, D + H, false, ok),
            CheckResult::Skipped(Skip::NotDue)
        );
        // The button is.
        assert_eq!(run_check(&store, D + H, true, ok), CheckResult::Completed);
        assert_eq!(on_disk(&path).unwrap().last_check_unix, Some(D + H));
        // Undisclosed but forced: also runs (the button exists only after
        // the first render, which acknowledges).
        store.lock().prefs.disclosed = false;
        assert_eq!(
            run_check(&store, 2 * D + H, true, ok),
            CheckResult::Completed
        );
    }

    #[test]
    fn run_check_passes_url_and_user_agent() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = store_in(dir.path(), "0.5.1");
        disclosed(&store);
        let seen = std::cell::RefCell::new((String::new(), String::new()));
        let fetch = |url: &str, ua: &str| {
            *seen.borrow_mut() = (url.to_string(), ua.to_string());
            FetchOutcome::NoInfo(404)
        };
        run_check(&store, D, false, fetch);
        assert_eq!(
            *seen.borrow(),
            (
                "https://example.invalid/latest.json".to_string(),
                "GrepFocus/0.5.1 (linux)".to_string()
            )
        );
    }

    #[test]
    fn run_check_persists_release() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store_in(dir.path(), "0.5.1");
        disclosed(&store);
        let now = 5 * D;
        assert_eq!(
            run_check(&store, now, false, |_, _| FetchOutcome::Release(release(
                "0.6.0"
            ))),
            CheckResult::Completed
        );
        let disk = on_disk(&path).unwrap();
        assert_eq!(disk.last_check_unix, Some(now));
        assert_eq!(disk.latest, Some(release("0.6.0")));
        assert_eq!(disk.check_error, None);
        let info = store.info(now + 30);
        assert!(info.available && !info.dismissed && !info.checking);
        assert_eq!(
            info.status,
            "Checked just now: GrepFocus 0.6.0 is available."
        );
        assert_eq!(
            info.notice.as_deref(),
            Some("GrepFocus 0.6.0 is available (released 2026-10-01) — you have 0.5.1.")
        );
        // Dismiss: strip gone, row still says available, survives on disk.
        let info = store.dismiss(now + 30);
        assert!(info.dismissed && info.notice.is_none());
        assert_eq!(
            info.status,
            "Checked just now: GrepFocus 0.6.0 is available."
        );
        assert_eq!(
            on_disk(&path).unwrap().dismissed_version.as_deref(),
            Some("0.6.0")
        );
        // A newer release un-dismisses.
        run_check(&store, now + D, false, |_, _| {
            FetchOutcome::Release(release("0.6.1"))
        });
        let info = store.info(now + D);
        assert!(!info.dismissed && info.notice.is_some());
        // Turning checks off hides the notice without forgetting it.
        let info = store.set_enabled(false, now + D);
        assert!(info.notice.is_none() && info.latest.is_some());
    }

    #[test]
    fn run_check_up_to_date_and_no_info_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store_in(dir.path(), "0.5.1");
        disclosed(&store);
        run_check(&store, D, false, |_, _| {
            FetchOutcome::Release(release("0.5.1"))
        });
        let info = store.info(D + 2 * H);
        assert!(!info.available && info.notice.is_none());
        assert_eq!(info.status, "Checked 2 h ago: up to date (0.5.1).");

        // 404 completes the check and is remembered across a restart.
        assert_eq!(
            run_check(&store, 2 * D, false, |_, _| FetchOutcome::NoInfo(404)),
            CheckResult::Completed
        );
        let disk = on_disk(&path).unwrap();
        assert_eq!(disk.last_check_unix, Some(2 * D));
        assert_eq!(
            disk.check_error.as_deref(),
            Some("grepfocus.com has no update information yet (HTTP 404)")
        );
        let (again, _) = store_in(dir.path(), "0.5.1");
        assert_eq!(
            again.info(2 * D + 90).status,
            "Checked 1 min ago: grepfocus.com has no update information yet (HTTP 404)"
        );
        // So do an unusable body and a TLS failure.
        run_check(&store, 3 * D, false, |_, _| {
            FetchOutcome::Unusable("not JSON: expected value".to_string())
        });
        assert!(store
            .info(3 * D)
            .status
            .starts_with("Checked just now: unexpected reply from grepfocus.com ("));
        run_check(&store, 4 * D, false, |_, _| {
            FetchOutcome::Tls("rustls: invalid peer certificate".to_string())
        });
        assert_eq!(
            store.info(4 * D).status,
            "Checked just now: secure connection to grepfocus.com failed (rustls: invalid peer certificate) — a TLS-intercepting proxy?"
        );
        assert_eq!(on_disk(&path).unwrap().last_check_unix, Some(4 * D));
    }

    #[test]
    fn run_check_unreachable_not_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let (store, path) = store_in(dir.path(), "0.5.1");
        disclosed(&store);
        run_check(&store, D, false, |_, _| {
            FetchOutcome::Release(release("0.5.1"))
        });
        let before = std::fs::read_to_string(&path).unwrap();

        let now = 2 * D;
        assert_eq!(
            run_check(&store, now, false, |_, _| FetchOutcome::Unreachable(
                "connection failed".to_string()
            )),
            CheckResult::Unreachable
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(
            store.info(now).status,
            "Could not reach grepfocus.com (connection failed). Will retry."
        );
        // The attempt still holds the hourly retry back...
        assert_eq!(
            run_check(&store, now + 600, false, |_, _| panic!("too soon")),
            CheckResult::Skipped(Skip::NotDue)
        );
        // ...and an hour later the retry completes and clears the line.
        assert_eq!(
            run_check(&store, now + H, false, |_, _| FetchOutcome::Release(
                release("0.5.1")
            )),
            CheckResult::Completed
        );
        assert_eq!(
            store.info(now + H).status,
            "Checked just now: up to date (0.5.1)."
        );
        assert_ne!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn run_check_in_flight_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = store_in(dir.path(), "0.5.1");
        disclosed(&store);
        let nested = |_: &str, _: &str| {
            assert_eq!(
                run_check(&store, D, true, |_, _| panic!("nested fetch")),
                CheckResult::Skipped(Skip::InFlight)
            );
            assert_eq!(store.info(D).status, "Checking…");
            FetchOutcome::Release(release("0.5.1"))
        };
        assert_eq!(run_check(&store, D, false, nested), CheckResult::Completed);
        assert!(!store.info(D).checking);
    }

    // ── the fetch, against a loopback stub ──

    /// Answer the next connection on a loopback port with `reply`, verbatim.
    /// Returns the URL and a handle yielding the request head as received.
    fn serve_once(reply: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/latest.json", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
            }
            // The client may hang up before the whole body is written
            // (the oversize case), which is its point.
            let _ = stream.write_all(&reply);
            String::from_utf8_lossy(&head).into_owned()
        });
        (url, handle)
    }

    fn http_reply(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        reply.extend_from_slice(body);
        reply
    }

    #[test]
    fn fetch_latest_reads_a_release_and_sends_only_the_user_agent() {
        let body = br#"{"schema": 1, "version": "0.6.0", "published": "2026-10-01",
            "notes_url": "https://grepfocus.com/changelog"}"#;
        let (url, server) = serve_once(http_reply("200 OK", "application/json", body));
        assert_eq!(
            fetch_latest(&url, &user_agent("0.5.1")),
            FetchOutcome::Release(release("0.6.0"))
        );
        let head = server.join().unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /latest.json http/1.1\r\n"), "{head}");
        assert!(
            head.contains("\r\nuser-agent: grepfocus/0.5.1 (linux)\r\n"),
            "{head}"
        );
        assert!(head.contains("\r\naccept: application/json\r\n"), "{head}");
        assert!(!head.contains("cookie"), "{head}");
        assert!(!head.contains('?'), "{head}");
    }

    #[test]
    fn fetch_latest_classifies_replies() {
        for (status, code) in [("404 Not Found", 404), ("503 Service Unavailable", 503)] {
            let (url, server) = serve_once(http_reply(status, "text/html", b"<html>nope</html>"));
            assert_eq!(fetch_latest(&url, "t"), FetchOutcome::NoInfo(code));
            server.join().unwrap();
        }
        let (url, server) = serve_once(http_reply("403 Forbidden", "text/plain", b"no"));
        assert_eq!(
            fetch_latest(&url, "t"),
            FetchOutcome::Unusable("HTTP 403".to_string())
        );
        server.join().unwrap();

        let (url, server) = serve_once(http_reply("200 OK", "text/html", b"<html>hi</html>"));
        assert!(
            matches!(fetch_latest(&url, "t"), FetchOutcome::Unusable(e) if e.starts_with("not JSON"))
        );
        server.join().unwrap();

        let (url, server) = serve_once(http_reply("200 OK", "application/json", b"{}"));
        assert_eq!(
            fetch_latest(&url, "t"),
            FetchOutcome::Unusable("no version field".to_string())
        );
        server.join().unwrap();

        let big = vec![b' '; 300 * 1024];
        let (url, server) = serve_once(http_reply("200 OK", "application/json", &big));
        assert_eq!(
            fetch_latest(&url, "t"),
            FetchOutcome::Unusable("reply larger than 64 KiB".to_string())
        );
        server.join().unwrap();
    }

    #[test]
    fn fetch_latest_refused_connection_is_transient() {
        // Bind, note the port, close: nothing listens there now.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/latest.json", listener.local_addr().unwrap());
        drop(listener);
        assert_eq!(
            fetch_latest(&url, "t"),
            FetchOutcome::Unreachable("connection failed".to_string())
        );
    }

    #[test]
    fn info_shape_on_the_wire() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = store_in(dir.path(), "0.5.1");
        let v = serde_json::to_value(store.info(0)).unwrap();
        for key in [
            "enabled",
            "disclosed",
            "current",
            "latest",
            "available",
            "dismissed",
            "checking",
            "last_check_unix",
            "status",
            "notice",
            "persist_error",
        ] {
            assert!(v.get(key).is_some(), "{key}");
        }
        assert_eq!(v["current"], "0.5.1");
        assert_eq!(v["latest"], serde_json::Value::Null);
    }
}
