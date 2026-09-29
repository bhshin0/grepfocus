//! Browser DNS-over-HTTPS policies: the first line of defence against DoH
//! bypassing `/etc/hosts`.
//!
//! Firefox self-enrols in Mozilla's DoH rollout and Mullvad Browser ships
//! TRR-only DoH, so both resolve names without ever reading `/etc/hosts`.
//! Every browser we care about honours an enterprise policy that switches
//! DoH off at the source, so this module writes one — from daemon start,
//! unconditionally (free tier, no toggle), reconciled every `RECHECK` by its
//! own task rather than on the 1 s enforcement tick: Firefox reads policies
//! only when it starts, so writing at block start would be too late. The
//! `nftables` table stays as the backstop for browsers not restarted since
//! the write and for browsers this module does not cover.
//!
//! Ownership rules, because these files belong to the administrator first:
//! the Chromium family gets a file of its own (`grepfocus.json`; the name is
//! the marker). The Firefox family has one `policies.json` per install, so
//! ours is merged in — only `policies.DNSOverHTTPS` is set, every other key
//! is kept, and a top-level `grepfocus` object marks the file as touched. A
//! pre-existing file's exact bytes go to `paths::POLICY_ORIG_DIR` before the
//! first merge; removal restores them when nothing else changed since. A
//! file we created is deleted on removal, which lets a shadowed
//! `distribution/policies.json` apply again. Symlinks and invalid JSON are
//! refused, never rewritten.
//!
//! Every outcome is a `BrowserPolicyStatus` on `GetStatus.health`; nothing
//! here can fail the daemon. Stopping the daemon leaves the files in place:
//! `grepfocusd cleanup` (and the package/AppImage uninstall paths that run
//! it) removes or restores them, `packaging/uninstall.sh` carries a shell
//! mirror for the binary-already-gone case, and `managed_paths` is the one
//! list both are checked against.
//!
//! The decision core (`plan`, `build_firefox_policy`, `strip_firefox_policy`,
//! `transitions`, `fold_cleanup`) is pure; the IO layer is parametrised by a
//! `root` so the whole thing runs in a tempdir under test.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Context;
use grepfocus_core::{now_unix, BrowserPolicyFailKind, BrowserPolicyState, BrowserPolicyStatus};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{cleanup, health, hosts, paths, Daemon};

/// How often the policy files are re-checked. Cheap (seven stats and at most
/// two small reads when nothing changed), and a browser installed after
/// daemon start gets its policy within a minute.
pub const RECHECK: Duration = Duration::from_secs(60);

/// The whole Chromium-family file. Chromium applies every file in
/// `policies/managed` and the filename is what marks this one as ours.
const CHROMIUM_CONTENT: &str = "{\n  \"DnsOverHttpsMode\": \"off\"\n}\n";

/// Top-level key that marks a Firefox-family file as touched by us. Firefox
/// ignores every key but `policies`.
const MARKER_KEY: &str = "grepfocus";
const POLICIES_KEY: &str = "policies";
const DOH_KEY: &str = "DNSOverHTTPS";
/// Goes into the marker so whoever opens the file knows what happened and
/// how to undo it.
const NOTE: &str = "GrepFocus (grepfocusd) set policies.DNSOverHTTPS so /etc/hosts blocks \
    apply in this browser; every other key is yours. `grepfocusd cleanup` or uninstalling \
    GrepFocus removes the key again, restoring the pre-existing file from \
    /var/lib/grepfocus/policies when nothing else changed.";

const POLICY_MODE: u32 = 0o644;
const ORIG_MODE: u32 = 0o600;
const ORIG_DIR_MODE: u32 = 0o700;

/// Where a Flatpak Firefox would read a system policy from. Never written:
/// the extension mount is not something we manage yet (BACKLOG).
const FLATPAK_FIREFOX_POLICY: &str = "var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/x86_64/stable/policies/policies.json";

/// The browsers we know about, in the fixed order `browser_policies` is
/// reported in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Browser {
    Firefox,
    FirefoxFlatpak,
    Mullvad,
    Chromium,
    ChromiumSnap,
    Chrome,
    Brave,
}

impl Browser {
    pub const ALL: [Browser; 7] = [
        Browser::Firefox,
        Browser::FirefoxFlatpak,
        Browser::Mullvad,
        Browser::Chromium,
        Browser::ChromiumSnap,
        Browser::Chrome,
        Browser::Brave,
    ];

    /// The wire slug; the GUI maps it to a display name.
    pub fn slug(self) -> &'static str {
        match self {
            Browser::Firefox => "firefox",
            Browser::FirefoxFlatpak => "firefox-flatpak",
            Browser::Mullvad => "mullvad-browser",
            Browser::Chromium => "chromium",
            Browser::ChromiumSnap => "chromium-snap",
            Browser::Chrome => "chrome",
            Browser::Brave => "brave",
        }
    }

    fn format(self) -> Format {
        match self {
            Browser::Firefox | Browser::Mullvad => Format::Firefox,
            Browser::FirefoxFlatpak => Format::Unsupported,
            Browser::Chromium | Browser::ChromiumSnap | Browser::Chrome | Browser::Brave => {
                Format::Chromium
            }
        }
    }
}

/// Which policy dialect a target speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One shared `policies.json` we merge into.
    Firefox,
    /// A `grepfocus.json` of our own in a `managed` directory.
    Chromium,
    /// Detected but never written.
    Unsupported,
}

/// One browser's policy file and how to find the browser.
#[derive(Debug)]
pub struct Target {
    pub browser: Browser,
    /// Any of these existing means the browser is installed. Install trees,
    /// not `/usr/bin` launchers: a wrapper-only Mullvad tarball must not make
    /// us create `/usr/lib/mullvad-browser/distribution/`.
    probes: Vec<PathBuf>,
    /// The file we manage (or would manage), under `root`.
    file: PathBuf,
    /// Firefox only: the first existing one seeds a fresh `/etc` file, which
    /// shadows it while it exists.
    seeds: Vec<PathBuf>,
    /// Firefox family only: where a pre-existing file's bytes are kept.
    orig: Option<PathBuf>,
    /// Directories to `rmdir` (deepest first, non-recursive, best-effort)
    /// once the browser is gone and our file removed. Never a shared parent
    /// such as `/etc/opt` or `/usr/lib`.
    rmdir_chain: Vec<PathBuf>,
}

/// Every target in slug order. `root` is `/` in production; `orig_dir` is
/// `paths::POLICY_ORIG_DIR`. Both are parameters so tests run in a tempdir.
pub fn targets(root: &Path, orig_dir: &Path) -> Vec<Target> {
    Browser::ALL
        .iter()
        .map(|&browser| {
            let (probes, file, seeds, chain): (&[&str], &str, &[&str], &[&str]) = match browser {
                Browser::Firefox => (
                    &[
                        "usr/bin/firefox",
                        "usr/bin/firefox-esr",
                        "usr/lib64/firefox/firefox",
                        "usr/lib/firefox/firefox",
                        "usr/lib/firefox-esr/firefox-esr",
                        "opt/firefox/firefox",
                        "snap/bin/firefox",
                    ],
                    "etc/firefox/policies/policies.json",
                    &[
                        "usr/lib64/firefox/distribution/policies.json",
                        "usr/lib/firefox/distribution/policies.json",
                        "usr/lib/firefox-esr/distribution/policies.json",
                        "opt/firefox/distribution/policies.json",
                    ],
                    &["etc/firefox/policies", "etc/firefox"],
                ),
                Browser::FirefoxFlatpak => (
                    &["var/lib/flatpak/app/org.mozilla.firefox"],
                    FLATPAK_FIREFOX_POLICY,
                    &[],
                    &[],
                ),
                Browser::Mullvad => (
                    &[
                        "usr/lib/mullvad-browser/application.ini",
                        "usr/lib/mullvad-browser/mullvadbrowser",
                    ],
                    "usr/lib/mullvad-browser/distribution/policies.json",
                    &[],
                    &[
                        "usr/lib/mullvad-browser/distribution",
                        "usr/lib/mullvad-browser",
                    ],
                ),
                Browser::Chromium => (
                    &[
                        "usr/lib64/chromium-browser/chromium-browser",
                        "usr/lib/chromium/chromium",
                        "usr/lib/chromium-browser/chromium-browser",
                    ],
                    "etc/chromium/policies/managed/grepfocus.json",
                    &[],
                    &[
                        "etc/chromium/policies/managed",
                        "etc/chromium/policies",
                        "etc/chromium",
                    ],
                ),
                Browser::ChromiumSnap => (
                    &["var/snap/chromium/current"],
                    "var/snap/chromium/current/policies/managed/grepfocus.json",
                    &[],
                    &[
                        "var/snap/chromium/current/policies/managed",
                        "var/snap/chromium/current/policies",
                    ],
                ),
                Browser::Chrome => (
                    &["opt/google/chrome/chrome"],
                    "etc/opt/chrome/policies/managed/grepfocus.json",
                    &[],
                    &[
                        "etc/opt/chrome/policies/managed",
                        "etc/opt/chrome/policies",
                        "etc/opt/chrome",
                    ],
                ),
                Browser::Brave => (
                    &["opt/brave.com/brave/brave"],
                    "etc/brave/policies/managed/grepfocus.json",
                    &[],
                    &[
                        "etc/brave/policies/managed",
                        "etc/brave/policies",
                        "etc/brave",
                    ],
                ),
            };
            let join_all = |rels: &[&str]| rels.iter().map(|r| root.join(r)).collect::<Vec<_>>();
            Target {
                browser,
                probes: join_all(probes),
                file: root.join(file),
                seeds: join_all(seeds),
                orig: (browser.format() == Format::Firefox).then(|| orig_path_for(orig_dir, file)),
                rmdir_chain: join_all(chain),
            }
        })
        .collect()
}

/// Where the pre-existing bytes of the policy file at `rel` (root-relative,
/// no leading slash) are kept: one flat name per file, `/` → `_`.
pub fn orig_path_for(orig_dir: &Path, rel: &str) -> PathBuf {
    orig_dir.join(format!("_{}.orig", rel.replace('/', "_")))
}

/// Every file this module may create: the six policy files and the two
/// recovery copies. `cleanup` sweeps their `.grepfocus.tmp` orphans and a
/// test holds `packaging/uninstall.sh` to this list.
pub fn managed_paths(root: &Path, orig_dir: &Path) -> Vec<String> {
    let targets = targets(root, orig_dir);
    let files = targets
        .iter()
        .filter(|t| t.browser.format() != Format::Unsupported)
        .map(|t| t.file.to_string_lossy().into_owned());
    let origs = targets
        .iter()
        .filter_map(|t| t.orig.as_ref())
        .map(|p| p.to_string_lossy().into_owned());
    files.chain(origs).collect()
}

// ── Pure core ─────────────────────────────────────────────────────────────

/// Why a target could not be brought into line, as it goes on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fail {
    kind: BrowserPolicyFailKind,
    reason: String,
}

impl Fail {
    fn new(kind: BrowserPolicyFailKind, reason: impl Into<String>) -> Self {
        Fail {
            kind,
            reason: reason.into(),
        }
    }

    fn into_state(self) -> BrowserPolicyState {
        BrowserPolicyState::Failed {
            kind: self.kind,
            reason: self.reason,
        }
    }
}

/// What `reconcile_one` should do to the file.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Browser not installed: remove anything of ours.
    Remove,
    /// The file already reads exactly as we would write it.
    Unchanged { merged: bool },
    /// Write `content`. `merged` says the file carries someone else's keys
    /// too (reported `Merged`, not `Written`); `first_touch_of_foreign_file`
    /// says the current bytes are not ours at all and must be saved first.
    Write {
        content: String,
        merged: bool,
        first_touch_of_foreign_file: bool,
    },
}

/// A `distribution/policies.json` a fresh Firefox `/etc` file starts from.
#[derive(Clone, Copy, Debug)]
pub struct Seed<'a> {
    path: &'a str,
    bytes: &'a [u8],
}

/// Decide what to do for one target. Pure: `current` is the file's bytes
/// (`None` = absent), `seed` the distribution file (Firefox, used only when
/// creating). Symlink refusal and read errors happen before this, in the
/// caller.
pub fn plan(
    format: Format,
    installed: bool,
    current: Option<&[u8]>,
    seed: Option<Seed<'_>>,
) -> Result<Plan, Fail> {
    if !installed {
        return Ok(Plan::Remove);
    }
    match format {
        Format::Unsupported => Err(Fail::new(
            BrowserPolicyFailKind::Unsupported,
            "Flatpak Firefox reads system policies from the org.mozilla.firefox.systemconfig \
             extension, which GrepFocus does not manage; DoH stays on unless the nftables table \
             catches it",
        )),
        Format::Chromium => Ok(if current == Some(CHROMIUM_CONTENT.as_bytes()) {
            Plan::Unchanged { merged: false }
        } else {
            Plan::Write {
                content: CHROMIUM_CONTENT.to_string(),
                merged: false,
                first_touch_of_foreign_file: false,
            }
        }),
        Format::Firefox => {
            let existing = current.map(parse_policy_doc).transpose()?;
            let ours = existing.as_ref().is_some_and(has_marker);
            let foreign = existing.is_some() && !ours;
            // The seed matters only when we create the file; once it exists
            // the marker remembers where it came from.
            let seed = if existing.is_none() {
                seed.and_then(parse_seed)
            } else {
                None
            };
            let doc = build_firefox_policy(
                existing.as_ref(),
                seed.as_ref()
                    .map(|(path, policies)| (path.as_str(), policies)),
            );
            let merged = !marker_created(&doc);
            let content = render(&doc);
            Ok(if current == Some(content.as_bytes()) {
                Plan::Unchanged { merged }
            } else {
                Plan::Write {
                    content,
                    merged,
                    first_touch_of_foreign_file: foreign,
                }
            })
        }
    }
}

/// Parse a Firefox-family policy file. Anything but an object with an
/// object (or absent) `policies` key is refused: rewriting such a file could
/// only destroy what the administrator meant.
fn parse_policy_doc(bytes: &[u8]) -> Result<Value, Fail> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| {
        Fail::new(
            BrowserPolicyFailKind::NotJson,
            format!("not valid JSON: {e}"),
        )
    })?;
    let Some(obj) = doc.as_object() else {
        return Err(Fail::new(
            BrowserPolicyFailKind::NotJson,
            "top level is not a JSON object",
        ));
    };
    if obj.get(POLICIES_KEY).is_some_and(|p| !p.is_object()) {
        return Err(Fail::new(
            BrowserPolicyFailKind::NotJson,
            "\"policies\" is not a JSON object",
        ));
    }
    Ok(doc)
}

/// The seed's `policies` object, or `None` for a seed Firefox would ignore
/// anyway (not JSON, not an object). A seed without `policies` still counts
/// as seeded — our file shadows it either way.
fn parse_seed(seed: Seed<'_>) -> Option<(String, Map<String, Value>)> {
    let doc: Value = serde_json::from_slice(seed.bytes).ok()?;
    let obj = doc.as_object()?;
    let policies = match obj.get(POLICIES_KEY) {
        None => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return None,
    };
    Some((seed.path.to_string(), policies))
}

/// The merged document: `existing` (or the seed's `policies`, or nothing)
/// with `policies.DNSOverHTTPS` forced off and the marker refreshed. The
/// marker's `created` and `seeded_*` survive from an existing marker;
/// `managed` and `note` are always this build's. Idempotent over its own
/// output.
pub fn build_firefox_policy(
    existing: Option<&Value>,
    seed: Option<(&str, &Map<String, Value>)>,
) -> Value {
    let mut doc = match existing {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    let prev_marker = doc.remove(MARKER_KEY).and_then(|v| v.as_object().cloned());
    let mut policies = match doc.remove(POLICIES_KEY) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    let mut marker = Map::new();
    let created = match &prev_marker {
        Some(m) => m.get("created").and_then(Value::as_bool).unwrap_or(false),
        None => existing.is_none(),
    };
    if existing.is_none() {
        if let Some((path, seed_policies)) = seed {
            policies = seed_policies.clone();
            // Hashed without DNSOverHTTPS, i.e. exactly what a strip of the
            // seeded file leaves behind when nobody edited it.
            let mut hashed = seed_policies.clone();
            hashed.remove(DOH_KEY);
            marker.insert("seeded_from".into(), Value::String(path.to_string()));
            marker.insert(
                "seeded_sha256".into(),
                Value::String(sha256_hex(&render(&Value::Object(hashed)))),
            );
        }
    } else if let Some(m) = &prev_marker {
        for key in ["seeded_from", "seeded_sha256"] {
            if let Some(v) = m.get(key) {
                marker.insert(key.into(), v.clone());
            }
        }
    }
    policies.insert(DOH_KEY.into(), json!({ "Enabled": false, "Locked": true }));
    marker.insert("created".into(), Value::Bool(created));
    marker.insert("managed".into(), json!([DOH_KEY]));
    marker.insert("note".into(), Value::String(NOTE.into()));
    doc.insert(POLICIES_KEY.into(), Value::Object(policies));
    doc.insert(MARKER_KEY.into(), Value::Object(marker));
    Value::Object(doc)
}

/// What removing our part of a Firefox-family file leaves.
#[derive(Debug, PartialEq, Eq)]
pub enum Strip {
    /// No marker: not ours, never touched.
    NotOurs,
    /// We created it and nothing but our key (or the seed we copied) is
    /// left: delete, so a shadowed distribution file applies again.
    Delete,
    /// Someone else's keys remain: write this instead (or restore the
    /// recovery copy when the file is byte-identical to our merge of it).
    Rewrite(Value),
}

pub fn strip_firefox_policy(current: &Value) -> Strip {
    let Some(obj) = current.as_object() else {
        return Strip::NotOurs;
    };
    let Some(marker) = obj.get(MARKER_KEY).and_then(Value::as_object) else {
        return Strip::NotOurs;
    };
    let created = marker
        .get("created")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let seeded_sha = marker.get("seeded_sha256").and_then(Value::as_str);
    let mut doc = obj.clone();
    doc.remove(MARKER_KEY);
    let mut policies = match doc.remove(POLICIES_KEY) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    policies.remove(DOH_KEY);
    if created && doc.is_empty() {
        let seed_only =
            seeded_sha.is_some_and(|s| s == sha256_hex(&render(&Value::Object(policies.clone()))));
        if policies.is_empty() || seed_only {
            return Strip::Delete;
        }
    }
    doc.insert(POLICIES_KEY.into(), Value::Object(policies));
    Strip::Rewrite(Value::Object(doc))
}

pub fn has_marker(doc: &Value) -> bool {
    doc.get(MARKER_KEY).is_some_and(Value::is_object)
}

fn marker_created(doc: &Value) -> bool {
    doc.get(MARKER_KEY)
        .and_then(|m| m.get("created"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The canonical bytes of a document: pretty-printed with every object's
/// keys sorted, trailing newline. Explicit sorting because `serde_json`'s
/// map keeps insertion order when any crate in the build enables
/// `preserve_order` (the GUI's Tauri does), and the byte comparison that
/// decides "unchanged" must not depend on how the workspace was built.
pub fn render(doc: &Value) -> String {
    let mut out = serde_json::to_string_pretty(&sorted(doc)).expect("Value serializes");
    out.push('\n');
    out
}

fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), sorted(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Map a write/read failure to its wire kind: a read-only filesystem at the
/// root of the chain (Mullvad under a read-only `/usr`, an immutable
/// image) is not fixable from here and is reported as such; anything else
/// is `Io`.
pub fn classify_io(err: &anyhow::Error) -> Fail {
    let read_only = err
        .root_cause()
        .downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::ReadOnlyFilesystem);
    let kind = if read_only {
        BrowserPolicyFailKind::ReadOnlyFs
    } else {
        BrowserPolicyFailKind::Io
    };
    Fail::new(kind, health::reason(err))
}

fn fail_kind_label(kind: BrowserPolicyFailKind) -> &'static str {
    match kind {
        BrowserPolicyFailKind::Unsupported => "unsupported",
        BrowserPolicyFailKind::ReadOnlyFs => "read_only_fs",
        BrowserPolicyFailKind::NotJson => "not_json",
        BrowserPolicyFailKind::Symlink => "symlink",
        BrowserPolicyFailKind::Io => "io",
        BrowserPolicyFailKind::Unknown => "unknown",
    }
}

/// The journal spelling of a state; a failure carries its kind so a change
/// of failure kind counts as a transition.
fn state_label(state: &BrowserPolicyState) -> String {
    match state {
        BrowserPolicyState::NotInstalled => "not_installed".into(),
        BrowserPolicyState::Written => "written".into(),
        BrowserPolicyState::Merged => "merged".into(),
        BrowserPolicyState::Failed { kind, .. } => format!("failed:{}", fail_kind_label(*kind)),
        BrowserPolicyState::Unknown => "unknown".into(),
    }
}

/// The first-pass journal line: every browser and where it stands.
pub fn summary(list: &[BrowserPolicyStatus]) -> String {
    let parts: Vec<String> = list
        .iter()
        .map(|s| match s.state {
            BrowserPolicyState::NotInstalled => format!("{}={}", s.browser, state_label(&s.state)),
            _ => format!("{}={}({})", s.browser, state_label(&s.state), s.path),
        })
        .collect();
    format!("browser DoH policies: {}", parts.join(" "))
}

/// Journal lines for what changed between two passes: `(info, warn)`. A
/// change into a failure is the warning (with the reason, once per distinct
/// failure); every other change is one info line. Nothing for an entry
/// whose label is unchanged, so a steady state is silent.
pub fn transitions(
    prev: &[BrowserPolicyStatus],
    next: &[BrowserPolicyStatus],
) -> (Vec<String>, Vec<String>) {
    let mut info = Vec::new();
    let mut warns = Vec::new();
    for n in next {
        let old = prev.iter().find(|p| p.browser == n.browser);
        let old_label = old.map(|p| state_label(&p.state));
        let new_label = state_label(&n.state);
        if old_label.as_deref() == Some(new_label.as_str()) {
            continue;
        }
        match &n.state {
            BrowserPolicyState::Failed { kind, reason } => warns.push(format!(
                "browser DoH policy for {} failed ({}): {} — DoH may bypass blocks in that \
                 browser until this is fixed",
                n.browser,
                fail_kind_label(*kind),
                reason
            )),
            _ => info.push(format!(
                "browser DoH policy for {}: {} -> {} ({})",
                n.browser,
                old_label.as_deref().unwrap_or("none"),
                new_label,
                n.path
            )),
        }
    }
    (info, warns)
}

/// What a pass writes to the journal: `(info, warn)`. The first pass (no
/// `prev`; also the one after a daemon restart) gets the summary line in
/// place of a `none -> <state>` line per browser, but its failures are
/// warned about like any later ones, so a policy that has been failing
/// since install still gets its reason logged.
pub fn pass_lines(
    prev: &[BrowserPolicyStatus],
    next: &[BrowserPolicyStatus],
) -> (Vec<String>, Vec<String>) {
    let (info, warns) = transitions(prev, next);
    if prev.is_empty() {
        (vec![summary(next)], warns)
    } else {
        (info, warns)
    }
}

/// Keep `since_unix` from the previous pass for an entry whose state label
/// did not change. `Written`/`Merged` are excluded: their value is the
/// file's mtime, which is authoritative and survives daemon restarts.
pub fn carry_since(prev: &[BrowserPolicyStatus], next: &mut [BrowserPolicyStatus]) {
    for n in next.iter_mut() {
        if matches!(
            n.state,
            BrowserPolicyState::Written | BrowserPolicyState::Merged
        ) {
            continue;
        }
        if let Some(p) = prev.iter().find(|p| p.browser == n.browser) {
            if state_label(&p.state) == state_label(&n.state) {
                n.since_unix = p.since_unix;
            }
        }
    }
}

// ── Thin IO ───────────────────────────────────────────────────────────────

/// One pass over every target.
pub fn reconcile(targets: &[Target], now: u64) -> Vec<BrowserPolicyStatus> {
    targets.iter().map(|t| reconcile_one(t, now)).collect()
}

/// Bring one target's file into line and report where it stands. Every
/// error becomes a `Failed` status for this target alone.
fn reconcile_one(t: &Target, now: u64) -> BrowserPolicyStatus {
    let path = t.file.to_string_lossy().into_owned();
    let status = |state: BrowserPolicyState, since: u64| BrowserPolicyStatus {
        browser: t.browser.slug().into(),
        path: path.clone(),
        state,
        since_unix: since,
    };

    let installed = t.probes.iter().any(|p| fs::symlink_metadata(p).is_ok());
    if !installed {
        match remove_one(t) {
            RemoveOutcome::Absent | RemoveOutcome::NotOurs => {}
            RemoveOutcome::Failed { reason, .. } => {
                warn!(browser = t.browser.slug(), path = %path, %reason, "could not remove the DoH policy of a browser that is no longer installed");
            }
            done => {
                info!(browser = t.browser.slug(), path = %path, ?done, "browser no longer installed — DoH policy removed");
            }
        }
        rmdir_chain(t);
        return status(BrowserPolicyState::NotInstalled, now);
    }

    let current = match read_regular(&t.file) {
        Ok(c) => c,
        Err(f) => return status(f.into_state(), now),
    };
    let seed = if current.is_none() {
        read_seed(t)
    } else {
        None
    };
    let plan = plan(
        t.browser.format(),
        true,
        current.as_deref(),
        seed.as_ref().map(|(p, b)| Seed { path: p, bytes: b }),
    );
    let (merged, wrote) = match plan {
        Err(f) => return status(f.into_state(), now),
        Ok(Plan::Remove) => return status(BrowserPolicyState::NotInstalled, now),
        Ok(Plan::Unchanged { merged }) => {
            reassert_mode(&t.file);
            (merged, false)
        }
        Ok(Plan::Write {
            content,
            merged,
            first_touch_of_foreign_file,
        }) => {
            if first_touch_of_foreign_file {
                // The recovery copy is what makes the merge reversible, so a
                // failure to keep it means no merge at all.
                let bytes = current.as_deref().unwrap_or_default();
                if let Err(e) = save_orig(t, bytes) {
                    return status(classify_io(&e).into_state(), now);
                }
            } else if !merged {
                // A fresh file has no predecessor; a copy left from an
                // earlier merge (the admin deleted their file since) would
                // restore something they removed on purpose.
                remove_orig(t);
            }
            if let Err(e) = write_policy(&t.file, &content) {
                return status(classify_io(&e).into_state(), now);
            }
            (merged, true)
        }
    };
    if wrote {
        info!(browser = t.browser.slug(), path = %path, merged, "wrote browser DoH policy");
    } else {
        debug!(browser = t.browser.slug(), path = %path, merged, "browser DoH policy unchanged");
    }
    let state = if merged {
        BrowserPolicyState::Merged
    } else {
        BrowserPolicyState::Written
    };
    status(state, mtime_unix(&t.file).unwrap_or(now))
}

/// The file's bytes, `None` when absent. A symlink is refused outright: we
/// would be rewriting whatever it points at.
fn read_regular(path: &Path) -> Result<Option<Vec<u8>>, Fail> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(classify_io(
                &anyhow::Error::new(e).context(format!("stat {}", path.display())),
            ))
        }
    };
    if meta.file_type().is_symlink() {
        return Err(Fail::new(
            BrowserPolicyFailKind::Symlink,
            format!("{} is a symlink — refusing to manage it", path.display()),
        ));
    }
    if !meta.is_file() {
        return Err(Fail::new(
            BrowserPolicyFailKind::Io,
            format!("{} is not a regular file", path.display()),
        ));
    }
    fs::read(path).map(Some).map_err(|e| {
        classify_io(&anyhow::Error::new(e).context(format!("reading {}", path.display())))
    })
}

fn read_seed(t: &Target) -> Option<(String, Vec<u8>)> {
    t.seeds.iter().find_map(|p| {
        let bytes = fs::read(p).ok()?;
        Some((p.to_string_lossy().into_owned(), bytes))
    })
}

fn write_policy(path: &Path, content: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    hosts::write_atomic(&path.to_string_lossy(), content, POLICY_MODE)
}

fn save_orig(t: &Target, bytes: &[u8]) -> anyhow::Result<()> {
    let Some(orig) = &t.orig else {
        return Ok(());
    };
    if let Some(dir) = orig.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(ORIG_DIR_MODE))
            .with_context(|| format!("setting mode on {}", dir.display()))?;
    }
    // Parsed as JSON before we got here, so the bytes are UTF-8.
    let content = String::from_utf8_lossy(bytes);
    hosts::write_atomic(&orig.to_string_lossy(), &content, ORIG_MODE)
}

fn remove_orig(t: &Target) {
    if let Some(orig) = &t.orig {
        match fs::remove_file(orig) {
            Ok(()) => debug!(path = %orig.display(), "removed stale policy recovery copy"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!(path = %orig.display(), ?e, "could not remove policy recovery copy"),
        }
    }
}

/// An unchanged file still gets its mode and owner re-asserted: a policy
/// file the browser cannot read is a policy that does not apply. Owner only
/// when running as root — the tests are not. Never touches directories.
fn reassert_mode(path: &Path) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.permissions().mode() & 0o7777 != POLICY_MODE {
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(POLICY_MODE)) {
            warn!(path = %path.display(), ?e, "could not re-assert policy file mode");
        }
    }
    if nix::unistd::Uid::effective().is_root() && (meta.uid() != 0 || meta.gid() != 0) {
        if let Err(e) = std::os::unix::fs::chown(path, Some(0), Some(0)) {
            warn!(path = %path.display(), ?e, "could not re-assert policy file owner");
        }
    }
}

fn mtime_unix(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

/// Remove empty directories we may have created, deepest first. Stops at
/// the first one that is not empty (its parents cannot be either); a
/// missing one is skipped.
fn rmdir_chain(t: &Target) {
    for dir in &t.rmdir_chain {
        match fs::remove_dir(dir) {
            Ok(()) => debug!(path = %dir.display(), "removed empty policy directory"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => break,
        }
    }
}

/// What removing one target's file did.
#[derive(Debug, PartialEq, Eq)]
pub enum RemoveOutcome {
    Absent,
    Removed,
    /// Pre-existing file put back byte-exact from the recovery copy.
    Restored,
    /// Our keys stripped, the rest kept (edited since the merge, so the
    /// recovery copy no longer describes it).
    Rewritten,
    /// No marker (or a symlink, or not JSON): never touched.
    NotOurs,
    Failed {
        reason: String,
        /// The recovery copy still on disk, when one exists — the reason
        /// `cleanup --purge` must not delete the state dir.
        surviving_orig: Option<String>,
    },
}

/// Remove our part of every target, installed or not. Used by
/// `grepfocusd cleanup`; the not-installed path of `reconcile_one` uses
/// `remove_one` directly.
pub fn remove_all(targets: &[Target]) -> Vec<(Browser, RemoveOutcome)> {
    targets.iter().map(|t| (t.browser, remove_one(t))).collect()
}

fn remove_one(t: &Target) -> RemoveOutcome {
    let path = &t.file;
    let surviving = || {
        t.orig
            .as_ref()
            .filter(|o| o.exists())
            .map(|o| o.to_string_lossy().into_owned())
    };
    let failed = |e: anyhow::Error| RemoveOutcome::Failed {
        reason: health::reason(&e),
        surviving_orig: surviving(),
    };
    match t.browser.format() {
        Format::Unsupported => RemoveOutcome::Absent,
        Format::Chromium => match fs::remove_file(path) {
            Ok(()) => RemoveOutcome::Removed,
            Err(e) if e.kind() == io::ErrorKind::NotFound => RemoveOutcome::Absent,
            Err(e) => failed(anyhow::Error::new(e).context(format!("removing {}", path.display()))),
        },
        Format::Firefox => {
            let meta = match fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return RemoveOutcome::Absent,
                Err(e) => {
                    return failed(
                        anyhow::Error::new(e).context(format!("stat {}", path.display())),
                    )
                }
            };
            if meta.file_type().is_symlink() || !meta.is_file() {
                return RemoveOutcome::NotOurs;
            }
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    return failed(
                        anyhow::Error::new(e).context(format!("reading {}", path.display())),
                    )
                }
            };
            let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
                return RemoveOutcome::NotOurs;
            };
            match strip_firefox_policy(&doc) {
                Strip::NotOurs => RemoveOutcome::NotOurs,
                Strip::Delete => {
                    if let Err(e) = fs::remove_file(path) {
                        return failed(
                            anyhow::Error::new(e).context(format!("removing {}", path.display())),
                        );
                    }
                    remove_orig(t);
                    RemoveOutcome::Removed
                }
                Strip::Rewrite(stripped) => {
                    if let Some(orig_bytes) = t.orig.as_ref().and_then(|o| fs::read(o).ok()) {
                        // Byte-exact restore only when the live file is still
                        // exactly our merge of the copy: any edit since is the
                        // administrator's and survives via the stripped write.
                        let untouched = serde_json::from_slice::<Value>(&orig_bytes)
                            .ok()
                            .map(|orig| render(&build_firefox_policy(Some(&orig), None)))
                            .is_some_and(|merge| merge.as_bytes() == bytes.as_slice());
                        if untouched {
                            let content = String::from_utf8_lossy(&orig_bytes);
                            if let Err(e) =
                                hosts::write_atomic(&path.to_string_lossy(), &content, POLICY_MODE)
                            {
                                return failed(e.context(format!(
                                    "restoring {} from its recovery copy",
                                    path.display()
                                )));
                            }
                            remove_orig(t);
                            return RemoveOutcome::Restored;
                        }
                    }
                    if let Err(e) = hosts::write_atomic(
                        &path.to_string_lossy(),
                        &render(&stripped),
                        POLICY_MODE,
                    ) {
                        return failed(e.context(format!("rewriting {}", path.display())));
                    }
                    remove_orig(t);
                    RemoveOutcome::Rewritten
                }
            }
        }
    }
}

/// Fold `remove_all`'s results into one cleanup step, plus the recovery
/// copies a failed restore left behind (the purge gate's input).
pub fn fold_cleanup(results: &[(Browser, RemoveOutcome)]) -> (cleanup::Outcome, Vec<String>) {
    let mut done = Vec::new();
    let mut failed = Vec::new();
    let mut not_ours = Vec::new();
    let mut surviving = Vec::new();
    for (browser, outcome) in results {
        let slug = browser.slug();
        match outcome {
            RemoveOutcome::Absent => {}
            RemoveOutcome::Removed => done.push(format!("{slug}: removed")),
            RemoveOutcome::Restored => done.push(format!("{slug}: restored from recovery copy")),
            RemoveOutcome::Rewritten => done.push(format!("{slug}: our keys stripped")),
            RemoveOutcome::NotOurs => not_ours.push(slug),
            RemoveOutcome::Failed {
                reason,
                surviving_orig,
            } => {
                failed.push(format!("{slug}: {reason}"));
                if let Some(o) = surviving_orig {
                    surviving.push(o.clone());
                }
            }
        }
    }
    let outcome = if !failed.is_empty() {
        let mut msg = failed.join("; ");
        if !surviving.is_empty() {
            msg.push_str(&format!(
                " — recovery copies kept: {}",
                surviving.join(", ")
            ));
        }
        cleanup::Outcome::Failed(msg)
    } else if done.is_empty() {
        cleanup::Outcome::Skipped(if not_ours.is_empty() {
            "none present".into()
        } else {
            format!(
                "none of ours present ({} not managed by GrepFocus)",
                not_ours.join(", ")
            )
        })
    } else {
        cleanup::Outcome::Done(done.join(", "))
    };
    (outcome, surviving)
}

// ── Task ──────────────────────────────────────────────────────────────────

/// The reconcile loop: `procwatch::run`'s shape (interval, skip missed
/// ticks, blocking work off the runtime). The first tick fires at once, so
/// the policies are in place before the GUI's first status poll.
pub async fn run(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(RECHECK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let targets = Arc::new(targets(Path::new("/"), Path::new(paths::POLICY_ORIG_DIR)));
    let mut prev: Vec<BrowserPolicyStatus> = Vec::new();
    loop {
        ticker.tick().await;
        let now = now_unix();
        let pass = targets.clone();
        let mut next = match tokio::task::spawn_blocking(move || reconcile(&pass, now)).await {
            Ok(list) => list,
            Err(e) => {
                warn!(?e, "browser policy pass panicked");
                continue;
            }
        };
        carry_since(&prev, &mut next);
        let (info_lines, warn_lines) = pass_lines(&prev, &next);
        if info_lines.is_empty() && warn_lines.is_empty() {
            debug!("browser DoH policies unchanged");
        }
        for line in info_lines {
            info!("{line}");
        }
        for line in warn_lines {
            warn!("{line}");
        }
        daemon.health().set_browser_policies(next.clone());
        prev = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grepfocus_core::BrowserPolicyFailKind::{Io, NotJson, ReadOnlyFs, Symlink, Unsupported};
    use grepfocus_core::BrowserPolicyState::{Merged, NotInstalled, Written};
    use tempfile::TempDir;

    const NOW: u64 = 1_790_000_000;
    const SCRIPT: &str = include_str!("../../../packaging/uninstall.sh");

    /// A fake `/` with the recovery dir where production keeps it.
    struct Fixture {
        dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn root(&self) -> &Path {
            self.dir.path()
        }
        fn orig_dir(&self) -> PathBuf {
            self.root().join("var/lib/grepfocus/policies")
        }
        fn path(&self, rel: &str) -> PathBuf {
            self.root().join(rel)
        }
        fn targets(&self) -> Vec<Target> {
            targets(self.root(), &self.orig_dir())
        }
        fn target(&self, b: Browser) -> Target {
            self.targets().into_iter().find(|t| t.browser == b).unwrap()
        }
        fn write(&self, rel: &str, content: &str) -> PathBuf {
            let p = self.path(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, content).unwrap();
            p
        }
        fn touch(&self, rel: &str) -> PathBuf {
            self.write(rel, "")
        }
        fn read(&self, rel: &str) -> String {
            fs::read_to_string(self.path(rel)).unwrap()
        }
        fn reconcile(&self, b: Browser) -> BrowserPolicyStatus {
            reconcile_one(&self.target(b), NOW)
        }
        fn remove(&self, b: Browser) -> RemoveOutcome {
            remove_all(&self.targets())
                .into_iter()
                .find(|(browser, _)| *browser == b)
                .unwrap()
                .1
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn doc(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn policies_of(v: &Value) -> Map<String, Value> {
        v[POLICIES_KEY].as_object().unwrap().clone()
    }

    fn st(browser: &str, state: BrowserPolicyState) -> BrowserPolicyStatus {
        st_at(browser, state, NOW)
    }

    fn st_at(browser: &str, state: BrowserPolicyState, since: u64) -> BrowserPolicyStatus {
        BrowserPolicyStatus {
            browser: browser.into(),
            path: format!("/etc/{browser}/policies.json"),
            state,
            since_unix: since,
        }
    }

    fn failed(kind: BrowserPolicyFailKind) -> BrowserPolicyState {
        BrowserPolicyState::Failed {
            kind,
            reason: "boom".into(),
        }
    }

    const FIREFOX_ETC: &str = "etc/firefox/policies/policies.json";
    const MULLVAD_FILE: &str = "usr/lib/mullvad-browser/distribution/policies.json";
    const CHROMIUM_FILE: &str = "etc/chromium/policies/managed/grepfocus.json";

    // ── pure core ────────────────────────────────────────────────────────

    #[test]
    fn build_fresh_file_has_doh_off_and_a_created_marker() {
        let v = build_firefox_policy(None, None);
        assert_eq!(
            v["policies"]["DNSOverHTTPS"],
            json!({"Enabled": false, "Locked": true})
        );
        assert_eq!(v["grepfocus"]["created"], json!(true));
        assert_eq!(v["grepfocus"]["managed"], json!(["DNSOverHTTPS"]));
        assert_eq!(v["grepfocus"]["note"], json!(NOTE));
        assert!(v["grepfocus"].get("seeded_from").is_none());
        assert!(has_marker(&v));
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    #[test]
    fn build_merges_into_a_foreign_file_and_keeps_every_other_key() {
        let existing = doc(r#"{"policies": {"DisableTelemetry": true,
                             "DNSOverHTTPS": {"Enabled": true, "ProviderURL": "https://x/"}},
                "extra": 1}"#);
        let v = build_firefox_policy(Some(&existing), None);
        assert_eq!(v["policies"]["DisableTelemetry"], json!(true));
        assert_eq!(
            v["policies"]["DNSOverHTTPS"],
            json!({"Enabled": false, "Locked": true})
        );
        assert_eq!(v["extra"], json!(1));
        assert_eq!(v["grepfocus"]["created"], json!(false));
        assert!(!has_marker(&existing));
    }

    #[test]
    fn build_is_idempotent_and_refreshes_an_older_note() {
        let once = build_firefox_policy(None, None);
        let twice = build_firefox_policy(Some(&once), None);
        assert_eq!(render(&once), render(&twice));

        let mut old = once.clone();
        old["grepfocus"]["note"] = json!("older wording");
        old["grepfocus"]["managed"] = json!([]);
        let rebuilt = build_firefox_policy(Some(&old), None);
        assert_eq!(render(&rebuilt), render(&once));
    }

    #[test]
    fn seeded_build_records_the_source_and_strips_back_to_delete() {
        let seed = policies_of(&doc(
            r#"{"policies": {"DisableAppUpdate": true, "DNSOverHTTPS": {"Enabled": true}}}"#,
        ));
        let from = "/usr/lib64/firefox/distribution/policies.json";
        let v = build_firefox_policy(None, Some((from, &seed)));
        assert_eq!(v["policies"]["DisableAppUpdate"], json!(true));
        assert_eq!(
            v["policies"]["DNSOverHTTPS"],
            json!({"Enabled": false, "Locked": true})
        );
        assert_eq!(v["grepfocus"]["created"], json!(true));
        assert_eq!(v["grepfocus"]["seeded_from"], json!(from));
        let mut hashed = seed.clone();
        hashed.remove(DOH_KEY);
        assert_eq!(
            v["grepfocus"]["seeded_sha256"],
            json!(sha256_hex(&render(&Value::Object(hashed))))
        );
        // Nothing left but the seed: delete, so the distribution file
        // applies again — even though the seed set DoH itself.
        assert_eq!(strip_firefox_policy(&v), Strip::Delete);
        // The marker carries the seed record through later rebuilds.
        let again = build_firefox_policy(Some(&v), None);
        assert_eq!(render(&again), render(&v));
    }

    #[test]
    fn seeded_then_edited_strips_to_a_rewrite() {
        let seed = policies_of(&doc(r#"{"policies": {"DisableAppUpdate": true}}"#));
        let mut v = build_firefox_policy(
            None,
            Some(("/opt/firefox/distribution/policies.json", &seed)),
        );
        v["policies"]["Homepage"] = json!({"URL": "https://example.com"});
        match strip_firefox_policy(&v) {
            Strip::Rewrite(stripped) => {
                assert!(!has_marker(&stripped));
                assert!(stripped["policies"].get("DNSOverHTTPS").is_none());
                assert_eq!(
                    stripped["policies"]["Homepage"]["URL"],
                    json!("https://example.com")
                );
                assert_eq!(stripped["policies"]["DisableAppUpdate"], json!(true));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn strip_cases() {
        // No marker: never ours, whatever the content says about DoH.
        assert_eq!(
            strip_firefox_policy(&doc(
                r#"{"policies": {"DNSOverHTTPS": {"Enabled": false}}}"#
            )),
            Strip::NotOurs
        );
        assert_eq!(strip_firefox_policy(&json!([1])), Strip::NotOurs);
        assert_eq!(
            strip_firefox_policy(&doc(r#"{"grepfocus": "not an object"}"#)),
            Strip::NotOurs
        );
        // Created, only our key: delete.
        assert_eq!(
            strip_firefox_policy(&build_firefox_policy(None, None)),
            Strip::Delete
        );
        // Merged (created:false) is always a rewrite, even when empty.
        let merged = build_firefox_policy(Some(&doc(r#"{"policies": {}}"#)), None);
        assert_eq!(
            strip_firefox_policy(&merged),
            Strip::Rewrite(doc(r#"{"policies": {}}"#))
        );
        // Created, but a top-level key was added since: keep it.
        let mut v = build_firefox_policy(None, None);
        v["comment"] = json!("mine");
        assert_eq!(
            strip_firefox_policy(&v),
            Strip::Rewrite(doc(r#"{"comment": "mine", "policies": {}}"#))
        );
    }

    #[test]
    fn plan_for_all_three_formats() {
        for f in [Format::Firefox, Format::Chromium, Format::Unsupported] {
            assert_eq!(plan(f, false, Some(b"x"), None), Ok(Plan::Remove));
        }
        assert_eq!(
            plan(Format::Unsupported, true, None, None)
                .unwrap_err()
                .kind,
            Unsupported
        );

        // Chromium: fresh → write, exact bytes → unchanged, anything else → write.
        assert_eq!(
            plan(Format::Chromium, true, None, None),
            Ok(Plan::Write {
                content: CHROMIUM_CONTENT.into(),
                merged: false,
                first_touch_of_foreign_file: false,
            })
        );
        assert_eq!(
            plan(
                Format::Chromium,
                true,
                Some(CHROMIUM_CONTENT.as_bytes()),
                None
            ),
            Ok(Plan::Unchanged { merged: false })
        );
        assert!(matches!(
            plan(Format::Chromium, true, Some(b"{}"), None),
            Ok(Plan::Write {
                merged: false,
                first_touch_of_foreign_file: false,
                ..
            })
        ));

        // Firefox, fresh: write a created file; the same bytes back are unchanged.
        let Ok(Plan::Write {
            content,
            merged: false,
            first_touch_of_foreign_file: false,
        }) = plan(Format::Firefox, true, None, None)
        else {
            panic!("fresh firefox plan")
        };
        assert_eq!(doc(&content), build_firefox_policy(None, None));
        assert_eq!(
            plan(Format::Firefox, true, Some(content.as_bytes()), None),
            Ok(Plan::Unchanged { merged: false })
        );

        // Foreign file: first touch, reported merged; then unchanged.
        let foreign = br#"{"policies": {"DisableTelemetry": true}}"#;
        let Ok(Plan::Write {
            content: merged_content,
            merged: true,
            first_touch_of_foreign_file: true,
        }) = plan(Format::Firefox, true, Some(foreign), None)
        else {
            panic!("foreign firefox plan")
        };
        assert_eq!(
            plan(Format::Firefox, true, Some(merged_content.as_bytes()), None),
            Ok(Plan::Unchanged { merged: true })
        );

        // An older render with a different note: one write, then unchanged.
        let mut old = doc(&content);
        old["grepfocus"]["note"] = json!("older");
        let old_bytes = render(&old);
        let Ok(Plan::Write {
            content: refreshed,
            merged: false,
            first_touch_of_foreign_file: false,
        }) = plan(Format::Firefox, true, Some(old_bytes.as_bytes()), None)
        else {
            panic!("older render plan")
        };
        assert_eq!(refreshed, content);

        // Refused shapes.
        for bad in [&b"{not json"[..], b"[]", br#"{"policies": 5}"#] {
            assert_eq!(
                plan(Format::Firefox, true, Some(bad), None)
                    .unwrap_err()
                    .kind,
                NotJson,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }

        // The seed is used only when creating; an unparseable one is ignored.
        let seed = Seed {
            path: "/opt/firefox/distribution/policies.json",
            bytes: br#"{"policies": {"DisableAppUpdate": true}}"#,
        };
        let Ok(Plan::Write {
            content: seeded, ..
        }) = plan(Format::Firefox, true, None, Some(seed))
        else {
            panic!("seeded plan")
        };
        assert_eq!(
            doc(&seeded)["grepfocus"]["seeded_from"],
            json!("/opt/firefox/distribution/policies.json")
        );
        assert_eq!(doc(&seeded)["policies"]["DisableAppUpdate"], json!(true));
        assert_eq!(
            plan(Format::Firefox, true, Some(content.as_bytes()), Some(seed)),
            Ok(Plan::Unchanged { merged: false })
        );
        let junk = Seed {
            path: "x",
            bytes: b"nope",
        };
        let Ok(Plan::Write {
            content: unseeded, ..
        }) = plan(Format::Firefox, true, None, Some(junk))
        else {
            panic!("junk seed plan")
        };
        assert_eq!(unseeded, content);
    }

    #[test]
    fn chromium_content_parses_to_exactly_the_mode_key() {
        assert_eq!(doc(CHROMIUM_CONTENT), json!({"DnsOverHttpsMode": "off"}));
        assert_eq!(render(&doc(CHROMIUM_CONTENT)), CHROMIUM_CONTENT);
    }

    #[test]
    fn render_sorts_keys_at_every_level() {
        let v = doc(r#"{"b": {"z": 1, "a": [{"y": 1, "x": 2}]}, "a": 0}"#);
        assert_eq!(
            render(&v),
            "{\n  \"a\": 0,\n  \"b\": {\n    \"a\": [\n      {\n        \"x\": 2,\n        \"y\": 1\n      }\n    ],\n    \"z\": 1\n  }\n}\n"
        );
    }

    #[test]
    fn orig_path_for_pins_the_flat_name() {
        assert_eq!(
            orig_path_for(
                Path::new(paths::POLICY_ORIG_DIR),
                "etc/firefox/policies/policies.json"
            ),
            Path::new("/var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig")
        );
    }

    #[test]
    fn targets_are_in_slug_order_with_seven_entries() {
        let ts = targets(Path::new("/"), Path::new(paths::POLICY_ORIG_DIR));
        let slugs: Vec<&str> = ts.iter().map(|t| t.browser.slug()).collect();
        assert_eq!(
            slugs,
            [
                "firefox",
                "firefox-flatpak",
                "mullvad-browser",
                "chromium",
                "chromium-snap",
                "chrome",
                "brave"
            ]
        );
        assert_eq!(ts[0].file, Path::new("/etc/firefox/policies/policies.json"));
        assert_eq!(
            ts[1].file,
            Path::new("/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/x86_64/stable/policies/policies.json")
        );
        assert_eq!(
            ts[2].file,
            Path::new("/usr/lib/mullvad-browser/distribution/policies.json")
        );
        assert_eq!(
            ts[0].orig.as_deref(),
            Some(Path::new(
                "/var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig"
            ))
        );
        assert!(ts[1].orig.is_none());
        assert!(ts[3].orig.is_none());
        // The rmdir chains never reach a shared parent.
        let shared = [
            "/etc",
            "/etc/opt",
            "/usr",
            "/usr/lib",
            "/var/snap/chromium/current",
            "/var",
        ];
        for t in &ts {
            for d in &t.rmdir_chain {
                assert!(!shared.contains(&d.to_str().unwrap()), "{d:?}");
            }
        }
    }

    #[test]
    fn managed_paths_pins_six_files_and_two_origs() {
        assert_eq!(
            managed_paths(Path::new("/"), Path::new(paths::POLICY_ORIG_DIR)),
            [
                "/etc/firefox/policies/policies.json",
                "/usr/lib/mullvad-browser/distribution/policies.json",
                "/etc/chromium/policies/managed/grepfocus.json",
                "/var/snap/chromium/current/policies/managed/grepfocus.json",
                "/etc/opt/chrome/policies/managed/grepfocus.json",
                "/etc/brave/policies/managed/grepfocus.json",
                "/var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig",
                "/var/lib/grepfocus/policies/_usr_lib_mullvad-browser_distribution_policies.json.orig",
            ]
        );
    }

    #[test]
    fn uninstall_script_mirrors_managed_paths() {
        for p in managed_paths(Path::new("/"), Path::new(paths::POLICY_ORIG_DIR)) {
            assert!(SCRIPT.contains(&p), "uninstall.sh does not mention {p}");
            let tmp = format!("{p}{}", hosts::TMP_SUFFIX);
            assert!(SCRIPT.contains(&tmp), "uninstall.sh does not sweep {tmp}");
        }
        // The marker lines the script greps for are what `render` produces.
        let ours = render(&build_firefox_policy(None, None));
        assert!(ours.contains("\n  \"grepfocus\": {\n"));
        assert!(ours.contains("\n    \"created\": true,\n"));
        assert!(SCRIPT.contains(r#"'^  "grepfocus": {'"#));
        assert!(SCRIPT.contains(r#"'^    "created": true'"#));
    }

    #[test]
    fn transitions_report_changes_and_warn_on_failure() {
        let prev = vec![
            st("firefox", Written),
            st("chromium", NotInstalled),
            st("brave", failed(Io)),
        ];
        let next = vec![
            st("firefox", Written),
            st("chromium", Written),
            st("brave", failed(Io)),
            st("chrome", failed(ReadOnlyFs)),
        ];
        let (info, warns) = transitions(&prev, &next);
        assert_eq!(
            info,
            vec!["browser DoH policy for chromium: not_installed -> written (/etc/chromium/policies.json)"]
        );
        assert_eq!(
            warns,
            vec!["browser DoH policy for chrome failed (read_only_fs): boom — DoH may bypass blocks in that browser until this is fixed"]
        );
        // A new reason for the same failure is not a transition; a new kind is.
        let same_kind = vec![st(
            "brave",
            BrowserPolicyState::Failed {
                kind: Io,
                reason: "other".into(),
            },
        )];
        assert_eq!(transitions(&prev, &same_kind), (vec![], vec![]));
        let (info, warns) = transitions(&prev, &[st("brave", failed(NotJson))]);
        assert!(info.is_empty());
        assert_eq!(warns.len(), 1);
        assert!(warns[0].starts_with("browser DoH policy for brave failed (not_json): boom"));
        // Healing is an info line; a steady state is silent.
        let (info, warns) = transitions(&prev, &[st("brave", Written)]);
        assert_eq!(
            info,
            vec!["browser DoH policy for brave: failed:io -> written (/etc/brave/policies.json)"]
        );
        assert!(warns.is_empty());
        assert_eq!(transitions(&next, &next), (vec![], vec![]));
    }

    #[test]
    fn first_pass_logs_the_summary_and_warns_about_each_failure() {
        let next = vec![
            st("firefox", Written),
            st("firefox-flatpak", failed(Unsupported)),
            st("mullvad-browser", failed(ReadOnlyFs)),
            st("chromium", NotInstalled),
        ];
        let (info, warns) = pass_lines(&[], &next);
        assert_eq!(info, vec![summary(&next)]);
        assert_eq!(
            warns,
            vec![
                "browser DoH policy for firefox-flatpak failed (unsupported): boom — DoH may bypass blocks in that browser until this is fixed",
                "browser DoH policy for mullvad-browser failed (read_only_fs): boom — DoH may bypass blocks in that browser until this is fixed",
            ]
        );
        // A first pass with nothing failing is the summary alone.
        let healthy = vec![st("firefox", Written), st("chromium", NotInstalled)];
        assert_eq!(pass_lines(&[], &healthy), (vec![summary(&healthy)], vec![]));
        // Later passes are the plain transitions: silent while steady, and
        // a failure already reported is not repeated.
        assert_eq!(pass_lines(&next, &next), (vec![], vec![]));
        let healed = vec![st("mullvad-browser", Written)];
        assert_eq!(pass_lines(&next, &healed), transitions(&next, &healed));
    }

    #[test]
    fn summary_line_lists_every_browser() {
        let list = vec![
            st("firefox", Written),
            st("firefox-flatpak", NotInstalled),
            st("mullvad-browser", failed(ReadOnlyFs)),
            st("chromium", Merged),
        ];
        assert_eq!(
            summary(&list),
            "browser DoH policies: firefox=written(/etc/firefox/policies.json) \
             firefox-flatpak=not_installed \
             mullvad-browser=failed:read_only_fs(/etc/mullvad-browser/policies.json) \
             chromium=merged(/etc/chromium/policies.json)"
        );
    }

    #[test]
    fn carry_since_keeps_the_first_seen_time_for_unchanged_states_only() {
        let prev = vec![
            st_at("firefox", NotInstalled, 100),
            st_at("chromium", failed(Io), 100),
            st_at("brave", Written, 100),
        ];
        let mut next = vec![
            st_at("firefox", NotInstalled, 200),
            st_at(
                "chromium",
                BrowserPolicyState::Failed {
                    kind: Io,
                    reason: "new reason".into(),
                },
                200,
            ),
            st_at("brave", Written, 200),
            st_at("chrome", NotInstalled, 200),
        ];
        carry_since(&prev, &mut next);
        assert_eq!(next[0].since_unix, 100);
        assert_eq!(next[1].since_unix, 100);
        // Written/Merged carry the file's mtime, which is authoritative.
        assert_eq!(next[2].since_unix, 200);
        assert_eq!(next[3].since_unix, 200);

        let mut changed = vec![st_at("firefox", failed(Io), 200)];
        carry_since(&prev, &mut changed);
        assert_eq!(changed[0].since_unix, 200);
    }

    #[test]
    fn classify_io_maps_a_read_only_root_cause() {
        let erofs = anyhow::Error::new(io::Error::from_raw_os_error(30))
            .context("opening /usr/lib/mullvad-browser/distribution/policies.json.grepfocus.tmp");
        let f = classify_io(&erofs);
        assert_eq!(f.kind, ReadOnlyFs);
        assert!(
            f.reason.starts_with(
                "opening /usr/lib/mullvad-browser/distribution/policies.json.grepfocus.tmp: "
            ),
            "{}",
            f.reason
        );
        assert!(f.reason.ends_with("(os error 30)"), "{}", f.reason);

        let eacces = anyhow::Error::new(io::Error::from_raw_os_error(13)).context("creating x");
        assert_eq!(classify_io(&eacces).kind, Io);
        assert_eq!(classify_io(&anyhow::anyhow!("no io error")).kind, Io);
        // Only the root cause counts.
        let wrapped = anyhow::Error::new(io::Error::from_raw_os_error(30))
            .context(io::Error::from_raw_os_error(13));
        assert_eq!(classify_io(&wrapped).kind, ReadOnlyFs);
    }

    #[test]
    fn fold_cleanup_outcomes() {
        use RemoveOutcome::*;
        let (o, s) = fold_cleanup(&[(Browser::Firefox, Absent), (Browser::Chromium, Absent)]);
        assert!(
            matches!(o, cleanup::Outcome::Skipped(ref m) if m == "none present"),
            "{o:?}"
        );
        assert!(s.is_empty());

        let (o, _) = fold_cleanup(&[(Browser::Firefox, NotOurs), (Browser::Chromium, Absent)]);
        assert!(
            matches!(o, cleanup::Outcome::Skipped(ref m) if m.contains("firefox not managed")),
            "{o:?}"
        );

        let (o, s) = fold_cleanup(&[
            (Browser::Firefox, Restored),
            (Browser::Mullvad, Rewritten),
            (Browser::Chromium, Removed),
            (Browser::Brave, Absent),
        ]);
        assert!(
            matches!(o, cleanup::Outcome::Done(ref m) if m == "firefox: restored from recovery copy, mullvad-browser: our keys stripped, chromium: removed"),
            "{o:?}"
        );
        assert!(s.is_empty());

        let orig = "/var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig";
        let (o, s) = fold_cleanup(&[
            (
                Browser::Firefox,
                Failed {
                    reason: "EROFS".into(),
                    surviving_orig: Some(orig.into()),
                },
            ),
            (Browser::Chromium, Removed),
            (
                Browser::Brave,
                Failed {
                    reason: "EACCES".into(),
                    surviving_orig: None,
                },
            ),
        ]);
        match o {
            cleanup::Outcome::Failed(m) => {
                assert!(m.contains("firefox: EROFS"), "{m}");
                assert!(m.contains("brave: EACCES"), "{m}");
                assert!(
                    m.ends_with(&format!(" — recovery copies kept: {orig}")),
                    "{m}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(s, vec![orig.to_string()]);
    }

    // ── tempdir IO ───────────────────────────────────────────────────────

    #[test]
    fn not_installed_writes_nothing_and_creates_no_dirs() {
        let fx = Fixture::new();
        let list = reconcile(&fx.targets(), NOW);
        assert_eq!(list.len(), 7);
        for s in &list {
            assert_eq!(s.state, NotInstalled, "{}", s.browser);
            assert_eq!(s.since_unix, NOW);
        }
        assert_eq!(fs::read_dir(fx.root()).unwrap().count(), 0);
    }

    #[test]
    fn fresh_write_creates_0644_files_and_reports_written() {
        let fx = Fixture::new();
        fx.touch("usr/lib64/firefox/firefox");
        fx.touch("usr/lib/chromium/chromium");
        fx.touch("opt/google/chrome/chrome");
        let list = reconcile(&fx.targets(), NOW);
        let by = |slug: &str| list.iter().find(|s| s.browser == slug).unwrap();
        assert_eq!(by("firefox").state, Written);
        assert_eq!(by("chromium").state, Written);
        assert_eq!(by("chrome").state, Written);
        assert_eq!(by("brave").state, NotInstalled);
        assert_eq!(by("mullvad-browser").state, NotInstalled);

        let ff = fx.path(FIREFOX_ETC);
        assert_eq!(mode(&ff), 0o644);
        let v = doc(&fx.read(FIREFOX_ETC));
        assert_eq!(
            v["policies"]["DNSOverHTTPS"],
            json!({"Enabled": false, "Locked": true})
        );
        assert_eq!(v["grepfocus"]["created"], json!(true));
        assert_eq!(by("firefox").path, ff.to_string_lossy());
        assert_eq!(by("firefox").since_unix, mtime_unix(&ff).unwrap());

        let cr = fx.path(CHROMIUM_FILE);
        assert_eq!(fx.read(CHROMIUM_FILE), CHROMIUM_CONTENT);
        assert_eq!(mode(&cr), 0o644);
        assert!(fx
            .path("etc/opt/chrome/policies/managed/grepfocus.json")
            .is_file());
        // Nothing for the browsers that are absent, no recovery copy for a
        // file we created.
        assert!(!fx.path("etc/brave").exists());
        assert!(!fx.path("usr/lib/mullvad-browser").exists());
        assert!(!fx.orig_dir().exists());
    }

    #[test]
    fn second_pass_is_a_byte_and_mtime_no_op() {
        let fx = Fixture::new();
        fx.touch("usr/bin/firefox");
        fx.touch("opt/brave.com/brave/brave");
        let first = reconcile(&fx.targets(), NOW);
        let ff = fx.path(FIREFOX_ETC);
        let br = fx.path("etc/brave/policies/managed/grepfocus.json");
        let snapshot = |p: &Path| {
            let m = fs::metadata(p).unwrap();
            (fs::read(p).unwrap(), m.modified().unwrap())
        };
        let (ff_before, br_before) = (snapshot(&ff), snapshot(&br));

        std::thread::sleep(Duration::from_millis(20));
        let second = reconcile(&fx.targets(), NOW + 60);
        assert_eq!(snapshot(&ff), ff_before);
        assert_eq!(snapshot(&br), br_before);
        for (a, b) in first.iter().zip(&second) {
            assert_eq!(a.state, b.state, "{}", a.browser);
            if matches!(a.state, Written | Merged) {
                assert_eq!(a.since_unix, b.since_unix, "{}", a.browser);
            }
        }
        assert!(!fx
            .path("etc/firefox/policies/policies.json.grepfocus.tmp")
            .exists());
        assert!(!fx
            .path("etc/brave/policies/managed/grepfocus.json.grepfocus.tmp")
            .exists());
    }

    #[test]
    fn mode_drift_is_reasserted_without_a_rewrite() {
        let fx = Fixture::new();
        fx.touch("usr/bin/firefox-esr");
        fx.touch("usr/lib/chromium-browser/chromium-browser");
        assert_eq!(fx.reconcile(Browser::Firefox).state, Written);
        assert_eq!(fx.reconcile(Browser::Chromium).state, Written);
        for rel in [FIREFOX_ETC, CHROMIUM_FILE] {
            let p = fx.path(rel);
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            let before = (
                fs::read(&p).unwrap(),
                fs::metadata(&p).unwrap().modified().unwrap(),
            );
            std::thread::sleep(Duration::from_millis(20));
            let s = reconcile_one(
                &fx.targets().into_iter().find(|t| t.file == p).unwrap(),
                NOW,
            );
            assert_eq!(s.state, Written, "{rel}");
            assert_eq!(mode(&p), 0o644, "{rel}");
            let after = (
                fs::read(&p).unwrap(),
                fs::metadata(&p).unwrap().modified().unwrap(),
            );
            assert_eq!(after, before, "{rel}");
        }
    }

    #[test]
    fn merge_keeps_a_0600_recovery_copy_in_a_0700_dir_and_reports_merged() {
        let fx = Fixture::new();
        fx.touch("usr/lib/mullvad-browser/application.ini");
        let admin = "{\"policies\": {\"DisableTelemetry\": true}}";
        fx.write(MULLVAD_FILE, admin);

        let s = fx.reconcile(Browser::Mullvad);
        assert_eq!(s.state, Merged);
        let orig = fx
            .orig_dir()
            .join("_usr_lib_mullvad-browser_distribution_policies.json.orig");
        assert_eq!(fs::read_to_string(&orig).unwrap(), admin);
        assert_eq!(mode(&orig), 0o600);
        assert_eq!(mode(&fx.orig_dir()), 0o700);
        assert!(!fx
            .orig_dir()
            .join("_usr_lib_mullvad-browser_distribution_policies.json.orig.grepfocus.tmp")
            .exists());

        let v = doc(&fx.read(MULLVAD_FILE));
        assert_eq!(v["policies"]["DisableTelemetry"], json!(true));
        assert_eq!(
            v["policies"]["DNSOverHTTPS"],
            json!({"Enabled": false, "Locked": true})
        );
        assert_eq!(v["grepfocus"]["created"], json!(false));
        assert_eq!(mode(&fx.path(MULLVAD_FILE)), 0o644);
        assert_eq!(s.since_unix, mtime_unix(&fx.path(MULLVAD_FILE)).unwrap());

        // Second pass: still merged, copy untouched.
        let again = fx.reconcile(Browser::Mullvad);
        assert_eq!(again.state, Merged);
        assert_eq!(fs::read_to_string(&orig).unwrap(), admin);
    }

    #[test]
    fn merge_fails_closed_when_the_recovery_copy_cannot_be_kept() {
        let fx = Fixture::new();
        fx.touch("usr/bin/firefox");
        let admin = "{\"policies\": {\"DisableTelemetry\": true}}";
        fx.write(FIREFOX_ETC, admin);
        // A regular file where the recovery dir should be: create_dir_all fails.
        fx.write("var/lib/grepfocus/policies", "in the way");

        let s = fx.reconcile(Browser::Firefox);
        assert!(
            matches!(s.state, BrowserPolicyState::Failed { kind: Io, .. }),
            "{s:?}"
        );
        assert_eq!(fx.read(FIREFOX_ETC), admin);
    }

    #[test]
    fn fresh_firefox_file_is_seeded_from_distribution_policies() {
        let fx = Fixture::new();
        fx.touch("usr/lib64/firefox/firefox");
        let seed_rel = "usr/lib64/firefox/distribution/policies.json";
        let seed_content = r#"{"policies": {"DisableAppUpdate": true}}"#;
        fx.write(seed_rel, seed_content);

        let s = fx.reconcile(Browser::Firefox);
        assert_eq!(s.state, Written);
        let v = doc(&fx.read(FIREFOX_ETC));
        assert_eq!(v["policies"]["DisableAppUpdate"], json!(true));
        assert_eq!(
            v["grepfocus"]["seeded_from"],
            json!(fx.path(seed_rel).to_string_lossy())
        );
        assert!(v["grepfocus"]["seeded_sha256"].is_string());
        assert_eq!(fx.read(seed_rel), seed_content);
        assert!(!fx.orig_dir().exists());

        // Browser gone: our file is deleted so the seed applies again, and
        // the directories we created go with it.
        fs::remove_file(fx.path("usr/lib64/firefox/firefox")).unwrap();
        let s = fx.reconcile(Browser::Firefox);
        assert_eq!(s.state, NotInstalled);
        assert!(!fx.path(FIREFOX_ETC).exists());
        assert!(!fx.path("etc/firefox").exists());
        assert!(fx.path("etc").is_dir());
        assert_eq!(fx.read(seed_rel), seed_content);
    }

    #[test]
    fn invalid_json_is_refused_and_untouched() {
        let fx = Fixture::new();
        fx.touch("usr/bin/firefox");
        fx.write(FIREFOX_ETC, "{not json");
        let s = fx.reconcile(Browser::Firefox);
        assert!(
            matches!(s.state, BrowserPolicyState::Failed { kind: NotJson, .. }),
            "{s:?}"
        );
        assert_eq!(fx.read(FIREFOX_ETC), "{not json");
        assert!(!fx.orig_dir().exists());
        assert_eq!(s.since_unix, NOW);
    }

    #[test]
    fn symlink_is_refused() {
        let fx = Fixture::new();
        fx.touch("usr/bin/firefox");
        fx.touch("usr/lib/chromium/chromium");
        let real = fx.write("srv/policies.json", "{}");
        for rel in [FIREFOX_ETC, CHROMIUM_FILE] {
            let link = fx.path(rel);
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&real, &link).unwrap();
        }
        for b in [Browser::Firefox, Browser::Chromium] {
            let s = fx.reconcile(b);
            assert!(
                matches!(s.state, BrowserPolicyState::Failed { kind: Symlink, .. }),
                "{s:?}"
            );
        }
        assert_eq!(fs::read_to_string(&real).unwrap(), "{}");
        // Removal leaves a symlink alone too.
        assert_eq!(fx.remove(Browser::Firefox), RemoveOutcome::NotOurs);
        assert!(fx.path(FIREFOX_ETC).is_symlink());
    }

    #[test]
    fn a_regular_file_where_the_policy_dir_should_be_fails_only_that_target() {
        let fx = Fixture::new();
        fx.touch("usr/lib/chromium/chromium");
        fx.touch("opt/brave.com/brave/brave");
        fx.write("etc/chromium/policies/managed", "not a dir");
        let list = reconcile(&fx.targets(), NOW);
        let by = |slug: &str| list.iter().find(|s| s.browser == slug).unwrap();
        assert!(
            matches!(
                by("chromium").state,
                BrowserPolicyState::Failed { kind: Io, .. }
            ),
            "{:?}",
            by("chromium")
        );
        assert_eq!(by("brave").state, Written);
        assert_eq!(fx.read("etc/chromium/policies/managed"), "not a dir");
    }

    #[test]
    fn write_failure_is_reported_as_io() {
        if nix::unistd::Uid::effective().is_root() {
            return; // root ignores directory modes; nothing to provoke
        }
        let fx = Fixture::new();
        fx.touch("opt/brave.com/brave/brave");
        let dir = fx.path("etc/brave/policies/managed");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let s = fx.reconcile(Browser::Brave);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        match s.state {
            BrowserPolicyState::Failed { kind: Io, reason } => {
                assert!(reason.contains("grepfocus.json.grepfocus.tmp"), "{reason}");
                assert!(reason.contains("Permission denied"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!dir.join("grepfocus.json").exists());
    }

    #[test]
    fn remove_all_handles_every_ownership_case() {
        let fx = Fixture::new();
        fx.write(CHROMIUM_FILE, CHROMIUM_CONTENT);
        fx.write(FIREFOX_ETC, &render(&build_firefox_policy(None, None)));
        // Deliberately non-canonical bytes: the restore must be byte-exact.
        let admin = "{\"policies\":{\"DisableTelemetry\":true}}\n";
        fx.touch("usr/lib/mullvad-browser/application.ini");
        fx.write(MULLVAD_FILE, admin);
        assert_eq!(fx.reconcile(Browser::Mullvad).state, Merged);
        assert_ne!(fx.read(MULLVAD_FILE), admin);

        let results = remove_all(&fx.targets());
        let of = |b: Browser| &results.iter().find(|(x, _)| *x == b).unwrap().1;
        assert_eq!(of(Browser::Chromium), &RemoveOutcome::Removed);
        assert_eq!(of(Browser::Firefox), &RemoveOutcome::Removed);
        assert_eq!(of(Browser::Mullvad), &RemoveOutcome::Restored);
        assert_eq!(of(Browser::Brave), &RemoveOutcome::Absent);
        assert_eq!(of(Browser::FirefoxFlatpak), &RemoveOutcome::Absent);
        assert!(!fx.path(CHROMIUM_FILE).exists());
        assert!(!fx.path(FIREFOX_ETC).exists());
        assert_eq!(fx.read(MULLVAD_FILE), admin);
        assert_eq!(mode(&fx.path(MULLVAD_FILE)), 0o644);
        assert_eq!(fs::read_dir(fx.orig_dir()).unwrap().count(), 0);
        // Directories are never removed on the cleanup path.
        assert!(fx.path("etc/firefox/policies").is_dir());
        assert!(fx.path("etc/chromium/policies/managed").is_dir());
        // Idempotent.
        let again = remove_all(&fx.targets());
        assert!(again
            .iter()
            .all(|(_, o)| matches!(o, RemoveOutcome::Absent | RemoveOutcome::NotOurs)));
        assert_eq!(fx.read(MULLVAD_FILE), admin);
    }

    #[test]
    fn remove_rewrites_a_merged_file_edited_since() {
        let fx = Fixture::new();
        fx.touch("usr/bin/firefox");
        fx.write(FIREFOX_ETC, r#"{"policies": {"DisableTelemetry": true}}"#);
        assert_eq!(fx.reconcile(Browser::Firefox).state, Merged);
        let mut v = doc(&fx.read(FIREFOX_ETC));
        v["policies"]["Homepage"] = json!({"URL": "https://example.com"});
        fs::write(fx.path(FIREFOX_ETC), render(&v)).unwrap();

        assert_eq!(fx.remove(Browser::Firefox), RemoveOutcome::Rewritten);
        let after = doc(&fx.read(FIREFOX_ETC));
        assert!(!has_marker(&after));
        assert!(after["policies"].get("DNSOverHTTPS").is_none());
        assert_eq!(after["policies"]["DisableTelemetry"], json!(true));
        assert_eq!(
            after["policies"]["Homepage"]["URL"],
            json!("https://example.com")
        );
        assert_eq!(fs::read_dir(fx.orig_dir()).unwrap().count(), 0);
    }

    #[test]
    fn remove_leaves_foreign_files_alone() {
        let fx = Fixture::new();
        let foreign = r#"{"policies": {"DNSOverHTTPS": {"Enabled": false}}}"#;
        fx.write(FIREFOX_ETC, foreign);
        fx.write(MULLVAD_FILE, "{not json");
        assert_eq!(fx.remove(Browser::Firefox), RemoveOutcome::NotOurs);
        assert_eq!(fx.remove(Browser::Mullvad), RemoveOutcome::NotOurs);
        assert_eq!(fx.read(FIREFOX_ETC), foreign);
        assert_eq!(fx.read(MULLVAD_FILE), "{not json");
    }

    #[test]
    fn not_installed_path_removes_and_rmdirs_only_empty_chain_dirs() {
        let fx = Fixture::new();
        fx.touch("usr/lib/chromium/chromium");
        assert_eq!(fx.reconcile(Browser::Chromium).state, Written);
        fs::remove_file(fx.path("usr/lib/chromium/chromium")).unwrap();
        // A sibling file keeps /etc/chromium.
        fx.write("etc/chromium/chromium.conf", "x");
        assert_eq!(fx.reconcile(Browser::Chromium).state, NotInstalled);
        assert!(!fx.path(CHROMIUM_FILE).exists());
        assert!(!fx.path("etc/chromium/policies").exists());
        assert!(fx.path("etc/chromium/chromium.conf").is_file());

        // An empty chain goes up to the vendor dir; /etc/opt stays.
        fx.touch("opt/google/chrome/chrome");
        assert_eq!(fx.reconcile(Browser::Chrome).state, Written);
        fs::remove_file(fx.path("opt/google/chrome/chrome")).unwrap();
        assert_eq!(fx.reconcile(Browser::Chrome).state, NotInstalled);
        assert!(!fx.path("etc/opt/chrome").exists());
        assert!(fx.path("etc/opt").is_dir());

        // A merged file goes back to its recovery copy on this path too.
        fx.touch("usr/lib/mullvad-browser/mullvadbrowser");
        let admin = "{\"policies\": {\"DisableTelemetry\": true}}";
        fx.write(MULLVAD_FILE, admin);
        assert_eq!(fx.reconcile(Browser::Mullvad).state, Merged);
        fs::remove_file(fx.path("usr/lib/mullvad-browser/mullvadbrowser")).unwrap();
        assert_eq!(fx.reconcile(Browser::Mullvad).state, NotInstalled);
        assert_eq!(fx.read(MULLVAD_FILE), admin);
        assert_eq!(fs::read_dir(fx.orig_dir()).unwrap().count(), 0);
    }

    #[test]
    fn wrapper_only_mullvad_is_not_installed() {
        let fx = Fixture::new();
        fx.touch("usr/bin/mullvad-browser");
        let s = fx.reconcile(Browser::Mullvad);
        assert_eq!(s.state, NotInstalled);
        assert!(!fx.path("usr/lib/mullvad-browser").exists());
    }

    #[test]
    fn flatpak_firefox_is_reported_unsupported_and_never_written() {
        let fx = Fixture::new();
        fs::create_dir_all(fx.path("var/lib/flatpak/app/org.mozilla.firefox")).unwrap();
        let s = fx.reconcile(Browser::FirefoxFlatpak);
        assert!(
            matches!(
                s.state,
                BrowserPolicyState::Failed {
                    kind: Unsupported,
                    ..
                }
            ),
            "{s:?}"
        );
        assert!(s.path.ends_with(FLATPAK_FIREFOX_POLICY));
        assert!(!fx.path("var/lib/flatpak/extension").exists());
        assert_eq!(fx.remove(Browser::FirefoxFlatpak), RemoveOutcome::Absent);
    }
}
