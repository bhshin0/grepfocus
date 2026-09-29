//! /etc/hosts manipulation, with chattr +i to make the block tamper-resistant.
//!
//! The managed region is delimited by `HOSTS_BEGIN` / `HOSTS_END` markers.
//! Any content outside that region is preserved verbatim.
//!
//! The address every blocked name is pointed at — the *sink IP* — is a
//! parameter of `apply_block`, not a constant of this module. It is `0.0.0.0`
//! as it always has been, except while the loopback proxy holds both ports,
//! when it becomes `127.0.0.1` so a blocked connection is refused by our own
//! listener; `enforce` owns that choice and this module only writes what it is
//! handed. Both addresses block equally (nothing answers on either unless the
//! proxy itself is listening), which is why the choice never belongs to
//! enforcement.
//!
//! Degradation policy: the hosts CONTENT is the enforcement; the immutable
//! bit is hardening on top. A `write_atomic` failure is fatal — it propagates,
//! `enforce::sync` clears its memo, and the next 1s tick retries. A failed
//! `chattr +i` (SELinux, or a filesystem without immutable-flag support) only
//! logs a warning: the block is active, just not tamper-protected, and
//! refusing to enforce at all would be strictly worse. `chattr -i` in the
//! clear paths is likewise best-effort.

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::Command;

use anyhow::{anyhow, Context};
use tracing::{debug, info, warn};

use crate::paths::{HOSTS, HOSTS_BEGIN, HOSTS_END, HOSTS_ORIG};

/// Standard mode for `/etc/hosts`: world-readable so the libc resolver works
/// for non-root processes.
pub(crate) const HOSTS_MODE: u32 = 0o644;
/// Recovery copy is root-only.
const HOSTS_ORIG_MODE: u32 = 0o600;

/// Apply the block: remove any existing managed region, append a fresh one
/// pointing all blocked domains at `sink`, then — when `tamper_protect` (the
/// premium `tamper_protection` feature) is granted — mark /etc/hosts
/// immutable.
///
/// `sink` is chosen by `enforce::sink_ip` and is simply written here (see the
/// module docs). Callers must pass the *current* sink on every apply,
/// including a drift re-apply: the address is file content, so a stale one
/// would be re-installed verbatim.
///
/// The hosts CONTENT is free-tier enforcement; only the `chattr +i`
/// hardening on top is license-gated. The pre-write `chattr -i` below stays
/// unconditional regardless of license: it is the mechanical unlock needed
/// to rewrite a possibly-still-locked file (e.g. locked by a previously
/// licensed apply), not a license decision.
pub fn apply_block(domains: &[String], sink: Ipv4Addr, tamper_protect: bool) -> anyhow::Result<()> {
    chattr_immutable(HOSTS, false).ok(); // best-effort unlock if previously locked
    let original = fs::read_to_string(HOSTS).context("reading /etc/hosts")?;
    let stripped = strip_managed(&original);
    // Snapshot the unmanaged content before we touch /etc/hosts, so it can be
    // recovered by hand if a later edit corrupts the live file. Best-effort:
    // a state-dir write failure must not block the enforcement change itself.
    write_recovery_copy(&stripped);
    let new = if domains.is_empty() {
        stripped
    } else {
        format!(
            "{}\n{}\n{}{}\n",
            stripped.trim_end(),
            HOSTS_BEGIN,
            render_block(domains, sink),
            HOSTS_END
        )
    };
    write_atomic(HOSTS, &new, HOSTS_MODE)?;
    match hardening_for(tamper_protect) {
        // The immutable bit is hardening, not enforcement (see module docs):
        // the block is live once the write lands, so degrade gracefully here.
        Hardening::SetImmutable => {
            if let Err(e) = chattr_immutable(HOSTS, true) {
                warn!(
                    ?e,
                    "chattr +i failed — hosts block is active but NOT tamper-protected \
                     (SELinux or the filesystem may forbid the immutable flag)"
                );
            }
        }
        // info! rather than debug!: apply_block runs only when the enforced
        // union changes or drift was detected — a handful of times per block
        // lifetime, never per tick — and the missing lock is the first thing
        // support will ask about ("why isn't /etc/hosts immutable?").
        Hardening::Skip => {
            info!("hosts block active without tamper protection (premium feature)");
        }
    }
    Ok(())
}

/// What `apply_block` does about the immutable bit after writing. Split out
/// as data so the license gate on the premium hardening step is pinned by a
/// unit test — the `chattr` side effect itself needs root, `/etc/hosts`, and
/// an immutable-flag-capable filesystem, none of which tests have.
#[derive(Debug, PartialEq, Eq)]
enum Hardening {
    /// Licensed for `tamper_protection`: set `chattr +i` (best-effort).
    SetImmutable,
    /// Unlicensed: leave the bit clear. The hosts content still enforces —
    /// only the hardening layer is withheld, and never retroactively (the
    /// unconditional pre-write `chattr -i` is mechanical, see `apply_block`).
    Skip,
}

fn hardening_for(tamper_protect: bool) -> Hardening {
    if tamper_protect {
        Hardening::SetImmutable
    } else {
        Hardening::Skip
    }
}

/// Remove the managed region and clear the immutable bit.
pub fn clear_block() -> anyhow::Result<()> {
    chattr_immutable(HOSTS, false).ok();
    let original = match fs::read_to_string(HOSTS) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("reading /etc/hosts"),
    };
    let stripped = strip_managed(&original);
    // Refresh the recovery copy before editing (matches apply_block); best-effort.
    write_recovery_copy(&stripped);
    if stripped != original {
        write_atomic(HOSTS, &stripped, HOSTS_MODE)?;
    }
    Ok(())
}

/// Whether the live `/etc/hosts` still contains a managed block region. Used
/// by `enforce::sync` to detect drift — with chattr protection degraded, the
/// file can be rewritten externally. An unreadable file reads as "absent" so
/// the caller re-applies (and that path surfaces the real error).
pub fn block_present() -> bool {
    fs::read_to_string(HOSTS)
        .map(|s| contains_managed(&s))
        .unwrap_or(false)
}

/// Whether `s` contains a managed-region begin marker. Matches after
/// `trim_start`, mirroring `strip_managed`.
pub(crate) fn contains_managed(s: &str) -> bool {
    s.lines()
        .any(|line| line.trim_start().starts_with(HOSTS_BEGIN))
}

/// Whether `d` can stand as one name on one `/etc/hosts` line: printable
/// ASCII, no whitespace (a second field would be a second alias, a newline a
/// second line) and no `#` (a comment start). The last belt before root
/// writes the file, deliberately independent of core's validator.
fn line_safe(d: &str) -> bool {
    d.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'#')
}

/// Render the managed region's body: one line per blocked name, plus the
/// `www.` alias for any name that isn't already one, every line pointing at
/// `sink`.
fn render_block(domains: &[String], sink: Ipv4Addr) -> String {
    let mut out = String::from("\n");
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        if !line_safe(d) {
            warn!(domain = ?d, "refusing to write unsafe hosts entry");
            continue;
        }
        out.push_str(&format!("{} {}\n", sink, d));
        if !d.starts_with("www.") {
            out.push_str(&format!("{} www.{}\n", sink, d));
        }
    }
    out
}

pub(crate) fn strip_managed(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut inside = false;
    for line in s.lines() {
        if line.trim_start().starts_with(HOSTS_BEGIN) {
            inside = true;
            continue;
        }
        if inside {
            if line.trim_start().starts_with(HOSTS_END) {
                inside = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Suffix of the scratch file `write_atomic` creates next to its target.
/// `cleanup` uses it to find and remove orphans left by an interrupted
/// write; the on-disk convention is pinned by a test there.
pub(crate) const TMP_SUFFIX: &str = ".grepfocus.tmp";

/// Write `content` to `path` durably: write a sibling tmp file, fsync it, then
/// rename over the target. Mirrors `state::save_in`. `mode` is the final file
/// mode (0644 for /etc/hosts so the resolver can read it, 0600 for the
/// root-only recovery copy).
pub(crate) fn write_atomic(path: &str, content: &str, mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = format!("{}{}", path, TMP_SUFFIX);
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("opening {}", tmp))?;
        f.write_all(content.as_bytes())
            .with_context(|| format!("writing {}", tmp))?;
        f.sync_all().with_context(|| format!("fsync {}", tmp))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming over {}", path))?;
    // Guarantee the final mode even if a stale tmp was reused (mode() only
    // applies on fresh creation).
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path))?;
    // Persist the rename itself: fsync the parent directory so the new entry
    // survives a power loss, not just the file's contents. Best-effort.
    fsync_parent_dir(std::path::Path::new(path));
    Ok(())
}

/// Best-effort recovery snapshot of the unmanaged hosts content. Failures are
/// logged, never propagated, so a full or read-only state dir cannot block the
/// actual `/etc/hosts` enforcement change.
fn write_recovery_copy(stripped: &str) {
    if let Err(e) = write_atomic(HOSTS_ORIG, stripped, HOSTS_ORIG_MODE) {
        warn!(?e, "failed to write hosts recovery copy (continuing)");
    }
}

/// Best-effort `fsync` of a path's parent directory, so a `rename` into it is
/// durable across power loss. A failure here doesn't undo the write.
fn fsync_parent_dir(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::File::open(parent).and_then(|d| d.sync_all()) {
            debug!(?e, "best-effort parent-dir fsync failed");
        }
    }
}

/// Set or clear the immutable bit by shelling out to `chattr`.
/// We rely on coreutils being installed (it always is on a Linux system).
pub(crate) fn chattr_immutable(path: &str, set: bool) -> anyhow::Result<()> {
    let flag = if set { "+i" } else { "-i" };
    let out = Command::new("/usr/bin/chattr")
        .args([flag, path])
        .output()
        .context("running chattr")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("chattr {} {} failed: {}", flag, path, stderr));
    }
    debug!(path, set, "chattr immutable applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_round_trip() {
        let input = format!(
            "127.0.0.1 localhost\n{}\n0.0.0.0 reddit.com\n{}\n::1 localhost\n",
            HOSTS_BEGIN, HOSTS_END
        );
        let stripped = strip_managed(&input);
        assert!(!stripped.contains("reddit.com"));
        assert!(stripped.contains("127.0.0.1 localhost"));
        assert!(stripped.contains("::1 localhost"));
    }

    #[test]
    fn renders_www_alias() {
        let r = render_block(&["reddit.com".to_string()], Ipv4Addr::UNSPECIFIED);
        assert!(r.contains("0.0.0.0 reddit.com"));
        assert!(r.contains("0.0.0.0 www.reddit.com"));
    }

    #[test]
    fn skips_www_alias_when_already_www() {
        let r = render_block(&["www.example.com".to_string()], Ipv4Addr::UNSPECIFIED);
        assert!(r.contains("0.0.0.0 www.example.com"));
        assert!(!r.contains("www.www.example.com"));
    }

    /// The sink is written, not assumed: both the bare name and its `www.`
    /// alias must carry the address the caller chose, with no `0.0.0.0` left
    /// anywhere in the region.
    #[test]
    fn renders_the_given_sink_for_the_bare_and_www_forms() {
        let r = render_block(&["reddit.com".to_string()], Ipv4Addr::LOCALHOST);
        assert!(r.contains("127.0.0.1 reddit.com"));
        assert!(r.contains("127.0.0.1 www.reddit.com"));
        assert!(!r.contains("0.0.0.0"));
        // An already-`www.` name keeps the same single-line treatment.
        let r = render_block(&["www.example.com".to_string()], Ipv4Addr::LOCALHOST);
        assert!(r.contains("127.0.0.1 www.example.com"));
        assert!(!r.contains("www.www.example.com"));
    }

    #[test]
    fn strip_unterminated_region_drops_to_eof() {
        // A begin marker with no matching end marker: everything from the
        // marker to EOF is treated as managed and dropped. Documents current
        // behavior — a truncated region can never leak stale block entries.
        let input = format!(
            "127.0.0.1 localhost\n{}\n0.0.0.0 reddit.com\n0.0.0.0 news.ycombinator.com\n",
            HOSTS_BEGIN
        );
        let stripped = strip_managed(&input);
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }

    #[test]
    fn strip_removes_multiple_regions() {
        let input = format!(
            "127.0.0.1 localhost\n{b}\n0.0.0.0 reddit.com\n{e}\n::1 localhost\n{b}\n0.0.0.0 x.com\n{e}\n# user comment\n",
            b = HOSTS_BEGIN,
            e = HOSTS_END
        );
        let stripped = strip_managed(&input);
        assert!(!stripped.contains("reddit.com"));
        assert!(!stripped.contains("x.com"));
        assert!(stripped.contains("127.0.0.1 localhost"));
        assert!(stripped.contains("::1 localhost"));
        assert!(stripped.contains("# user comment"));
    }

    #[test]
    fn strip_recognizes_indented_markers() {
        // Markers are matched after trim_start, so a hand-indented region is
        // still recognized and stripped.
        let input = format!(
            "127.0.0.1 localhost\n  {}\n0.0.0.0 reddit.com\n\t{}\n::1 localhost\n",
            HOSTS_BEGIN, HOSTS_END
        );
        let stripped = strip_managed(&input);
        assert!(!stripped.contains("reddit.com"));
        assert!(stripped.contains("127.0.0.1 localhost"));
        assert!(stripped.contains("::1 localhost"));
    }

    #[test]
    fn strip_region_only_file_yields_empty() {
        let input = format!("{}\n0.0.0.0 reddit.com\n{}\n", HOSTS_BEGIN, HOSTS_END);
        let stripped = strip_managed(&input);
        assert!(stripped.trim().is_empty());
    }

    #[test]
    fn contains_managed_detects_marker() {
        let input = format!(
            "127.0.0.1 localhost\n{}\n0.0.0.0 reddit.com\n{}\n",
            HOSTS_BEGIN, HOSTS_END
        );
        assert!(contains_managed(&input));
    }

    #[test]
    fn contains_managed_absent_without_marker() {
        assert!(!contains_managed("127.0.0.1 localhost\n::1 localhost\n"));
        assert!(!contains_managed(""));
    }

    #[test]
    fn contains_managed_detects_indented_marker() {
        // Same trim_start tolerance as strip_managed: a hand-indented begin
        // marker still counts as an active region.
        let input = format!("127.0.0.1 localhost\n\t  {}\n0.0.0.0 x.com\n", HOSTS_BEGIN);
        assert!(contains_managed(&input));
    }

    #[test]
    fn tamper_license_gates_the_immutable_bit() {
        // The one license-sensitive decision in this module: +i only with
        // the tamper_protection feature; without it the write still happens
        // (free-tier enforcement) and only the hardening step is skipped.
        assert_eq!(hardening_for(true), Hardening::SetImmutable);
        assert_eq!(hardening_for(false), Hardening::Skip);
    }

    /// Nothing that could break out of its line reaches the file: a newline
    /// (a second, attacker-chosen line), whitespace (a second alias on the
    /// same line), a comment start, or anything outside printable ASCII.
    #[test]
    fn render_block_never_emits_an_unsafe_line() {
        let unsafe_entries = [
            "reddit.com\n0.0.0.0 evil.example",
            "reddit.com\r\n0.0.0.0 evil.example",
            "reddit.com evil.example",
            "reddit.com\tevil.example",
            "reddit.com#evil",
            "#reddit.com",
            "r\u{00e9}ddit.com",
            "reddit.com\0",
            "\u{7f}",
        ];
        let domains: Vec<String> = unsafe_entries.iter().map(|s| s.to_string()).collect();
        assert_eq!(render_block(&domains, Ipv4Addr::UNSPECIFIED), "\n");
        // And each one alone, so a later entry cannot mask an earlier miss.
        for d in unsafe_entries {
            assert_eq!(
                render_block(&[d.to_string()], Ipv4Addr::UNSPECIFIED),
                "\n",
                "entry {d:?}"
            );
        }
    }

    /// Every accepted domain yields at most two lines (name + `www.` alias),
    /// so the region's size is bounded by the list length — an entry cannot
    /// smuggle extra lines in.
    #[test]
    fn render_block_line_count_is_bounded() {
        let domains: Vec<String> = [
            "reddit.com",
            "www.example.com",
            "reddit.com\n0.0.0.0 evil.example\n0.0.0.0 more.example",
            "news.ycombinator.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let rendered = render_block(&domains, Ipv4Addr::UNSPECIFIED);
        // The body opens with one blank line, then the entries.
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "");
        assert!(lines.len() <= 1 + 2 * domains.len());
        // Exactly: two names with an alias, one already-www, one refused.
        assert_eq!(lines.len(), 1 + 2 + 1 + 2);
        assert!(!rendered.contains("evil.example"));
        assert!(!rendered.contains("more.example"));
        // Every emitted line is `<sink> <name>` and nothing else.
        for line in &lines[1..] {
            let mut fields = line.split(' ');
            assert_eq!(fields.next(), Some("0.0.0.0"));
            assert!(fields.next().is_some_and(line_safe));
            assert_eq!(fields.next(), None, "line {line:?}");
        }
    }

    #[test]
    fn empty_domains_keep_stripped_only() {
        let input = "127.0.0.1 localhost\n";
        // strip + render with empty list yields the unchanged input
        let stripped = strip_managed(input);
        let rendered = render_block(&[], Ipv4Addr::UNSPECIFIED);
        assert!(rendered.is_empty() || rendered.trim().is_empty());
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }
}
