//! Where an export lands and what it is called. Pure: `main.rs` supplies
//! `$HOME`, the text of `user-dirs.dirs`, the directory probe and the clock,
//! and calls [`write_new`] for the one write.
//!
//! Rust-side rather than an `<a download>` of a Blob: WebKitGTK's default
//! download handler saves silently into XDG Downloads, fails silently on an
//! existing name, and there is no Save-As without the dialog plugin. Writing
//! here costs the same zero dependencies and lets the GUI say exactly where
//! the file went.

use std::path::{Path, PathBuf};

/// The user's download directory: the `XDG_DOWNLOAD_DIR` entry of
/// `~/.config/user-dirs.dirs` (xdg-user-dirs' format — a shell-quoted value
/// that is absolute or `$HOME`-relative) when it names a directory, else
/// `~/Downloads` when that is one, else `~`. `is_dir` is the probe, passed
/// in so the parsing is testable without a filesystem.
pub fn download_dir(
    home: &Path,
    user_dirs: Option<&str>,
    is_dir: impl Fn(&Path) -> bool,
) -> PathBuf {
    if let Some(dir) = user_dirs.and_then(|text| xdg_download_dir(home, text)) {
        if is_dir(&dir) {
            return dir;
        }
    }
    let downloads = home.join("Downloads");
    if is_dir(&downloads) {
        downloads
    } else {
        home.to_path_buf()
    }
}

/// The `XDG_DOWNLOAD_DIR` entry of a `user-dirs.dirs` text, `$HOME`
/// expanded; `None` when absent or not an absolute or `$HOME` path. The
/// last entry wins, as it would in the shell that sources the file, and
/// `$HOME` counts only on its own or before a `/` — `$HOMEfoo` is another
/// (unset) variable there.
fn xdg_download_dir(home: &Path, text: &str) -> Option<PathBuf> {
    let value = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.strip_prefix("XDG_DOWNLOAD_DIR="))
        .next_back()?
        .trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    if let Some(rest) = value.strip_prefix("$HOME") {
        if !(rest.is_empty() || rest.starts_with('/')) {
            return None;
        }
        let rest = rest.trim_start_matches('/');
        return Some(if rest.is_empty() {
            home.to_path_buf()
        } else {
            home.join(rest)
        });
    }
    if value.starts_with('/') {
        return Some(PathBuf::from(value));
    }
    None
}

/// `grepfocus-config-YYYYMMDD-HHMMSS.json` for the local wall time `now`
/// (the caller passes `Local::now().naive_local()`; a naive time keeps the
/// formatting independent of the machine's zone).
pub fn export_file_name(now: chrono::NaiveDateTime) -> String {
    format!("grepfocus-config-{}.json", now.format("%Y%m%d-%H%M%S"))
}

/// `path` for the Block list's message: a `$HOME` prefix shown as `~`.
pub fn display_path(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if !rest.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    }
}

/// Create `path` holding `contents`, never overwriting: two exports in the
/// same second get an error, not a silent replacement. Private to the user
/// (mode 0600) — block names and domains are personal, and a download
/// directory is often readable by every account on the machine.
pub fn write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    const HOME: &str = "/home/kat";

    fn home() -> PathBuf {
        PathBuf::from(HOME)
    }

    /// A probe that says yes to exactly `dirs`.
    fn dirs(dirs: &'static [&'static str]) -> impl Fn(&Path) -> bool {
        move |p| dirs.iter().any(|d| Path::new(d) == p)
    }

    const USER_DIRS: &str = r#"# This file is written by xdg-user-dirs-update
# Format is XDG_xxx_DIR="$HOME/yyy", where yyy is a shell-escaped
# homedir-relative path, or XDG_xxx_DIR="/yyy", where /yyy is an
# absolute path. No other format is supported.
#
XDG_DESKTOP_DIR="$HOME/Desktop"
XDG_DOWNLOAD_DIR="$HOME/Pobrane"
XDG_TEMPLATES_DIR="$HOME/Templates"
"#;

    #[test]
    fn download_dir_reads_the_xdg_entry_with_home_expansion_and_quotes() {
        let d = download_dir(&home(), Some(USER_DIRS), dirs(&["/home/kat/Pobrane"]));
        assert_eq!(d, Path::new("/home/kat/Pobrane"));
        // Absolute entries and unquoted values are read as-is; the last
        // entry wins; surrounding whitespace is ignored.
        let text = "XDG_DOWNLOAD_DIR=\"$HOME/old\"\n  XDG_DOWNLOAD_DIR=/mnt/data/dl  \n";
        let d = download_dir(
            &home(),
            Some(text),
            dirs(&["/mnt/data/dl", "/home/kat/old"]),
        );
        assert_eq!(d, Path::new("/mnt/data/dl"));
        // `$HOME` alone (xdg-user-dirs' "disabled") is the home directory.
        let d = download_dir(&home(), Some("XDG_DOWNLOAD_DIR=\"$HOME\"\n"), dirs(&[HOME]));
        assert_eq!(d, home());
        let d = download_dir(
            &home(),
            Some("XDG_DOWNLOAD_DIR=\"$HOME/\"\n"),
            dirs(&[HOME]),
        );
        assert_eq!(d, home());
    }

    #[test]
    fn download_dir_ignores_comments_and_unusable_entries() {
        // A commented-out entry is not an entry.
        let text = "#XDG_DOWNLOAD_DIR=\"$HOME/Nope\"\n";
        let d = download_dir(
            &home(),
            Some(text),
            dirs(&["/home/kat/Nope", "/home/kat/Downloads"]),
        );
        assert_eq!(d, Path::new("/home/kat/Downloads"));
        // Relative, empty and oddly-prefixed values fall back too.
        for text in [
            "XDG_DOWNLOAD_DIR=\"Downloads\"\n",
            "XDG_DOWNLOAD_DIR=\"\"\n",
            "XDG_DOWNLOAD_DIR=\n",
            "XDG_DOWNLOAD_DIR=\"~/dl\"\n",
            "XDG_DOWNLOAD_DIR=\"${HOME}/dl\"\n",
        ] {
            let d = download_dir(&home(), Some(text), dirs(&["/home/kat/Downloads"]));
            assert_eq!(d, Path::new("/home/kat/Downloads"), "{text:?}");
        }
        // `$HOME` is a variable name, not a prefix: `$HOMEfoo` is not
        // `$HOME/foo`, even when that directory exists.
        for text in [
            "XDG_DOWNLOAD_DIR=\"$HOMEfoo\"\n",
            "XDG_DOWNLOAD_DIR=\"$HOME_backup/foo\"\n",
        ] {
            let d = download_dir(
                &home(),
                Some(text),
                dirs(&[
                    "/home/kat/foo",
                    "/home/kat/_backup/foo",
                    "/home/kat/Downloads",
                ]),
            );
            assert_eq!(d, Path::new("/home/kat/Downloads"), "{text:?}");
        }
    }

    #[test]
    fn download_dir_falls_back_to_downloads_then_home() {
        // The configured directory is gone: ~/Downloads if it exists…
        let d = download_dir(&home(), Some(USER_DIRS), dirs(&["/home/kat/Downloads"]));
        assert_eq!(d, Path::new("/home/kat/Downloads"));
        // …else the home directory itself.
        let d = download_dir(&home(), Some(USER_DIRS), dirs(&[]));
        assert_eq!(d, home());
        // No user-dirs.dirs at all: the same two steps.
        let d = download_dir(&home(), None, dirs(&["/home/kat/Downloads"]));
        assert_eq!(d, Path::new("/home/kat/Downloads"));
        let d = download_dir(&home(), None, dirs(&[]));
        assert_eq!(d, home());
    }

    #[test]
    fn export_file_name_is_dated_to_the_second() {
        let at = NaiveDate::from_ymd_opt(2026, 10, 2)
            .unwrap()
            .and_hms_opt(10, 15, 7)
            .unwrap();
        assert_eq!(
            export_file_name(at),
            "grepfocus-config-20261002-101507.json"
        );
        // Every field zero-padded, so the names sort by time.
        let at = NaiveDate::from_ymd_opt(2026, 1, 5)
            .unwrap()
            .and_hms_opt(3, 4, 5)
            .unwrap();
        assert_eq!(
            export_file_name(at),
            "grepfocus-config-20260105-030405.json"
        );
    }

    #[test]
    fn display_path_abbreviates_home() {
        let p = Path::new("/home/kat/Downloads/grepfocus-config-20261002-101507.json");
        assert_eq!(
            display_path(p, &home()),
            "~/Downloads/grepfocus-config-20261002-101507.json"
        );
        assert_eq!(
            display_path(Path::new("/mnt/dl/x.json"), &home()),
            "/mnt/dl/x.json"
        );
        // A prefix match is by path component, not by text.
        assert_eq!(
            display_path(Path::new("/home/kate/x.json"), &home()),
            "/home/kate/x.json"
        );
        assert_eq!(display_path(&home(), &home()), HOME);
    }

    #[test]
    fn write_new_creates_the_file_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grepfocus-config-20261002-101507.json");
        write_new(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }

    #[test]
    fn write_new_refuses_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grepfocus-config-20261002-101507.json");
        write_new(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        let e = write_new(&path, b"[]").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"{}", "untouched");
    }
}
