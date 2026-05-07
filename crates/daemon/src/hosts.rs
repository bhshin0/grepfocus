//! /etc/hosts manipulation, with chattr +i to make the block tamper-resistant.
//!
//! The managed region is delimited by `HOSTS_BEGIN` / `HOSTS_END` markers.
//! Any content outside that region is preserved verbatim.

use std::fs;
use std::process::Command;

use anyhow::{anyhow, Context};
use tracing::debug;

use crate::paths::{HOSTS, HOSTS_BEGIN, HOSTS_END};

/// Apply the block: remove any existing managed region, append a fresh one
/// with all blocked domains, then mark /etc/hosts immutable.
pub fn apply_block(domains: &[String]) -> anyhow::Result<()> {
    chattr_immutable(HOSTS, false).ok(); // best-effort unlock if previously locked
    let original = fs::read_to_string(HOSTS).context("reading /etc/hosts")?;
    let stripped = strip_managed(&original);
    let new = if domains.is_empty() {
        stripped
    } else {
        format!("{}\n{}\n{}{}\n", stripped.trim_end(), HOSTS_BEGIN, render_block(domains), HOSTS_END)
    };
    write_atomic(HOSTS, &new)?;
    chattr_immutable(HOSTS, true)?;
    Ok(())
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
    if stripped != original {
        write_atomic(HOSTS, &stripped)?;
    }
    Ok(())
}

fn render_block(domains: &[String]) -> String {
    let mut out = String::from("\n");
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        out.push_str(&format!("0.0.0.0 {}\n", d));
        if !d.starts_with("www.") {
            out.push_str(&format!("0.0.0.0 www.{}\n", d));
        }
    }
    out
}

fn strip_managed(s: &str) -> String {
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

fn write_atomic(path: &str, content: &str) -> anyhow::Result<()> {
    let tmp = format!("{}.frostbite.tmp", path);
    fs::write(&tmp, content).with_context(|| format!("writing {}", tmp))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming over {}", path))?;
    Ok(())
}

/// Set or clear the immutable bit by shelling out to `chattr`.
/// We rely on coreutils being installed (it always is on a Linux system).
fn chattr_immutable(path: &str, set: bool) -> anyhow::Result<()> {
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
        let r = render_block(&["reddit.com".to_string()]);
        assert!(r.contains("0.0.0.0 reddit.com"));
        assert!(r.contains("0.0.0.0 www.reddit.com"));
    }

    #[test]
    fn skips_www_alias_when_already_www() {
        let r = render_block(&["www.example.com".to_string()]);
        assert!(r.contains("0.0.0.0 www.example.com"));
        assert!(!r.contains("www.www.example.com"));
    }

    #[test]
    fn empty_domains_keep_stripped_only() {
        let input = "127.0.0.1 localhost\n";
        // strip + render with empty list yields the unchanged input
        let stripped = strip_managed(input);
        let rendered = render_block(&[]);
        assert!(rendered.is_empty() || rendered.trim().is_empty());
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }
}
