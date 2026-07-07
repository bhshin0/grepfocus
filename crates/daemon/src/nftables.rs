//! DoH (DNS-over-HTTPS) endpoint blocking via `nft`.
//!
//! We install a small `inet` table that drops TCP 443 (DoH) and TCP/UDP
//! 853 (DNS-over-TLS) traffic to known public DoH resolver IPs. This
//! closes the bypass where browsers — chiefly Firefox — skip `/etc/hosts`
//! by resolving names directly via Cloudflare/Mozilla over HTTPS.
//!
//! Trade-offs (documented, not fixed):
//! - Doesn't catch DoH providers we don't list (custom endpoints,
//!   self-hosted resolvers, etc.).
//! - Breaks any legitimate non-DNS use of the listed IPs on port 443
//!   during active blocks (e.g. Cloudflare WARP, 1.1.1.1 marketing site).
//! - DoT to unlisted/custom endpoints is allowed by design — the same
//!   line we draw for custom DoH. An unscoped 853 drop would kill ALL
//!   DNS for a system resolver (e.g. systemd-resolved) doing DoT to a
//!   private or custom endpoint: an effective network brick.
//! - A system resolver doing DoT to a *listed* public IP (e.g.
//!   `1.1.1.1:853`) still loses DNS during active blocks. The README
//!   documents it.
//! - A determined user can configure their browser to use a different
//!   DoH endpoint. Same friction-vs-adversary line we already drew.
//!
//! The table is named `frostbite_doh` and is independent of firewalld /
//! any existing user firewall rules. Drop rules in any table take effect
//! regardless of accept rules elsewhere.
//!
//! Every `nft` exec here is timeout-bounded (see `nft_command`): they all
//! run synchronously under the daemon's `applied` mutex, so a hung nft
//! would wedge the scheduler tick and Start/Break IPC forever.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context};
use tracing::{debug, warn};

const NFT: &str = "/usr/sbin/nft";
const TABLE: &str = "frostbite_doh";
/// coreutils `timeout` — same "coreutils is always installed" assumption we
/// already make for `chattr` in hosts.rs.
const TIMEOUT_BIN: &str = "/usr/bin/timeout";
/// Wall-clock bound for a single `nft` exec, in seconds. Generous for a
/// command that normally completes in milliseconds, but tight enough that a
/// stuck nf_tables commit lock can't wedge the daemon indefinitely.
const NFT_TIMEOUT_SECS: &str = "10";

/// IPv4 addresses of well-known public DoH resolvers, plus NextDNS anycast
/// ranges. Only TCP 443 and TCP/UDP 853 to these are dropped — port 53 is
/// intentionally left alone so the OS resolver (and our `/etc/hosts`
/// override) still work.
const DOH_V4: &[&str] = &[
    // Cloudflare 1.1.1.1
    "1.1.1.1",
    "1.0.0.1",
    // Google
    "8.8.8.8",
    "8.8.4.4",
    // Quad9
    "9.9.9.9",
    "149.112.112.112",
    // AdGuard
    "94.140.14.14",
    "94.140.15.15",
    // NextDNS anycast
    "45.90.28.0/24",
    "45.90.30.0/24",
];

const DOH_V6: &[&str] = &[
    // Cloudflare
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    // Google
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    // Quad9
    "2620:fe::fe",
    "2620:fe::9",
    // AdGuard
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
];

/// Build an `nft` invocation bounded by coreutils `timeout` (SIGTERM at
/// `NFT_TIMEOUT_SECS`, SIGKILL 2s later). A timed-out exec exits 124, which
/// reads as a plain failure and flows through the existing drift/retry
/// paths. Callers add their own stdio config (e.g. `apply`'s piped stdin).
fn nft_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(TIMEOUT_BIN);
    cmd.arg("--kill-after=2")
        .arg(NFT_TIMEOUT_SECS)
        .arg(NFT)
        .args(args);
    cmd
}

/// Install the table. Idempotent — removes any prior copy first.
pub fn apply() -> anyhow::Result<()> {
    let _ = clear(); // ignore "table doesn't exist" failures

    let ruleset = build_ruleset();
    let mut child = nft_command(&["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning nft (is nftables installed?)")?;

    child
        .stdin
        .as_mut()
        .expect("piped")
        .write_all(ruleset.as_bytes())
        .context("writing ruleset to nft stdin")?;
    drop(child.stdin.take());

    let out = child.wait_with_output().context("waiting on nft")?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft -f failed (status {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    debug!("installed nftables DoH block table");
    Ok(())
}

/// Whether the DoH block table currently exists in the live ruleset. Used by
/// `enforce::sync` to detect drift — a firewalld/ufw reload can flush the
/// whole ruleset and take our table with it. A spawn failure reads as
/// "absent": the caller re-applies, and *that* path surfaces the real error.
pub fn table_exists() -> bool {
    nft_command(&["list", "table", "inet", TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Remove the table if present. Idempotent — silent on absence.
pub fn clear() -> anyhow::Result<()> {
    let out = nft_command(&["delete", "table", "inet", TABLE])
        .output()
        .context("spawning nft delete")?;
    if !out.status.success() {
        // Common case: table doesn't exist (first run, or already cleared).
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
            return Ok(());
        }
        warn!(stderr = %stderr.trim(), "nft delete returned non-zero");
    } else {
        debug!("removed nftables DoH block table");
    }
    Ok(())
}

fn build_ruleset() -> String {
    let v4 = DOH_V4.join(", ");
    let v6 = DOH_V6.join(", ");
    format!(
        r#"table inet {TABLE} {{
    chain output {{
        type filter hook output priority filter; policy accept;

        # Block known DoH endpoints (TCP 443 only).
        ip daddr {{ {v4} }} tcp dport 443 drop
        ip6 daddr {{ {v6} }} tcp dport 443 drop

        # Block DNS-over-TLS to the same known resolver IPs. Never drop
        # 853 globally: a system resolver doing DoT to a private/custom
        # endpoint would lose ALL DNS during blocks.
        ip daddr {{ {v4} }} tcp dport 853 drop
        ip daddr {{ {v4} }} udp dport 853 drop
        ip6 daddr {{ {v6} }} tcp dport 853 drop
        ip6 daddr {{ {v6} }} udp dport 853 drop
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_contains_critical_entries() {
        let r = build_ruleset();
        assert!(r.contains("1.1.1.1"));
        assert!(r.contains("8.8.8.8"));
        assert!(r.contains("2606:4700:4700::1111"));
        assert!(r.contains("tcp dport 443 drop"));
        assert!(r.contains("tcp dport 853 drop"));
        assert!(r.contains("udp dport 853 drop"));
        // Both families, both protocols: 2x 443 rules, 4x 853 rules.
        assert_eq!(r.lines().filter(|l| l.contains("dport 443")).count(), 2);
        assert_eq!(r.lines().filter(|l| l.contains("dport 853")).count(), 4);
    }

    /// Every 853 drop must be daddr-scoped. A global drop kills ALL DNS
    /// for anyone whose system resolver speaks DoT to a custom endpoint.
    #[test]
    fn dot_drops_are_scoped_to_known_resolvers() {
        let r = build_ruleset();
        for line in r.lines().filter(|l| l.contains("dport 853")) {
            assert!(line.contains("daddr"), "unscoped DoT drop: {line}");
        }
    }

    /// Plain DNS (port 53) must never be touched — the OS resolver and our
    /// `/etc/hosts` override depend on it. Check every token after a
    /// `dport`/`sport`, so port-set syntax (`dport { 53, 853 }`) is caught
    /// too; set punctuation is trimmed per token, which keeps "853" distinct
    /// from "53" and avoids a false positive.
    #[test]
    fn plain_dns_is_never_touched() {
        let r = build_ruleset();
        for line in r.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            for (i, tok) in tokens.iter().enumerate() {
                if *tok != "dport" && *tok != "sport" {
                    continue;
                }
                for port in &tokens[i + 1..] {
                    assert_ne!(
                        port.trim_matches(['{', '}', ',']),
                        "53",
                        "rule touches plain DNS: {line}"
                    );
                }
            }
        }
    }
}
