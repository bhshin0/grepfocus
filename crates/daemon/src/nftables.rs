//! DoH (DNS-over-HTTPS) endpoint blocking via `nft`.
//!
//! We install a small `inet` table that drops TCP 443 traffic to known
//! public DoH resolver IPs and all traffic on port 853 (DNS-over-TLS).
//! This closes the bypass where browsers — chiefly Firefox — skip
//! `/etc/hosts` by resolving names directly via Cloudflare/Mozilla over
//! HTTPS.
//!
//! Trade-offs (documented, not fixed):
//! - Doesn't catch DoH providers we don't list (custom endpoints,
//!   self-hosted resolvers, etc.).
//! - Breaks any legitimate non-DNS use of the listed IPs on port 443
//!   during active blocks (e.g. Cloudflare WARP, 1.1.1.1 marketing site).
//! - A determined user can configure their browser to use a different
//!   DoH endpoint. Same friction-vs-adversary line we already drew.
//!
//! The table is named `frostbite_doh` and is independent of firewalld /
//! any existing user firewall rules. Drop rules in any table take effect
//! regardless of accept rules elsewhere.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context};
use tracing::{debug, warn};

const NFT: &str = "/usr/sbin/nft";
const TABLE: &str = "frostbite_doh";

/// IPv4 addresses of well-known public DoH resolvers, plus NextDNS anycast
/// ranges. Only TCP 443 to these is dropped — port 53 is intentionally
/// left alone so the OS resolver (and our `/etc/hosts` override) still
/// work.
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

/// Install the table. Idempotent — removes any prior copy first.
pub fn apply() -> anyhow::Result<()> {
    let _ = clear(); // ignore "table doesn't exist" failures

    let ruleset = build_ruleset();
    let mut child = Command::new(NFT)
        .arg("-f")
        .arg("-")
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
    Command::new(NFT)
        .args(["list", "table", "inet", TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Remove the table if present. Idempotent — silent on absence.
pub fn clear() -> anyhow::Result<()> {
    let out = Command::new(NFT)
        .args(["delete", "table", "inet", TABLE])
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

        # Block all DNS-over-TLS (port 853 has no legitimate non-resolver use).
        tcp dport 853 drop
        udp dport 853 drop
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
    }
}
