// Health: the Status-tab notices, the Settings diagnostics line and the about
// line. Pure (status in, text out) so every severity rule reads in one place;
// main.ts owns the DOM writers. All of it is silent on a daemon too old to
// report (`health.daemon_version === ""`) and for any `unknown` value.

import type { Health, Status } from "../types";
import { fmtClock } from "./format";

/// RED = blocking may not hold; YELLOW = enforced but degraded; INFO = worth
/// knowing, nothing to do.
export type NoticeLevel = "error" | "warn" | "info";

export interface HealthNotice {
  level: NoticeLevel;
  text: string;
}

/// Display names for the daemon's browser slugs. An unknown slug (a newer
/// daemon's browser) renders raw rather than being dropped.
const BROWSER_NAME: Record<string, string> = {
  firefox: "Firefox",
  "firefox-flatpak": "Firefox (Flatpak)",
  "mullvad-browser": "Mullvad Browser",
  chromium: "Chromium",
  "chromium-snap": "Chromium (snap)",
  chrome: "Google Chrome",
  brave: "Brave",
};

export function browserName(slug: string): string {
  return BROWSER_NAME[slug] ?? slug;
}

/// "Firefox" · "Firefox and Chromium" · "Firefox, Mullvad Browser and Chromium".
export function joinNames(names: string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/// How long after a policy file was written the "restart your browser" hint
/// stays up. Firefox-based browsers read policies only at start, so one that
/// was open at write time keeps DoH until restarted; past this window assume
/// it has been.
export const RESTART_HINT_SECS = 900;

/// The Status-tab notices for a status, RED → YELLOW → INFO.
///
/// The two RED rules are mirrored by `enforcement_red` in src/main.rs, which
/// drives the tray notification — change together.
export function healthNotices(s: Status): HealthNotice[] {
  const h = s.health;
  if (h.daemon_version === "") return [];
  const domainBlockActive = s.active.some((a) => a.block.domains.length > 0);
  const red: HealthNotice[] = [];
  const yellow: HealthNotice[] = [];
  const info: HealthNotice[] = [];

  // RED: the hosts write itself failed. Always shown — with no domain block
  // active it is a failed teardown, and the previous block's entries may
  // still be in /etc/hosts.
  if (h.last_error != null) {
    red.push({
      level: "error",
      text: domainBlockActive
        ? `Website blocking may not be enforced: the /etc/hosts change could not be applied (${h.last_error}). The daemon retries every second; see journalctl -u grepfocusd`
        : `The last /etc/hosts change could not be applied (${h.last_error}) — previously blocked sites may still be blocked. The daemon retries every second; see journalctl -u grepfocusd`,
    });
  }
  // RED: no DoH table under a live domain block. Without one there is nothing
  // to bypass, and the state clears at the next apply.
  if (h.nft.kind === "failed" && domainBlockActive) {
    red.push({
      level: "error",
      text: `Active blocks can be bypassed: DoH protection (nftables) failed — ${h.nft.reason}. Browsers using DNS-over-HTTPS (Firefox, Mullvad Browser) may still reach blocked sites.`,
    });
  }

  if (h.hosts.kind === "unlocked") {
    yellow.push({
      level: "warn",
      text: `Tamper protection off: /etc/hosts is not locked (${h.hosts.reason}). Blocking still works, but the file can be edited while a block is active.`,
    });
  }
  if (h.nft.kind === "stale_table") {
    yellow.push({
      level: "warn",
      text: `The DoH block table could not be removed after the last block (${h.nft.reason}) — DNS-over-HTTPS resolvers stay blocked (Mullvad Browser loses DNS). The daemon retries every 30 s; to remove it now: sudo nft delete table inet grepfocus_doh`,
    });
  }

  // Browser policies: a fixable failure is YELLOW with its remedy, one the
  // daemon cannot fix on this layout is INFO, and a fresh write earns the
  // one-time restart hint.
  const recentlyWritten: string[] = [];
  let lastWriteUnix = 0;
  for (const bp of h.browser_policies) {
    const name = browserName(bp.browser);
    const st = bp.state;
    if (st.kind === "failed") {
      switch (st.fail_kind) {
        case "not_json":
        case "symlink":
        case "io": {
          const remedy =
            st.fail_kind === "not_json"
              ? `Fix or remove ${bp.path}; GrepFocus retries every minute.`
              : st.fail_kind === "symlink"
                ? `Replace ${bp.path} with a real file or add DNSOverHTTPS there yourself.`
                : "GrepFocus retries every minute.";
          yellow.push({
            level: "warn",
            text: `${name}: DoH policy not installed (${st.reason}). ${name} may bypass blocks via DNS-over-HTTPS. ${remedy}`,
          });
          break;
        }
        case "unsupported":
          info.push({
            level: "info",
            text: `${name} is present but not covered (${st.reason}). DoH may bypass blocks in it — see README → Known limits.`,
          });
          break;
        case "read_only_fs":
          info.push({
            level: "info",
            text: `Cannot write ${bp.path}: read-only filesystem. DoH may bypass blocks in ${name}; not fixable on this system layout.`,
          });
          break;
        default:
          // `unknown`: a newer daemon's kind this build cannot judge.
          break;
      }
    } else if (
      (st.kind === "written" || st.kind === "merged") &&
      s.now_unix - bp.since_unix < RESTART_HINT_SECS
    ) {
      recentlyWritten.push(name);
      // The latest write is the conservative cut-off for "open before".
      lastWriteUnix = Math.max(lastWriteUnix, bp.since_unix);
    }
  }

  if (h.startup_notes.length > 0) {
    yellow.push({
      level: "warn",
      text: `${h.startup_notes.length} stored block entries were changed or dropped when the daemon started (invalid domains or app matchers from an older version). Details: journalctl -u grepfocusd | grep sanitized`,
    });
  }
  if (recentlyWritten.length > 0) {
    info.push({
      level: "info",
      text: `GrepFocus switched DNS-over-HTTPS off in ${joinNames(recentlyWritten)} through a system policy so blocks apply there (they will say 'managed by your organization'). Restart Firefox-based browsers once if they were open before ${fmtClock(lastWriteUnix)}.`,
    });
  }
  // The Settings tab carries the same note off the legacy bool; this one is
  // on the Status tab because that is where a lagging break is noticed.
  if (h.proxy === "degraded" && s.settings.instant_breaks) {
    info.push({
      level: "info",
      text: "Instant breaks unavailable — port 80 or 443 is in use, so breaks may take up to a minute to show in an already-open tab. Blocking is unaffected.",
    });
  }
  return [...red, ...yellow, ...info];
}

/// The Settings diagnostics line: every enforcement state on one row, for a
/// bug report or a journal cross-check. The drift counters are diagnostics
/// only — they never raise a notice. "off (premium feature)" is this side's
/// reading of a hosts lock that was never attempted; the daemon stays the only
/// source of "NOT locked" (attempted and failed).
export function healthSummary(s: Status): string {
  const h = s.health;
  const domainBlockActive = s.active.some((a) => a.block.domains.length > 0);
  const tamperLicensed = s.license_valid && s.licensed_features.includes("tamper_protection");
  let nft: string;
  switch (h.nft.kind) {
    case "ok":
      nft = "ok";
      break;
    case "failed":
      nft = "FAILED";
      break;
    case "stale_table":
      nft = `stale table (${h.nft.reason})`;
      break;
    case "not_applicable":
      nft = "not applicable";
      break;
    default:
      nft = "unknown";
  }
  let hosts: string;
  switch (h.hosts.kind) {
    case "locked":
      hosts = "locked";
      break;
    case "unlocked":
      hosts = "NOT locked";
      break;
    case "not_applicable":
      hosts = domainBlockActive && !tamperLicensed ? "off (premium feature)" : "not applicable";
      break;
    default:
      hosts = "unknown";
  }
  return `Enforcement — DoH block (nft): ${nft} · /etc/hosts lock: ${hosts} · instant-break proxy: ${h.proxy} · re-applies since daemon start: hosts ${h.hosts_reapplies}, nft ${h.nft_reinstalls}`;
}

/// The Settings about line: our version beside the daemon's. `h` null means
/// the daemon could not be reached; an empty `daemon_version` means it
/// answered but predates health reporting. `gui` null means `app_env` itself
/// failed, which leaves the version out rather than guessing one.
export function aboutLine(gui: string | null, h: Health | null): string {
  const app = gui ? `GrepFocus ${gui}` : "GrepFocus";
  if (h === null) return `${app} · daemon unreachable`;
  if (h.daemon_version === "") return `${app} · daemon: older version (no health reporting)`;
  return `${app} · daemon ${h.daemon_version} (${h.daemon_exe || h.install_kind})`;
}
