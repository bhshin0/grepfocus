import { describe, expect, it } from "vitest";
import type {
  ActiveBlock,
  Block,
  BrowserPolicyFailKind,
  BrowserPolicyState,
  BrowserPolicyStatus,
  Health,
  HostsLockStatus,
  NftStatus,
  Status,
} from "../types";
import { fmtClock } from "./format";
import { RESTART_HINT_SECS, aboutLine, browserName, healthNotices, healthSummary, joinNames } from "./health";

const NOW = 1_700_000_000;

/// A current daemon with nothing to report — the counterpart of the Rust
/// tests' `reporting()`.
function health(over: Partial<Health> = {}): Health {
  return {
    daemon_version: "0.6.0",
    daemon_exe: "/usr/bin/grepfocusd",
    install_kind: "package",
    nft: { kind: "ok" },
    hosts: { kind: "locked" },
    hosts_reapplies: 0,
    nft_reinstalls: 0,
    proxy: "holding",
    browser_policies: [],
    startup_notes: [],
    last_error: null,
    last_error_unix: null,
    ...over,
  };
}

function status(over: Partial<Status> = {}, h: Partial<Health> = {}): Status {
  return {
    active: [],
    now_unix: NOW,
    password_set: false,
    unlocked: false,
    allowance: [],
    allowance_used: [],
    license_present: false,
    license_valid: false,
    license_kind: null,
    license_email: null,
    license_expires_at: null,
    licensed_features: [],
    pomodoro: null,
    settings: { notifications: true, instant_breaks: true },
    instant_breaks_degraded: false,
    health: health(h),
    update: { kind: "up_to_date" },
    ...over,
  };
}

function block(domains: string[]): Block {
  return { id: 1, name: "Social", domains, apps: [], allowance_secs_per_day: 0, allowance: null, lock: "normal" };
}

function active(domains: string[]): ActiveBlock {
  return {
    block: block(domains),
    started_at_unix: NOW - 60,
    ends_at_unix: NOW + 600,
    originator: { kind: "manual" },
    break_until_unix: null,
    allowance: null,
    lock: "normal",
  };
}

function policy(browser: string, state: BrowserPolicyState, since = NOW): BrowserPolicyStatus {
  return { browser, path: `/etc/${browser}/policies.json`, state, since_unix: since };
}

describe("healthNotices", () => {
  it("says nothing for a daemon too old to report, whatever the fields hold", () => {
    const s = status(
      { active: [active(["reddit.com"])] },
      {
        daemon_version: "",
        last_error: "hosts: read-only file system",
        nft: { kind: "failed", reason: "nft: command not found" },
        hosts: { kind: "unlocked", reason: "chattr failed" },
      },
    );
    expect(healthNotices(s)).toEqual([]);
  });

  it("a healthy reporting daemon raises no notice", () => {
    expect(healthNotices(status())).toEqual([]);
  });

  it("last_error under a domain block is RED and names the enforcement gap", () => {
    const s = status({ active: [active(["reddit.com"])] }, { last_error: "hosts: read-only file system" });
    expect(healthNotices(s)).toEqual([
      {
        level: "error",
        text: "Website blocking may not be enforced: the /etc/hosts change could not be applied (hosts: read-only file system). The daemon retries every second; see journalctl -u grepfocusd",
      },
    ]);
  });

  it("last_error without a domain block is still RED, as a failed teardown", () => {
    const s = status({}, { last_error: "hosts: read-only file system" });
    expect(healthNotices(s)).toEqual([
      {
        level: "error",
        text: "The last /etc/hosts change could not be applied (hosts: read-only file system) — previously blocked sites may still be blocked. The daemon retries every second; see journalctl -u grepfocusd",
      },
    ]);
  });

  it("an app-only active block is not a domain block", () => {
    const s = status({ active: [active([])] }, { last_error: "x" });
    expect(healthNotices(s)[0].text).toMatch(/^The last \/etc\/hosts change/);
  });

  it("nft failed is RED only while a domain block is active", () => {
    const failed: Partial<Health> = { nft: { kind: "failed", reason: "nft: command not found" } };
    expect(healthNotices(status({ active: [active(["reddit.com"])] }, failed))).toEqual([
      {
        level: "error",
        text: "Active blocks can be bypassed: DoH protection (nftables) failed — nft: command not found. Browsers using DNS-over-HTTPS (Firefox, Mullvad Browser) may still reach blocked sites.",
      },
    ]);
    expect(healthNotices(status({}, failed))).toEqual([]);
  });

  it("an unlocked hosts file is YELLOW", () => {
    const s = status({}, { hosts: { kind: "unlocked", reason: "chattr: Operation not permitted" } });
    expect(healthNotices(s)).toEqual([
      {
        level: "warn",
        text: "Tamper protection off: /etc/hosts is not locked (chattr: Operation not permitted). Blocking still works, but the file can be edited while a block is active.",
      },
    ]);
  });

  it("a stale DoH table is YELLOW with the nft command that removes it", () => {
    const s = status({}, { nft: { kind: "stale_table", reason: "table busy" } });
    expect(healthNotices(s)).toEqual([
      {
        level: "warn",
        text: "The DoH block table could not be removed after the last block (table busy) — DNS-over-HTTPS resolvers stay blocked (Mullvad Browser loses DNS). The daemon retries every 30 s; to remove it now: sudo nft delete table inet grepfocus_doh",
      },
    ]);
  });

  const remedies: [BrowserPolicyFailKind, string][] = [
    ["not_json", "Fix or remove /etc/firefox/policies.json; GrepFocus retries every minute."],
    ["symlink", "Replace /etc/firefox/policies.json with a real file or add DNSOverHTTPS there yourself."],
    ["io", "GrepFocus retries every minute."],
  ];
  it.each(remedies)("a fixable browser policy failure (%s) is YELLOW with its remedy", (failKind, remedy) => {
    const s = status(
      {},
      { browser_policies: [policy("firefox", { kind: "failed", fail_kind: failKind, reason: "parse error" })] },
    );
    expect(healthNotices(s)).toEqual([
      {
        level: "warn",
        text: `Firefox: DoH policy not installed (parse error). Firefox may bypass blocks via DNS-over-HTTPS. ${remedy}`,
      },
    ]);
  });

  it("an unsupported browser is INFO", () => {
    const s = status(
      {},
      {
        browser_policies: [
          policy("chromium-snap", { kind: "failed", fail_kind: "unsupported", reason: "snap confinement" }),
        ],
      },
    );
    expect(healthNotices(s)).toEqual([
      {
        level: "info",
        text: "Chromium (snap) is present but not covered (snap confinement). DoH may bypass blocks in it — see README → Known limits.",
      },
    ]);
  });

  it("a read-only policy path is INFO and names the path", () => {
    const s = status(
      {},
      {
        browser_policies: [
          policy("firefox-flatpak", { kind: "failed", fail_kind: "read_only_fs", reason: "EROFS" }),
        ],
      },
    );
    expect(healthNotices(s)).toEqual([
      {
        level: "info",
        text: "Cannot write /etc/firefox-flatpak/policies.json: read-only filesystem. DoH may bypass blocks in Firefox (Flatpak); not fixable on this system layout.",
      },
    ]);
  });

  it("a failure kind this build cannot judge says nothing", () => {
    const s = status(
      {},
      { browser_policies: [policy("firefox", { kind: "failed", fail_kind: "unknown", reason: "?" })] },
    );
    expect(healthNotices(s)).toEqual([]);
  });

  it("a browser slug this build does not know renders raw", () => {
    const s = status(
      {},
      { browser_policies: [policy("librewolf", { kind: "failed", fail_kind: "io", reason: "EACCES" })] },
    );
    expect(healthNotices(s)[0].text).toBe(
      "librewolf: DoH policy not installed (EACCES). librewolf may bypass blocks via DNS-over-HTTPS. GrepFocus retries every minute.",
    );
  });

  it("not_installed policies say nothing", () => {
    expect(healthNotices(status({}, { browser_policies: [policy("brave", { kind: "not_installed" })] }))).toEqual(
      [],
    );
  });

  it("startup notes are one YELLOW line with the count", () => {
    const s = status({}, { startup_notes: ["a", "b", "c"] });
    expect(healthNotices(s)).toEqual([
      {
        level: "warn",
        text: "3 stored block entries were changed or dropped when the daemon started (invalid domains or app matchers from an older version). Details: journalctl -u grepfocusd | grep sanitized",
      },
    ]);
  });

  it("a fresh policy write earns the restart hint, cut off at the latest write", () => {
    const s = status(
      {},
      {
        browser_policies: [
          policy("firefox", { kind: "written" }, NOW - 100),
          policy("mullvad-browser", { kind: "merged" }, NOW - 50),
          policy("chromium", { kind: "written" }, NOW - 200),
        ],
      },
    );
    expect(healthNotices(s)).toEqual([
      {
        level: "info",
        text: `GrepFocus switched DNS-over-HTTPS off in Firefox, Mullvad Browser and Chromium through a system policy so blocks apply there (they will say 'managed by your organization'). Restart Firefox-based browsers once if they were open before ${fmtClock(NOW - 50)}.`,
      },
    ]);
  });

  it("the restart hint expires RESTART_HINT_SECS after the write", () => {
    const at = (age: number) => status({}, { browser_policies: [policy("firefox", { kind: "written" }, NOW - age)] });
    expect(healthNotices(at(RESTART_HINT_SECS))).toEqual([]);
    expect(healthNotices(at(RESTART_HINT_SECS - 1))).toHaveLength(1);
  });

  it("a degraded proxy is INFO only while instant breaks are on", () => {
    expect(healthNotices(status({}, { proxy: "degraded" }))).toEqual([
      {
        level: "info",
        text: "Instant breaks unavailable — port 80 or 443 is in use, so breaks may take up to a minute to show in an already-open tab. Blocking is unaffected.",
      },
    ]);
    const off = status({ settings: { notifications: true, instant_breaks: false } }, { proxy: "degraded" });
    expect(healthNotices(off)).toEqual([]);
  });

  it("orders RED before YELLOW before INFO whatever the rule order", () => {
    const s = status(
      { active: [active(["reddit.com"])] },
      {
        proxy: "degraded",
        hosts: { kind: "unlocked", reason: "r" },
        last_error: "e",
        nft: { kind: "failed", reason: "n" },
        startup_notes: ["x"],
      },
    );
    expect(healthNotices(s).map((n) => n.level)).toEqual(["error", "error", "warn", "warn", "info"]);
  });
});

describe("browserName", () => {
  it.each([
    ["firefox", "Firefox"],
    ["firefox-flatpak", "Firefox (Flatpak)"],
    ["mullvad-browser", "Mullvad Browser"],
    ["chromium", "Chromium"],
    ["chromium-snap", "Chromium (snap)"],
    ["chrome", "Google Chrome"],
    ["brave", "Brave"],
  ])("maps the slug %s to %s", (slug, name) => {
    expect(browserName(slug)).toBe(name);
  });

  it("leaves an unknown slug raw rather than dropping it", () => {
    expect(browserName("librewolf")).toBe("librewolf");
  });
});

describe("joinNames", () => {
  it.each([
    [[], ""],
    [["Firefox"], "Firefox"],
    [["Firefox", "Chromium"], "Firefox and Chromium"],
    [["Firefox", "Mullvad Browser", "Chromium"], "Firefox, Mullvad Browser and Chromium"],
  ])("joins %j as %j", (names, text) => {
    expect(joinNames(names)).toBe(text);
  });
});

describe("healthSummary", () => {
  it("renders every enforcement state on one row", () => {
    expect(healthSummary(status({}, { hosts_reapplies: 2, nft_reinstalls: 1 }))).toBe(
      "Enforcement — DoH block (nft): ok · /etc/hosts lock: locked · instant-break proxy: holding · re-applies since daemon start: hosts 2, nft 1",
    );
  });

  const nftWords: [NftStatus, string][] = [
    [{ kind: "failed", reason: "nft: command not found" }, "FAILED"],
    [{ kind: "stale_table", reason: "table busy" }, "stale table (table busy)"],
    [{ kind: "not_applicable" }, "not applicable"],
    [{ kind: "unknown" }, "unknown"],
  ];
  it.each(nftWords)("words the nft state %j as %s", (nft, word) => {
    expect(healthSummary(status({}, { nft }))).toContain(`DoH block (nft): ${word} ·`);
  });

  const hostsWords: [HostsLockStatus, string][] = [
    [{ kind: "unlocked", reason: "chattr failed" }, "NOT locked"],
    [{ kind: "not_applicable" }, "not applicable"],
    [{ kind: "unknown" }, "unknown"],
  ];
  it.each(hostsWords)("words the hosts lock %j as %s", (hosts, word) => {
    expect(healthSummary(status({}, { hosts }))).toContain(`/etc/hosts lock: ${word} ·`);
  });

  it("reads an unattempted lock under a domain block as the premium gate", () => {
    const unlicensed = status({ active: [active(["reddit.com"])] }, { hosts: { kind: "not_applicable" } });
    expect(healthSummary(unlicensed)).toContain("/etc/hosts lock: off (premium feature) ·");
    const licensed = status(
      { active: [active(["reddit.com"])], license_valid: true, licensed_features: ["tamper_protection"] },
      { hosts: { kind: "not_applicable" } },
    );
    expect(healthSummary(licensed)).toContain("/etc/hosts lock: not applicable ·");
  });

  it("passes the proxy state through verbatim", () => {
    expect(healthSummary(status({}, { proxy: "degraded" }))).toContain("instant-break proxy: degraded ·");
  });
});

describe("aboutLine", () => {
  it("an unreachable daemon", () => {
    expect(aboutLine("0.6.0", null)).toBe("GrepFocus 0.6.0 · daemon unreachable");
  });

  it("leaves the app version out when app_env failed", () => {
    expect(aboutLine(null, null)).toBe("GrepFocus · daemon unreachable");
  });

  it("a daemon that predates health reporting", () => {
    expect(aboutLine("0.6.0", health({ daemon_version: "" }))).toBe(
      "GrepFocus 0.6.0 · daemon: older version (no health reporting)",
    );
  });

  it("a reporting daemon names its executable", () => {
    expect(aboutLine("0.6.0", health())).toBe("GrepFocus 0.6.0 · daemon 0.6.0 (/usr/bin/grepfocusd)");
  });

  it("falls back to the install kind without an executable path", () => {
    expect(aboutLine("0.6.0", health({ daemon_exe: "", install_kind: "local" }))).toBe(
      "GrepFocus 0.6.0 · daemon 0.6.0 (local)",
    );
  });
});
