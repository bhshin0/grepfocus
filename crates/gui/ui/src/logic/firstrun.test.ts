import { describe, expect, it } from "vitest";
import type { ActiveBlock, AppEnv, PomodoroStatus, Status } from "../types";
import { serviceRemovalOffered, serviceRemovalRefusal, unreachableMode } from "./firstrun";

function env(over: Partial<AppEnv> = {}): AppEnv {
  return { appimage: false, gui_version: "0.6.0", packaged_daemon: false, local_daemon: false, ...over };
}

const NOW = 1_700_000_000;

/// An idle, current daemon; only `active` and `pomodoro` matter here.
function status(over: Partial<Status> = {}): Status {
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
    health: {
      daemon_version: "0.6.0",
      daemon_exe: "/usr/local/bin/grepfocusd",
      install_kind: "local",
      nft: { kind: "ok" },
      hosts: { kind: "locked" },
      hosts_reapplies: 0,
      nft_reinstalls: 0,
      proxy: "holding",
      browser_policies: [],
      startup_notes: [],
      last_error: null,
      last_error_unix: null,
    },
    update: { kind: "up_to_date" },
    ...over,
  };
}

const RUNNING_BLOCK: ActiveBlock = {
  block: {
    id: 1,
    name: "Social",
    domains: ["reddit.com"],
    apps: [],
    allowance_secs_per_day: 0,
    allowance: null,
    lock: "normal",
  },
  started_at_unix: NOW - 60,
  ends_at_unix: NOW + 600,
  originator: { kind: "manual" },
  break_until_unix: null,
  allowance: null,
  lock: "normal",
};

const RUNNING_POMODORO: PomodoroStatus = {
  block_id: 1,
  phase: "focus",
  phase_ends_unix: NOW + 1500,
  cycle_index: 0,
  cycles_total: 4,
};

// The connect-class messages verbatim from `connect_error_message` in
// crates/gui/src/client.rs, with the raw-error line `call()` appends.
// `unreachableMode` keys on two substrings of them — "daemon is not running"
// and "not allowed to talk" — which client.rs's tests pin; change together.
const NOT_RUNNING =
  "The GrepFocus daemon is not running.\n" +
  "Start it: sudo systemctl start grepfocusd\n" +
  "Not installed yet? From the repo: sudo ./packaging/install.sh\n" +
  "(connect /run/grepfocus/sock: No such file or directory (os error 2))";
// Same copy for a socket nobody listens on; only the raw error differs.
const REFUSED =
  "The GrepFocus daemon is not running.\n" +
  "Start it: sudo systemctl start grepfocusd\n" +
  "Not installed yet? From the repo: sudo ./packaging/install.sh\n" +
  "(connect /run/grepfocus/sock: Connection refused (os error 111))";
const DENIED =
  "Your user is not allowed to talk to the GrepFocus daemon.\n" +
  "Fix: sudo usermod -aG grepfocus $USER\n" +
  "then log out and back in — the new group needs a fresh login.\n" +
  "(connect /run/grepfocus/sock: Permission denied (os error 13))";

describe("unreachableMode", () => {
  it("a socket we may not open asks for a relogin, whatever the environment", () => {
    expect(unreachableMode(DENIED, null, false)).toBe("relogin");
    expect(unreachableMode(DENIED, env({ appimage: true, packaged_daemon: true }), true)).toBe("relogin");
  });

  it("the relogin tell wins over the not-running tell", () => {
    // Synthetic: client.rs never emits both, this pins the precedence.
    expect(unreachableMode(`${NOT_RUNNING}; ${DENIED}`, env({ appimage: true }), false)).toBe("relogin");
  });

  it("nothing listening with a packaged daemon is a stopped package service", () => {
    expect(unreachableMode(NOT_RUNNING, env({ packaged_daemon: true }), false)).toBe("packaged");
  });

  it("a refused connection reads like a missing socket", () => {
    expect(unreachableMode(REFUSED, env({ packaged_daemon: true }), false)).toBe("packaged");
    expect(unreachableMode(REFUSED, env({ appimage: true }), false)).toBe("install");
  });

  it("nothing listening with a local daemon is a stopped local service", () => {
    expect(unreachableMode(NOT_RUNNING, env({ local_daemon: true }), false)).toBe("stopped");
    expect(unreachableMode(NOT_RUNNING, env({ appimage: true, local_daemon: true }), false)).toBe("stopped");
  });

  it("with both binaries the package one decides", () => {
    expect(unreachableMode(NOT_RUNNING, env({ packaged_daemon: true, local_daemon: true }), false)).toBe(
      "packaged",
    );
  });

  it("an AppImage with no daemon binary is a first run", () => {
    expect(unreachableMode(NOT_RUNNING, env({ appimage: true }), false)).toBe("install");
  });

  it("an AppImage with no daemon binary after a removal says so instead", () => {
    expect(unreachableMode(NOT_RUNNING, env({ appimage: true }), true)).toBe("removed");
  });

  it("a reinstalled binary brings the ordinary modes back after a removal", () => {
    expect(unreachableMode(NOT_RUNNING, env({ appimage: true, local_daemon: true }), true)).toBe("stopped");
  });

  it("a non-AppImage with no daemon binary keeps the per-tab error", () => {
    expect(unreachableMode(NOT_RUNNING, env(), false)).toBeNull();
    expect(unreachableMode(NOT_RUNNING, env(), true)).toBeNull();
  });

  it("without an environment answer the dialog stays closed", () => {
    expect(unreachableMode(NOT_RUNNING, null, false)).toBeNull();
  });

  it.each([
    "invalid frame from daemon: expected value at line 1 column 1",
    "daemon protocol error: unexpected reply",
    "connection reset by peer",
  ])("a daemon we did reach (%s) never opens the dialog", (msg) => {
    expect(unreachableMode(msg, env({ appimage: true }), false)).toBeNull();
  });
});

describe("serviceRemovalOffered", () => {
  it("is for an AppImage with a local daemon and no packaged one", () => {
    expect(serviceRemovalOffered(env({ appimage: true, local_daemon: true }))).toBe(true);
  });

  it("is withheld without an environment answer", () => {
    expect(serviceRemovalOffered(null)).toBe(false);
  });

  it("is withheld from a non-AppImage, with or without a local daemon", () => {
    expect(serviceRemovalOffered(env())).toBe(false);
    expect(serviceRemovalOffered(env({ local_daemon: true }))).toBe(false);
  });

  it("is withheld from an AppImage with no local daemon to remove", () => {
    expect(serviceRemovalOffered(env({ appimage: true }))).toBe(false);
    expect(serviceRemovalOffered(env({ appimage: true, packaged_daemon: true }))).toBe(false);
  });

  it("is withheld while a package also owns a daemon — the package manager's to remove", () => {
    expect(serviceRemovalOffered(env({ appimage: true, local_daemon: true, packaged_daemon: true }))).toBe(false);
  });
});

describe("serviceRemovalRefusal", () => {
  it("an idle daemon may be removed", () => {
    expect(serviceRemovalRefusal(status())).toBeNull();
  });

  it("a running block refuses with the exact sentence", () => {
    expect(serviceRemovalRefusal(status({ active: [RUNNING_BLOCK] }))).toBe(
      "A block is running — the service cannot be removed until it ends.",
    );
  });

  it("a running pomodoro refuses with the exact sentence", () => {
    expect(serviceRemovalRefusal(status({ pomodoro: RUNNING_POMODORO }))).toBe(
      "A pomodoro session is running — the service cannot be removed until it ends.",
    );
  });

  it("the pomodoro sentence wins when its block is also running", () => {
    expect(serviceRemovalRefusal(status({ active: [RUNNING_BLOCK], pomodoro: RUNNING_POMODORO }))).toBe(
      "A pomodoro session is running — the service cannot be removed until it ends.",
    );
  });
});
