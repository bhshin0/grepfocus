// Builders for a `Status` frame and its parts, shared by the logic tests so
// a new `Status` field is a one-place change. Not a test file — vitest
// collects src/**/*.test.ts only — but `pnpm build`'s tsc pass type-checks
// it with the rest of src.

import type { ActiveBlock, Health, PomodoroStatus, Status } from "../../types";

/// The frame's clock; every stamp below is relative to it.
export const NOW = 1_700_000_000;

/// A current daemon with nothing to report — the counterpart of the Rust
/// tests' `reporting()`.
export function health(over: Partial<Health> = {}): Health {
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

/// An idle, current, unlicensed daemon with no password set; `over`
/// replaces top-level fields and `h` the health fields.
export function status(over: Partial<Status> = {}, h: Partial<Health> = {}): Status {
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
    settings: { notifications: true, instant_breaks: true, attempt_nudges: false },
    instant_breaks_degraded: false,
    health: health(h),
    recent_events: [],
    update: { kind: "up_to_date" },
    ...over,
  };
}

/// Block 1, "Social", on `domains`, started by hand a minute ago with ten
/// to go.
export function runningBlock(domains: string[] = ["reddit.com"]): ActiveBlock {
  return {
    block: { id: 1, name: "Social", domains, apps: [], allowance_secs_per_day: 0, allowance: null, lock: "normal" },
    started_at_unix: NOW - 60,
    ends_at_unix: NOW + 600,
    originator: { kind: "manual" },
    break_until_unix: null,
    allowance: null,
    lock: "normal",
  };
}

/// A pomodoro session on block 1, in its first focus phase.
export function pomodoro(over: Partial<PomodoroStatus> = {}): PomodoroStatus {
  return { block_id: 1, phase: "focus", phase_ends_unix: NOW + 1500, cycle_index: 0, cycles_total: 4, ...over };
}
