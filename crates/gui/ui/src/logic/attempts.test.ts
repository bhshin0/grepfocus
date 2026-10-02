import { describe, expect, it } from "vitest";
import type { DayStat, Settings } from "../types";
import {
  ATTEMPT_DETAIL_DAYS,
  ATTEMPT_DOMAINS_PER_DAY,
  attemptRows,
  blockedTimesText,
  CAP_HINT_TEXT,
  NO_ATTEMPTS_TEXT,
  nudgeToggle,
  otherAttempts,
  timesText,
  topAttempted,
} from "./attempts";

const TODAY = 740_000;

/// A day row `ago` days before TODAY. `attempts` omitted = an old daemon's
/// row (no attempt fields at all); `total` omitted = sum of the map, the
/// daemon's invariant below the cap.
function day(ago: number, attempts?: Record<string, number>, total?: number): DayStat {
  const row: DayStat = {
    day: TODAY - ago,
    focus_secs: 0,
    sessions_completed: 0,
    breaks_taken: 0,
    break_secs: 0,
    breaks_refused: 0,
    app_kills: 0,
  };
  if (attempts !== undefined) {
    row.attempts = attempts;
    row.attempts_total = total ?? Object.values(attempts).reduce((a, b) => a + b, 0);
  }
  return row;
}

describe("CAP_HINT_TEXT", () => {
  it("states the per-day cap from the shared constant, both times it is named", () => {
    expect(CAP_HINT_TEXT).toContain(`first ${ATTEMPT_DOMAINS_PER_DAY} sites attempted each day`);
    expect(CAP_HINT_TEXT).toContain(`(not the ${ATTEMPT_DOMAINS_PER_DAY} most attempted)`);
  });
});

describe("topAttempted", () => {
  it("sums one host across days", () => {
    const days = [day(2, { "reddit.com": 3 }), day(1, { "reddit.com": 4 }), day(0, { "reddit.com": 1 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([["reddit.com", 8]]);
  });

  it("orders by count, most attempted first", () => {
    const days = [day(0, { "a.com": 1, "b.com": 9, "c.com": 4 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([
      ["b.com", 9],
      ["c.com", 4],
      ["a.com", 1],
    ]);
  });

  it("breaks a tie by name, ascending", () => {
    const days = [day(0, { "zeta.com": 5, "alpha.com": 5, "mid.com": 5 })];
    expect(topAttempted(days, 10, TODAY).map(([h]) => h)).toEqual(["alpha.com", "mid.com", "zeta.com"]);
  });

  it("orders by the cross-day sum, not any single day", () => {
    const days = [day(1, { "x.com": 5, "y.com": 1 }), day(0, { "y.com": 6 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([
      ["y.com", 7],
      ["x.com", 5],
    ]);
  });

  it("applies the limit after sorting", () => {
    const days = [day(0, { "a.com": 1, "b.com": 2, "c.com": 3, "d.com": 4 })];
    expect(topAttempted(days, 2, TODAY)).toEqual([
      ["d.com", 4],
      ["c.com", 3],
    ]);
  });

  it("a limit of 0 (or less) lists nothing", () => {
    const days = [day(0, { "a.com": 1 })];
    expect(topAttempted(days, 0, TODAY)).toEqual([]);
    expect(topAttempted(days, -1, TODAY)).toEqual([]);
  });

  it("ignores rows older than the 30-day window", () => {
    // The daemon has already cleared this row's map; even an uncleared one
    // (a row written by an older daemon, say) must not count.
    const days = [day(31, { "old.com": 50 }), day(0, { "new.com": 1 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([["new.com", 1]]);
  });

  it("keeps the row exactly at the cutoff, like core's compact_attempt_detail", () => {
    const days = [day(ATTEMPT_DETAIL_DAYS, { "edge.com": 2 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([["edge.com", 2]]);
  });

  it("reads an old daemon's row (no attempt fields) as zero", () => {
    const days = [day(0), day(1, { "a.com": 2 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([["a.com", 2]]);
  });

  it("drops zero and non-positive entries rather than listing a 0", () => {
    const days = [day(0, { "a.com": 0, "b.com": 3 })];
    expect(topAttempted(days, 10, TODAY)).toEqual([["b.com", 3]]);
  });

  it("is empty for no rows", () => {
    expect(topAttempted([], 10, TODAY)).toEqual([]);
  });
});

describe("otherAttempts", () => {
  it("is the window's total minus every listed count", () => {
    // Day 0 hit the cap: 7 attempts, 5 attributed.
    const days = [day(1, { "a.com": 2 }), day(0, { "a.com": 3, "b.com": 2 }, 7)];
    expect(otherAttempts(days, TODAY)).toBe(2);
  });

  it("is 0 while every attempt is attributed", () => {
    const days = [day(0, { "a.com": 3, "b.com": 2 })];
    expect(otherAttempts(days, TODAY)).toBe(0);
  });

  it("does not count an old row's surviving total (its map was cleared)", () => {
    // This is the trap WP1's review named: beyond 30 days the daemon keeps
    // attempts_total and drops the map, so summing every row would turn the
    // whole old history into "other".
    const days = [day(40, {}, 500), day(0, { "a.com": 1 })];
    expect(otherAttempts(days, TODAY)).toBe(0);
  });

  it("a compacted row inside the window contributes no other", () => {
    // A positive total with an empty map can only be a row the daemon has
    // compacted (a day's first attempt always enters the map). If this
    // side's local date runs a day behind the daemon's, such a row slips
    // inside the window — and must still not become a phantom "other".
    const days = [day(ATTEMPT_DETAIL_DAYS, {}, 500), day(1, {}, 9), day(0, { "a.com": 1 })];
    expect(otherAttempts(days, TODAY)).toBe(0);
  });

  it("counts a capped row exactly at the cutoff", () => {
    const days = [day(ATTEMPT_DETAIL_DAYS, { "a.com": 1 }, 4)];
    expect(otherAttempts(days, TODAY)).toBe(3);
  });

  it("reads missing fields on an old daemon's rows as 0", () => {
    expect(otherAttempts([day(0), day(1)], TODAY)).toBe(0);
  });

  it("never goes negative", () => {
    // total < sum cannot come from the daemon; clamp rather than render -2.
    const days = [day(0, { "a.com": 5 }, 3)];
    expect(otherAttempts(days, TODAY)).toBe(0);
  });

  it("is 0 for no rows", () => {
    expect(otherAttempts([], TODAY)).toBe(0);
  });
});

describe("attemptRows", () => {
  it("pins the empty-state sentence and renders it as no rows and no hint", () => {
    expect(NO_ATTEMPTS_TEXT).toBe(
      "No blocked attempts recorded yet — counted only while the instant-breaks proxy holds ports 80 and 443.",
    );
    expect(attemptRows([], 10, TODAY)).toEqual({ rows: [], capHint: false });
    // Old-daemon rows carry no attempt fields: still the empty state.
    expect(attemptRows([day(0), day(1)], 10, TODAY)).toEqual({ rows: [], capHint: false });
  });

  it("lists hosts most attempted first, each flagged as not other", () => {
    const days = [day(0, { "a.com": 1, "b.com": 4 })];
    expect(attemptRows(days, 10, TODAY).rows).toEqual([
      { label: "b.com", count: 4, other: false },
      { label: "a.com", count: 1, other: false },
    ]);
  });

  it('puts the remainder last as a row labelled "other"', () => {
    // Day 0 hit the cap: 7 attempts, 5 attributed.
    const days = [day(1, { "a.com": 2 }), day(0, { "a.com": 3, "b.com": 2 }, 7)];
    const { rows } = attemptRows(days, 10, TODAY);
    expect(rows.at(-1)).toEqual({ label: "other", count: 2, other: true });
    expect(rows.slice(0, -1).every((r) => !r.other)).toBe(true);
    expect(rows.map((r) => r.label)).toEqual(["a.com", "b.com", "other"]);
  });

  it("shows the cap hint exactly when an other row is present", () => {
    const attributed = [day(0, { "a.com": 3, "b.com": 2 })];
    const capped = [day(0, { "a.com": 3, "b.com": 2 }, 7)];
    expect(attemptRows(attributed, 10, TODAY).capHint).toBe(false);
    expect(attemptRows(capped, 10, TODAY).capHint).toBe(true);
    expect(attemptRows(capped, 10, TODAY).rows.some((r) => r.other)).toBe(true);
  });

  it("applies the limit to hosts only; the other row is never cut", () => {
    const days = [day(0, { "a.com": 1, "b.com": 2, "c.com": 3 }, 10)];
    expect(attemptRows(days, 1, TODAY).rows).toEqual([
      { label: "c.com", count: 3, other: false },
      { label: "other", count: 4, other: true },
    ]);
  });

  it("treats a compacted row inside the window as fully attributed", () => {
    const days = [day(1, {}, 500), day(0, { "a.com": 1 })];
    expect(attemptRows(days, 10, TODAY)).toEqual({
      rows: [{ label: "a.com", count: 1, other: false }],
      capHint: false,
    });
  });
});

describe("timesText", () => {
  it.each([
    [1, "1 time"],
    [0, "0 times"],
    [2, "2 times"],
    [37, "37 times"],
  ])("%i reads %s", (n, text) => {
    expect(timesText(n)).toBe(text);
  });
});

describe("blockedTimesText", () => {
  it.each([
    [1, "blocked 1 time"],
    [2, "blocked 2 times"],
    [37, "blocked 37 times"],
  ])("%i attempts while the proxy holds reads %s", (n, text) => {
    expect(blockedTimesText(n, "holding")).toBe(text);
  });

  it("says nothing for zero or a daemon without the field", () => {
    expect(blockedTimesText(0, "holding")).toBe("");
    expect(blockedTimesText(undefined, "holding")).toBe("");
  });

  it.each(["degraded", "off", "unknown"] as const)("says nothing when the proxy is %s", (proxy) => {
    // A count only grows while the proxy holds; showing it otherwise would be
    // a stale or misleading number.
    expect(blockedTimesText(5, proxy)).toBe("");
  });
});

describe("nudgeToggle", () => {
  const settings = (notifications: boolean, attempt_nudges: boolean): Settings => ({
    notifications,
    instant_breaks: true,
    attempt_nudges,
  });

  it("is checked and enabled with both switches on", () => {
    expect(nudgeToggle(settings(true, true))).toEqual({ checked: true, enabled: true });
  });

  it("is unchecked but enabled with only the master on", () => {
    expect(nudgeToggle(settings(true, false))).toEqual({ checked: false, enabled: true });
  });

  it("keeps the stored value visible but disabled with the master off", () => {
    expect(nudgeToggle(settings(false, true))).toEqual({ checked: true, enabled: false });
    expect(nudgeToggle(settings(false, false))).toEqual({ checked: false, enabled: false });
  });

  it("reads a settings object without the field (old daemon) as off", () => {
    const old = { notifications: true, instant_breaks: true } as Settings;
    expect(nudgeToggle(old)).toEqual({ checked: false, enabled: true });
  });
});
