import { describe, expect, it } from "vitest";
import type { ActiveBlock, Block, Originator } from "../types";
import { runningHint, runningSchedules, runningSchedulesKey } from "./running";

function block(id: number): Block {
  return { id, name: `b${id}`, domains: [], apps: [], allowance_secs_per_day: 0, allowance: null, lock: "normal" };
}

function active(blockId: number, originator: Originator, endsAt: number): ActiveBlock {
  return {
    block: block(blockId),
    started_at_unix: endsAt - 600,
    ends_at_unix: endsAt,
    originator,
    break_until_unix: null,
    allowance: null,
    lock: "normal",
  };
}

const manual = active(1, { kind: "manual" }, 1_000);
const schedA = active(2, { kind: "schedule", schedule_id: 7 }, 2_000);
const schedB = active(3, { kind: "schedule", schedule_id: 3 }, 3_000);

describe("runningSchedules", () => {
  it("nothing active is an empty map", () => {
    expect(runningSchedules([])).toEqual(new Map());
  });

  it("a manually started block names no schedule", () => {
    expect(runningSchedules([manual])).toEqual(new Map());
  });

  it("maps each schedule-started active to the end it snapshotted", () => {
    expect(runningSchedules([manual, schedA, schedB])).toEqual(
      new Map([
        [7, 2_000],
        [3, 3_000],
      ]),
    );
  });
});

describe("runningSchedulesKey", () => {
  it("is empty with nothing schedule-started", () => {
    expect(runningSchedulesKey([])).toBe("");
    expect(runningSchedulesKey([manual])).toBe("");
  });

  it("does not depend on the daemon's listing order", () => {
    expect(runningSchedulesKey([schedA, schedB])).toBe(runningSchedulesKey([schedB, manual, schedA]));
    expect(runningSchedulesKey([schedA, schedB])).toBe("3:3000,7:2000");
  });

  it("changes when a window fires, ends, or re-fires to a later end", () => {
    const before = runningSchedulesKey([schedA]);
    expect(runningSchedulesKey([schedA, schedB])).not.toBe(before);
    expect(runningSchedulesKey([])).not.toBe(before);
    expect(runningSchedulesKey([active(2, { kind: "schedule", schedule_id: 7 }, 2_500)])).not.toBe(before);
  });
});

describe("runningHint", () => {
  it("names the end through the given clock and says changes wait for the next window", () => {
    const fmt = (unix: number) => `clock(${unix})`;
    expect(runningHint(2_000, fmt)).toBe(" · running now until clock(2000) — changes apply from the next window");
  });
});
