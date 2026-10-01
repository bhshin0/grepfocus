import { describe, expect, it } from "vitest";
import type { Schedule } from "../types";
import { DAY_LABEL, DISPLAY_DAYS, type DayLayout, assignLanes, layoutDay } from "./week";

const SUN = 1 << 0;
const MON = 1 << 1;
const TUE = 1 << 2;
const SAT = 1 << 6;

let nextId = 1;
function sched(start: number, duration: number, days = MON, over: Partial<Schedule> = {}): Schedule {
  const id = nextId++;
  return { id, name: `s${id}`, block_id: 1, days, start_minute: start, duration_minutes: duration, enabled: true, ...over };
}

/// [start minute, lane] per placed window, in layout order.
function placed(layout: DayLayout): [number, number][] {
  return layout.windows.map((w) => [w.schedule.start_minute, w.lane]);
}

describe("layoutDay", () => {
  it("no schedules is an empty column with one lane", () => {
    expect(layoutDay([], 1)).toEqual({ windows: [], laneCount: 1 });
  });

  it("a column no schedule fires on is empty with one lane", () => {
    expect(layoutDay([sched(540, 60, MON)], 2)).toEqual({ windows: [], laneCount: 1 });
  });

  it("reads the wire bitmask with Sunday as bit 0 and Saturday as bit 6", () => {
    const weekend = sched(540, 60, SUN | SAT);
    expect(layoutDay([weekend], 0).windows).toHaveLength(1);
    expect(layoutDay([weekend], 6).windows).toHaveLength(1);
    expect(layoutDay([weekend], 1).windows).toHaveLength(0);
  });

  it("a schedule on several days appears in each of its columns", () => {
    const s = sched(540, 60, MON | TUE);
    expect(layoutDay([s], 1).windows[0].schedule).toBe(s);
    expect(layoutDay([s], 2).windows[0].schedule).toBe(s);
  });

  it("orders windows earliest first whatever the config order", () => {
    const layout = layoutDay([sched(900, 60), sched(540, 60), sched(720, 60)], 1);
    expect(placed(layout)).toEqual([
      [540, 0],
      [720, 0],
      [900, 0],
    ]);
  });

  it("non-overlapping windows share lane 0", () => {
    const layout = layoutDay([sched(540, 60), sched(720, 60)], 1);
    expect(layout.laneCount).toBe(1);
    expect(placed(layout)).toEqual([
      [540, 0],
      [720, 0],
    ]);
  });

  it("two overlapping windows take two lanes", () => {
    const layout = layoutDay([sched(540, 120), sched(600, 60)], 1);
    expect(layout.laneCount).toBe(2);
    expect(placed(layout)).toEqual([
      [540, 0],
      [600, 1],
    ]);
  });

  it("back-to-back windows share a lane: the previous end may equal the next start", () => {
    const layout = layoutDay([sched(540, 60), sched(600, 60)], 1);
    expect(layout.laneCount).toBe(1);
    expect(placed(layout)).toEqual([
      [540, 0],
      [600, 0],
    ]);
  });

  it("a window starting after the first lane has ended reuses lane 0", () => {
    const layout = layoutDay([sched(540, 60), sched(570, 90), sched(600, 30)], 1);
    expect(layout.laneCount).toBe(2);
    expect(placed(layout)).toEqual([
      [540, 0],
      [570, 1],
      [600, 0],
    ]);
  });

  it("three mutually overlapping windows take three lanes", () => {
    const layout = layoutDay([sched(540, 180), sched(600, 120), sched(660, 60)], 1);
    expect(layout.laneCount).toBe(3);
    expect(placed(layout)).toEqual([
      [540, 0],
      [600, 1],
      [660, 2],
    ]);
  });

  it("the lane count is the column's widest overlap, not its window count", () => {
    // Two overlapping pairs, never three at once.
    const layout = layoutDay([sched(540, 60), sched(570, 60), sched(720, 60), sched(750, 60)], 1);
    expect(layout.laneCount).toBe(2);
    expect(placed(layout)).toEqual([
      [540, 0],
      [570, 1],
      [720, 0],
      [750, 1],
    ]);
  });

  it("a tie on the start minute keeps config order", () => {
    const first = sched(540, 60);
    const second = sched(540, 30);
    const layout = layoutDay([first, second], 1);
    expect(layout.windows.map((w) => w.schedule)).toEqual([first, second]);
    expect(placed(layout)).toEqual([
      [540, 0],
      [540, 1],
    ]);
  });

  it("a disabled schedule is still laid out — the grid greys it, never hides it", () => {
    const layout = layoutDay([sched(540, 60, MON, { enabled: false })], 1);
    expect(layout.windows).toHaveLength(1);
    expect(layout.windows[0].schedule.enabled).toBe(false);
  });

  it("leaves the input array in config order", () => {
    const input = [sched(900, 60), sched(540, 60)];
    const starts = input.map((s) => s.start_minute);
    layoutDay(input, 1);
    expect(input.map((s) => s.start_minute)).toEqual(starts);
  });
});

describe("assignLanes", () => {
  it("no intervals is one empty lane", () => {
    expect(assignLanes([])).toEqual({ lanes: [], laneCount: 1 });
  });

  it("overlapping intervals take separate lanes, back-to-back ones share, earliest first", () => {
    // Given out of order; an end equal to the next start does not overlap.
    const { lanes, laneCount } = assignLanes([
      { start: 60, end: 120 },
      { start: 0, end: 90 },
      { start: 120, end: 180 },
    ]);
    expect(laneCount).toBe(2);
    expect(lanes).toEqual([
      { start: 0, end: 90, lane: 0 },
      { start: 60, end: 120, lane: 1 },
      { start: 120, end: 180, lane: 0 },
    ]);
  });

  it("carries each item's own fields through and leaves the input untouched", () => {
    const later = { tag: "later", start: 30, end: 60 };
    const earlier = { tag: "earlier", start: 0, end: 45 };
    const input = [later, earlier];
    const { lanes } = assignLanes(input);
    expect(lanes).toEqual([
      { tag: "earlier", start: 0, end: 45, lane: 0 },
      { tag: "later", start: 30, end: 60, lane: 1 },
    ]);
    expect(input).toEqual([later, earlier]);
    expect(later).toEqual({ tag: "later", start: 30, end: 60 });
  });
});

describe("DISPLAY_DAYS", () => {
  it("runs Mon→Sun and covers every weekday bit once", () => {
    expect(DISPLAY_DAYS.map((bit) => DAY_LABEL[bit])).toEqual(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]);
    expect([...DISPLAY_DAYS].sort()).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });
});
