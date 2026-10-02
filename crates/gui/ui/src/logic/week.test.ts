import { describe, expect, it } from "vitest";
import type { Schedule } from "../types";
import {
  DAY_LABEL,
  DISPLAY_DAYS,
  type DayLayout,
  assignLanes,
  layoutDay,
  segmentLabel,
  segmentTitle,
  windowSegments,
} from "./week";

const SUN = 1 << 0;
const MON = 1 << 1;
const TUE = 1 << 2;
const WED = 1 << 3;
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

describe("windowSegments", () => {
  it("a window inside its day is one same-day segment", () => {
    expect(windowSegments(sched(540, 60, MON), 1)).toEqual([{ start: 540, end: 600, cont: false }]);
  });

  it("a column the window neither starts on nor spills into is empty", () => {
    expect(windowSegments(sched(540, 60, MON), 2)).toEqual([]);
    expect(windowSegments(sched(1380, 120, MON), 3)).toEqual([]);
  });

  it("a wrapping window on Mon is a Mon segment to 24:00 and a Tue continuation", () => {
    const s = sched(1380, 120, MON); // 23:00–01:00 (+1 day)
    expect(windowSegments(s, 1)).toEqual([{ start: 1380, end: 1440, cont: false }]);
    expect(windowSegments(s, 2)).toEqual([{ start: 0, end: 60, cont: true }]);
  });

  it("the Tue bit alone gives Tue its own segment and no continuation — that goes to Wed", () => {
    const s = sched(1380, 120, TUE);
    expect(windowSegments(s, 2)).toEqual([{ start: 1380, end: 1440, cont: false }]);
    expect(windowSegments(s, 3)).toEqual([{ start: 0, end: 60, cont: true }]);
    expect(windowSegments(s, 1)).toEqual([]);
  });

  it("a day both starting a window and receiving one gets both, continuation included", () => {
    expect(windowSegments(sched(1380, 120, MON | TUE), 2)).toEqual([
      { start: 1380, end: 1440, cont: false },
      { start: 0, end: 60, cont: true },
    ]);
  });

  it("wraps the week: Saturday spills into Sunday and Sunday into Monday", () => {
    expect(windowSegments(sched(1380, 120, SAT), 0)).toEqual([{ start: 0, end: 60, cont: true }]);
    expect(windowSegments(sched(1380, 120, SUN), 1)).toEqual([{ start: 0, end: 60, cont: true }]);
  });

  it("a window ending exactly at 24:00 has no continuation", () => {
    const s = sched(1380, 60, MON);
    expect(windowSegments(s, 1)).toEqual([{ start: 1380, end: 1440, cont: false }]);
    expect(windowSegments(s, 2)).toEqual([]);
  });

  it("a full day from 09:00 continues to 09:00 next day", () => {
    const s = sched(540, 1440, MON);
    expect(windowSegments(s, 1)).toEqual([{ start: 540, end: 1440, cont: false }]);
    expect(windowSegments(s, 2)).toEqual([{ start: 0, end: 540, cont: true }]);
  });
});

describe("layoutDay with windows past midnight", () => {
  it("places the continuation in the next day's column, flagged", () => {
    const s = sched(1380, 120, MON);
    const mon = layoutDay([s], 1);
    expect(mon.windows).toEqual([{ schedule: s, start: 1380, end: 1440, cont: false, lane: 0 }]);
    const tue = layoutDay([s], 2);
    expect(tue.windows).toEqual([{ schedule: s, start: 0, end: 60, cont: true, lane: 0 }]);
    expect(layoutDay([s], 3).windows).toEqual([]);
  });

  it("lanes a continuation against the day's own windows", () => {
    const wrap = sched(1380, 120, MON); // continues 00:00–01:00 Tue
    const early = sched(30, 60, TUE); // 00:30–01:30 Tue, overlaps it
    const later = sched(90, 60, TUE); // 01:30–02:30 Tue, after both
    const layout = layoutDay([later, early, wrap], 2);
    expect(layout.laneCount).toBe(2);
    expect(layout.windows.map((w) => [w.schedule, w.lane, w.cont])).toEqual([
      [wrap, 0, true],
      [early, 1, false],
      [later, 0, false],
    ]);
  });

  it("a schedule on consecutive days shows its continuation before its own window", () => {
    const s = sched(1380, 120, MON | TUE | WED);
    const tue = layoutDay([s], 2);
    expect(tue.laneCount).toBe(1);
    expect(tue.windows.map((w) => [w.start, w.end, w.cont])).toEqual([
      [0, 60, true],
      [1380, 1440, false],
    ]);
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

describe("segmentLabel", () => {
  const cont = { start: 0, end: 60, cont: true };
  const own = { start: 1380, end: 1440, cont: false };

  it("arrows a continuation from the day before", () => {
    expect(segmentLabel(cont, "Deep work 00:00–01:00", true)).toBe("↳ Deep work 00:00–01:00");
    expect(segmentLabel(own, "Deep work 23:00–01:00 (+1 day)", true)).toBe("Deep work 23:00–01:00 (+1 day)");
  });

  it("flags a disabled schedule", () => {
    expect(segmentLabel(own, "Deep work 09:00–10:00", false)).toBe("Deep work 09:00–10:00 (off)");
    expect(segmentLabel(cont, "Deep work 00:00–01:00", false)).toBe("↳ Deep work 00:00–01:00 (off)");
  });
});

describe("segmentTitle", () => {
  const cont = { start: 0, end: 60, cont: true };
  const own = { start: 1380, end: 1440, cont: false };

  it("a continuation names the day it came from and the whole range", () => {
    expect(segmentTitle("Deep work", 2, cont, "23:00–01:00 (+1 day)", true)).toBe(
      "Deep work · continues from Mon · 23:00–01:00 (+1 day)",
    );
    // Sunday's continuation came from Saturday — the week wraps.
    expect(segmentTitle("Deep work", 0, cont, "23:00–01:00 (+1 day)", true)).toBe(
      "Deep work · continues from Sat · 23:00–01:00 (+1 day)",
    );
  });

  it("a same-day segment names its own day", () => {
    expect(segmentTitle("Deep work", 1, own, "23:00–01:00 (+1 day)", true)).toBe(
      "Deep work · Mon · 23:00–01:00 (+1 day)",
    );
  });

  it("flags a disabled schedule", () => {
    expect(segmentTitle("Deep work", 1, own, "09:00–10:00", false)).toBe("Deep work · Mon · 09:00–10:00 (disabled)");
  });
});
