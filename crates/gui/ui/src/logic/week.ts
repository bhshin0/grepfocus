// Week grid layout: which day column a schedule window falls in and which
// lane it takes when windows overlap. Pure; `buildWeekGrid` in main.ts does
// the rendering.

import type { Schedule } from "../types";

export const DAY_LABEL = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Display columns run Mon→Sun for readability, but the wire bitmask is
/// Sun-first (bit 0 = Sunday … bit 6 = Saturday, matching `DAY_LABEL`). This
/// maps each display column to the bit it represents; `DAY_LABEL[bit]` then
/// labels it, keeping the column order and the bit order from drifting apart.
export const DISPLAY_DAYS = [1, 2, 3, 4, 5, 6, 0];

/// Per-block colours: eight distinct hues as {fill, text} pairs, indexed by
/// `blockId % length`. Each fill is a light pastel with an explicit dark text
/// colour, so the label reads on the window in BOTH light and dark themes —
/// the window carries its own background, so no `prefers-color-scheme` branch
/// is needed for it (unlike the CSS vars, which do have one). The legend below
/// the grid disambiguates the rare case where two blocks share a palette slot.
export const WEEK_PALETTE: { fill: string; text: string }[] = [
  { fill: "#cfe3ff", text: "#0b2a5b" },
  { fill: "#cdefd6", text: "#0e3d20" },
  { fill: "#ffe6b3", text: "#5a3d00" },
  { fill: "#ffd6e7", text: "#5c1236" },
  { fill: "#e2d5f8", text: "#331457" },
  { fill: "#c9eef0", text: "#06393d" },
  { fill: "#ffd9c2", text: "#5a2405" },
  { fill: "#e4f0b8", text: "#35400a" },
];

/// A schedule window placed in its day column: the minutes it spans
/// (`start` inclusive, `end` exclusive) and `lane`, its slot among the
/// column's overlapping windows, 0-based from the left.
export interface PlacedWindow {
  schedule: Schedule;
  start: number;
  end: number;
  lane: number;
}

/// One day column's windows, earliest first, and how many lanes split its
/// width — at least 1, so an empty column still divides.
export interface DayLayout {
  windows: PlacedWindow[];
  laneCount: number;
}

/// Lane assignment (greedy interval partition): the intervals earliest first
/// (a tie keeps their given order), each dropped into the first lane whose
/// previous interval has already ended (`prevEnd <= start`), else a new lane.
/// Intervals in one lane never overlap, so laying the lanes side-by-side
/// keeps every overlapping one visible instead of hidden behind another.
/// Generic over the item so a caller may carry whatever it needs through —
/// the input is left untouched, every item comes back copied with its `lane`.
export function assignLanes<T extends { start: number; end: number }>(
  items: T[],
): { lanes: (T & { lane: number })[]; laneCount: number } {
  const sorted = [...items].sort((a, b) => a.start - b.start);
  // `laneEnds[i]` is the end of the last interval placed in lane i.
  const laneEnds: number[] = [];
  const lanes: (T & { lane: number })[] = [];
  for (const item of sorted) {
    let lane = laneEnds.findIndex((prevEnd) => prevEnd <= item.start);
    if (lane === -1) {
      lane = laneEnds.length;
      laneEnds.push(item.end);
    } else {
      laneEnds[lane] = item.end;
    }
    lanes.push({ ...item, lane });
  }
  return { lanes, laneCount: Math.max(1, laneEnds.length) };
}

/// One day column: every schedule firing on weekday `bit` (0 = Sunday … 6 =
/// Saturday, the wire bitmask) as the window it spans, laned by `assignLanes`.
export function layoutDay(schedules: Schedule[], bit: number): DayLayout {
  const todays = schedules
    .filter((s) => (s.days & (1 << bit)) !== 0)
    .map((schedule) => ({
      schedule,
      start: schedule.start_minute,
      end: schedule.start_minute + schedule.duration_minutes,
    }));
  const { lanes, laneCount } = assignLanes(todays);
  return { windows: lanes, laneCount };
}
