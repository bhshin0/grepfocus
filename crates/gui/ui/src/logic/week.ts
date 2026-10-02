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

/// One piece of a schedule window inside a day column: the minutes of that
/// day it spans (`start` inclusive, `end` exclusive) and whether it is the
/// continuation of a window that began the day before (`cont`).
export interface WindowSegment {
  start: number;
  end: number;
  cont: boolean;
}

/// A window segment placed in its day column, with `lane`, its slot among
/// the column's overlapping segments, 0-based from the left.
export interface PlacedWindow extends WindowSegment {
  schedule: Schedule;
  lane: number;
}

/// The pieces of `s` that fall in weekday `bit`'s column. A window belongs
/// to the weekday it STARTS on: its same-day part `[start, min(end, 1440))`
/// shows when `bit` is selected, and the part past midnight `[0, end − 1440)`
/// shows in the NEXT day's column — here when the PREVIOUS weekday,
/// `(bit + 6) % 7`, is selected. Mirrors the daemon's `window_start_date_at`.
/// A window ending exactly at 1440 has no continuation.
export function windowSegments(s: Schedule, bit: number): WindowSegment[] {
  const end = s.start_minute + s.duration_minutes;
  const out: WindowSegment[] = [];
  if ((s.days & (1 << bit)) !== 0) out.push({ start: s.start_minute, end: Math.min(end, 1440), cont: false });
  if (end > 1440 && (s.days & (1 << ((bit + 6) % 7))) !== 0) out.push({ start: 0, end: end - 1440, cont: true });
  return out;
}

/// A segment's text in the grid: `label` (the block and the range the
/// caller chose for it), arrowed when the segment continues a window from
/// the day before, "(off)" when the schedule is disabled.
export function segmentLabel(seg: WindowSegment, label: string, enabled: boolean): string {
  return `${seg.cont ? "↳ " : ""}${label}${enabled ? "" : " (off)"}`;
}

/// A segment's tooltip: the block, the day — named as where it continues
/// from for a continuation — and the window's whole range ("23:00–01:00
/// (+1 day)" says it continues), "(disabled)" when the schedule is off.
export function segmentTitle(name: string, bit: number, seg: WindowSegment, wholeRange: string, enabled: boolean): string {
  const where = seg.cont ? `continues from ${DAY_LABEL[(bit + 6) % 7]}` : DAY_LABEL[bit];
  return `${name} · ${where} · ${wholeRange}${enabled ? "" : " (disabled)"}`;
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

/// One day column: every segment (`windowSegments`) of every schedule that
/// falls on weekday `bit` (0 = Sunday … 6 = Saturday, the wire bitmask),
/// laned by `assignLanes`. A continuation from the previous day lanes like
/// any other segment, so it never hides behind an early window of its own
/// day.
export function layoutDay(schedules: Schedule[], bit: number): DayLayout {
  const segments = schedules.flatMap((schedule) =>
    windowSegments(schedule, bit).map((segment) => ({ schedule, ...segment })),
  );
  const { lanes, laneCount } = assignLanes(segments);
  return { windows: lanes, laneCount };
}
