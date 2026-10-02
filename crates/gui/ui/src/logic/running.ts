// Which schedules have a block running right now — the Block list's
// "running now until HH:MM" hint on a schedule row. Pure: actives in, a
// `schedule_id → ends_at_unix` map out; main.ts owns the DOM and the poll.

import type { ActiveBlock } from "../types";

/// `schedule_id → ends_at_unix` for every active a schedule started. A
/// manual or pomodoro-started active names no schedule and is skipped. The
/// daemon keeps one active per block and a schedule drives one block, so a
/// schedule id appears at most once.
export function runningSchedules(active: ActiveBlock[]): Map<number, number> {
  const out = new Map<number, number>();
  for (const a of active) {
    if (a.originator.kind === "schedule") out.set(a.originator.schedule_id, a.ends_at_unix);
  }
  return out;
}

/// A fingerprint of `runningSchedules(active)`: equal for two polls iff the
/// same schedules are running to the same ends, whatever order the daemon
/// lists them in. The Block list re-renders on a poll only when it changes
/// — a window firing or ending — never on every tick.
export function runningSchedulesKey(active: ActiveBlock[]): string {
  return [...runningSchedules(active)]
    .sort(([a], [b]) => a - b)
    .map(([id, end]) => `${id}:${end}`)
    .join(",");
}

/// A schedule row's suffix while its block is running: until when, and that
/// a change to the schedule waits for the next window — the daemon lets the
/// schedule be edited, disabled or deleted meanwhile, since the running
/// block keeps the end it snapshotted. `fmt` turns the end (an absolute
/// instant) into a clock time; the row decides which frame it is in.
export function runningHint(endsAt: number, fmt: (unix: number) => string): string {
  return ` · running now until ${fmt(endsAt)} — changes apply from the next window`;
}
