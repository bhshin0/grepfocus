// Plan drift (for the WP7 docs package): topAttempted/otherAttempts take `today` (get_usage_stats returns the last 30 ROWS, not days), the module lives under src/logic/ (the plan said src/attempts.ts), and it also owns blockedTimesText/nudgeToggle/attemptRows.
//
// Blocked-attempt counts: the Stats tab's "Most attempted" rows and "other"
// row, the active card's "blocked N times" suffix, and the attempt-nudge
// toggle's state. Pure (stats or settings in, rows or text out) so the two
// storage caveats below are honoured in exactly one place; main.ts owns the
// DOM writers.

import type { DayStat, ProxyStatus, Settings } from "../types";

/// Mirrors core's `UsageStats::ATTEMPT_DETAIL_DAYS`: a day row more than
/// this many days before today keeps only `attempts_total` — its per-entry
/// map is cleared. The daemon slices `get_usage_stats` to the last 30 ROWS
/// (not calendar days), so a returned row can still be older than this, and
/// a reader that summed every row would count all of an old row's total as
/// "other". Both functions below therefore cut at the same `day >= today -
/// 30` the daemon's `compact_attempt_detail` uses.
export const ATTEMPT_DETAIL_DAYS = 30;

/// Mirrors core's `UsageStats::ATTEMPT_DOMAINS_PER_DAY`: distinct entries a
/// day row keeps counts for, FIRST COME per day rather than the day's top 50.
/// Past the cap a new entry moves only `attempts_total`, so "other" is the
/// remainder; `CAP_HINT_TEXT` under the list says so.
export const ATTEMPT_DOMAINS_PER_DAY = 50;

/// The Stats tab's empty state for the "Most attempted" section.
export const NO_ATTEMPTS_TEXT =
  "No blocked attempts recorded yet — counted only while the instant-breaks proxy holds ports 80 and 443.";

/// Shown under the list only while an "other" row is present — the one time
/// the first-come cap is visible.
export const CAP_HINT_TEXT = `Per-site counts cover the first ${ATTEMPT_DOMAINS_PER_DAY} sites attempted each day (not the ${ATTEMPT_DOMAINS_PER_DAY} most attempted); anything beyond that is grouped under “other”.`;

/// The rows whose per-entry detail the daemon still keeps. `today` is a local
/// `num_days_from_ce` day like `DayStat.day` (see `todayFromCe` in main.ts).
function detailWindow(days: DayStat[], today: number): DayStat[] {
  const cutoff = today - ATTEMPT_DETAIL_DAYS;
  return days.filter((d) => d.day >= cutoff);
}

/// A count read off the wire. An old daemon omits the field (undefined), and
/// nothing on this side should ever turn that into NaN.
function count(n: number | undefined): number {
  return typeof n === "number" && n > 0 ? n : 0;
}

/// A row the daemon has already compacted: `attempts_total` survives but the
/// map is empty. By construction a day's first attempt always enters the map
/// (core's `credit_attempt` inserts while the map holds fewer than
/// `ATTEMPT_DOMAINS_PER_DAY` keys), so this shape never arises any other
/// way. `otherAttempts` skips it regardless of the window cutoff: a one-day
/// skew between this side's local date and the daemon's would otherwise let
/// a just-compacted row through the window and render its whole total as a
/// phantom "other".
function isCompacted(d: DayStat): boolean {
  return count(d.attempts_total) > 0 && Object.keys(d.attempts ?? {}).length === 0;
}

/// Hosts summed across the rows inside the 30-day detail window, most
/// attempted first, ties broken by name (code-point order — hosts are ASCII),
/// at most `limit` rows. Rows outside the window and rows from a daemon
/// without attempt counts contribute nothing.
export function topAttempted(days: DayStat[], limit: number, today: number): Array<[string, number]> {
  const totals = new Map<string, number>();
  for (const d of detailWindow(days, today)) {
    for (const [host, n] of Object.entries(d.attempts ?? {})) {
      const c = count(n);
      if (c === 0) continue;
      totals.set(host, (totals.get(host) ?? 0) + c);
    }
  }
  return [...totals.entries()]
    .sort(([ha, na], [hb, nb]) => nb - na || (ha < hb ? -1 : ha > hb ? 1 : 0))
    .slice(0, Math.max(0, limit));
}

/// Attempts inside the detail window that no listed host accounts for: the
/// window's summed `attempts_total` minus the sum of every per-entry count,
/// skipping rows the daemon has already compacted (`isCompacted`). Only
/// non-zero once some day hit the 50-entry cap. Never negative — the daemon
/// keeps total ≥ sum, but a seal-tampered or hand-edited state file is not
/// this side's problem to render as a negative number.
export function otherAttempts(days: DayStat[], today: number): number {
  let total = 0;
  let listed = 0;
  for (const d of detailWindow(days, today)) {
    if (isCompacted(d)) continue;
    total += count(d.attempts_total);
    for (const n of Object.values(d.attempts ?? {})) listed += count(n);
  }
  return Math.max(0, total - listed);
}

/// One row of the "Most attempted" section.
export interface AttemptRow {
  /// A host, or "other" on the trailing remainder row.
  label: string;
  count: number;
  /// True only on the trailing remainder row.
  other: boolean;
}

/// The "Most attempted" section: the top `limit` hosts, then — only when the
/// remainder is non-zero, and always last — one "other" row for the attempts
/// no listed host accounts for. `capHint` is true exactly when that row is
/// present, the only time the first-come cap is worth explaining
/// (`CAP_HINT_TEXT`). Empty `rows` is the section's empty state
/// (`NO_ATTEMPTS_TEXT`).
export function attemptRows(days: DayStat[], limit: number, today: number): { rows: AttemptRow[]; capHint: boolean } {
  const rows: AttemptRow[] = topAttempted(days, limit, today).map(([label, n]) => ({ label, count: n, other: false }));
  const other = otherAttempts(days, today);
  if (other > 0) rows.push({ label: "other", count: other, other: true });
  return { rows, capHint: other > 0 };
}

/// "1 time" / "3 times": the count text shared by the active card's suffix
/// and every "Most attempted" row.
export function timesText(n: number): string {
  return `${n} time${n === 1 ? "" : "s"}`;
}

/// The active card's meta-line suffix ("blocked 3 times"), or "" when there
/// is nothing honest to say: attempts are counted only while the proxy holds
/// ports 80 and 443, so a degraded or off proxy shows nothing rather than a
/// misleading zero (or a stale count from before it lost the port).
export function blockedTimesText(attempts: number | undefined, proxy: ProxyStatus): string {
  const n = count(attempts);
  if (n === 0 || proxy !== "holding") return "";
  return `blocked ${timesText(n)}`;
}

/// What the Settings tab shows for the attempt-nudges sub-toggle. `checked`
/// is the stored preference, read as `=== true` so a settings object from a
/// daemon that predates the field reads OFF. `enabled` follows the
/// notifications master: with it off the row is visually disabled but keeps
/// showing (and `applySettings` keeps sending) the stored value, so turning
/// the master back on restores nudges without a second click.
export function nudgeToggle(settings: Settings): { checked: boolean; enabled: boolean } {
  return { checked: settings.attempt_nudges === true, enabled: settings.notifications === true };
}
