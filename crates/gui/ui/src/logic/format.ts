// Number → text helpers shared by the Status, Block list, Week and Pomodoro
// surfaces. Pure: no DOM, no state.

/// Minutes-since-midnight → "HH:MM". A window's end can be exactly 1440 (a
/// full-day span), rendered as "24:00" rather than wrapping to "00:00" so the
/// end of the day is unambiguous.
export function fmtMinute(m: number): string {
  const h = Math.floor(m / 60);
  return `${String(h).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
}

/// A schedule window as "HH:MM–HH:MM", flagging one that runs past midnight:
/// "23:00–01:00 (+1 day)". An end of exactly 1440 is "24:00" (`fmtMinute`),
/// the end of the same day rather than a spill-over.
export function fmtWindowRange(start: number, duration: number): string {
  const end = start + duration;
  if (end > 1440) return `${fmtMinute(start)}–${fmtMinute(end - 1440)} (+1 day)`;
  return `${fmtMinute(start)}–${fmtMinute(end)}`;
}

/// HH:MM:SS countdown, never negative.
export function fmtRemaining(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return [h, m, r].map((n) => String(n).padStart(2, "0")).join(":");
}

/// Phase-countdown format: MM:SS, rolling up to H:MM:SS past an hour (a focus
/// interval can be up to 180 min). Same math as `fmtRemaining`, but a bare
/// clock without the always-present hours field reads better in the banner.
export function fmtPhaseRemaining(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  const mm = String(m).padStart(2, "0");
  const rr = String(r).padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${rr}` : `${mm}:${rr}`;
}

/// Compact focus duration: "3h 20m" / "45m" / "30s". Distinct from
/// `fmtRemaining` (a HH:MM:SS countdown) — a headline total reads better as
/// human units than as a colon-clock.
export function fmtDuration(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

/// A rolling window's length, phrased for prose: "per rolling ${fmtWindow(w)}".
/// The common hour reads as a word rather than "60 min"; other round hours
/// follow suit, and anything else falls back to minutes.
export function fmtWindow(windowSecs: number): string {
  if (windowSecs === 3600) return "hour";
  if (windowSecs % 3600 === 0) return `${windowSecs / 3600} hours`;
  return `${Math.max(1, Math.round(windowSecs / 60))} min`;
}

/// Format an ABSOLUTE unix instant as a local wall-clock time.
///
/// Deliberately not adjusted by main.ts's `activeServerSkew`: that skew exists
/// to tick countdowns off a client clock that may disagree with the daemon's,
/// whereas an instant like `next_free_unix` is already absolute and agreed on
/// by both machines. Skewing it would double-count the correction. The one
/// instant that IS moved first is a running block's end, which the daemon
/// keeps on its block clock: after a clock step mid-block that frame and the
/// desktop's differ by exactly that skew, so the caller subtracts it before
/// printing (`renderScheduleRow` in main.ts).
export function fmtClock(unix: number): string {
  return new Date(unix * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
