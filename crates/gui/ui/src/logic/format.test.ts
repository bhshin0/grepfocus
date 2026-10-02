import { describe, expect, it } from "vitest";
import { fmtClock, fmtDuration, fmtMinute, fmtPhaseRemaining, fmtRemaining, fmtWindow, fmtWindowRange } from "./format";

describe("fmtMinute", () => {
  it.each([
    [0, "00:00"],
    [545, "09:05"],
    [1439, "23:59"],
    [1440, "24:00"],
  ])("%i minutes since midnight is %s", (m, text) => {
    expect(fmtMinute(m)).toBe(text);
  });
});

describe("fmtWindowRange", () => {
  it.each([
    [540, 60, "09:00–10:00"],
    [1380, 60, "23:00–24:00"],
    [0, 1440, "00:00–24:00"],
    [1380, 120, "23:00–01:00 (+1 day)"],
    [1439, 2, "23:59–00:01 (+1 day)"],
    [540, 1440, "09:00–09:00 (+1 day)"],
  ])("a window at %i for %i min reads as %s", (start, duration, text) => {
    expect(fmtWindowRange(start, duration)).toBe(text);
  });
});

describe("fmtRemaining", () => {
  it.each([
    [0, "00:00:00"],
    [-5, "00:00:00"],
    [59.9, "00:00:59"],
    [3661, "01:01:01"],
    [90000, "25:00:00"],
  ])("%d s is the countdown %s", (secs, text) => {
    expect(fmtRemaining(secs)).toBe(text);
  });
});

describe("fmtPhaseRemaining", () => {
  it.each([
    [0, "00:00"],
    [-1, "00:00"],
    [59, "00:59"],
    [1500, "25:00"],
    [3600, "1:00:00"],
    [3661, "1:01:01"],
  ])("%d s is the phase countdown %s", (secs, text) => {
    expect(fmtPhaseRemaining(secs)).toBe(text);
  });
});

describe("fmtDuration", () => {
  it.each([
    [0, "0s"],
    [-5, "0s"],
    [30, "30s"],
    [60, "1m"],
    [2700, "45m"],
    [3600, "1h"],
    [12000, "3h 20m"],
  ])("%d s reads as %s", (secs, text) => {
    expect(fmtDuration(secs)).toBe(text);
  });
});

describe("fmtWindow", () => {
  it.each([
    [3600, "hour"],
    [7200, "2 hours"],
    [1800, "30 min"],
    [5400, "90 min"],
    [90, "2 min"],
    [10, "1 min"],
  ])("a %d s window is phrased as %s", (secs, text) => {
    expect(fmtWindow(secs)).toBe(text);
  });
});

describe("fmtClock", () => {
  it("renders the absolute instant as the locale's two-digit wall-clock time", () => {
    // Compared against the same Intl call, so the assertion holds in every
    // locale and time zone a runner may have — not only those whose hours are
    // two ASCII digits.
    expect(fmtClock(1_700_000_000)).toBe(
      new Date(1_700_000_000_000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    );
  });
});
