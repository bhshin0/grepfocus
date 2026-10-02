import { describe, expect, it } from "vitest";
import {
  MAX_IMPORT_BYTES,
  exportedText,
  importFileLabel,
  importFileRefusal,
  importSummaryText,
  replaceRefusal,
} from "./config";
import { NOW, pomodoro, runningBlock, status } from "./testing/status";

const RUNNING_BLOCK = runningBlock();

/// On its break, between two actives.
const POMODORO = pomodoro({ phase: "break", phase_ends_unix: NOW + 120, cycle_index: 1 });

describe("replaceRefusal — which mode is allowed while a block runs", () => {
  it("offers Replace when nothing runs", () => {
    expect(replaceRefusal(status())).toBeNull();
  });

  it("withholds Replace while a block runs", () => {
    expect(replaceRefusal(status({ active: [RUNNING_BLOCK] }))).toBe(
      "A block is running — Replace is unavailable until it ends.",
    );
  });

  it("names the pomodoro session, even between its actives", () => {
    const expected = "A pomodoro session is running — Replace is unavailable until it ends.";
    expect(replaceRefusal(status({ pomodoro: POMODORO }))).toBe(expected);
    expect(replaceRefusal(status({ pomodoro: POMODORO, active: [RUNNING_BLOCK] }))).toBe(expected);
  });
});

describe("importSummaryText", () => {
  const cases: [string, Parameters<typeof importSummaryText>[0], string][] = [
    ["blocks and schedules", { blocks: 3, schedules: 2, renamed: [], skipped_schedules: 0 }, "Imported 3 blocks and 2 schedules"],
    ["singular", { blocks: 1, schedules: 1, renamed: [], skipped_schedules: 0 }, "Imported 1 block and 1 schedule"],
    ["blocks only", { blocks: 2, schedules: 0, renamed: [], skipped_schedules: 0 }, "Imported 2 blocks"],
    [
      "the documented line",
      { blocks: 3, schedules: 2, renamed: ["Work → Work (imported)"], skipped_schedules: 1 },
      "Imported 3 blocks and 2 schedules · renamed: Work → Work (imported) · 1 duplicate schedule in the file skipped",
    ],
    [
      "several renames, several duplicates",
      { blocks: 2, schedules: 0, renamed: ["Work → Work (imported)", "Games → Games (imported 2)"], skipped_schedules: 2 },
      "Imported 2 blocks · renamed: Work → Work (imported), Games → Games (imported 2) · 2 duplicate schedules in the file skipped",
    ],
    ["nothing added", { blocks: 0, schedules: 0, renamed: [], skipped_schedules: 0 }, "Imported nothing new"],
  ];
  for (const [name, summary, text] of cases) {
    it(name, () => expect(importSummaryText(summary)).toBe(text));
  }
});

describe("file label and size guard", () => {
  it("shows the file name and a readable size, in the binary units the refusal uses", () => {
    expect(importFileLabel("grepfocus-config-20261002-101507.json", 512)).toBe(
      "grepfocus-config-20261002-101507.json · 512 B",
    );
    expect(importFileLabel("x.json", 12_595)).toBe("x.json · 12.3 KiB");
    expect(importFileLabel("x.json", 12 * 1024)).toBe("x.json · 12 KiB");
    expect(importFileLabel("x.json", 3 * 1024 * 1024 + 512 * 1024)).toBe("x.json · 3.5 MiB");
  });

  it("refuses only a file over core's 8 MiB cap, in core's words", () => {
    expect(MAX_IMPORT_BYTES).toBe(8 << 20);
    expect(importFileRefusal(0)).toBeNull();
    expect(importFileRefusal(MAX_IMPORT_BYTES)).toBeNull();
    expect(importFileRefusal(MAX_IMPORT_BYTES + 1)).toBe("file is too large (max 8 MiB)");
  });
});

describe("exportedText", () => {
  it("names the path the Rust side chose", () => {
    expect(exportedText("~/Downloads/grepfocus-config-20261002-101507.json")).toBe(
      "Exported to ~/Downloads/grepfocus-config-20261002-101507.json",
    );
  });
});
