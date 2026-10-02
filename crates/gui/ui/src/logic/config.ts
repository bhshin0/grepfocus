// Export / import of blocks and schedules: the copy around the Block list's
// two buttons and the import dialog's decisions. Pure; main.ts owns the file
// input, the dialog and the invokes. The document itself — parsing,
// validation, id remapping, renames, duplicate schedules — is core's
// config_doc and Rust-tested; none of it is repeated here.

import type { ImportSummary, Status } from "../types";

/// Largest file the import reads into the page before handing its text to
/// the Rust side. A MIRROR of `MAX_DOC_BYTES` in crates/core/src/config_doc.rs,
/// which is the source of truth: its `parse` repeats the check on the text,
/// so this one only spares the webview reading a huge file for nothing.
/// Change the two together.
export const MAX_IMPORT_BYTES = 8 * 1024 * 1024;

/// Why a chosen file is not even read, null when it is. Core's wording.
export function importFileRefusal(bytes: number): string | null {
  return bytes > MAX_IMPORT_BYTES ? `file is too large (max ${MAX_IMPORT_BYTES / (1024 * 1024)} MiB)` : null;
}

/// The import dialog's file line: the chosen file's name and size.
export function importFileLabel(name: string, bytes: number): string {
  return `${name} · ${fmtBytes(bytes)}`;
}

/// Binary units, spelled as such — the refusal above says "MiB".
function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${trim1(bytes / 1024)} KiB`;
  return `${trim1(bytes / (1024 * 1024))} MiB`;
}

/// One decimal, dropped when it is zero: 12.3, 12 — never 12.0.
function trim1(n: number): string {
  return n.toFixed(1).replace(/\.0$/, "");
}

/// Why Replace is unavailable right now, null when it may be offered. The
/// daemon has the last word ("cannot replace configuration while a block is
/// active", which also covers a pomodoro session); this only keeps the radio
/// from inviting that refusal. Merge is always offered: adding never touches
/// a running block.
export function replaceRefusal(s: Status): string | null {
  if (s.pomodoro != null) {
    return "A pomodoro session is running — Replace is unavailable until it ends.";
  }
  if (s.active.length > 0) {
    return "A block is running — Replace is unavailable until it ends.";
  }
  return null;
}

/// The Block list's line after an import: what was added, then the renames,
/// then the duplicates skipped, " · " separated like the card summaries. A
/// skipped schedule can only duplicate one earlier in the same file (every
/// imported block is new), so it is worded that way.
export function importSummaryText(s: ImportSummary): string {
  const added: string[] = [];
  if (s.blocks > 0) added.push(plural(s.blocks, "block"));
  if (s.schedules > 0) added.push(plural(s.schedules, "schedule"));
  const parts = [added.length > 0 ? `Imported ${added.join(" and ")}` : "Imported nothing new"];
  if (s.renamed.length > 0) parts.push(`renamed: ${s.renamed.join(", ")}`);
  if (s.skipped_schedules > 0) {
    parts.push(`${plural(s.skipped_schedules, "duplicate schedule")} in the file skipped`);
  }
  return parts.join(" · ");
}

/// The Block list's line after an export; `path` is the Rust side's
/// `~`-abbreviated path.
export function exportedText(path: string): string {
  return `Exported to ${path}`;
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}
