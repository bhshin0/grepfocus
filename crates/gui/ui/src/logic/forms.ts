// Block-form parsing: textarea text → wire matchers and domains, form fields →
// a wire `Block`. Pure over a field getter so `FormData` stays in main.ts.

import type { AllowancePolicy, AppMatcher, Block, LockMode } from "../types";

/// Spelling of a `cmdline` matcher in the app textarea. The block card renders
/// a saved cmdline matcher with the same prefix, so an Edit → Save round trip
/// keeps its kind instead of silently turning it into a basename.
export const CMDLINE_PREFIX = "cmdline:";

export function parseAppLines(raw: string): AppMatcher[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((line): AppMatcher => {
      if (line.startsWith(CMDLINE_PREFIX)) {
        return { kind: "cmdline", contains: line.slice(CMDLINE_PREFIX.length) };
      }
      return line.startsWith("/") ? { kind: "exe_path", path: line } : { kind: "basename", name: line };
    });
}

/// Any whitespace or comma separates entries, so a pasted `reddit.com
/// twitter.com` becomes two domains rather than one refused entry.
export function parseDomains(raw: string): string[] {
  return raw.split(/[\s,]+/).filter(Boolean);
}

/// A form's controls by name, as `FormData.get` answers: the control's text,
/// or null for a control the form does not have.
export type FormField = (name: string) => string | null;

/// Read a block form's allowance controls into a wire policy, minutes → secs.
/// Shared by the New-block tab and every per-card edit form so the two cannot
/// drift into disagreeing about the encoding. Selects fields by kind and never
/// reads one the kind does not own, so hidden inputs may hold anything.
export function policyFromFields(get: FormField): AllowancePolicy {
  // Text `<input type=number>` cannot hold still reads as 0 rather than NaN,
  // which `Math.max` would pass through and JSON would put on the wire as null.
  const mins = (name: string) => {
    const n = Number(get(name) ?? 0);
    return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
  };
  const secs = mins("allowance_minutes") * 60;
  switch (get("allowance_kind") ?? "none") {
    case "per_day":
      return { kind: "per_day", secs };
    case "rolling_window":
      return { kind: "rolling_window", secs, window_secs: mins("window_minutes") * 60 };
    case "per_break":
      return { kind: "per_break", secs };
    default:
      return { kind: "none" };
  }
}

/// Read a whole block form into a wire `Block`. `id` is 0 for a new block and
/// the existing id for an edit — the only difference between the two forms.
///
/// Both `allowance` and its legacy `allowance_secs_per_day` mirror go on the
/// wire. The daemon re-derives the mirror from the policy on save, so this is
/// not load-bearing, but sending a self-consistent frame beats sending one
/// whose two halves contradict each other.
export function blockFromFields(get: FormField, id: number): Block {
  const allowance = policyFromFields(get);
  return {
    id,
    name: (get("name") ?? "").trim(),
    domains: parseDomains(get("domains") ?? ""),
    apps: parseAppLines(get("apps") ?? ""),
    allowance_secs_per_day: allowance.kind === "none" ? 0 : allowance.secs,
    allowance,
    // `"normal"` is the wire spelling of the unlocked mode (see `LockMode`).
    lock: (get("lock") ?? "normal") as LockMode,
  };
}

/// Why a block read off a form cannot be sent, null when it can. Everything
/// else is the daemon's to validate, and its refusal renders verbatim.
export function blockFormError(b: Block): string | null {
  return b.name ? null : "name is required";
}
