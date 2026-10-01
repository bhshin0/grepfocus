import { describe, expect, it } from "vitest";
import type { AppMatcher } from "../types";
import {
  CMDLINE_PREFIX,
  type FormField,
  blockFormError,
  blockFromFields,
  parseAppLines,
  parseDomains,
  policyFromFields,
} from "./forms";

/// A form holding exactly these controls; any other name reads as absent.
function fields(values: Record<string, string>): FormField {
  return (name) => (name in values ? values[name] : null);
}

describe("parseAppLines", () => {
  it("empty text yields no matchers", () => {
    expect(parseAppLines("")).toEqual([]);
    expect(parseAppLines("\n  \n\t\n")).toEqual([]);
  });

  it("an absolute path is an exe_path matcher", () => {
    expect(parseAppLines("/usr/bin/steam")).toEqual([{ kind: "exe_path", path: "/usr/bin/steam" }]);
  });

  it("a bare name is a basename matcher", () => {
    expect(parseAppLines("discord")).toEqual([{ kind: "basename", name: "discord" }]);
  });

  it("the cmdline: prefix is a cmdline matcher on the rest of the line", () => {
    expect(parseAppLines("cmdline:com.discordapp.Discord")).toEqual([
      { kind: "cmdline", contains: "com.discordapp.Discord" },
    ]);
  });

  it("trims each line and drops blank ones", () => {
    expect(parseAppLines("  discord \n\n/usr/bin/steam\r\n")).toEqual([
      { kind: "basename", name: "discord" },
      { kind: "exe_path", path: "/usr/bin/steam" },
    ]);
  });

  it("keeps every kind through the block card's spelling (Edit → Save round trip)", () => {
    const saved: AppMatcher[] = [
      { kind: "exe_path", path: "/usr/bin/steam" },
      { kind: "basename", name: "discord" },
      { kind: "cmdline", contains: "com.discordapp.Discord" },
    ];
    // How renderBlockCard fills the edit textarea.
    const textarea = saved
      .map((a) => {
        if (a.kind === "exe_path") return a.path;
        if (a.kind === "basename") return a.name;
        return `${CMDLINE_PREFIX}${a.contains}`;
      })
      .join("\n");
    expect(parseAppLines(textarea)).toEqual(saved);
  });

  it("CMDLINE_PREFIX is the textarea spelling", () => {
    expect(CMDLINE_PREFIX).toBe("cmdline:");
  });
});

describe("parseDomains", () => {
  it.each([
    ["reddit.com twitter.com", ["reddit.com", "twitter.com"]],
    ["reddit.com,twitter.com", ["reddit.com", "twitter.com"]],
    ["reddit.com, twitter.com\n  youtube.com\t", ["reddit.com", "twitter.com", "youtube.com"]],
    [",reddit.com,", ["reddit.com"]],
    ["", []],
    [" , \n", []],
  ])("%j splits into %j", (raw, domains) => {
    expect(parseDomains(raw)).toEqual(domains);
  });
});

describe("policyFromFields", () => {
  it("no breaks ignores the minute boxes", () => {
    expect(
      policyFromFields(fields({ allowance_kind: "none", allowance_minutes: "15", window_minutes: "60" })),
    ).toEqual({ kind: "none" });
  });

  it("a form without an allowance kind reads as none", () => {
    expect(policyFromFields(fields({}))).toEqual({ kind: "none" });
  });

  it("an unknown kind reads as none", () => {
    expect(policyFromFields(fields({ allowance_kind: "weekly", allowance_minutes: "15" }))).toEqual({
      kind: "none",
    });
  });

  it("per_day encodes minutes as seconds", () => {
    expect(policyFromFields(fields({ allowance_kind: "per_day", allowance_minutes: "15" }))).toEqual({
      kind: "per_day",
      secs: 900,
    });
  });

  it("rolling_window also reads the window length", () => {
    expect(
      policyFromFields(
        fields({ allowance_kind: "rolling_window", allowance_minutes: "15", window_minutes: "60" }),
      ),
    ).toEqual({ kind: "rolling_window", secs: 900, window_secs: 3600 });
  });

  it("per_break encodes minutes as seconds", () => {
    expect(policyFromFields(fields({ allowance_kind: "per_break", allowance_minutes: "5" }))).toEqual({
      kind: "per_break",
      secs: 300,
    });
  });

  it("never reads a field the kind does not own", () => {
    expect(
      policyFromFields(fields({ allowance_kind: "per_day", allowance_minutes: "15", window_minutes: "garbage" })),
    ).toEqual({ kind: "per_day", secs: 900 });
  });

  it("floors fractional minutes and clamps negatives to 0", () => {
    expect(policyFromFields(fields({ allowance_kind: "per_day", allowance_minutes: "2.7" }))).toEqual({
      kind: "per_day",
      secs: 120,
    });
    expect(policyFromFields(fields({ allowance_kind: "per_day", allowance_minutes: "-3" }))).toEqual({
      kind: "per_day",
      secs: 0,
    });
  });

  it("a missing minutes box is 0", () => {
    expect(policyFromFields(fields({ allowance_kind: "per_break" }))).toEqual({ kind: "per_break", secs: 0 });
  });

  it("a minutes box holding no number is 0, never NaN", () => {
    expect(policyFromFields(fields({ allowance_kind: "per_day", allowance_minutes: "abc" }))).toEqual({
      kind: "per_day",
      secs: 0,
    });
    expect(
      policyFromFields(fields({ allowance_kind: "rolling_window", allowance_minutes: "15", window_minutes: "abc" })),
    ).toEqual({ kind: "rolling_window", secs: 900, window_secs: 0 });
  });
});

describe("blockFromFields", () => {
  const full = fields({
    name: "  Social  ",
    domains: "reddit.com, twitter.com",
    apps: "discord\ncmdline:com.discordapp.Discord",
    allowance_kind: "rolling_window",
    allowance_minutes: "15",
    window_minutes: "60",
    lock: "password_breaks",
  });

  it("reads a whole form into a wire block with the legacy mirror in step", () => {
    expect(blockFromFields(full, 7)).toEqual({
      id: 7,
      name: "Social",
      domains: ["reddit.com", "twitter.com"],
      apps: [
        { kind: "basename", name: "discord" },
        { kind: "cmdline", contains: "com.discordapp.Discord" },
      ],
      allowance_secs_per_day: 900,
      allowance: { kind: "rolling_window", secs: 900, window_secs: 3600 },
      lock: "password_breaks",
    });
  });

  it("the legacy per-day mirror is 0 for no breaks", () => {
    const b = blockFromFields(fields({ name: "Games", allowance_kind: "none", allowance_minutes: "15" }), 0);
    expect(b.allowance).toEqual({ kind: "none" });
    expect(b.allowance_secs_per_day).toBe(0);
  });

  it("a form without a lock control is unlocked, spelled normal on the wire", () => {
    expect(blockFromFields(fields({ name: "Games" }), 0).lock).toBe("normal");
  });

  it("passes the id through: 0 for a new block, the saved id for an edit", () => {
    expect(blockFromFields(full, 0).id).toBe(0);
    expect(blockFromFields(full, 42).id).toBe(42);
  });

  it("absent controls read as empty", () => {
    const b = blockFromFields(fields({}), 0);
    expect(b.name).toBe("");
    expect(b.domains).toEqual([]);
    expect(b.apps).toEqual([]);
  });
});

describe("blockFormError", () => {
  it("a blank name is refused with the exact message", () => {
    expect(blockFormError(blockFromFields(fields({ name: "   " }), 0))).toBe("name is required");
    expect(blockFormError(blockFromFields(fields({}), 0))).toBe("name is required");
  });

  it("a named block passes; everything else is the daemon's call", () => {
    expect(blockFormError(blockFromFields(fields({ name: "Games" }), 0))).toBeNull();
  });
});
