import { describe, expect, it } from "vitest";
import type { InstallKind, UpdateAdvice } from "../types";
import { DOWNLOAD_URL, adviceOffersDownload, releaseNoticeVisible, updateAdviceText } from "./update";

const RESTART =
  "Active blocks stay enforced across the restart; settings relock, and a pending break challenge is lost.";
const OLDER = "The GrepFocus service (0.6.0) is older than this app (0.7.0)";
const PRE_REPORTING =
  "The installed GrepFocus service predates version reporting and is older than this app (0.7.0)";
const NEWER = "The GrepFocus service (0.7.0) is newer than this app (0.6.0)";

const outdated: UpdateAdvice = { kind: "gui_outdated", gui: "0.6.0", daemon: "0.7.0" };

describe("updateAdviceText", () => {
  it("up_to_date has no copy", () => {
    expect(updateAdviceText({ kind: "up_to_date" }, true, "local")).toBe("");
  });

  it("update_service from a reporting daemon offers the service update", () => {
    expect(updateAdviceText({ kind: "update_service", from: "0.6.0", to: "0.7.0" }, true, "local")).toBe(
      `${OLDER}. Update the service so both match — you'll be asked to authorize with your password. ${RESTART}`,
    );
  });

  it("update_service from a pre-reporting daemon says it predates version reporting", () => {
    expect(updateAdviceText({ kind: "update_service", from: null, to: "0.7.0" }, true, "unknown")).toBe(
      `${PRE_REPORTING}. Update the service so both match — you'll be asked to authorize with your password. ${RESTART}`,
    );
  });

  it("package_manager sends the user to the package", () => {
    expect(updateAdviceText({ kind: "package_manager", from: "0.6.0", to: "0.7.0" }, false, "package")).toBe(
      `${OLDER}. It was installed by your package manager — update the grepfocus package (rpm/deb/AUR) to 0.7.0; this app cannot replace a packaged service.`,
    );
  });

  it("both_installs names both binaries", () => {
    expect(updateAdviceText({ kind: "both_installs", from: "0.6.0", to: "0.7.0" }, true, "local")).toBe(
      `${OLDER}. grepfocusd is installed twice — by a package (/usr/bin/grepfocusd) and locally (/usr/local/bin/grepfocusd) — and the installer will not run over a package install: remove one of the two (the package with your package manager), then update the other.`,
    );
  });

  it("manual from a pre-reporting daemon names every install path", () => {
    expect(updateAdviceText({ kind: "manual", from: null, to: "0.7.0" }, false, "unknown")).toBe(
      `${PRE_REPORTING}. Update it the way it was installed: ./packaging/upgrade.sh from a source checkout, your package manager, or the newer AppImage, which offers the update on this tab.`,
    );
  });

  it("manual for a local daemon under a non-AppImage names every install path", () => {
    expect(updateAdviceText({ kind: "manual", from: "0.6.0", to: "0.7.0" }, false, "local")).toBe(
      `${OLDER}. Update it the way it was installed: ./packaging/upgrade.sh from a source checkout, your package manager, or the newer AppImage, which offers the update on this tab.`,
    );
  });

  it("manual for a daemon at an unknown location", () => {
    expect(updateAdviceText({ kind: "manual", from: "0.6.0", to: "0.7.0" }, true, "unknown")).toBe(
      `${OLDER} and is not at a location this app can update. Update it the way it was installed.`,
    );
  });

  it("gui_outdated under a package install sends an AppImage to the packaged app", () => {
    expect(updateAdviceText(outdated, true, "package")).toBe(
      `${NEWER}. Launch the GrepFocus that came with the package instead of this AppImage.`,
    );
  });

  it("gui_outdated under a package install sends a checkout build to the packaged app", () => {
    expect(updateAdviceText(outdated, false, "package")).toBe(
      `${NEWER}. Launch the GrepFocus that came with the package instead of this build.`,
    );
  });

  it("gui_outdated AppImage over a local daemon offers the download", () => {
    expect(updateAdviceText(outdated, true, "local")).toBe(
      `${NEWER}. Download the latest AppImage from https://grepfocus.com/download.`,
    );
  });

  it("gui_outdated AppImage over a daemon of unknown kind also offers the download", () => {
    expect(updateAdviceText(outdated, true, "unknown")).toBe(
      `${NEWER}. Download the latest AppImage from https://grepfocus.com/download.`,
    );
  });

  it("gui_outdated checkout build over a local daemon points at upgrade.sh", () => {
    expect(updateAdviceText(outdated, false, "local")).toBe(
      `${NEWER} — quit and relaunch GrepFocus; if this notice stays, ./packaging/upgrade.sh from the checkout rebuilds both.`,
    );
  });

  it("gui_outdated anywhere else asks for a relaunch, then the install path", () => {
    expect(updateAdviceText(outdated, false, "unknown")).toBe(
      `${NEWER} — quit and relaunch GrepFocus; if this notice stays, update the app the way it was installed.`,
    );
  });

  it("gui_outdated copy never offers an install", () => {
    for (const appimage of [true, false]) {
      for (const kind of ["package", "local", "unknown"] as InstallKind[]) {
        expect(updateAdviceText(outdated, appimage, kind)).not.toMatch(/Update the service/);
      }
    }
  });
});

describe("adviceOffersDownload", () => {
  const rows: [UpdateAdvice, boolean, InstallKind, boolean][] = [
    [outdated, true, "local", true],
    [outdated, true, "unknown", true],
    [outdated, true, "package", false],
    [outdated, false, "local", false],
    [{ kind: "update_service", from: "0.6.0", to: "0.7.0" }, true, "local", false],
    [{ kind: "up_to_date" }, true, "local", false],
  ];
  it.each(rows)("%j · appimage %s · %s → %s", (a, appimage, kind, offered) => {
    expect(adviceOffersDownload(a, appimage, kind)).toBe(offered);
  });

  it("DOWNLOAD_URL is the website's stable download route", () => {
    expect(DOWNLOAD_URL).toBe("https://grepfocus.com/download");
  });
});

describe("releaseNoticeVisible", () => {
  const notice = "GrepFocus 0.7.0 is available (released 2026-10-01) — you have 0.6.0.";
  it.each([
    [null, false, false, false, false],
    [notice, false, false, false, true],
    [notice, true, false, false, false],
    [notice, false, true, false, false],
    [notice, false, false, true, false],
  ])("notice %j · block %s · skew %s · card %s → %s", (text, blockActive, skewActive, cardShown, visible) => {
    expect(releaseNoticeVisible(text, blockActive, skewActive, cardShown)).toBe(visible);
  });
});
