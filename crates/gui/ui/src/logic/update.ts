// GUI/daemon version skew and the release notice. `get_status` computes the
// skew advice (Rust `version::advise`, one decision table); this side turns
// each variant into the Status-tab card's copy. Pure; main.ts renders.

import type { InstallKind, UpdateAdvice } from "../types";

/// Where an outdated AppImage is sent: selectable text in the advice, and
/// the "Download" button beside it opens the same page (`open_url`). The
/// website keeps this route stable for exactly that.
export const DOWNLOAD_URL = "https://grepfocus.com/download";

/// The opening sentence: which service, how it compares. A pre-reporting
/// daemon (`from` null) is older than any app that asks.
function serviceOlder(from: string | null, to: string): string {
  return from === null
    ? `The installed GrepFocus service predates version reporting and is older than this app (${to})`
    : `The GrepFocus service (${from}) is older than this app (${to})`;
}

/// The one advice answered with `DOWNLOAD_URL`: an AppImage older than a
/// service no package owns. Decides both the copy and the "Download" button.
export function adviceOffersDownload(a: UpdateAdvice, appimage: boolean, kind: InstallKind): boolean {
  return a.kind === "gui_outdated" && appimage && kind !== "package";
}

/// The skew card's copy. `gui_outdated` branches on how this app and the
/// daemon were installed: a packaged app should be launched instead, an
/// AppImage replaced, a checkout rebuilt. A pre-reporting daemon's
/// `install_kind` is necessarily `unknown`, so `manual` with `from` null
/// names every install path rather than a location.
export function updateAdviceText(a: UpdateAdvice, appimage: boolean, kind: InstallKind): string {
  const restartNote =
    "Active blocks stay enforced across the restart; settings relock, and a pending break challenge is lost.";
  switch (a.kind) {
    case "up_to_date":
      return "";
    case "update_service":
      return `${serviceOlder(a.from, a.to)}. Update the service so both match — you'll be asked to authorize with your password. ${restartNote}`;
    case "package_manager":
      return `${serviceOlder(a.from, a.to)}. It was installed by your package manager — update the grepfocus package (rpm/deb/AUR) to ${a.to}; this app cannot replace a packaged service.`;
    case "both_installs":
      return `${serviceOlder(a.from, a.to)}. grepfocusd is installed twice — by a package (/usr/bin/grepfocusd) and locally (/usr/local/bin/grepfocusd) — and the installer will not run over a package install: remove one of the two (the package with your package manager), then update the other.`;
    case "manual":
      if (a.from === null || kind === "local") {
        return `${serviceOlder(a.from, a.to)}. Update it the way it was installed: ./packaging/upgrade.sh from a source checkout, your package manager, or the newer AppImage, which offers the update on this tab.`;
      }
      return `${serviceOlder(a.from, a.to)} and is not at a location this app can update. Update it the way it was installed.`;
    case "gui_outdated": {
      const lead = `The GrepFocus service (${a.daemon}) is newer than this app (${a.gui})`;
      if (kind === "package") {
        return `${lead}. Launch the GrepFocus that came with the package instead of this ${appimage ? "AppImage" : "build"}.`;
      }
      if (adviceOffersDownload(a, appimage, kind)) {
        return `${lead}. Download the latest AppImage from ${DOWNLOAD_URL}.`;
      }
      if (kind === "local") {
        return `${lead} — quit and relaunch GrepFocus; if this notice stays, ./packaging/upgrade.sh from the checkout rebuilds both.`;
      }
      return `${lead} — quit and relaunch GrepFocus; if this notice stays, update the app the way it was installed.`;
    }
  }
}

/// Whether the release notice may show. It yields to a running block and to
/// the skew banner — fix what is installed first; the Settings row still
/// reports the release. `skewCardShown` is checked on top of `skewActive`
/// because a finished service update holds the card for its outcome line
/// after the skew is gone.
///
/// A type predicate so the caller keeps `notice` narrowed to a string past
/// the check. It also answers false for a string (held back by a block or the
/// skew card), so only the true branch may rely on the narrowing.
export function releaseNoticeVisible(
  notice: string | null,
  blockActive: boolean,
  skewActive: boolean,
  skewCardShown: boolean,
): notice is string {
  return !(blockActive || skewActive || skewCardShown || notice === null);
}
