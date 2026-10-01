// The service's lifecycle as the GUI sees it: which installer-dialog mode a
// failed daemon call asks for, and whether the Settings tab may offer to
// remove the service. Pure; main.ts owns the dialog, the busy flags around it
// and the Settings section.

import type { AppEnv, Status } from "../types";

export type FirstRunMode = "install" | "relogin" | "packaged" | "stopped" | "removed";

/// Which dialog mode a failed daemon call asks for; null leaves the dialog
/// alone. The error strings come from crates/gui/src/client.rs; only the two
/// connect-class failures pick a mode — a deserialize or protocol error is a
/// daemon we DID reach, and never opens the dialog. `removed` is main.ts's
/// `serviceRemoved`: with no binary left it turns "not installed yet" into
/// "you just removed it"; once a reinstall has put a binary back the ordinary
/// modes apply again.
export function unreachableMode(msg: string, env: AppEnv | null, removed: boolean): FirstRunMode | null {
  // Socket exists but we lack group membership — installed, needs relogin.
  if (msg.includes("not allowed to talk")) return "relogin";
  if (!msg.includes("daemon is not running")) return null;
  // Nothing listening on the socket: which binary exists says whether that
  // is "not installed" or "installed but stopped".
  if (env?.packaged_daemon) return "packaged";
  if (env?.local_daemon) return "stopped";
  if (env?.appimage) return removed ? "removed" : "install";
  // Non-AppImage, no daemon binary: leave the per-tab error.
  return null;
}

/// The Settings tab's service section is for the service this AppImage
/// installed: running as an AppImage, a daemon at /usr/local/bin, and none at
/// /usr/bin — a package's daemon is the package manager's to remove (the
/// script refuses it, exit 98).
export function serviceRemovalOffered(env: AppEnv | null): boolean {
  return env !== null && env.appimage && env.local_daemon && !env.packaged_daemon;
}

/// Why the service may not be removed right now, null when it may. Mirrors
/// the two running-block sentences of `removal_refusal` in src/main.rs, which
/// has the last word — change together.
export function serviceRemovalRefusal(s: Status): string | null {
  if (s.pomodoro != null) {
    return "A pomodoro session is running — the service cannot be removed until it ends.";
  }
  if (s.active.length > 0) {
    return "A block is running — the service cannot be removed until it ends.";
  }
  return null;
}
