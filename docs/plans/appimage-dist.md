# AppImage + first-run daemon installer (distribution reach)

> **Status (0.5.0): implemented — AUR and AppImage both ship.** The AppImage
> carries the GUI + a bundled `grepfocusd` payload and self-installs the daemon
> via pkexec on first run (`install_service` + first-run UI). The long white
> screen / "Could not create default EGL display: EGL_BAD_PARAMETER" saga had
> ONE root cause, proven by coredumps (all 14 aborts were WebKitWebProcess) and
> a symbol audit: linuxdeploy bundled Ubuntu 22.04's `libwayland-client` (1.20),
> which shadowed the host's via LD_LIBRARY_PATH; Fedora's Mesa references
> `wl_fixes_interface` (wayland 1.23), so the Mesa vendor lib failed to dlopen
> → glvnd had zero EGL vendors → every EGL platform (even the web process's
> surfaceless one) failed → SIGABRT. Fix: `build-appimage.sh` strips ALL
> `libwayland-*.so*` from the AppDir and repacks (host copy is used — anything
> ≥ our glibc floor ships wayland ≥1.20 via GTK3), plus `WEBKIT_EXEC_PATH` /
> `WEBKIT_INJECTED_BUNDLE_PATH` set under `$APPIMAGE` (main.rs) so the bundled
> webkit finds its helper processes. Verified end-user-style on Fedora/Wayland:
> all processes alive, clean stderr, no coredumps. Debug leads for any future
> host issue: `coredumpctl list` (which process died), the dlopen test
> (`LD_LIBRARY_PATH=<AppDir>/usr/lib python3 -c "import ctypes;
> ctypes.CDLL('/usr/lib64/libEGL_mesa.so.0')"`), and the shadow audit (AppDir
> sonames ∩ GPU-stack DT_NEEDED). This file is the design record.
>
> **Updates (hardening-health, WP6):** the daemon reports
> `health.daemon_version` and `health.install_kind` on `get_status`
> (`grepfocusd --version` prints the same), the GUI compares it with its own
> `CARGO_PKG_VERSION` through `crates/gui/src/version.rs` (semver; one
> decision table, `advise`) and the Status tab offers *Update system service*
> when an AppImage is newer than a `/usr/local/bin` daemon — the same pkexec
> installer re-run. The bootstrap now runs the installer with `bash` (it was
> `/bin/sh`, which is dash on Debian/Ubuntu and killed the first-run install
> there); the installer refuses to run over a package install (exit 98) and
> to downgrade (exit 99, `--force` from the CLI only), and saves a customised
> unit as `.bak`. Design: `docs/plans/hardening-health-updates.md` (§8, WP6).

## Why

/download's .deb needs WebKitGTK 4.1 (Ubuntu 24.04+/Debian 13) and the RPM is
Fedora-built — Mint, older Ubuntu, openSUSE, Arch users hit a wall. AppImage is
the reach-expander; Flatpak was considered and rejected (sandbox cannot install
a systemd unit, write /etc/hosts, or run a root daemon — the product's core).
Optional cheap sidecar: an AUR PKGBUILD (native packaging handles the daemon
exactly like the RPM/deb; an afternoon, mostly the existing build steps).

## Current state (verified 2026-08-02, repo survey)

- **Tauri bundler is OFF**: `crates/gui/tauri.conf.json` has
  `"bundle": { "active": false, "category": "Utility" }` — no targets, no icon
  array, no linux section. `grep -rni appimage` over the repo: zero hits.
  tauri-cli is NOT installed (README suggests `cargo install tauri-cli
  --version "^2.0"`). Tauri v2 (tauri 2.11.1 / wry 0.55.1 in Cargo.lock).
- **Icons**: `crates/gui/icons/` has only a 64×64 `icon.png` + `icon.svg`.
  The bundler wants a proper icon set (32/128/256 PNGs); today codegen falls
  back to `icons/icon.png` and `main.rs:473` `expect("bundled icon")`s on it.
- **GUI serves its frontend over real localhost HTTP** (not `tauri://`):
  `main.rs:423-432`, portpicker + tauri-plugin-localhost, because wry's custom
  scheme is unreliable on webkit2gtk-4.1 (2.52). Every command is ACL'd as
  "remote" in `capabilities/default.json`. Bundling must not disturb this.
- **IPC/auth**: socket `/run/grepfocus/sock`, mode 0660 group `grepfocus` —
  group membership IS the authorization. Path is hardcoded in TWO places
  (`crates/daemon/src/paths.rs:15` and `crates/gui/src/client.rs:9`).
- **Daemon-missing detection exists only as error strings**:
  `crates/gui/src/client.rs:11-28` maps NotFound/ConnectionRefused ("daemon is
  not running… sudo ./packaging/install.sh") and PermissionDenied ("usermod
  -aG grepfocus… relogin"). Frontend has NO first-run screen — errors land in
  generic `catch` blocks (`ui/src/main.ts:356` etc.). Tray watcher shows
  "daemon unreachable" tooltip (`main.rs:346-382`).
- **No pkexec/polkit anywhere in the repo** — the GUI never escalates; the
  only subprocess it spawns is `busctl` (tray detection).
- **Existing install machinery to reuse**: RPM spec + debian/ both install
  grepfocusd + unit (`packaging/systemd/grepfocusd.service`, ExecStart sed'd
  from /usr/local/bin), sysusers `g grepfocus -`, tmpfiles
  `d /run/grepfocus 0755`, preset, enable+start on install, and
  `grepfocusd cleanup` on remove. Dev-path equivalent: `packaging/install.sh`
  (root; groupadd, usermod -aG for $SUDO_USER, /usr/local/bin, enable,
  restart). Build scripts: `packaging/build-rpm.sh` (clean-tree git archive →
  rpmbuild → dist/), `packaging/build-deb.sh` (podman ubuntu:24.04 →
  dpkg-buildpackage → dist/).
- Version lives in 5 hand-synced places (root Cargo.toml, tauri.conf.json,
  spec, debian/changelog, PKGBUILD); the binaries read it via
  `CARGO_PKG_VERSION` and a gui test pins tauri.conf.json to it. No CI
  (`.github/` absent).

## Scope

### 1. AppImage build of the GUI

- Turn the bundler on for an appimage target only (leave rpm/deb to the
  existing native packaging — do NOT let tauri bundle those). Needs a real
  icon set first (derive 32/128/256/512 from `icon.svg`).
- The AppImage bundles the GUI + webkit runtime. Known Tauri-v2 pain points:
  linuxdeploy fetching at build time, webkit2gtk bundling size (~100MB+),
  and the tray's dlopened libayatana-appindicator (must be bundled or the
  tray silently fails — verify on a GNOME box and one non-GNOME box).
- Build on the OLDEST convenient base (the ubuntu:24.04 podman image already
  exists in `packaging/deb/Containerfile`) so glibc is broadly compatible.
  Add a `packaging/build-appimage.sh` in the style of the other two scripts,
  outputting `dist/GrepFocus-<ver>-x86_64.AppImage` + a `grepfocus.AppImage`
  stable-name copy.

### 2. First-run daemon installer (the real engineering)

The AppImage carries only the GUI; the daemon must be installed system-side.
Plan:

- Ship `grepfocusd` INSIDE the AppImage (both binaries build from one
  workspace anyway) plus the unit/sysusers/tmpfiles files as resources.
- New GUI state: on connect failure with NotFound/ConnectionRefused AND
  running from an AppImage (detect via $APPIMAGE env), show a proper
  first-run screen (new UI state in `ui/`, not just an error string) with an
  "Install system service" button.
- The button runs a single self-contained install script via **pkexec**
  (polkit is present on every desktop distro; no polkit policy file needed
  for a one-shot `pkexec /path/script`, it just prompts). Script does what
  the RPM %post + install.sh already do: copy grepfocusd to /usr/local/bin
  (NOT /usr/bin — that's package-manager turf), install unit (ExecStart
  /usr/local/bin), sysusers/groupadd, tmpfiles, `usermod -aG grepfocus
  <invoking user>`, daemon-reload, enable, start.
- After install: the relogin-for-group-membership problem. Either tell the
  user to relogin (current packages do), or better: `sg grepfocus` won't help
  a running GUI — just detect PermissionDenied and show the "log out and back
  in" state distinctly.
- Upgrades: on version mismatch (GUI newer than daemon — needs a
  daemon-version field in get_status if absent), offer "Update system
  service" via the same pkexec path. DONE — see hardening-health-updates.md
  WP6; note `install_kind` is `local` for BOTH the AppImage installer and
  the dev scripts, so the offer keys off `$APPIMAGE` plus the two binary
  probes, never off `install_kind` alone.
- Uninstall parity: ship the teardown (`grepfocusd cleanup` + file removal)
  as a flag of the same script; mention it on the first-run screen.

### 3. Website follow-up (grepfocus-web, separate session)

- Fill the AppImage "Coming soon" row on /download: href, sha256, hint
  (`chmod +x && ./`), note about first-run installer prompting for the
  system service.
- Release-swap checklist gains a third artifact (aliases:
  `/downloads/grepfocus.AppImage`).

## Constraints / cautions

- The GUI's localhost-HTTP serving + remote-ACL setup must keep working from
  inside the AppImage mount (it should — it's all in-process — but verify).
- pkexec runs the script as root from a user-writable location (the AppImage
  mount): copy the script+payload to a root-owned temp dir first, or verify
  payload hashes from the script, so an attacker can't swap the binary
  between click and execution. At minimum: install script must be executed
  from the mounted (read-only) AppImage path, never from /tmp.
- Signing-key rule (see grepfocus-web memory) is irrelevant here — no keys
  touched.
- License note: artifacts are PolyForm Shield; keep LICENSE inside the
  AppImage like the deb does (`/usr/share/doc/grepfocus/LICENSE`).
- Commit-message policy: no AI attribution (repo CLAUDE.md).

## Order

1. Icon set + bundler config + build script → a GUI-only AppImage that runs
   on a machine WITH the daemon already installed (validates the bundling).
2. First-run screen + pkexec installer → works on a clean machine.
3. AUR PKGBUILD (independent, can happen any time).
4. Website /download row once artifacts are audited (sha256s, strings-grep
   for pubkey `q4Zz7G8tXk2KYUp_JjLIZhOHdElcjhJ37GyyA-aVfJc`, same as
   RPM/deb audits).
