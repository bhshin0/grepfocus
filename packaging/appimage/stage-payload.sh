#!/usr/bin/env bash
# Stage the files that get bundled INSIDE the AppImage as Tauri resources
# (tauri.conf.json bundle.resources -> "appimage-payload/*"). The AppImage
# carries only the GUI by nature; these let its first-run installer set up the
# system-side daemon via pkexec (see appimage-install.sh + the install_service
# command in crates/gui/src/main.rs).
#
# Run from the repo root AFTER `cargo build --release` (needs target/release/
# grepfocusd). build-appimage.sh calls this before `cargo tauri build`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

DEST="crates/gui/appimage-payload"

if [[ ! -x target/release/grepfocusd ]]; then
    echo "error: target/release/grepfocusd missing — run 'cargo build --release' first." >&2
    exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"

# The daemon binary + the system unit/config files, copied verbatim from the
# same sources the RPM/deb/AUR install. The install script relocates them at
# first run; it sets executable modes on copy, so nothing here needs +x.
install -m 0644 target/release/grepfocusd            "$DEST/grepfocusd"
install -m 0644 packaging/systemd/grepfocusd.service "$DEST/grepfocusd.service"
install -m 0644 packaging/sysusers.d/grepfocus.conf  "$DEST/grepfocus.sysusers.conf"
install -m 0644 packaging/tmpfiles.d/grepfocus.conf  "$DEST/grepfocus.tmpfiles.conf"
install -m 0644 packaging/grepfocus.desktop          "$DEST/grepfocus.desktop"
install -m 0644 packaging/appimage/appimage-install.sh "$DEST/appimage-install.sh"
install -m 0644 LICENSE                               "$DEST/LICENSE"

echo "==> Staged AppImage payload into $DEST:"
ls -la "$DEST"
