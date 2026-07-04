#!/usr/bin/env bash
# Frostbite dev upgrade loop — the one command to run after every change.
#
# Rebuilds the UI, daemon, and GUI, then redeploys:
#   /usr/local/bin/frostbited          (+ restart the frostbited service)
#   /usr/local/bin/frostbite-gui
#   ~/.local/share/applications/frostbite.desktop   (app-grid launcher)
#   ~/.local/share/icons/hicolor/64x64/apps/frostbite.png
#   ~/.config/autostart/frostbite.desktop           (start GUI + tray at login)
#
# Run as your normal user (NOT root). It uses sudo only for the system steps;
# your sudo may prompt for a fingerprint/password there.
#
# Usage: ./packaging/upgrade.sh

set -euo pipefail

if [[ $EUID -eq 0 ]]; then
    echo "Run this as your normal user, not root (it uses sudo where needed)." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Order matters: the Tauri build embeds ui/dist at compile time, and a plain
# `cargo build` does not run tauri.conf.json's beforeBuildCommand, so the UI
# must be built BEFORE cargo.
echo "==> Building UI (embedded into the GUI at compile time)"
pnpm --dir crates/gui/ui install
pnpm --dir crates/gui/ui build

echo "==> Building release binaries"
cargo build --release

echo "==> Installing daemon and restarting service (sudo)"
sudo install -m0755 target/release/frostbited /usr/local/bin/frostbited
sudo systemctl restart frostbited

echo "==> Installing GUI binary (sudo)"
sudo install -m0755 target/release/frostbite-gui /usr/local/bin/frostbite-gui

echo "==> Installing launcher, icon, and autostart entry (no sudo needed)"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/64x64/apps"
AUTOSTART_DIR="$HOME/.config/autostart"
install -d "$APP_DIR" "$ICON_DIR" "$AUTOSTART_DIR"
install -m0644 packaging/frostbite.desktop "$APP_DIR/frostbite.desktop"
install -m0644 crates/gui/icons/icon.png "$ICON_DIR/frostbite.png"
install -m0644 packaging/frostbite.desktop "$AUTOSTART_DIR/frostbite.desktop"

# Best-effort cache refresh so the launcher icon/entry show up promptly.
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi

echo
echo "==> Upgrade complete."
echo "    Daemon:  $(systemctl is-active frostbited 2>/dev/null || echo unknown)"
echo "    Launch 'Frostbite' from your app grid, or run: /usr/local/bin/frostbite-gui"
