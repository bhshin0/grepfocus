#!/usr/bin/env bash
# Frostbite dev installer.
#
# Builds the UI, daemon, and GUI in release mode and installs:
#   /usr/local/bin/frostbited
#   /usr/local/bin/frostbite-gui
#   /etc/systemd/system/frostbited.service
#   ~/.local/share/applications/frostbite.desktop   (app-grid launcher)
#   ~/.local/share/icons/hicolor/64x64/apps/frostbite.png
#   ~/.config/autostart/frostbite.desktop           (start GUI + tray at login)
# Creates the `frostbite` group, runtime/state directories, and enables the
# systemd unit. Run as root.
#
# Usage: sudo ./packaging/install.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (try: sudo $0)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Build as the invoking user so the cargo cache and node_modules live in
# their home dir instead of root's.
INVOKING_USER="${SUDO_USER:-$USER}"

echo "==> Checking prerequisites"
if ! sudo -u "$INVOKING_USER" -H bash -lc 'command -v pnpm' >/dev/null 2>&1; then
    echo "pnpm not found on $INVOKING_USER's PATH — the UI build needs it." >&2
    echo "Install it first (https://pnpm.io/installation), then re-run." >&2
    exit 1
fi
if ! sudo -u "$INVOKING_USER" -H bash -lc 'command -v cargo || [ -f "$HOME/.cargo/env" ]' >/dev/null 2>&1; then
    echo "cargo not found on $INVOKING_USER's PATH and no ~/.cargo/env — the daemon build needs it." >&2
    echo "Install Rust via rustup (https://rustup.rs) first, then re-run." >&2
    exit 1
fi

# Order matters: the Tauri build embeds ui/dist at compile time, and a plain
# `cargo build` does not run tauri.conf.json's beforeBuildCommand, so the UI
# must be built BEFORE cargo.
echo "==> Building UI (embedded into the GUI at compile time)"
sudo -u "$INVOKING_USER" -H bash -lc \
    'pnpm --dir crates/gui/ui install && pnpm --dir crates/gui/ui build'

echo "==> Building release binaries"
# Login shell so PATH-based toolchains (mise, asdf, profile) work; source
# ~/.cargo/env only if rustup actually wrote one.
sudo -u "$INVOKING_USER" -H bash -lc '[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; cargo build --release'

echo "==> Creating frostbite group (if missing)"
if ! getent group frostbite >/dev/null; then
    groupadd --system frostbite
fi

echo "==> Adding $INVOKING_USER to frostbite group"
usermod -aG frostbite "$INVOKING_USER" || true

echo "==> Installing binaries"
install -m 0755 target/release/frostbited /usr/local/bin/frostbited
install -m 0755 target/release/frostbite-gui /usr/local/bin/frostbite-gui

echo "==> Installing systemd unit"
install -m 0644 packaging/systemd/frostbited.service /etc/systemd/system/frostbited.service

echo "==> Creating runtime directories"
install -d -m 0700 /etc/frostbite
install -d -m 0700 /var/lib/frostbite
install -d -m 0755 /run/frostbite

echo "==> Enabling and starting frostbited"
systemctl daemon-reload
# restart, not `enable --now`: --now is a no-op for an already-active unit,
# which would leave an old process running after a re-install. restart also
# starts an inactive unit.
systemctl enable frostbited
systemctl restart frostbited

echo "==> Installing launcher, icon, and autostart entry for $INVOKING_USER"
USER_HOME="$(getent passwd "$INVOKING_USER" | cut -d: -f6)"
APP_DIR="$USER_HOME/.local/share/applications"
ICON_DIR="$USER_HOME/.local/share/icons/hicolor/64x64/apps"
AUTOSTART_DIR="$USER_HOME/.config/autostart"
# `sudo -u ... install` so the files are owned by the user, not root.
sudo -u "$INVOKING_USER" install -d "$APP_DIR" "$ICON_DIR" "$AUTOSTART_DIR"
sudo -u "$INVOKING_USER" install -m 0644 packaging/frostbite.desktop "$APP_DIR/frostbite.desktop"
sudo -u "$INVOKING_USER" install -m 0644 crates/gui/icons/icon.png "$ICON_DIR/frostbite.png"
sudo -u "$INVOKING_USER" install -m 0644 packaging/frostbite.desktop "$AUTOSTART_DIR/frostbite.desktop"

# Best-effort cache refresh so the launcher icon/entry show up promptly.
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    sudo -u "$INVOKING_USER" gtk-update-icon-cache -f -t \
        "$USER_HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    sudo -u "$INVOKING_USER" update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi

cat <<EOF

==> Install complete.

Next steps:
  1. Log out and back in (or run 'newgrp frostbite') so your group membership
     takes effect — needed to talk to /run/frostbite/sock.
  2. Check the daemon is running:   systemctl status frostbited
  3. Tail the logs:                  journalctl -u frostbited -f
  4. Launch 'Frostbite' from your app grid, or run: /usr/local/bin/frostbite-gui

To uninstall:
  sudo ./packaging/uninstall.sh [--purge]
EOF
