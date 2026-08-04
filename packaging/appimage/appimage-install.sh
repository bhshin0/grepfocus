#!/usr/bin/env bash
# Privileged first-run installer for the AppImage build. Run as root BY the
# GUI's `install_service` command, via a pkexec'd bootstrap:
#
#     /bin/sh <root-tmp>/appimage-install.sh <action> <user>
#
#   <action>  install | uninstall
#   <user>    the desktop user to add to the grepfocus group (install only)
#
# It does ONLY the system-side steps the RPM %post / packaging/install.sh do —
# it never builds. It CANNOT run from the AppImage mount: that mount is
# user-private FUSE (no allow_other), unreadable by every other uid including
# root. So the GUI stages this script + the daemon + unit/config files into a
# temp dir with their sha256es passed via pkexec argv, and the bootstrap (see
# BOOTSTRAP in crates/gui/src/main.rs) copies them into a ROOT-owned temp dir
# and re-verifies the hashes there before executing this script — the payload
# siblings are found via dirname "$0" as before. Binaries are installed to
# /usr/local/bin so this never collides with a package-manager install in
# /usr/bin.
set -euo pipefail

PAYLOAD="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-install}"
TARGET_USER="${2:-}"

BIN=/usr/local/bin/grepfocusd
UNIT=/etc/systemd/system/grepfocusd.service

do_install() {
    echo "==> Creating grepfocus group (if missing)"
    getent group grepfocus >/dev/null || groupadd --system grepfocus

    if [[ -n "$TARGET_USER" ]]; then
        echo "==> Adding $TARGET_USER to grepfocus group"
        usermod -aG grepfocus "$TARGET_USER" || true
    fi

    echo "==> Installing daemon + unit"
    # `install` sets the mode on copy, so the 0644 payload binary lands as 0755.
    install -D -m 0755 "$PAYLOAD/grepfocusd" "$BIN"
    install -D -m 0644 "$PAYLOAD/grepfocusd.service" "$UNIT"
    # The packaged unit's ExecStart points at /usr/local/bin already (that's the
    # source path); no sed needed here.

    echo "==> Installing sysusers/tmpfiles drop-ins"
    install -D -m 0644 "$PAYLOAD/grepfocus.sysusers.conf" /usr/lib/sysusers.d/grepfocus.conf
    install -D -m 0644 "$PAYLOAD/grepfocus.tmpfiles.conf" /usr/lib/tmpfiles.d/grepfocus.conf
    systemd-sysusers /usr/lib/sysusers.d/grepfocus.conf || true
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/grepfocus.conf || true

    echo "==> Creating runtime directories"
    install -d -m 0700 /etc/grepfocus
    install -d -m 0700 /var/lib/grepfocus
    install -d -m 0755 /run/grepfocus

    echo "==> Enabling and starting grepfocusd"
    systemctl daemon-reload
    systemctl enable grepfocusd.service
    systemctl restart grepfocusd.service
    echo "==> Done. The user must log out and back in for group membership to apply."
}

do_uninstall() {
    echo "==> Stopping and disabling grepfocusd"
    systemctl disable --now grepfocusd.service || true
    # Tear down enforcement (immutable /etc/hosts bit, nftables) while the binary
    # still exists.
    [[ -x "$BIN" ]] && timeout --kill-after=5 30 "$BIN" cleanup || true
    echo "==> Removing files"
    rm -f "$BIN" "$UNIT" \
          /usr/lib/sysusers.d/grepfocus.conf \
          /usr/lib/tmpfiles.d/grepfocus.conf
    systemctl daemon-reload || true
    echo "==> Removed. Saved data in /var/lib/grepfocus and /etc/grepfocus is kept."
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    *) echo "usage: $0 install <user> | uninstall" >&2; exit 2 ;;
esac
