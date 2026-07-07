#!/usr/bin/env bash
# Frostbite uninstaller.
#
# Tears down enforcement FIRST (via `frostbited cleanup`, or an inline
# fallback if the binary is already gone), then removes:
#   /usr/local/bin/frostbited and /usr/local/bin/frostbite-gui
#   /etc/systemd/system/frostbited.service
#   the invoking user's launcher, icon, and autostart files
#   /run/frostbite
# Every step tolerates absence, so running this twice is safe. Run as root.
#
# Usage: sudo ./packaging/uninstall.sh [--purge]
#   --purge   also delete /var/lib/frostbite (saved blocks, password),
#             /etc/frostbite (secret), and the frostbite group

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (try: sudo $0)" >&2
    exit 1
fi

PURGE=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        *)
            echo "Unknown flag: $arg" >&2
            echo "Usage: sudo $0 [--purge]" >&2
            exit 2
            ;;
    esac
done

# Interactive with no flag given: ask. Non-interactive defaults to keep, so
# scripted uninstalls never destroy saved data by surprise.
if [[ $# -eq 0 && -t 0 ]]; then
    # Drain stale buffered keystrokes first: a leftover "y" queued during an
    # earlier sudo prompt must not be able to answer a destructive question.
    while read -r -t 0; do
        read -r -t 1 _ || break
    done
    read -r -p "Also delete saved blocks, password, and secret? [y/N] " answer || answer=""
    case "$answer" in
        [yY]|[yY][eE][sS]) PURGE=1 ;;
    esac
fi

# Echo the decision so a mis-answered prompt is visible before it acts.
if [[ $PURGE -eq 1 ]]; then
    echo "==> Will PURGE saved data (blocks, password, secret, group)"
else
    echo "==> Keeping saved data (re-run with --purge to delete it)"
fi

# Minimal teardown of the artifacts that block traffic on their own. Used
# when the binary is missing (broken/partial install) or when delegation to
# `frostbited cleanup` fails or times out.
inline_teardown() {
    chattr -i /etc/hosts 2>/dev/null || true
    if [[ -f /etc/hosts ]]; then
        sed -i '/# frostbite-begin/,/# frostbite-end/d' /etc/hosts \
            || { echo "failed to strip the managed region from /etc/hosts" >&2; exit 1; }
    elif [[ -f /var/lib/frostbite/hosts.orig ]]; then
        # /etc/hosts is gone entirely — restore the snapshot before a purge
        # deletes the only copy. install, not cp: the mode matters, because
        # the resolver in non-root processes needs 0644.
        install -m 0644 /var/lib/frostbite/hosts.orig /etc/hosts
    fi
    rm -f /etc/hosts.frostbite.tmp /var/lib/frostbite/hosts.orig.frostbite.tmp
    nft delete table inet frostbite_doh 2>/dev/null || true
    if [[ $PURGE -eq 1 ]]; then
        rm -rf /var/lib/frostbite /etc/frostbite
    else
        cat <<'EOF'
Note: the state file is HMAC-signed, so this fallback cannot clear persisted
active blocks. If you reinstall later, any block that was active will
re-apply until it expires. Re-run with --purge (or run `frostbited cleanup`
from the reinstall) to avoid that.
EOF
    fi
}

echo "==> Stopping and disabling frostbited"
systemctl disable --now frostbited 2>/dev/null || true

echo "==> Stopping the GUI (if running)"
pkill -x frostbite-gui || true

# Tear down enforcement while the binary still exists — the daemon's own
# cleanup path handles the immutable bit, hosts strip/restore, atomic-write
# orphans, the nftables table, and persisted active blocks. Removing the
# binary first would strand a chattr +i /etc/hosts: that is the brick.
if [[ -x /usr/local/bin/frostbited ]]; then
    echo "==> Tearing down enforcement (frostbited cleanup)"
    CLEANUP_ARGS=()
    if [[ $PURGE -eq 1 ]]; then
        CLEANUP_ARGS+=(--purge)
    fi
    # Bound the delegation: a binary built before the cleanup subcommand
    # existed ignores argv and boots the full daemon, serving forever. 30s
    # caps that, and the fallback strips whatever it re-applied.
    if ! timeout --kill-after=5 30 /usr/local/bin/frostbited cleanup "${CLEANUP_ARGS[@]}"; then
        echo "frostbited cleanup failed or timed out (pre-cleanup binary?) — falling back to inline teardown" >&2
        inline_teardown
    fi
else
    # Broken/partial install: no binary to delegate to.
    echo "==> frostbited binary missing — inline enforcement teardown"
    inline_teardown
fi

echo "==> Removing binaries"
rm -f /usr/local/bin/frostbited /usr/local/bin/frostbite-gui

echo "==> Removing systemd unit"
# Remove the enablement symlink explicitly too: in a chroot (recovery
# environment) the earlier `systemctl disable` is swallowed, and a bare
# daemon-reload would die there under set -e, skipping every later step.
rm -f /etc/systemd/system/frostbited.service \
    /etc/systemd/system/multi-user.target.wants/frostbited.service
systemctl daemon-reload 2>/dev/null || true

echo "==> Removing launcher, icon, and autostart entry"
INVOKING_USER="${SUDO_USER:-$USER}"
USER_HOME="$(getent passwd "$INVOKING_USER" | cut -d: -f6 || true)"
if [[ -n "$USER_HOME" ]]; then
    rm -f "$USER_HOME/.local/share/applications/frostbite.desktop" \
        "$USER_HOME/.config/autostart/frostbite.desktop" \
        "$USER_HOME/.local/share/icons/hicolor/64x64/apps/frostbite.png"
    # Best-effort cache refresh so the stale entry disappears promptly.
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        sudo -u "$INVOKING_USER" gtk-update-icon-cache -f -t \
            "$USER_HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        sudo -u "$INVOKING_USER" update-desktop-database \
            "$USER_HOME/.local/share/applications" >/dev/null 2>&1 || true
    fi
fi
echo "    (launcher files under other users' homes, if any, need manual removal)"

echo "==> Removing runtime directory"
rm -rf /run/frostbite

if [[ $PURGE -eq 1 ]]; then
    echo "==> Removing frostbite group"
    groupdel frostbite 2>/dev/null || true
fi

cat <<EOF

==> Uninstall complete.

Removed: enforcement (/etc/hosts region, nftables table), binaries,
systemd unit, launcher files for $INVOKING_USER, /run/frostbite.
EOF
if [[ $PURGE -eq 1 ]]; then
    echo "Purged: /var/lib/frostbite, /etc/frostbite, and the frostbite group."
else
    cat <<EOF
Kept: /var/lib/frostbite (saved blocks, password) and /etc/frostbite
(secret) — a reinstall picks them up. Re-run with --purge to delete them.
EOF
fi
