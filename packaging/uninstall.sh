#!/usr/bin/env bash
# GrepFocus uninstaller.
#
# Tears down enforcement FIRST (via `grepfocusd cleanup`, or an inline
# fallback if the binary is already gone), then removes:
#   /usr/local/bin/grepfocusd and /usr/local/bin/grepfocus-gui
#   /etc/systemd/system/grepfocusd.service
#   the invoking user's launcher, icon, and autostart files
#   /run/grepfocus
# Every step tolerates absence, so running this twice is safe. Run as root.
#
# Usage: sudo ./packaging/uninstall.sh [--purge]
#   --purge   also delete /var/lib/grepfocus (saved blocks, password),
#             /etc/grepfocus (secret), and the grepfocus group

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

# Shell mirror of the daemon's Firefox-family policy removal
# (browser_policy::remove_one), for one file and its recovery copy. The
# daemon parses the JSON; this fallback only looks for the marker lines the
# daemon's canonical render produces, so: no marker → not ours, keep it (and
# any recovery copy); recovery copy present → put it back byte-exact (both
# files stay if that fails: the rest of the teardown must still run);
# marker says we created the file → delete it; otherwise the file is a merge
# whose copy is gone, and the DNSOverHTTPS and grepfocus keys need a hand.
restore_firefox_policy() {
    local f="$1" orig="$2"
    [[ -f "$f" ]] || return 0
    if ! grep -q '^  "grepfocus": {' "$f"; then
        if [[ -f "$orig" ]]; then
            echo "note: $f is not managed by GrepFocus — keeping it and $orig" >&2
        fi
        return 0
    fi
    if [[ -f "$orig" ]]; then
        if install -m 0644 "$orig" "$f"; then
            rm -f "$orig"
        else
            echo "note: could not restore $f from $orig — both kept, restore it by hand" >&2
        fi
    elif grep -q '^    "created": true' "$f"; then
        rm -f "$f"
    else
        echo "note: $f carries GrepFocus's DNSOverHTTPS policy and its recovery copy is gone — remove the \"DNSOverHTTPS\" and \"grepfocus\" keys by hand" >&2
    fi
}

# Minimal teardown of the artifacts that block traffic on their own. Used
# when the binary is missing (broken/partial install) or when delegation to
# `grepfocusd cleanup` fails or times out. The browser policy files do not
# block traffic, but they outlive the daemon, so they go here too: every
# path below is pinned to browser_policy::managed_paths by a daemon test.
inline_teardown() {
    chattr -i /etc/hosts 2>/dev/null || true
    if [[ -f /etc/hosts ]]; then
        sed -i '/# grepfocus-begin/,/# grepfocus-end/d' /etc/hosts \
            || { echo "failed to strip the managed region from /etc/hosts" >&2; exit 1; }
    elif [[ -f /var/lib/grepfocus/hosts.orig ]]; then
        # /etc/hosts is gone entirely — restore the snapshot before a purge
        # deletes the only copy. install, not cp: the mode matters, because
        # the resolver in non-root processes needs 0644.
        install -m 0644 /var/lib/grepfocus/hosts.orig /etc/hosts
    fi
    rm -f /etc/hosts.grepfocus.tmp /var/lib/grepfocus/hosts.orig.grepfocus.tmp
    nft delete table inet grepfocus_doh 2>/dev/null || true
    # Browser DoH policies. The Chromium-family files are ours outright (the
    # filename is the marker); the Firefox-family files are shared.
    rm -f /etc/chromium/policies/managed/grepfocus.json \
        /var/snap/chromium/current/policies/managed/grepfocus.json \
        /etc/opt/chrome/policies/managed/grepfocus.json \
        /etc/brave/policies/managed/grepfocus.json
    restore_firefox_policy /etc/firefox/policies/policies.json \
        /var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig
    restore_firefox_policy /usr/lib/mullvad-browser/distribution/policies.json \
        /var/lib/grepfocus/policies/_usr_lib_mullvad-browser_distribution_policies.json.orig
    rm -f /etc/firefox/policies/policies.json.grepfocus.tmp \
        /usr/lib/mullvad-browser/distribution/policies.json.grepfocus.tmp \
        /etc/chromium/policies/managed/grepfocus.json.grepfocus.tmp \
        /var/snap/chromium/current/policies/managed/grepfocus.json.grepfocus.tmp \
        /etc/opt/chrome/policies/managed/grepfocus.json.grepfocus.tmp \
        /etc/brave/policies/managed/grepfocus.json.grepfocus.tmp \
        /var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig.grepfocus.tmp \
        /var/lib/grepfocus/policies/_usr_lib_mullvad-browser_distribution_policies.json.orig.grepfocus.tmp
    if [[ $PURGE -eq 1 ]]; then
        rm -rf /var/lib/grepfocus /etc/grepfocus
    else
        cat <<'EOF'
Note: the state file is HMAC-signed, so this fallback cannot clear persisted
active blocks. If you reinstall later, any block that was active will
re-apply until it expires. Re-run with --purge (or run `grepfocusd cleanup`
from the reinstall) to avoid that.
EOF
    fi
}

echo "==> Stopping and disabling grepfocusd"
systemctl disable --now grepfocusd 2>/dev/null || true

echo "==> Stopping the GUI (if running)"
pkill -x grepfocus-gui || true

# Tear down enforcement while the binary still exists — the daemon's own
# cleanup path handles the immutable bit, hosts strip/restore, atomic-write
# orphans, the nftables table, the browser DoH policy files, and persisted
# active blocks. Removing the binary first would strand a chattr +i
# /etc/hosts: that is the brick.
if [[ -x /usr/local/bin/grepfocusd ]]; then
    echo "==> Tearing down enforcement (grepfocusd cleanup)"
    CLEANUP_ARGS=()
    if [[ $PURGE -eq 1 ]]; then
        CLEANUP_ARGS+=(--purge)
    fi
    # Bound the delegation: a binary built before the cleanup subcommand
    # existed ignores argv and boots the full daemon, serving forever. 30s
    # caps that, and the fallback strips whatever it re-applied.
    if ! timeout --kill-after=5 30 /usr/local/bin/grepfocusd cleanup "${CLEANUP_ARGS[@]}"; then
        echo "grepfocusd cleanup failed or timed out (pre-cleanup binary?) — falling back to inline teardown" >&2
        inline_teardown
    fi
else
    # Broken/partial install: no binary to delegate to.
    echo "==> grepfocusd binary missing — inline enforcement teardown"
    inline_teardown
fi

echo "==> Removing binaries"
rm -f /usr/local/bin/grepfocusd /usr/local/bin/grepfocus-gui

echo "==> Removing systemd unit"
# Remove the enablement symlink explicitly too: in a chroot (recovery
# environment) the earlier `systemctl disable` is swallowed, and a bare
# daemon-reload would die there under set -e, skipping every later step.
rm -f /etc/systemd/system/grepfocusd.service \
    /etc/systemd/system/multi-user.target.wants/grepfocusd.service
systemctl daemon-reload 2>/dev/null || true

echo "==> Removing launcher, icon, and autostart entry"
INVOKING_USER="${SUDO_USER:-$USER}"
USER_HOME="$(getent passwd "$INVOKING_USER" | cut -d: -f6 || true)"
if [[ -n "$USER_HOME" ]]; then
    rm -f "$USER_HOME/.local/share/applications/grepfocus.desktop" \
        "$USER_HOME/.config/autostart/grepfocus.desktop" \
        "$USER_HOME/.local/share/icons/hicolor/64x64/apps/grepfocus.png"
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
rm -rf /run/grepfocus

if [[ $PURGE -eq 1 ]]; then
    echo "==> Removing grepfocus group"
    groupdel grepfocus 2>/dev/null || true
fi

cat <<EOF

==> Uninstall complete.

Removed: enforcement (/etc/hosts region, nftables table, browser DoH
policies), binaries, systemd unit, launcher files for $INVOKING_USER,
/run/grepfocus. Restart any browser that was open so it drops the
"managed by your organization" notice.
EOF
if [[ $PURGE -eq 1 ]]; then
    echo "Purged: /var/lib/grepfocus, /etc/grepfocus, and the grepfocus group."
else
    cat <<EOF
Kept: /var/lib/grepfocus (saved blocks, password) and /etc/grepfocus
(secret) — a reinstall picks them up. Re-run with --purge to delete them.
EOF
fi
