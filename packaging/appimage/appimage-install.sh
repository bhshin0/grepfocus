#!/usr/bin/env bash
# Privileged installer for the AppImage build: first run AND update. Run as
# root BY the GUI's `install_service` command, via a pkexec'd bootstrap:
#
#     bash <root-tmp>/appimage-install.sh <action> <user>
#
#   <action>  install | uninstall
#   <user>    the desktop user to add to the grepfocus group (install only)
#   --force   install only, CLI only (the bootstrap never forwards it):
#             override the downgrade guard
#
# Re-running `install` is the update path: the daemon binary and unit are
# replaced and the service restarted (active blocks stay enforced across the
# restart; the settings lock, pending break challenges and unflushed kill
# counts are lost, as with packaging/upgrade.sh). Two guards keep a re-run
# from doing harm: it refuses to run over a package-manager install (rpm/deb/
# AUR own /usr/bin/grepfocusd) and it refuses to replace a newer service with
# an older payload unless --force. A unit the admin customised is saved as
# .bak before being replaced — use a drop-in instead.
#
# Exit codes: 0 ok · 2 usage · 98 a package install owns grepfocusd ·
# 99 would downgrade (97 = payload integrity, raised by the bootstrap). The
# GUI maps these in `installer_error` (crates/gui/src/main.rs).
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
# /usr/bin. This is a bash script and the bootstrap runs it with bash: /bin/sh
# is dash on Debian/Ubuntu, the AppImage's audience.
set -euo pipefail

PAYLOAD="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-install}"
TARGET_USER="${2:-}"
FORCE="${3:-}"

BIN=/usr/local/bin/grepfocusd
PACKAGED_BIN=/usr/bin/grepfocusd
UNIT=/etc/systemd/system/grepfocusd.service

usage() {
    echo "usage: $0 install <user> [--force] | uninstall" >&2
    exit 2
}

# A package install owns the daemon: installing a second copy under
# /usr/local/bin would leave two units fighting over the same socket, and
# uninstalling ours would tear down enforcement the package still expects.
refuse_over_package() {
    if [[ -e "$PACKAGED_BIN" ]]; then
        echo "error: $PACKAGED_BIN exists — a package install (rpm/deb/AUR) owns grepfocusd; update or remove it with your package manager" >&2
        exit 98
    fi
}

# Both binaries print "grepfocusd X.Y.Z"; a daemon too old to know --version
# prints usage and exits non-zero, which reads as "no current version" and
# lets the install proceed (it is older than any payload that gets here).
version_of() {
    local out
    out=$("$1" --version 2>/dev/null) || return 0
    printf '%s\n' "${out#grepfocusd }"
}

# Refuse to replace a newer service with an older payload. Releases are plain
# MAJOR.MINOR.PATCH, so `sort -V` agrees with the GUI's semver compare.
refuse_downgrade() {
    local new cur newest
    chmod 0755 "$PAYLOAD/grepfocusd"
    new=$(version_of "$PAYLOAD/grepfocusd")
    if [[ -z "$new" ]]; then
        echo "error: the bundled grepfocusd does not report a version" >&2
        exit 1
    fi
    cur=$([[ -x "$BIN" ]] && version_of "$BIN" || true)
    if [[ -n "$cur" && "$cur" != "$new" && "$FORCE" != "--force" ]]; then
        newest=$(printf '%s\n%s\n' "$new" "$cur" | sort -V | tail -n 1)
        if [[ "$newest" == "$cur" ]]; then
            echo "error: refusing to downgrade grepfocusd $cur -> $new (rerun with --force to override)" >&2
            exit 99
        fi
    fi
    echo "==> Installing grepfocusd $new${cur:+ (replacing $cur)}"
}

do_install() {
    refuse_over_package
    refuse_downgrade

    echo "==> Creating grepfocus group (if missing)"
    getent group grepfocus >/dev/null || groupadd --system grepfocus

    if [[ -n "$TARGET_USER" ]]; then
        echo "==> Adding $TARGET_USER to grepfocus group"
        usermod -aG grepfocus "$TARGET_USER" || true
    fi

    echo "==> Installing daemon + unit"
    # `install` sets the mode on copy, so the 0644 payload binary lands as 0755.
    install -D -m 0755 "$PAYLOAD/grepfocusd" "$BIN"
    # A unit that differs from the bundled one was edited by hand (or is an
    # older release's); keep a copy so the edit is not lost silently.
    if [[ -f "$UNIT" ]] && ! cmp -s "$PAYLOAD/grepfocusd.service" "$UNIT"; then
        echo "==> Existing $UNIT differs — saving it as $UNIT.bak"
        cp -p "$UNIT" "$UNIT.bak"
    fi
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

    echo "==> Enabling and (re)starting grepfocusd"
    systemctl daemon-reload
    systemctl enable grepfocusd.service
    systemctl restart grepfocusd.service
    echo "==> Done. On a first install the user must log out and back in for group membership to apply."
}

do_uninstall() {
    refuse_over_package
    echo "==> Stopping and disabling grepfocusd"
    systemctl disable --now grepfocusd.service || true
    # Tear down enforcement (immutable /etc/hosts bit, nftables, browser DoH
    # policies) while the binary still exists.
    [[ -x "$BIN" ]] && timeout --kill-after=5 30 "$BIN" cleanup || true
    echo "==> Removing files"
    rm -f "$BIN" "$UNIT" \
          /usr/lib/sysusers.d/grepfocus.conf \
          /usr/lib/tmpfiles.d/grepfocus.conf
    systemctl daemon-reload || true
    echo "==> Removed. Saved data in /var/lib/grepfocus and /etc/grepfocus is kept."
}

case "$ACTION" in
    install)
        [[ -z "$FORCE" || "$FORCE" == "--force" ]] || usage
        do_install
        ;;
    uninstall)
        [[ -z "$FORCE" ]] || usage
        do_uninstall
        ;;
    *) usage ;;
esac
