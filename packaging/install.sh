#!/usr/bin/env bash
# Frostbite dev installer.
#
# Builds the daemon in release mode and installs:
#   /usr/local/bin/frostbited
#   /etc/systemd/system/frostbited.service
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

echo "==> Building frostbited (release)"
# Build as the invoking user so the cargo cache lives in their home dir.
INVOKING_USER="${SUDO_USER:-$USER}"
sudo -u "$INVOKING_USER" -H bash -c 'source "$HOME/.cargo/env"; cargo build --release -p frostbited'

echo "==> Creating frostbite group (if missing)"
if ! getent group frostbite >/dev/null; then
    groupadd --system frostbite
fi

echo "==> Adding $INVOKING_USER to frostbite group"
usermod -aG frostbite "$INVOKING_USER" || true

echo "==> Installing binary"
install -m 0755 target/release/frostbited /usr/local/bin/frostbited

echo "==> Installing systemd unit"
install -m 0644 packaging/systemd/frostbited.service /etc/systemd/system/frostbited.service

echo "==> Creating runtime directories"
install -d -m 0700 /etc/frostbite
install -d -m 0700 /var/lib/frostbite
install -d -m 0755 /run/frostbite

echo "==> Enabling and starting frostbited"
systemctl daemon-reload
systemctl enable --now frostbited

cat <<EOF

==> Install complete.

Next steps:
  1. Log out and back in (or run 'newgrp frostbite') so your group membership
     takes effect — needed to talk to /run/frostbite/sock.
  2. Check the daemon is running:   systemctl status frostbited
  3. Tail the logs:                  journalctl -u frostbited -f
  4. The GUI (when built) talks to:  /run/frostbite/sock

To uninstall:
  sudo systemctl disable --now frostbited
  sudo rm /usr/local/bin/frostbited /etc/systemd/system/frostbited.service
  sudo rm -rf /etc/frostbite /var/lib/frostbite /run/frostbite
  sudo groupdel frostbite
EOF
