#!/usr/bin/env bash
# Build the GrepFocus .deb inside an ubuntu:24.04 podman container so the GUI
# links Ubuntu's libraries — a Fedora-built binary would not run on Ubuntu.
# Run as your normal user (NOT root); needs podman. Outputs dist/grepfocus.deb.
#
# Usage: ./packaging/build-deb.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE=grepfocus-deb-builder

echo "==> Building the toolchain image ($IMAGE) [cached after the first run]"
podman build -t "$IMAGE" packaging/deb

mkdir -p dist

echo "==> Building the .deb in the container"
# The repo is mounted at /src; a named volume caches the cargo registry across
# runs. `target/` lives in the mounted tree, so recompiles are incremental.
# dpkg-buildpackage writes the .deb to the PARENT of the source dir (/), so we
# copy it back into the mounted dist/.
podman run --rm \
    -v "$REPO_ROOT":/src:Z \
    -v grepfocus-deb-cargo:/root/.cargo/registry \
    "$IMAGE" bash -euo pipefail -c '
        dpkg-buildpackage -b -us -uc
        mkdir -p /src/dist
        cp /grepfocus_*_*.deb /src/dist/
        latest=$(ls -1t /src/dist/grepfocus_*_*.deb | head -n1)
        cp "$latest" /src/dist/grepfocus.deb
        echo "built: $(basename "$latest")"
    '

echo
echo "==> Built:"
ls -la dist/grepfocus*.deb
echo
echo "==> Package metadata:"
podman run --rm -v "$REPO_ROOT":/src:Z "$IMAGE" dpkg-deb -I /src/dist/grepfocus.deb
