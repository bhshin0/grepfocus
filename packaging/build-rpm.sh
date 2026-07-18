#!/usr/bin/env bash
# Build the GrepFocus RPM from HEAD.
#
# Run as your normal user (NOT root): the spec declares no rust/cargo/pnpm
# BuildRequires — the toolchain comes from the invoking user's PATH
# (rustup + standalone pnpm), which rpmbuild inherits.
#
# Usage: ./packaging/build-rpm.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# git archive packs HEAD, not the working tree: with uncommitted changes the
# RPM would silently be built from stale sources. Refuse instead.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working tree is dirty." >&2
    echo "git archive packs HEAD, so uncommitted changes would be silently" >&2
    echo "missing from the RPM. Commit or stash first, then re-run." >&2
    exit 1
fi

# Version from the [workspace.package] section of the root Cargo.toml.
VERSION="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' Cargo.toml | head -n1)"
if [[ -z "$VERSION" ]]; then
    echo "error: could not read version from [workspace.package] in Cargo.toml" >&2
    exit 1
fi

[[ -d "$HOME/rpmbuild" ]] || rpmdev-setuptree

echo "==> Archiving HEAD as grepfocus-$VERSION.tar.gz"
git archive --format=tar.gz --prefix="grepfocus-$VERSION/" \
    -o "$HOME/rpmbuild/SOURCES/grepfocus-$VERSION.tar.gz" HEAD

echo "==> Building RPM"
rpmbuild -ba packaging/grepfocus.spec

RPM_NAME="$(rpmspec -q --qf '%{name}-%{version}-%{release}.%{arch}.rpm\n' packaging/grepfocus.spec | head -n1)"
RPM_PATH="$HOME/rpmbuild/RPMS/$(arch)/$RPM_NAME"

# Two copies: the versioned name, and exactly `grepfocus.rpm` — the web
# store hardcodes releases/latest/download/grepfocus.rpm.
mkdir -p dist
install -m 0644 "$RPM_PATH" "dist/$RPM_NAME"
install -m 0644 "$RPM_PATH" dist/grepfocus.rpm

echo
echo "==> Built:"
echo "    $REPO_ROOT/dist/$RPM_NAME"
echo "    $REPO_ROOT/dist/grepfocus.rpm"
echo
rpm -qip "dist/grepfocus.rpm"
