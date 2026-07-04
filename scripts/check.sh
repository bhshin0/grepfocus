#!/usr/bin/env bash
# Frostbite pre-flight checks — run before committing.
#
# Runs, in order: formatting check, clippy (warnings are errors), the full test
# suite, and the UI type-check/build. Any failure stops the run (set -e).
#
# Requirements:
#   - rustfmt + clippy components:  rustup component add rustfmt clippy
#   - pnpm (for the UI build)
#   - the GUI crate compiles only where webkit2gtk-4.1 + gtk-3 dev libs are
#     present; on a headless box, scope the Rust steps to
#     `-p frostbite-core -p frostbited` by hand.
#
# Optional: use as a pre-commit hook (not installed automatically):
#   ln -s ../../scripts/check.sh .git/hooks/pre-commit
#
# Usage: ./scripts/check.sh

set -euo pipefail

# Resolve the repo root via git so this works both when run directly and when
# symlinked as .git/hooks/pre-commit (where $0 is the hook path under .git).
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test --workspace"
cargo test --workspace

echo "==> pnpm --dir crates/gui/ui install"
pnpm --dir crates/gui/ui install

echo "==> pnpm --dir crates/gui/ui build (tsc -noEmit + vite build)"
pnpm --dir crates/gui/ui build

echo
echo "==> All checks passed."
