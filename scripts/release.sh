#!/usr/bin/env bash
# Build, audit and checksum a GrepFocus release.
#
# Steps, in order:
#   1. preflight   clean tree, `bump-version.sh --check`, required tools, and
#                  no other container build running (the two podman builds
#                  share the repo mount and named volumes and MUST NOT overlap)
#   2. check       ./scripts/check.sh
#   3. build       rpm, then deb, then AppImage, strictly one after the other,
#                  through the existing packaging/build-*.sh scripts
#   4. audit       every artifact is unpacked into a temp dir and inspected:
#                  binaries present, license public key embedded, --version
#                  output, unit file, removal scripts, no bundled libwayland ...
#   5. checksums   dist/SHA256SUMS over the versioned files, written only
#                  when all three targets were audited and every check passed
#                  (otherwise the sums go to dist/SHA256SUMS.audit-failed or
#                  dist/SHA256SUMS.partial, and no dist/SHA256SUMS exists)
#   6. summary     one PASS/FAIL/SKIP line per audit check, the commit, the
#                  checksums, a latest.json snippet for the website, the
#                  manual steps left
#
# A failed audit check never stops the remaining checks; the script exits 1 at
# the end if any check failed. Nothing is published, tagged or pushed.
#
# Usage:
#   scripts/release.sh [--only rpm,deb,appimage] [--skip-check] [--no-build]
#                      [--dist DIR] [--allow-dirty] [-n|--dry-run]
#
#   --only LIST     build/audit only these targets (comma-separated). A
#                   partial run is for debugging: its checksums and snippet
#                   cover only those targets and are not a release set
#   --skip-check    skip step 2
#   --no-build      skip steps 2-3 and audit what is already in dist/
#   --dist DIR      with --no-build: audit the artifacts in DIR instead
#   --allow-dirty   do not insist on a clean working tree (prints a warning);
#                   cannot build the rpm, which is made from HEAD
#   -n, --dry-run   run the preflight, then only print what would be done
#
# Exit status: 0 all checks passed, 1 an audit check failed, 2 usage,
# preflight or build error.
#
# Environment:
#   GREPFOCUS_RELEASE_VERSION   test-only, needs --no-build: audit artifacts of
#                               this version instead of the Cargo.toml one.

set -euo pipefail

ORIG_PWD="$PWD"
# Absolute, because usage() reads this file after the cd below.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

ALL_TARGETS=(rpm deb appimage)
BUILDER_IMAGES=(grepfocus-deb-builder grepfocus-appimage-builder)
DOWNLOAD_BASE_URL="https://grepfocus.com/downloads"
NOTES_URL="https://grepfocus.com/changelog"
LICENSE_RS="crates/core/src/license.rs"
STAGE_PAYLOAD="packaging/appimage/stage-payload.sh"
GUI_MAIN_RS="crates/gui/src/main.rs"
DEB_CONTAINERFILE="packaging/deb/Containerfile"
VERSION_TIMEOUT=20
LOCK_FILE="${XDG_RUNTIME_DIR:-/tmp}/grepfocus-release.lock"
NOT_CHECKED="not checked: extraction failed"

ONLY=""
ONLY_SET=0
SKIP_CHECK=0
NO_BUILD=0
DIST=""
ALLOW_DIRTY=0
DRY_RUN=0

WORK=""
VERSION=""
PUBKEY=""
GUI_USES_LICENSE=0
START_MARKER=""
HEAD_COMMIT=""
TREE_DIRTY=0
EXTRACTED_OK=0
SUMS_TEXT=""
SUMS_FILE=""
PARTIAL=0
SELECTED=()
R_STATUS=()
R_TARGET=()
R_NAME=()
R_DETAIL=()
declare -A ART_FILE=()
declare -A ART_SHA=()
PROBE_RC=0
PROBE_OUT=""
PROBE_OUT_LINE=""
PROBE_ERR=""

usage() {
    # The header comment of this file, minus the shebang, is the help text.
    sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$SELF"
}

die() {
    echo "error: $*" >&2
    exit 2
}

step() {
    echo
    echo "==> $*"
}

cleanup() {
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        # An extracted AppDir can contain read-only directories.
        chmod -R u+w "$WORK" 2>/dev/null || true
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

is_selected() {
    local target
    for target in "${SELECTED[@]}"; do
        [[ "$target" == "$1" ]] && return 0
    done
    return 1
}

# First non-empty line of a file, shortened, for one-line failure details.
first_line() {
    if [[ -f "$1" ]]; then
        awk 'NF { print substr($0, 1, 160); exit }' "$1"
    fi
}

# Version from the [workspace.package] section of the root Cargo.toml.
workspace_version() {
    awk '
        /^\[workspace\.package\]/ { in_section = 1; next }
        /^\[/                     { in_section = 0 }
        in_section && /^version[[:space:]]*=/ {
            if (match($0, /"[^"]*"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
                exit
            }
        }
    ' Cargo.toml
}

# --------------------------------------------------------------- artifacts ---

artifact_pattern() {
    case "$1" in
        rpm) echo "grepfocus-${VERSION}-*.$(uname -m).rpm" ;;
        deb) echo "grepfocus_${VERSION}-*_amd64.deb" ;;
        appimage) echo "GrepFocus_${VERSION}_amd64.AppImage" ;;
    esac
}

# The stable-name copy each build script leaves next to the versioned file.
artifact_alias() {
    case "$1" in
        rpm) echo "grepfocus.rpm" ;;
        deb) echo "grepfocus.deb" ;;
        appimage) echo "grepfocus.AppImage" ;;
    esac
}

# Absolute path of the versioned artifact for a target, or nothing. If several
# match (two package releases of one version), the highest one wins.
artifact_path() {
    if [[ -d "$DIST" ]]; then
        find "$DIST" -maxdepth 1 -type f -name "$(artifact_pattern "$1")" | sort -V | tail -n1
    fi
}

# What an artifact was built for, as latest.json records it (empty = omit).
built_for() {
    local target="$1" name="$2" rest
    case "$target" in
        rpm)
            # grepfocus-<ver>-<rel>.<dist>.<arch>.rpm -> <dist>
            rest="${name#grepfocus-"${VERSION}"-}"
            rest="${rest#*.}"
            echo "${rest%%.*}"
            ;;
        deb)
            # The base image of the deb builder: ubuntu:24.04 -> ubuntu-24.04
            awk '$1 == "FROM" { sub(/:/, "-", $2); print $2; exit }' "$DEB_CONTAINERFILE"
            ;;
        *) ;;
    esac
}

# ---------------------------------------------------------------- preflight ---

check_tools() {
    local -a tools=(git sha256sum strings mktemp timeout find sort awk sed)
    local -a missing=()
    local tool
    if is_selected rpm; then
        tools+=(rpm rpm2cpio cpio)
    fi
    if is_selected deb; then
        tools+=(ar tar zstd)
    fi
    if [[ "$NO_BUILD" -eq 0 ]]; then
        tools+=(flock)
        if [[ "$SKIP_CHECK" -eq 0 ]] || is_selected rpm; then
            tools+=(cargo pnpm)
        fi
        if is_selected rpm; then
            tools+=(rpmbuild rpmspec)
        fi
        if is_selected deb || is_selected appimage; then
            tools+=(podman)
        fi
    fi
    for tool in "${tools[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [[ "${#missing[@]}" -gt 0 ]]; then
        die "missing required tools: ${missing[*]}"
    fi
    echo "    tools present: ${tools[*]}"
}

# Refuses to go on while a container that a build would collide with is
# running: one made from a builder image (their named target/ volumes are
# shared by every checkout), or one whose mounts or command mention this repo.
check_no_container_overlap() {
    local listing id image details builder reason busy=0
    # Only the ID and image are listed: a container command can span several
    # lines, which a line-per-container listing cannot carry. Everything else
    # comes from `podman inspect` of each ID.
    if ! listing="$(podman ps --no-trunc --format '{{.ID}}|{{.Image}}')"; then
        die "podman ps failed; cannot tell whether another container build is running"
    fi
    while IFS='|' read -r id image; do
        [[ "$id" =~ ^[0-9a-f]{12,64}$ ]] || continue
        reason=""
        for builder in "${BUILDER_IMAGES[@]}"; do
            if [[ "$image" == *"$builder"* ]]; then
                reason="builder image $image"
            fi
        done
        if [[ -z "$reason" ]]; then
            details="$(podman inspect "$id" 2>/dev/null || true)"
            if [[ "$details" == *"$REPO_ROOT"* ]]; then
                reason="its mounts or command mention $REPO_ROOT"
            fi
        fi
        if [[ -n "$reason" ]]; then
            echo "error: container ${id:0:12} is running ($reason)" >&2
            busy=1
        fi
    done <<<"$listing"
    if [[ "$busy" -ne 0 ]]; then
        die "another container build is in progress; the podman builds must never overlap. Wait for it to finish."
    fi
    echo "    no overlapping container build"
}

needs_podman_build() {
    [[ "$NO_BUILD" -eq 0 ]] && { is_selected deb || is_selected appimage; }
}

preflight() {
    local dirty

    step "Preflight"
    dirty="$(git status --porcelain)"
    if [[ -n "$dirty" ]]; then
        if [[ "$ALLOW_DIRTY" -ne 1 ]]; then
            echo "$dirty" | sed 's/^/    /' >&2
            die "working tree is dirty. Commit or stash first (or pass --allow-dirty)."
        fi
        if [[ "$NO_BUILD" -eq 0 ]] && is_selected rpm; then
            die "--allow-dirty cannot build the rpm: packaging/build-rpm.sh builds from HEAD and refuses a dirty tree. Commit first, or use --only deb,appimage or --no-build."
        fi
        TREE_DIRTY=1
        echo "    ##################################################################"
        echo "    # WARNING: --allow-dirty: the working tree has uncommitted changes."
        echo "    # The deb and AppImage are built from the working tree. Artifacts"
        echo "    # produced or audited now may not match any commit. Do NOT publish"
        echo "    # them."
        echo "    ##################################################################"
    else
        echo "    working tree clean"
    fi
    HEAD_COMMIT="$(git rev-parse HEAD)"
    echo "    HEAD is $HEAD_COMMIT"

    echo "    scripts/bump-version.sh --check"
    if ! scripts/bump-version.sh --check | sed 's/^/      /'; then
        die "the recorded versions are inconsistent (scripts/bump-version.sh --check)"
    fi

    check_tools

    if needs_podman_build; then
        check_no_container_overlap
    fi
}

# ------------------------------------------------------------------- builds ---

# Runs a build step, or only names it under --dry-run. The lock descriptor is
# closed for the child: the lock means "a release.sh is building", and must
# not be kept by a process that a build leaves behind.
run_or_print() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "    [dry-run] would run: $*"
        return 0
    fi
    "$@" 9>&-
}

build_all() {
    local target script

    # One release build at a time, across every checkout: the container builds
    # share named volumes, so a second release.sh must not start its own.
    if [[ "$DRY_RUN" -eq 0 ]]; then
        exec 9>"$LOCK_FILE"
        flock -n 9 ||
            die "another scripts/release.sh is already building (it holds the lock $LOCK_FILE)"
        remove_old_checksums
    fi

    if [[ "$SKIP_CHECK" -eq 1 ]]; then
        step "Checks skipped (--skip-check)"
    else
        step "Running ./scripts/check.sh"
        run_or_print ./scripts/check.sh || die "scripts/check.sh failed"
    fi

    for target in "${SELECTED[@]}"; do
        script="packaging/build-$target.sh"
        step "Building $target ($script)"
        if [[ "$target" != "rpm" && "$DRY_RUN" -eq 0 ]]; then
            check_no_container_overlap
        fi
        run_or_print "$script" || die "$script failed; nothing was audited"
    done
}

# -------------------------------------------------------------------- audit ---

record() {
    local status="$1" target="$2" name="$3" detail="${4:-}"
    R_STATUS+=("$status")
    R_TARGET+=("$target")
    R_NAME+=("$name")
    R_DETAIL+=("$detail")
    print_result "$status" "$target" "$name" "$detail"
}

print_result() {
    if [[ -n "$4" ]]; then
        printf '    %-4s  %-8s  %s -- %s\n' "$1" "$2" "$3" "$4"
    else
        printf '    %-4s  %-8s  %s\n' "$1" "$2" "$3"
    fi
}

pass() { record PASS "$@"; }
fail() { record FAIL "$@"; }
skip() { record SKIP "$@"; }

count_failed() {
    local status failed=0
    for status in "${R_STATUS[@]}"; do
        if [[ "$status" == "FAIL" ]]; then
            failed=$((failed + 1))
        fi
    done
    echo "$failed"
}

# True, after recording a FAIL, when the artifact did not extract. A check of
# the package contents must never say PASS about a partial or empty tree.
not_extracted() {
    if [[ "$EXTRACTED_OK" -eq 1 ]]; then
        return 1
    fi
    fail "$1" "$2" "$NOT_CHECKED"
    return 0
}

# check_present <target> <check name> <path> [executable]
# With "executable" the file must also carry an execute bit: a 0644 binary in
# /usr/bin is a packaging defect (the unit's ExecStart could not start it).
check_present() {
    if not_extracted "$1" "$2"; then
        return 0
    fi
    if [[ ! -f "$3" || ! -s "$3" ]]; then
        fail "$1" "$2" "not found in the package"
    elif [[ "${4:-}" == "executable" && ! -x "$3" ]]; then
        fail "$1" "$2" "packaged without an execute bit (mode $(stat -c '%a' "$3"))"
    else
        pass "$1" "$2"
    fi
}

count_key_hits() {
    strings -a "$1" | grep -cF -- "$PUBKEY" || true
}

# The daemon verifies licenses, so it must carry the key from license.rs. A
# binary built from a tree with another key has shipped once; never again.
check_daemon_pubkey() {
    local target="$1" binary="$2" hits
    local name="grepfocusd embeds the license public key from license.rs"
    if not_extracted "$target" "$name"; then
        return 0
    fi
    if [[ ! -f "$binary" ]]; then
        fail "$target" "$name" "binary not found"
        return 0
    fi
    hits="$(count_key_hits "$binary")"
    if [[ "${hits:-0}" -gt 0 ]]; then
        pass "$target" "$name"
    else
        fail "$target" "$name" "key not found in strings output: WRONG OR MISSING KEY"
    fi
}

# The GUI only carries the key if its crate uses the license verifier. While
# it does not (verification is daemon-side), the linker drops the constant and
# there is nothing to look for: report SKIP with that reason, never PASS.
check_gui_pubkey() {
    local target="$1" binary="$2" hits
    local name="grepfocus-gui embeds the license public key from license.rs"
    if not_extracted "$target" "$name"; then
        return 0
    fi
    if [[ ! -f "$binary" ]]; then
        fail "$target" "$name" "binary not found"
        return 0
    fi
    hits="$(count_key_hits "$binary")"
    if [[ "${hits:-0}" -gt 0 ]]; then
        pass "$target" "$name"
    elif [[ "$GUI_USES_LICENSE" -eq 1 ]]; then
        fail "$target" "$name" "key not found in strings output: WRONG OR MISSING KEY"
    else
        skip "$target" "$name" "crates/gui/src never references the license verifier, so no key is compiled into the GUI"
    fi
}

# Runs a command with a timeout and no display; leaves PROBE_RC / PROBE_OUT /
# PROBE_ERR behind. No display, session bus or runtime dir is passed on, so a
# GUI that ignores --version cannot open a window or poke a running instance.
probe_version() {
    PROBE_RC=0
    mkdir -p "$WORK/xdg-runtime"
    chmod 700 "$WORK/xdg-runtime"
    timeout --kill-after=5 "$VERSION_TIMEOUT" \
        env -u DISPLAY -u WAYLAND_DISPLAY -u DBUS_SESSION_BUS_ADDRESS \
        XDG_RUNTIME_DIR="$WORK/xdg-runtime" \
        "$@" >"$WORK/probe.out" 2>"$WORK/probe.err" </dev/null || PROBE_RC=$?
    PROBE_OUT="$(head -c 300 "$WORK/probe.out" | tr -d '\r\0')"
    PROBE_OUT_LINE="$(first_line "$WORK/probe.out")"
    PROBE_ERR="$(first_line "$WORK/probe.err")"
}

# The stderr line of the last probe that is positive evidence that this host
# cannot run the binary at all: wrong architecture, or it needs a newer
# glibc/libstdc++ than the host has. Nothing else counts. A bare exit 126/127,
# a missing shared library or an AppImage runtime error is what a broken
# package looks like too, so those are failures.
probe_host_cannot_run() {
    grep -m1 -E "Exec format error|GLIBC(XX)?_[0-9.]+' not found" "$WORK/probe.err" |
        cut -c1-200 || true
}

# True when the AppImage runtime's messages (it writes them to stdout and to
# stderr) say that this host has no usable FUSE: no fusermount, no /dev/fuse,
# no libfuse. Its generic "Cannot mount AppImage, please check your FUSE
# setup" does not count: it is printed for a damaged image as well.
probe_host_has_no_fuse() {
    grep -qiE 'No suitable fusermount binary|fusermount3?: |fuse: (device not found|failed to (open|exec))|/dev/fuse|error loading libfuse|AppImages require FUSE' \
        "$WORK/probe.out" "$WORK/probe.err"
}

# judge_probe <target> <check name> <expected stdout> [note]
# PASS only on exit 0 with exactly the expected output. Anything printed that
# is not that output is a FAIL, whatever else happened. SKIP (never PASS) only
# when nothing was printed and the host demonstrably cannot run the binary.
judge_probe() {
    local target="$1" name="$2" expected="$3" note="${4:-}"
    local reason detail
    if [[ "$PROBE_RC" -eq 0 && "$PROBE_OUT" == "$expected" ]]; then
        pass "$target" "$name" "$note"
        return 0
    fi
    if [[ "$PROBE_RC" -eq 124 || "$PROBE_RC" -eq 137 ]]; then
        detail="no answer within ${VERSION_TIMEOUT}s (timed out)"
    elif [[ -n "$PROBE_OUT" ]]; then
        detail="printed '$PROBE_OUT_LINE' (exit $PROBE_RC)${PROBE_ERR:+; stderr: $PROBE_ERR}"
    else
        reason="$(probe_host_cannot_run)"
        if [[ -n "$reason" ]]; then
            skip "$target" "$name" "${note:+$note: }cannot execute on this host (exit $PROBE_RC): $reason"
            return 0
        fi
        detail="printed nothing (exit $PROBE_RC)${PROBE_ERR:+; stderr: $PROBE_ERR}"
    fi
    fail "$target" "$name" "${note:+$note: }$detail"
}

# check_daemon_version <target> <binary> [payload]
# "payload" is the AppImage's copy of the daemon, which stage-payload.sh
# stages 0644 on purpose (the installer sets the mode): only that one may be
# run through an executable copy. A packaged /usr/bin/grepfocusd without an
# execute bit is a defect and is not run.
check_daemon_version() {
    local target="$1" binary="$2" kind="${3:-installed}"
    local name="grepfocusd --version prints 'grepfocusd $VERSION'"
    local runnable="$binary"
    if [[ "$kind" == "payload" ]]; then
        name="payload $name"
    fi
    if not_extracted "$target" "$name"; then
        return 0
    fi
    if [[ ! -f "$binary" ]]; then
        fail "$target" "$name" "binary not found"
        return 0
    fi
    if [[ ! -x "$binary" ]]; then
        if [[ "$kind" != "payload" ]]; then
            fail "$target" "$name" "not run: packaged without an execute bit (mode $(stat -c '%a' "$binary"))"
            return 0
        fi
        mkdir -p "$WORK/exec-copy"
        runnable="$WORK/exec-copy/grepfocusd"
        cp "$binary" "$runnable"
        chmod 0755 "$runnable"
    fi
    probe_version "$runnable" --version
    judge_probe "$target" "$name" "grepfocusd $VERSION"
}

# check_unit_execstart <target> <extracted package root>
check_unit_execstart() {
    local target="$1" root="$2" unit line
    local name="unit ExecStart is /usr/bin/grepfocusd"
    if not_extracted "$target" "$name"; then
        return 0
    fi
    unit=""
    if [[ -d "$root" ]]; then
        unit="$(find "$root" -type f -name grepfocusd.service -path '*/systemd/system/*' | sort | sed -n '1p')"
    fi
    if [[ -z "$unit" ]]; then
        fail "$target" "$name" "grepfocusd.service not found in the package"
        return 0
    fi
    line="$(grep -m1 '^ExecStart=' "$unit" || true)"
    if [[ "$line" =~ ^ExecStart=/usr/bin/grepfocusd([[:space:]]|$) ]]; then
        pass "$target" "$name"
    else
        fail "$target" "$name" "found '${line:-no ExecStart line}'"
    fi
}

# True when a non-comment line of the script text on stdin runs
# `grepfocusd cleanup` (a mention in a comment does not count).
runs_cleanup() {
    local hits
    hits="$(grep -v '^[[:space:]]*#' | grep -cE 'grepfocusd[[:space:]]+cleanup' || true)"
    [[ "${hits:-0}" -gt 0 ]]
}

# The stable-name copy (grepfocus.rpm ...) is what download links point at; a
# stale one next to a fresh versioned file would ship the old build.
check_alias() {
    local target="$1" file="$2" alias_name alias_path
    alias_name="$(artifact_alias "$target")"
    alias_path="$DIST/$alias_name"
    if [[ ! -f "$alias_path" ]]; then
        return 0
    fi
    if cmp -s "$file" "$alias_path"; then
        pass "$target" "$alias_name is identical to the versioned file"
    else
        fail "$target" "$alias_name is identical to the versioned file" "stale copy: contents differ"
    fi
}

check_fresh() {
    local target="$1" file="$2"
    if [[ -z "$START_MARKER" ]]; then
        return 0
    fi
    if [[ "$file" -nt "$START_MARKER" ]]; then
        pass "$target" "versioned file was written by this run"
    else
        fail "$target" "versioned file was written by this run" "older than this run: a stale leftover"
    fi
}

# The rpm is archived from HEAD and the container builds read the working
# tree, each at its own moment. A commit made in between (another terminal,
# another agent) would leave artifacts that are not from one commit.
check_head_unmoved() {
    local now name="HEAD did not move during the build"
    now="$(git rev-parse HEAD 2>/dev/null || true)"
    if [[ "$now" == "$HEAD_COMMIT" ]]; then
        pass repo "$name" "${HEAD_COMMIT:0:12}"
    else
        fail repo "$name" "was ${HEAD_COMMIT:0:12}, now ${now:0:12}: the artifacts are not from one commit"
    fi
}

audit_rpm() {
    local file="$1" root="$WORK/rpm" meta
    mkdir -p "$root"

    EXTRACTED_OK=0
    if (cd "$root" && rpm2cpio "$file" | cpio -idm --quiet --no-absolute-filenames) \
        2>"$WORK/rpm-extract.err"; then
        EXTRACTED_OK=1
        pass rpm "package extracts"
    else
        fail rpm "package extracts" "$(first_line "$WORK/rpm-extract.err")"
    fi

    meta="$(rpm -qp --qf '%{VERSION}' "$file" 2>/dev/null || true)"
    if [[ "$meta" == "$VERSION" ]]; then
        pass rpm "package metadata version is $VERSION"
    else
        fail rpm "package metadata version is $VERSION" "rpm says '${meta}'"
    fi

    check_present rpm "daemon binary present and executable (/usr/bin/grepfocusd)" \
        "$root/usr/bin/grepfocusd" executable
    check_present rpm "GUI binary present and executable (/usr/bin/grepfocus-gui)" \
        "$root/usr/bin/grepfocus-gui" executable
    check_daemon_pubkey rpm "$root/usr/bin/grepfocusd"
    check_gui_pubkey rpm "$root/usr/bin/grepfocus-gui"
    check_daemon_version rpm "$root/usr/bin/grepfocusd"
    check_unit_execstart rpm "$root"

    if rpm -qp --scripts "$file" 2>/dev/null | runs_cleanup; then
        pass rpm "scriptlets run 'grepfocusd cleanup' on erase"
    else
        fail rpm "scriptlets run 'grepfocusd cleanup' on erase" "not found in rpm -qp --scripts"
    fi

    check_present rpm "LICENSE packaged" "$root/usr/share/licenses/grepfocus/LICENSE"
    check_alias rpm "$file"
    check_fresh rpm "$file"
    return 0
}

audit_deb() {
    local file="$1" root="$WORK/deb" members data_member control_member meta name
    mkdir -p "$root/data" "$root/control"

    EXTRACTED_OK=0
    members="$(ar t "$file" 2>"$WORK/deb-extract.err" || true)"
    data_member="$(grep -m1 '^data\.tar' <<<"$members" || true)"
    control_member="$(grep -m1 '^control\.tar' <<<"$members" || true)"
    if [[ -n "$data_member" && -n "$control_member" ]] &&
        (cd "$root" && ar x "$file" "$control_member" "$data_member") 2>>"$WORK/deb-extract.err" &&
        tar -xf "$root/$data_member" -C "$root/data" 2>>"$WORK/deb-extract.err" &&
        tar -xf "$root/$control_member" -C "$root/control" 2>>"$WORK/deb-extract.err"; then
        EXTRACTED_OK=1
        pass deb "package extracts"
    else
        fail deb "package extracts" "$(first_line "$WORK/deb-extract.err")"
    fi

    name="package metadata version is $VERSION"
    if ! not_extracted deb "$name"; then
        meta=""
        if [[ -f "$root/control/control" ]]; then
            meta="$(awk -F': ' '$1 == "Version" { print $2; exit }' "$root/control/control")"
        fi
        if [[ "${meta%-*}" == "$VERSION" ]]; then
            pass deb "$name"
        else
            fail deb "$name" "control says '${meta}'"
        fi
    fi

    check_present deb "daemon binary present and executable (/usr/bin/grepfocusd)" \
        "$root/data/usr/bin/grepfocusd" executable
    check_present deb "GUI binary present and executable (/usr/bin/grepfocus-gui)" \
        "$root/data/usr/bin/grepfocus-gui" executable
    check_daemon_pubkey deb "$root/data/usr/bin/grepfocusd"
    check_gui_pubkey deb "$root/data/usr/bin/grepfocus-gui"
    check_daemon_version deb "$root/data/usr/bin/grepfocusd"
    check_unit_execstart deb "$root/data"

    name="prerm runs 'grepfocusd cleanup' on remove"
    if ! not_extracted deb "$name"; then
        if [[ -f "$root/control/prerm" ]] && runs_cleanup <"$root/control/prerm"; then
            pass deb "$name"
        else
            fail deb "$name" "not found in the control archive's prerm"
        fi
    fi

    name="copyright and LICENSE packaged"
    if ! not_extracted deb "$name"; then
        if [[ -s "$root/data/usr/share/doc/grepfocus/copyright" &&
            -s "$root/data/usr/share/doc/grepfocus/LICENSE" ]]; then
            pass deb "$name"
        else
            fail deb "$name" "missing under /usr/share/doc/grepfocus"
        fi
    fi

    check_alias deb "$file"
    check_fresh deb "$file"
    return 0
}

# Every file the AppImage must carry for its first-run daemon install: what
# stage-payload.sh stages plus what the GUI's PAYLOAD_FILES expects.
payload_file_names() {
    {
        sed -n 's/.*"\$DEST\/\([^"]*\)"[[:space:]]*$/\1/p' "$STAGE_PAYLOAD"
        awk '
            /^const PAYLOAD_FILES/ { in_list = 1; next }
            in_list && /^\];/      { exit }
            in_list && match($0, /"[^"]+"/) { print substr($0, RSTART + 1, RLENGTH - 2) }
        ' "$GUI_MAIN_RS"
    } | sort -u
}

audit_appimage() {
    local file="$1" root="$WORK/appimage" runner="$1"
    local appdir="$WORK/appimage/squashfs-root"
    local found payload_daemon payload_dir names item missing count name
    local gui_name="AppImage --version prints 'grepfocus-gui $VERSION'"
    mkdir -p "$root"

    if [[ ! -x "$file" ]]; then
        # Audit an executable copy rather than changing the file in dist.
        runner="$root/$(basename "$file")"
        cp "$file" "$runner"
        chmod 0755 "$runner"
    fi

    EXTRACTED_OK=0
    if (cd "$root" && timeout --kill-after=5 300 "$runner" --appimage-extract >/dev/null) \
        2>"$WORK/appimage-extract.err" && [[ -d "$appdir" ]]; then
        EXTRACTED_OK=1
        pass appimage "AppImage extracts (--appimage-extract)"
    else
        fail appimage "AppImage extracts (--appimage-extract)" "$(first_line "$WORK/appimage-extract.err")"
    fi

    name="no bundled libwayland-*.so* in the AppDir"
    if ! not_extracted appimage "$name"; then
        found="$(find "$appdir" -name 'libwayland-*.so*' | sort | tr '\n' ' ')"
        if [[ -z "$found" ]]; then
            pass appimage "$name"
        else
            fail appimage "$name" "found: ${found//"$appdir"\//}"
        fi
    fi

    check_present appimage "AppRun present and executable" "$appdir/AppRun" executable
    check_present appimage "GUI binary present and executable (usr/bin/grepfocus-gui)" \
        "$appdir/usr/bin/grepfocus-gui" executable

    payload_daemon=""
    if [[ "$EXTRACTED_OK" -eq 1 ]]; then
        payload_daemon="$(find "$appdir" -type f -name grepfocusd | sort | sed -n '1p')"
    fi
    payload_dir=""
    if [[ -n "$payload_daemon" ]]; then
        payload_dir="$(dirname "$payload_daemon")"
    fi

    names="$(payload_file_names)"
    count="$(grep -c . <<<"$names" || true)"
    name="daemon payload files present ($count)"
    if [[ -z "$names" ]]; then
        fail appimage "daemon payload files present" "could not read the payload list from $STAGE_PAYLOAD / $GUI_MAIN_RS"
    elif not_extracted appimage "$name"; then
        :
    elif [[ -z "$payload_dir" ]]; then
        fail appimage "$name" "no payload directory (no grepfocusd) in the AppDir"
    else
        missing=""
        while IFS= read -r item; do
            if [[ ! -s "$payload_dir/$item" ]]; then
                missing="$missing $item"
            fi
        done <<<"$names"
        if [[ -z "$missing" ]]; then
            pass appimage "$name" "${payload_dir#"$appdir"/}"
        else
            fail appimage "$name" "missing:$missing"
        fi
    fi

    check_daemon_pubkey appimage "${payload_daemon:-$appdir/payload/grepfocusd}"
    check_gui_pubkey appimage "$appdir/usr/bin/grepfocus-gui"
    check_daemon_version appimage "${payload_daemon:-$appdir/payload/grepfocusd}" payload

    # The AppImage itself. Only when its runtime says that this host has no
    # usable FUSE is the extracted AppRun run instead: the same entry point
    # without the mount. Any other runtime error (AppRun not executable, an
    # unreadable squashfs) is an AppImage that does not start: a FAIL.
    probe_version "$runner" --version
    if [[ "$PROBE_RC" -ne 0 ]] && probe_host_has_no_fuse; then
        if [[ "$EXTRACTED_OK" -eq 1 && -f "$appdir/AppRun" ]]; then
            probe_version "$appdir/AppRun" --version
            judge_probe appimage "$gui_name" "grepfocus-gui $VERSION" \
                "via the extracted AppRun (no FUSE mount on this host)"
        else
            fail appimage "$gui_name" "no FUSE mount on this host and no extracted AppRun to run instead"
        fi
    else
        judge_probe appimage "$gui_name" "grepfocus-gui $VERSION"
    fi

    check_alias appimage "$file"
    check_fresh appimage "$file"
    return 0
}

audit_target() {
    local target="$1" file
    local name="versioned file exists for $VERSION"
    step "Auditing $target"
    file="$(artifact_path "$target")"
    if [[ -z "$file" ]]; then
        fail "$target" "$name" "no $(artifact_pattern "$target") in $DIST; its other checks were not run"
        return 0
    fi
    pass "$target" "$name" "$(basename "$file")"
    case "$target" in
        rpm) audit_rpm "$file" ;;
        deb) audit_deb "$file" ;;
        appimage) audit_appimage "$file" ;;
    esac
    return 0
}

# ---------------------------------------------------------------- checksums ---

# Removes the checksum files of an earlier run. dist/SHA256SUMS is what the
# website hand-off takes, so it may only exist next to artifacts that passed
# the audit that wrote it: never left over from a run that built something
# else, died half-way, or failed.
remove_old_checksums() {
    local name
    for name in SHA256SUMS SHA256SUMS.audit-failed SHA256SUMS.partial; do
        if [[ -e "$DIST/$name" ]] && ! rm -f "$DIST/$name" 2>/dev/null; then
            fail dist "old $name removed" "could not delete $DIST/$name: it does NOT describe this run"
        fi
    done
}

# Hashes the versioned artifacts audited in this run (the selected targets; a
# file that was not audited is not vouched for) and writes them, with relative
# names, to DIST/SHA256SUMS. After a failed audit the file is named
# SHA256SUMS.audit-failed instead, and after a partial (--only) run
# SHA256SUMS.partial: DIST/SHA256SUMS exists only when the whole set passed.
# A failure to write is a recorded FAIL, not an abort: the summary is always
# printed.
write_checksums() {
    local target file line out_name
    SUMS_TEXT=""
    SUMS_FILE=""
    for target in "${SELECTED[@]}"; do
        file="$(artifact_path "$target")"
        [[ -n "$file" ]] || continue
        if ! line="$(sha256sum -- "$file" 2>/dev/null)"; then
            fail "$target" "sha256 computed" "could not read $(basename "$file")"
            continue
        fi
        ART_FILE[$target]="$(basename "$file")"
        ART_SHA[$target]="${line%% *}"
        SUMS_TEXT+="${line%% *}  $(basename "$file")"$'\n'
    done
    if [[ -z "$SUMS_TEXT" ]]; then
        return 0
    fi
    out_name="SHA256SUMS"
    if [[ "$(count_failed)" -gt 0 ]]; then
        out_name="SHA256SUMS.audit-failed"
    elif [[ "$PARTIAL" -eq 1 ]]; then
        out_name="SHA256SUMS.partial"
    fi
    if { printf '%s' "$SUMS_TEXT" >"$DIST/$out_name"; } 2>/dev/null; then
        SUMS_FILE="$DIST/$out_name"
    else
        fail dist "$out_name written" "could not write $DIST/$out_name"
    fi
}

print_latest_json() {
    local target for_what first=1
    printf '{\n'
    printf '  "schema": 1,\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "published": "%s",\n' "$(date +%F)"
    printf '  "notes_url": "%s",\n' "$NOTES_URL"
    printf '  "downloads": {'
    for target in "${ALL_TARGETS[@]}"; do
        [[ -n "${ART_FILE[$target]:-}" ]] || continue
        if [[ "$first" -eq 1 ]]; then
            printf '\n'
            first=0
        else
            printf ',\n'
        fi
        printf '    "%s": {\n' "$target"
        printf '      "url": "%s/%s",\n' "$DOWNLOAD_BASE_URL" "${ART_FILE[$target]}"
        printf '      "sha256": "%s"' "${ART_SHA[$target]}"
        for_what="$(built_for "$target" "${ART_FILE[$target]}")"
        if [[ -n "$for_what" ]]; then
            printf ',\n      "built_for": "%s"' "$for_what"
        fi
        printf '\n    }'
    done
    printf '\n  }\n}\n'
}

# ------------------------------------------------------------------ summary ---

print_summary() {
    local i passed=0 failed=0 skipped=0

    step "Audit summary for $VERSION ($DIST)"
    for i in "${!R_STATUS[@]}"; do
        print_result "${R_STATUS[$i]}" "${R_TARGET[$i]}" "${R_NAME[$i]}" "${R_DETAIL[$i]}"
        case "${R_STATUS[$i]}" in
            PASS) passed=$((passed + 1)) ;;
            FAIL) failed=$((failed + 1)) ;;
            *) skipped=$((skipped + 1)) ;;
        esac
    done
    echo "    ----"
    echo "    $passed passed, $failed failed, $skipped skipped"

    if [[ "$failed" -gt 0 ]]; then
        echo
        echo "    ##################################################################"
        echo "    # AUDIT FAILED ($failed check(s)). DO NOT PUBLISH these artifacts."
        echo "    # The checksums and snippet below are for reference only."
        echo "    ##################################################################"
    fi
    if [[ "$PARTIAL" -eq 1 ]]; then
        echo
        echo "    note: partial run (--only): only ${SELECTED[*]} audited. The checksums and"
        echo "    the snippet below cover only that and are NOT a release set; a"
        echo "    release needs a run without --only."
    fi

    step "Commit"
    if [[ "$NO_BUILD" -eq 1 ]]; then
        echo "    HEAD is $HEAD_COMMIT"
        echo "    --no-build: this run did not build the artifacts; it cannot tell"
        echo "    which commit they were built from."
    elif [[ "$TREE_DIRTY" -eq 1 ]]; then
        echo "    built from $HEAD_COMMIT PLUS uncommitted changes"
        echo "    (--allow-dirty): not a releasable build."
    else
        echo "    built from $HEAD_COMMIT"
    fi

    if [[ -n "$SUMS_FILE" ]]; then
        step "SHA256SUMS ($SUMS_FILE)"
        sed 's/^/    /' <<<"${SUMS_TEXT%$'\n'}"
        if [[ "$(basename "$SUMS_FILE")" != "SHA256SUMS" ]]; then
            echo "    (written as $(basename "$SUMS_FILE"); there is no $DIST/SHA256SUMS)"
        fi
    elif [[ -n "$SUMS_TEXT" ]]; then
        step "SHA256SUMS (NOT written, see the FAIL line above)"
        sed 's/^/    /' <<<"${SUMS_TEXT%$'\n'}"
    else
        step "SHA256SUMS"
        echo "    (no versioned artifacts for $VERSION; nothing written)"
    fi

    step "latest.json snippet"
    print_latest_json

    if [[ "$failed" -gt 0 ]]; then
        echo
        echo "==> RELEASE AUDIT FAILED: $failed check(s) failed. Nothing may be published."
        echo "    Fix the cause and run release.sh again."
        return 1
    fi
    if [[ "$PARTIAL" -eq 1 ]]; then
        echo
        echo "==> Audit passed for ${SELECTED[*]} only: $passed checks, $skipped skipped."
        echo "    A partial run is not a release; run release.sh without --only."
        return 0
    fi

    step "Remaining manual steps (docs/release.md)"
    echo "    1. Live verification on a real install: work through the checklist in"
    echo "       docs/plans/hardening-health-updates.md."
    echo "    2. Fast-forward master to the audited commit, tag that commit, push both:"
    echo "         git checkout master && git merge --ff-only $HEAD_COMMIT"
    echo "         git tag -a v$VERSION -m \"GrepFocus $VERSION\" $HEAD_COMMIT"
    echo "         git push origin master v$VERSION"
    echo "       If the merge is not a fast-forward, the merged tree is not the one"
    echo "       that was audited: bring the branch up to date and run release.sh again."
    if [[ "$NO_BUILD" -eq 1 ]]; then
        echo "       (--no-build: first make sure the artifacts were built from that commit.)"
    fi
    echo "    3. ./scripts/bump-version.sh --aur-sha   (after the tag is pushed),"
    echo "       then commit packaging/aur/PKGBUILD and .SRCINFO."
    echo "    4. Publish to the AUR: packaging/aur/README.md, \"Publishing to the AUR\"."
    echo "    5. Website hand-off: send the versioned files, $DIST/SHA256SUMS"
    echo "       and the latest.json snippet above to the website repo."
    echo
    echo "==> Release audit passed: $passed checks, $skipped skipped."
    return 0
}

print_dry_run_plan() {
    local target
    for target in "${SELECTED[@]}"; do
        step "Auditing $target"
        echo "    [dry-run] would audit $DIST/$(artifact_pattern "$target")"
    done
    step "SHA256SUMS"
    echo "    [dry-run] would remove the old $DIST/SHA256SUMS first, and write a"
    if [[ "$PARTIAL" -eq 1 ]]; then
        echo "    SHA256SUMS.partial over the audited files of $VERSION (partial run: --only)"
    else
        echo "    new one over the audited files of $VERSION if every check passes"
    fi
    step "Summary"
    echo "    [dry-run] would print the PASS/FAIL lines, the commit, the checksums, the"
    echo "    latest.json snippet and the remaining manual steps. Nothing was built or"
    echo "    written."
}

# --------------------------------------------------------------------- main ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        --only)
            [[ $# -ge 2 ]] || die "--only needs a comma-separated list (rpm,deb,appimage)"
            ONLY="$2"
            ONLY_SET=1
            shift
            ;;
        --only=*)
            ONLY="${1#--only=}"
            ONLY_SET=1
            ;;
        --skip-check) SKIP_CHECK=1 ;;
        --no-build) NO_BUILD=1 ;;
        --dist)
            [[ $# -ge 2 ]] || die "--dist needs a directory"
            DIST="$2"
            shift
            ;;
        --dist=*) DIST="${1#--dist=}" ;;
        --allow-dirty) ALLOW_DIRTY=1 ;;
        -n | --dry-run) DRY_RUN=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
done

# Selected targets, always in build order whatever order --only listed them.
if [[ "$ONLY_SET" -eq 0 ]]; then
    SELECTED=("${ALL_TARGETS[@]}")
else
    # An empty list is refused, never read as "everything": a caller passing
    # an empty variable must not start a full build.
    [[ -n "$ONLY" ]] || die "--only needs at least one of: ${ALL_TARGETS[*]}"
    IFS=',' read -r -a requested <<<"$ONLY"
    [[ "${#requested[@]}" -gt 0 ]] || die "--only needs at least one of: ${ALL_TARGETS[*]}"
    for item in "${requested[@]}"; do
        case "$item" in
            rpm | deb | appimage) ;;
            *) die "--only: unknown target '$item' (known: ${ALL_TARGETS[*]})" ;;
        esac
    done
    for target in "${ALL_TARGETS[@]}"; do
        for item in "${requested[@]}"; do
            if [[ "$item" == "$target" ]]; then
                SELECTED+=("$target")
                break
            fi
        done
    done
fi

if [[ "${#SELECTED[@]}" -lt "${#ALL_TARGETS[@]}" ]]; then
    PARTIAL=1
fi

if [[ -n "$DIST" ]]; then
    [[ "$NO_BUILD" -eq 1 ]] ||
        die "--dist needs --no-build (the build scripts always write to $REPO_ROOT/dist)"
    if [[ "$DIST" != /* ]]; then
        DIST="$ORIG_PWD/$DIST"
    fi
    [[ -d "$DIST" ]] || die "--dist: no such directory: $DIST"
    DIST="$(cd "$DIST" && pwd)"
else
    DIST="$REPO_ROOT/dist"
fi

VERSION="$(workspace_version)"
[[ -n "$VERSION" ]] || die "could not read the version from [workspace.package] in Cargo.toml"
if [[ -n "${GREPFOCUS_RELEASE_VERSION:-}" ]]; then
    [[ "$NO_BUILD" -eq 1 ]] ||
        die "GREPFOCUS_RELEASE_VERSION is a test-only override and needs --no-build"
    echo "WARNING: GREPFOCUS_RELEASE_VERSION is set: auditing $GREPFOCUS_RELEASE_VERSION artifacts, not $VERSION. Test use only."
    VERSION="$GREPFOCUS_RELEASE_VERSION"
fi

# The key is read from the source at run time, never written into this script.
PUBKEY="$(sed -n 's/^pub const LICENSE_PUBKEY_B64URL: &str = "\([A-Za-z0-9_-]*\)";.*$/\1/p' "$LICENSE_RS")"
[[ "$PUBKEY" =~ ^[A-Za-z0-9_-]{43}$ ]] ||
    die "could not read a 32-byte base64url LICENSE_PUBKEY_B64URL from $LICENSE_RS"
if grep -rqE 'license::|LICENSE_PUBKEY_B64URL|verify_token' crates/gui/src; then
    GUI_USES_LICENSE=1
fi

MODE_NOTE=""
if [[ "$DRY_RUN" -eq 1 ]]; then
    MODE_NOTE=" (dry run: nothing is built or written)"
fi
echo "==> GrepFocus release $VERSION: targets ${SELECTED[*]}$MODE_NOTE"

preflight

if [[ "$DRY_RUN" -eq 0 ]]; then
    WORK="$(mktemp -d)"
    # The --version checks execute files from the temp dir. On a noexec mount
    # every one of them would fail for a reason unrelated to the artifacts.
    printf '#!/bin/sh\nexit 0\n' >"$WORK/exec-test"
    chmod 0755 "$WORK/exec-test"
    "$WORK/exec-test" 2>/dev/null ||
        die "cannot execute files under $WORK (noexec mount?). Set TMPDIR to a directory that allows it."
fi

if [[ "$NO_BUILD" -eq 1 ]]; then
    step "Build skipped (--no-build): auditing what is in $DIST"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        remove_old_checksums
    fi
else
    if [[ "$DRY_RUN" -eq 0 ]]; then
        # Anything older than this marker was not produced by this run.
        START_MARKER="$WORK/start-marker"
        : >"$START_MARKER"
    fi
    build_all
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    print_dry_run_plan
    exit 0
fi

if [[ "$NO_BUILD" -eq 0 ]]; then
    step "Checking the build's commit"
    check_head_unmoved
fi

for target in "${SELECTED[@]}"; do
    # The `||` also switches errexit off inside the audit, so an unexpected
    # command failure there cannot abort the remaining checks.
    audit_target "$target" ||
        fail "$target" "audit ran to completion" "the audit of this target stopped early"
done

step "Checksums"
write_checksums || fail dist "checksums step ran to completion" "stopped early"

if print_summary; then
    exit 0
fi
exit 1
