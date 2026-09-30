#!/usr/bin/env bash
# Bump the GrepFocus version in every place it is recorded, or verify that all
# of those places agree.
#
# The version is written down in eight files, and a release that misses one
# ships a package whose metadata disagrees with its binaries:
#
#   Cargo.toml                   [workspace.package] version
#   Cargo.lock                   the three workspace members
#   crates/gui/tauri.conf.json   "version"
#   crates/gui/ui/package.json   "version"
#   packaging/grepfocus.spec     Version:, Release: + the top %changelog entry
#   debian/changelog             the top stanza
#   packaging/aur/PKGBUILD       pkgver (pkgrel, sha256sums)
#   packaging/aur/.SRCINFO       pkgver, source, sha256sums
#
# Usage:
#   scripts/bump-version.sh <X.Y.Z> [--notes FILE] [--force]
#       Set the version everywhere and prepend one changelog entry to the spec
#       and to debian/changelog (today's date, git identity). Each non-empty
#       line of FILE becomes one bullet (a leading "- " or "* " is dropped),
#       wrapped at 72 columns; an indented line under a "- " or "* " bullet
#       continues that bullet, so hard-wrapped markdown lists can be pasted.
#       Without --notes a "TODO: release notes" placeholder is inserted, which
#       --check then rejects. Refuses a version that is not higher than the
#       current one unless --force. Never commits.
#
#   scripts/bump-version.sh --check
#       Print every recorded version and exit 1 if they disagree, if the top
#       changelog entries are for another version, if the spec Release: and
#       its %changelog entry (or the two AUR pkgrel values) differ, or if a
#       release-notes placeholder is still present. Edits nothing. (release.sh
#       and CI run it.)
#
#   scripts/bump-version.sh --aur-sha
#       AFTER the vX.Y.Z tag is pushed: download the tag tarball, and write its
#       sha256 into PKGBUILD and .SRCINFO in place of SKIP. Refuses (and edits
#       nothing) if the download fails.
#
# Environment:
#   GREPFOCUS_TARBALL_URL   test-only: fetch the --aur-sha tarball from this
#                           URL (e.g. file:///tmp/x.tar.gz) instead of GitHub.

set -euo pipefail

ORIG_PWD="$PWD"
# Absolute, because usage() reads this file after the cd below.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

REPO_URL="https://github.com/bhshin0/grepfocus"
PLACEHOLDER="TODO: release notes"
WRAP_WIDTH=72
MEMBERS=(grepfocus-core grepfocus-gui grepfocusd)

CARGO_TOML="Cargo.toml"
CARGO_LOCK="Cargo.lock"
TAURI_CONF="crates/gui/tauri.conf.json"
UI_PACKAGE="crates/gui/ui/package.json"
SPEC="packaging/grepfocus.spec"
DEB_CHANGELOG="debian/changelog"
PKGBUILD="packaging/aur/PKGBUILD"
SRCINFO="packaging/aur/.SRCINFO"
ALL_FILES=("$CARGO_TOML" "$CARGO_LOCK" "$TAURI_CONF" "$UI_PACKAGE" "$SPEC"
    "$DEB_CHANGELOG" "$PKGBUILD" "$SRCINFO")

TMP_DIR=""
BACKUP_DIR=""
EDITS_COMPLETE=0
SPOT_LABELS=()
SPOT_VALUES=()
SPOT_EXPECT=()
BULLETS=()

usage() {
    # The header comment of this file, minus the shebang, is the help text.
    sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$SELF"
}

die() {
    echo "error: $*" >&2
    exit 1
}

# Restores every backed-up file if a bump or --aur-sha fails part-way, so a
# refusal or a crash never leaves a half-edited tree behind.
on_exit() {
    local rc=$? f
    if [[ -n "$BACKUP_DIR" && "$EDITS_COMPLETE" -ne 1 ]]; then
        for f in "${ALL_FILES[@]}"; do
            if [[ -f "$BACKUP_DIR/$f" ]]; then
                cp -p "$BACKUP_DIR/$f" "$f"
            fi
        done
        echo "error: the edit did not complete; every file was restored." >&2
    fi
    if [[ -n "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    return "$rc"
}
trap on_exit EXIT

make_tmp_dir() {
    if [[ -z "$TMP_DIR" ]]; then
        TMP_DIR="$(mktemp -d)"
    fi
}

require_files() {
    local f
    for f in "${ALL_FILES[@]}"; do
        [[ -f "$f" ]] || die "missing file: $f"
    done
}

# ---------------------------------------------------------------- readers ---

# Version from the [workspace.package] section of a Cargo.toml.
workspace_version_of() {
    awk '
        /^\[workspace\.package\]/ { in_section = 1; next }
        /^\[/                     { in_section = 0 }
        in_section && /^version[[:space:]]*=/ {
            if (match($0, /"[^"]*"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
                exit
            }
        }
    ' "$1"
}

# Version of one workspace member as recorded in Cargo.lock.
lock_member_version() {
    awk -v want="name = \"$1\"" '
        $0 == want { hit = 1; next }
        hit {
            if (match($0, /^version = "[^"]*"$/)) {
                print substr($0, 12, length($0) - 12)
            }
            exit
        }
    ' "$CARGO_LOCK"
}

# Top-level "version" of a two-space-indented JSON file.
json_version_of() {
    awk '
        match($0, /^  "version":[[:space:]]*"[^"]*"/) {
            value = substr($0, RSTART, RLENGTH)
            sub(/^  "version":[[:space:]]*"/, "", value)
            sub(/"$/, "", value)
            print value
            exit
        }
    ' "$1"
}

spec_version() {
    awk '/^Version:/ { print $2; exit }' "$SPEC"
}

# Version (release suffix dropped) of the newest %changelog entry.
spec_changelog_version() {
    awk '
        /^%changelog/ { in_log = 1; next }
        in_log && /^\* / {
            value = $NF
            sub(/-[^-]*$/, "", value)
            print value
            exit
        }
    ' "$SPEC"
}

# The number in the spec's Release: tag (the %{?dist} macro dropped).
spec_release() {
    awk '/^Release:/ { value = $2; sub(/%.*$/, "", value); print value; exit }' "$SPEC"
}

# Release suffix of the newest %changelog entry ("0.5.1-1" -> "1").
spec_changelog_release() {
    awk '
        /^%changelog/ { in_log = 1; next }
        in_log && /^\* / {
            value = $NF
            if (value ~ /-/) {
                sub(/^.*-/, "", value)
                print value
            }
            exit
        }
    ' "$SPEC"
}

# Version (revision suffix dropped) of the newest debian/changelog stanza.
deb_changelog_version() {
    awk '
        NR == 1 {
            if (match($0, /\([^)]*\)/)) {
                value = substr($0, RSTART + 1, RLENGTH - 2)
                sub(/-[^-]*$/, "", value)
                print value
            }
            exit
        }
    ' "$DEB_CHANGELOG"
}

pkgbuild_var() {
    awk -F= -v key="$1" '$1 == key { print $2; exit }' "$PKGBUILD"
}

# The single checksum inside sha256sums=('...').
pkgbuild_sha() {
    awk '
        /^sha256sums=/ {
            if (match($0, /\047[^\047]*\047/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
            }
            exit
        }
    ' "$PKGBUILD"
}

srcinfo_value() {
    awk -v key="$1" '
        {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (index(line, key " = ") == 1) {
                print substr(line, length(key) + 4)
                exit
            }
        }
    ' "$SRCINFO"
}

tarball_url() {
    echo "$REPO_URL/archive/refs/tags/v$1.tar.gz"
}

srcinfo_source_for() {
    echo "grepfocus-$1.tar.gz::$(tarball_url "$1")"
}

# ------------------------------------------------------------------ check ---

add_spot() {
    SPOT_LABELS+=("$1")
    SPOT_VALUES+=("$2")
    SPOT_EXPECT+=("${3:-}")
}

# Collects every recorded version. A third add_spot argument overrides what the
# spot is compared against (used where the spot is more than a bare version).
collect_spots() {
    local version member
    SPOT_LABELS=()
    SPOT_VALUES=()
    SPOT_EXPECT=()
    version="$(workspace_version_of "$CARGO_TOML")"
    add_spot "Cargo.toml [workspace.package]" "$version"
    for member in "${MEMBERS[@]}"; do
        add_spot "Cargo.lock $member" "$(lock_member_version "$member")"
    done
    add_spot "$TAURI_CONF" "$(json_version_of "$TAURI_CONF")"
    add_spot "$UI_PACKAGE" "$(json_version_of "$UI_PACKAGE")"
    add_spot "$SPEC Version:" "$(spec_version)"
    add_spot "$SPEC %changelog" "$(spec_changelog_version)"
    add_spot "$DEB_CHANGELOG (top stanza)" "$(deb_changelog_version)"
    add_spot "$PKGBUILD pkgver" "$(pkgbuild_var pkgver)"
    add_spot "$SRCINFO pkgver" "$(srcinfo_value pkgver)"
    add_spot "$SRCINFO source" "$(srcinfo_value source)" \
        "$(srcinfo_source_for "$version")"
}

# Prints the version table; returns 1 if any spot disagrees with Cargo.toml.
check_versions() {
    local reference expected shown mark i status=0
    collect_spots
    reference="${SPOT_VALUES[0]}"
    if [[ -z "$reference" ]]; then
        echo "error: could not read the version from [workspace.package] in $CARGO_TOML" >&2
        return 1
    fi
    for i in "${!SPOT_LABELS[@]}"; do
        expected="${SPOT_EXPECT[$i]:-$reference}"
        shown="${SPOT_VALUES[$i]:-(not found)}"
        mark=""
        if [[ "${SPOT_VALUES[$i]}" != "$expected" ]]; then
            mark="   <-- MISMATCH"
            status=1
        elif [[ -n "${SPOT_EXPECT[$i]}" ]]; then
            # A long matching value (the source URL) is shown as the version.
            shown="$reference"
        fi
        printf '  %-40s %s%s\n' "${SPOT_LABELS[$i]}" "$shown" "$mark"
    done
    return "$status"
}

# The PKGBUILD and .SRCINFO checksums must be the same value (SKIP until
# --aur-sha has run, a sha256 afterwards).
check_aur_sums() {
    local in_pkgbuild in_srcinfo
    in_pkgbuild="$(pkgbuild_sha)"
    in_srcinfo="$(srcinfo_value sha256sums)"
    if [[ -z "$in_pkgbuild" || "$in_pkgbuild" != "$in_srcinfo" ]]; then
        printf '  %-40s %s\n' "AUR sha256sums" \
            "PKGBUILD '${in_pkgbuild}' vs .SRCINFO '${in_srcinfo}'   <-- MISMATCH"
        return 1
    fi
    if [[ "$in_pkgbuild" == "SKIP" ]]; then
        printf '  %-40s %s\n' "AUR sha256sums" "SKIP (set by --aur-sha after tagging)"
    else
        printf '  %-40s %s\n' "AUR sha256sums" "$in_pkgbuild"
    fi
    return 0
}

# The package release is written twice for the rpm (Release: and the top
# %changelog entry) and twice for the AUR (PKGBUILD and .SRCINFO pkgrel); each
# pair must agree. The deb revision lives only in debian/changelog.
check_releases() {
    local spec_rel log_rel pkg_rel src_rel mark status=0
    spec_rel="$(spec_release)"
    log_rel="$(spec_changelog_release)"
    mark=""
    if [[ -z "$spec_rel" || "$spec_rel" != "$log_rel" ]]; then
        mark="   <-- MISMATCH"
        status=1
    fi
    printf '  %-40s %s%s\n' "rpm release (Release: / %changelog)" \
        "${spec_rel:-(not found)} / ${log_rel:-(not found)}" "$mark"
    pkg_rel="$(pkgbuild_var pkgrel)"
    src_rel="$(srcinfo_value pkgrel)"
    mark=""
    if [[ -z "$pkg_rel" || "$pkg_rel" != "$src_rel" ]]; then
        mark="   <-- MISMATCH"
        status=1
    fi
    printf '  %-40s %s%s\n' "AUR pkgrel (PKGBUILD / .SRCINFO)" \
        "${pkg_rel:-(not found)} / ${src_rel:-(not found)}" "$mark"
    return "$status"
}

check_placeholder() {
    local hits
    hits="$(grep -nF -- "$PLACEHOLDER" "$SPEC" "$DEB_CHANGELOG" || true)"
    if [[ -n "$hits" ]]; then
        echo "error: release-notes placeholder still present:" >&2
        echo "$hits" | sed 's/^/    /' >&2
        return 1
    fi
    return 0
}

cmd_check() {
    local status=0
    require_files
    echo "==> Recorded versions"
    check_versions || status=1
    check_releases || status=1
    check_aur_sums || status=1
    if [[ "$status" -ne 0 ]]; then
        echo "error: the recorded versions disagree (see MISMATCH above)." >&2
    fi
    check_placeholder || status=1
    if [[ "$status" -eq 0 ]]; then
        echo "==> Version check passed: ${SPOT_VALUES[0]} everywhere."
    fi
    return "$status"
}

# ------------------------------------------------------------------- bump ---

# True when $1 is strictly higher than $2 (sort -V ordering).
version_gt() {
    [[ "$1" != "$2" ]] &&
        [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]
}

# Reads the notes file into BULLETS: one entry per non-empty line, surrounding
# whitespace and a leading list marker ("- " or "* ") removed. An indented line
# that follows a marker bullet continues that bullet (a hard-wrapped markdown
# list); a blank line ends the bullet.
read_notes() {
    local raw line marker in_item=0 last
    BULLETS=()
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        raw="${raw%$'\r'}"
        line="${raw#"${raw%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        if [[ -z "$line" ]]; then
            in_item=0
            continue
        fi
        marker=0
        case "$line" in
            "- "* | "* "*)
                marker=1
                line="${line:2}"
                line="${line#"${line%%[![:space:]]*}"}"
                ;;
        esac
        if [[ "$marker" -eq 0 && "$in_item" -eq 1 && "$raw" == [[:space:]]* ]]; then
            last=$((${#BULLETS[@]} - 1))
            BULLETS[last]="${BULLETS[last]} $line"
            continue
        fi
        BULLETS+=("$line")
        in_item="$marker"
    done <"$1"
}

# wrap_bullet <first-line prefix> <continuation prefix> <text>
# Word-wraps one bullet so no line exceeds WRAP_WIDTH columns, prefix included.
# A single word longer than the width is left on a line of its own.
wrap_bullet() {
    awk -v first="$1" -v cont="$2" -v width="$WRAP_WIDTH" '
        {
            line = first
            started = 0
            count = split($0, words, /[ \t]+/)
            for (i = 1; i <= count; i++) {
                if (words[i] == "") {
                    continue
                }
                if (!started) {
                    line = line words[i]
                    started = 1
                } else if (length(line) + 1 + length(words[i]) <= width) {
                    line = line " " words[i]
                } else {
                    print line
                    line = cont words[i]
                }
            }
            if (started) {
                print line
            }
        }
    ' <<<"$3"
}

# Replaces the first top-level "version" of a two-space-indented JSON file.
set_json_version() {
    sed -i "0,/^  \"version\":[[:space:]]*\"[^\"]*\"/s//  \"version\": \"$2\"/" "$1"
}

# Rewrites a file in place from stdin, keeping its inode and mode.
overwrite() {
    local target="$1" staged
    staged="$TMP_DIR/$(basename "$target").new"
    cat >"$staged"
    cat "$staged" >"$target"
    rm -f "$staged"
}

# Sets pkgver, resets pkgrel and puts sha256sums back to SKIP under a fresh
# TODO comment, whether the file currently holds SKIP or a real checksum. An
# existing TODO block ("# TODO: ... tagging v..." and its "#   " continuation
# lines, in this or the older hand-written wording) is replaced.
reset_pkgbuild() {
    local new="$1"
    awk -v ver="$new" -v url="$(tarball_url "$new")" '
        /^# TODO: .*tagging v/ { in_todo = 1; next }
        in_todo && /^#   /     { next }
        { in_todo = 0 }
        /^pkgver=/ { print "pkgver=" ver; next }
        /^pkgrel=/ { print "pkgrel=1"; next }
        /^sha256sums=/ {
            print "# TODO: after tagging v" ver ", run scripts/bump-version.sh --aur-sha to record the"
            print "#   sha256 of " url
            print "sha256sums=(\047SKIP\047)"
            next
        }
        { print }
    ' "$PKGBUILD" | overwrite "$PKGBUILD"
}

reset_srcinfo() {
    local new="$1"
    sed -i \
        -e "s|^\([[:space:]]*pkgver = \).*|\1$new|" \
        -e "s|^\([[:space:]]*pkgrel = \).*|\1""1|" \
        -e "s|^\([[:space:]]*source = \).*|\1$(srcinfo_source_for "$new")|" \
        -e "s|^\([[:space:]]*sha256sums = \).*|\1SKIP|" \
        "$SRCINFO"
}

# Inserts a new entry directly under the spec's %changelog line. The entry is
# for release 1 of the new version, so Release: goes back to 1 with it.
prepend_spec_changelog() {
    local new="$1" who="$2" entry="$TMP_DIR/spec-entry" bullet
    {
        echo "* $(LC_ALL=C date '+%a %b %d %Y') $who - $new-1"
        for bullet in "${BULLETS[@]}"; do
            wrap_bullet "- " "  " "${bullet//%/%%}"
        done
        echo
    } >"$entry"
    awk -v entry="$entry" '
        { print }
        /^%changelog[[:space:]]*$/ && !inserted {
            while ((getline line < entry) > 0) {
                print line
            }
            inserted = 1
        }
    ' "$SPEC" | overwrite "$SPEC"
    # The replacement is group 1 followed by a literal "1%{?dist}".
    sed -i 's/^\(Release:[[:space:]]*\).*/\11%{?dist}/' "$SPEC"
}

prepend_deb_changelog() {
    local new="$1" who="$2" bullet
    {
        echo "grepfocus ($new-1) unstable; urgency=medium"
        echo
        for bullet in "${BULLETS[@]}"; do
            wrap_bullet "  * " "    " "$bullet"
        done
        echo
        echo " -- $who  $(LC_ALL=C date -R)"
        echo
        cat "$DEB_CHANGELOG"
    } | overwrite "$DEB_CHANGELOG"
}

cmd_bump() {
    local new="$1" notes_file="$2" force="$3"
    local current git_name git_email who f entries_added=0

    if [[ ! "$new" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
        die "'$new' is not a MAJOR.MINOR.PATCH version (e.g. 0.5.2)"
    fi
    require_files
    current="$(workspace_version_of "$CARGO_TOML")"
    [[ -n "$current" ]] ||
        die "could not read the version from [workspace.package] in $CARGO_TOML"

    if ! version_gt "$new" "$current"; then
        if [[ "$force" -ne 1 ]]; then
            die "refusing: $new is not higher than the current version $current (--force overrides)"
        fi
        echo "warning: --force: setting $new although the current version is $current" >&2
    fi

    if [[ -n "$notes_file" ]]; then
        if [[ "$notes_file" != /* ]]; then
            notes_file="$ORIG_PWD/$notes_file"
        fi
        [[ -f "$notes_file" && -r "$notes_file" ]] ||
            die "notes file not readable: $notes_file"
        read_notes "$notes_file"
        [[ "${#BULLETS[@]}" -gt 0 ]] ||
            die "notes file has no non-empty lines: $notes_file"
    else
        BULLETS=("$PLACEHOLDER")
    fi

    git_name="$(git config user.name || true)"
    git_email="$(git config user.email || true)"
    [[ -n "$git_name" && -n "$git_email" ]] ||
        die "git user.name / user.email are not set (needed for the changelog signatures)"
    who="$git_name <$git_email>"

    command -v cargo >/dev/null 2>&1 ||
        die "cargo not found (needed to refresh Cargo.lock)"
    grep -q '^%changelog[[:space:]]*$' "$SPEC" || die "no %changelog line in $SPEC"
    grep -q '^Version:' "$SPEC" || die "no Version: line in $SPEC"
    grep -q '^Release:' "$SPEC" || die "no Release: line in $SPEC"
    grep -q '^pkgver=' "$PKGBUILD" || die "no pkgver= line in $PKGBUILD"
    grep -q '^sha256sums=' "$PKGBUILD" || die "no sha256sums= line in $PKGBUILD"
    [[ -n "$(json_version_of "$TAURI_CONF")" ]] || die "no top-level version in $TAURI_CONF"
    [[ -n "$(json_version_of "$UI_PACKAGE")" ]] || die "no top-level version in $UI_PACKAGE"

    # Everything that can refuse has refused by now; from here on a failure
    # restores the backups (see on_exit).
    make_tmp_dir
    BACKUP_DIR="$TMP_DIR/backup"
    for f in "${ALL_FILES[@]}"; do
        mkdir -p "$BACKUP_DIR/$(dirname "$f")"
        cp -p "$f" "$BACKUP_DIR/$f"
    done

    echo "==> Bumping $current -> $new"
    sed -i "/^\[workspace\.package\]/,/^\[/{s/^version[[:space:]]*=[[:space:]]*\"[^\"]*\"/version = \"$new\"/}" \
        "$CARGO_TOML"
    set_json_version "$TAURI_CONF" "$new"
    set_json_version "$UI_PACKAGE" "$new"
    sed -i "s/^\(Version:[[:space:]]*\).*/\1$new/" "$SPEC"
    reset_pkgbuild "$new"
    reset_srcinfo "$new"

    # A changelog entry is only added when the top one is for another version,
    # so a --force re-sync of the current version does not duplicate it.
    if [[ "$(spec_changelog_version)" == "$new" ]]; then
        echo "note: $SPEC already has a %changelog entry for $new; left as is."
    else
        prepend_spec_changelog "$new" "$who"
        entries_added=1
    fi
    if [[ "$(deb_changelog_version)" == "$new" ]]; then
        echo "note: $DEB_CHANGELOG already has a stanza for $new; left as is."
    else
        prepend_deb_changelog "$new" "$who"
        entries_added=1
    fi

    echo "==> cargo update --workspace --offline"
    cargo update --workspace --offline

    echo "==> Verifying every spot"
    if ! check_versions; then
        die "not every spot carries $new after the bump (see MISMATCH above)"
    fi
    if [[ "${SPOT_VALUES[0]}" != "$new" ]]; then
        die "$CARGO_TOML still says ${SPOT_VALUES[0]}, not $new"
    fi
    check_releases || die "the package releases disagree after the bump (see MISMATCH above)"
    check_aur_sums || die "PKGBUILD and .SRCINFO checksums disagree after the bump"
    EDITS_COMPLETE=1

    if [[ -z "$notes_file" && "$entries_added" -eq 1 ]]; then
        {
            echo
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "WARNING: no --notes file was given. Both changelogs now carry the"
            echo "placeholder bullet '$PLACEHOLDER'. Replace it in"
            echo "  $SPEC"
            echo "  $DEB_CHANGELOG"
            echo "before committing: './scripts/bump-version.sh --check' fails while it"
            echo "is there."
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        } >&2
    fi

    echo
    echo "==> git diff --stat"
    git --no-pager diff --stat -- "${ALL_FILES[@]}"
    echo
    echo "==> Next steps (nothing was committed):"
    echo "    1. Review:   git diff"
    echo "    2. Verify:   ./scripts/bump-version.sh --check"
    echo "    3. Commit:   git commit -am \"Release $new\""
    echo "    4. Build + audit:  ./scripts/release.sh"
    echo "    Full procedure: docs/release.md"
}

# ---------------------------------------------------------------- aur-sha ---

cmd_aur_sha() {
    local version url tarball top tarball_version sha recorded tool f

    require_files
    for tool in curl sha256sum tar; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
    done
    if ! check_versions >/dev/null; then
        check_versions >&2 || true
        die "refusing: the recorded versions disagree; fix that first"
    fi
    version="${SPOT_VALUES[0]}"
    grep -q '^sha256sums=' "$PKGBUILD" || die "no sha256sums= line in $PKGBUILD"
    [[ -n "$(srcinfo_value sha256sums)" ]] || die "no sha256sums line in $SRCINFO"

    url="$(tarball_url "$version")"
    if [[ -n "${GREPFOCUS_TARBALL_URL:-}" ]]; then
        url="$GREPFOCUS_TARBALL_URL"
        echo "warning: GREPFOCUS_TARBALL_URL is set; fetching $url instead of the tag tarball" >&2
    fi

    make_tmp_dir
    tarball="$TMP_DIR/grepfocus-$version.tar.gz"
    echo "==> Downloading $url"
    if ! curl -fsSL --retry 2 -o "$tarball" "$url"; then
        die "refusing: download failed. Is the tag v$version pushed? Nothing was changed."
    fi
    [[ -s "$tarball" ]] || die "refusing: the download is empty. Nothing was changed."

    # The PKGBUILD does `cd grepfocus-<ver>`, and a tag placed on the wrong
    # commit would carry another version: check both before trusting the hash.
    if ! top="$(tar -tzf "$tarball" 2>/dev/null | awk 'NR == 1 { print }')"; then
        die "refusing: the download is not a gzip tarball. Nothing was changed."
    fi
    [[ "$top" == "grepfocus-$version/" ]] ||
        die "refusing: tarball top-level directory is '$top', expected 'grepfocus-$version/'. Nothing was changed."
    if ! tar -xzOf "$tarball" "grepfocus-$version/Cargo.toml" >"$TMP_DIR/Cargo.toml" 2>/dev/null; then
        die "refusing: no Cargo.toml in the tarball. Nothing was changed."
    fi
    tarball_version="$(workspace_version_of "$TMP_DIR/Cargo.toml")"
    [[ "$tarball_version" == "$version" ]] ||
        die "refusing: the tarball's Cargo.toml says '$tarball_version', not $version (tag on the wrong commit?). Nothing was changed."

    sha="$(sha256sum "$tarball" | awk '{ print $1 }')"
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "sha256sum produced no usable checksum"
    echo "==> sha256 $sha"

    recorded="$(pkgbuild_sha)"
    if [[ "$recorded" != "SKIP" && "$recorded" != "$sha" ]]; then
        echo "warning: PKGBUILD recorded a different checksum ($recorded); replacing it." >&2
        echo "warning: a changed tag tarball usually means the tag was moved." >&2
    fi

    # Both files change or neither: a failure between the two writes restores
    # the backups (see on_exit).
    BACKUP_DIR="$TMP_DIR/backup"
    for f in "$PKGBUILD" "$SRCINFO"; do
        mkdir -p "$BACKUP_DIR/$(dirname "$f")"
        cp -p "$f" "$BACKUP_DIR/$f"
    done
    awk -v sha="$sha" '
        /^# TODO: .*tagging v/ { in_todo = 1; next }
        in_todo && /^#   /     { next }
        { in_todo = 0 }
        /^sha256sums=/ { print "sha256sums=(\047" sha "\047)"; next }
        { print }
    ' "$PKGBUILD" | overwrite "$PKGBUILD"
    sed -i "s|^\([[:space:]]*sha256sums = \).*|\1$sha|" "$SRCINFO"
    EDITS_COMPLETE=1

    echo
    if git diff --quiet -- "$PKGBUILD" "$SRCINFO"; then
        echo "==> $PKGBUILD and $SRCINFO already carry this checksum; no change."
    else
        echo "==> git diff"
        git --no-pager diff -- "$PKGBUILD" "$SRCINFO"
        echo
        echo "==> Next: commit these two files, then publish to the AUR"
        echo "    (packaging/aur/README.md, \"Publishing to the AUR\")."
    fi
}

# ------------------------------------------------------------------- main ---

MODE=""
NEW_VERSION=""
NOTES_FILE=""
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            [[ -z "$MODE" ]] || die "--check cannot be combined with another mode"
            MODE="check"
            ;;
        --aur-sha)
            [[ -z "$MODE" ]] || die "--aur-sha cannot be combined with another mode"
            MODE="aur-sha"
            ;;
        --notes)
            [[ $# -ge 2 ]] || die "--notes needs a file argument"
            NOTES_FILE="$2"
            shift
            ;;
        --notes=*)
            NOTES_FILE="${1#--notes=}"
            ;;
        --force)
            FORCE=1
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1 (see --help)"
            ;;
        *)
            [[ -z "$MODE" ]] || die "unexpected argument: $1 (see --help)"
            MODE="bump"
            NEW_VERSION="$1"
            ;;
    esac
    shift
done

case "$MODE" in
    check | aur-sha)
        if [[ -n "$NOTES_FILE" || "$FORCE" -eq 1 ]]; then
            die "--notes and --force only apply to a version bump"
        fi
        ;;
esac

case "$MODE" in
    check) cmd_check ;;
    aur-sha) cmd_aur_sha ;;
    bump) cmd_bump "$NEW_VERSION" "$NOTES_FILE" "$FORCE" ;;
    *)
        usage >&2
        exit 2
        ;;
esac
