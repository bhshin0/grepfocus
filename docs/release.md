# Releasing GrepFocus

The procedure for cutting a release, in order. Two scripts carry most of it:

- `scripts/bump-version.sh` writes the version into every file that records it
  and checks that they agree.
- `scripts/release.sh` runs the checks, builds the rpm, deb and AppImage one
  after the other, audits each artifact and, if every check passes, writes
  `dist/SHA256SUMS`.

Neither script commits, tags, pushes or publishes anything. Both print their
options with `--help`.

## Two traps

**The podman builds must never overlap.** The deb and AppImage builds each
mount the repo into a container and keep `target/` in named volumes that every
checkout shares. Two of them running at once (two terminals, two worktrees, a
second agent) corrupt each other. Always build through `scripts/release.sh`,
which runs them strictly one after the other, refuses to start while a builder
container is running, and holds a lock so a second `release.sh` cannot build
at the same time. Do not start `packaging/build-deb.sh` or
`packaging/build-appimage.sh` by hand while a release is building.

**The public-key audit must pass before anything is published.** A build whose
daemon carries the wrong license public key rejects every license sold. It has
shipped once. `release.sh` reads the key from `crates/core/src/license.rs` and
looks for it in the `grepfocusd` inside every artifact. If that check, or any
other, says `FAIL`, nothing from that `dist/` goes to the website, the AUR or
a tag. Fix the cause and run `release.sh` again. To make that hard to get
wrong, `dist/SHA256SUMS` only exists after a run that audited all three
artifacts and passed; a failed run leaves `dist/SHA256SUMS.audit-failed`
instead.

## Checklist

### 1. Bump

- [ ] Start from the branch that will be released, with a clean tree.
- [ ] Write the release notes to a file, one line per bullet (plain text, no
      wrapping needed; write them for users, not for developers). A leading
      `- ` or `* ` is dropped. An indented line under a `- ` or `* ` bullet
      continues that bullet, so a hard-wrapped markdown list can be pasted as
      it is; any other non-empty line starts a new bullet.
- [ ] Bump:

      ```sh
      ./scripts/bump-version.sh X.Y.Z --notes /path/to/notes.txt
      ```

      This sets the version in `Cargo.toml`, `Cargo.lock`,
      `crates/gui/tauri.conf.json`, `crates/gui/ui/package.json`,
      `packaging/grepfocus.spec`, `packaging/aur/PKGBUILD` and
      `packaging/aur/.SRCINFO`, and prepends a dated entry to the spec
      `%changelog` and to `debian/changelog`. The spec `Release:` and the AUR
      `pkgrel` go back to 1, and the AUR checksum to `SKIP` until step 6.

### 2. Review and commit

- [ ] `git diff`: read both changelog entries (every bullet is one complete
      sentence, none was split or merged), and check nothing else moved.
- [ ] `./scripts/bump-version.sh --check` prints the same version on every
      line and exits 0.
- [ ] Commit with the subject `Release X.Y.Z`.

### 3. Build and audit

- [ ] Run:

      ```sh
      ./scripts/release.sh
      ```

      It needs a clean tree (the rpm is built from `HEAD`), takes a while, and
      must be the only build running on the machine (first trap).
- [ ] Every audit line is `PASS`, or `SKIP` with a reason you accept, and the
      script ends with `Release audit passed` (second trap). Expected `SKIP`:
      the GUI public-key line, because the GUI does not verify licenses and
      carries no key.
- [ ] Note the commit printed under `Commit` ("built from ..."): that commit,
      and no other, is what gets tagged in step 5.
- [ ] Keep the output: it ends with the `SHA256SUMS` content and the
      `latest.json` snippet needed in step 7.

Variants, none of which produces a release set on its own:

- `--dry-run` runs the preflight and shows what would run.
- `--no-build` audits what is already in `dist/` again, without building.
- `--only deb,appimage` builds and audits part of the set, for debugging a
  packaging problem. Its checksums go to `dist/SHA256SUMS.partial`, and an
  artifact it did not rebuild is not vouched for. Finish with a full run.
- `--allow-dirty` builds from an uncommitted tree. It cannot build the rpm
  (which is made from `HEAD`), so it only works with `--only deb,appimage` or
  `--no-build`.

### 4. Live verification

- [ ] Install the freshly built package on a real machine and work through the
      "Live verification checklist" in the plan document
      `hardening-health-updates.md` (under `docs/plans/`).

A problem found here means: fix, commit, and go back to step 3. Do not reuse
artifacts built before the fix.

### 5. Merge, tag, push

- [ ] Fast-forward `master` to the commit that `release.sh` built and
      audited (`<commit>` is the hash from its `Commit` section; the script
      prints these commands with it filled in), tag that commit and push both:

      ```sh
      git checkout master && git merge --ff-only <commit>
      git tag -a vX.Y.Z -m "GrepFocus X.Y.Z" <commit>
      git push origin master vX.Y.Z
      ```

If the merge is not a fast-forward, `master` has commits the release branch
lacks, and the merged tree would not be the one that was built and audited.
Bring the branch up to date first, then go back to step 3. The same holds for
any commit added after the build: the tag must be the audited commit.

### 6. AUR

- [ ] After the tag is pushed:

      ```sh
      ./scripts/bump-version.sh --aur-sha
      ```

      It downloads the tag tarball, checks that it is the tagged version, and
      writes its sha256 into `PKGBUILD` and `.SRCINFO`. It changes nothing if
      the tag is not on GitHub yet. Together with step 1 this replaces the
      manual "Per-release update" steps in `packaging/aur/README.md`.
- [ ] Commit the two files and push.
- [ ] Publish to the AUR as described in
      [packaging/aur/README.md](../packaging/aur/README.md) ("Publishing to
      the AUR"; the smoke build in that file is worth running first).

### 7. Website

- [ ] Send to the website repo: the three versioned files from `dist/`,
      `dist/SHA256SUMS`, and the `latest.json` snippet printed by
      `release.sh`. The download pages and `latest.json` must point at the
      versioned file names, so the checksums stay valid. If there is no
      `dist/SHA256SUMS`, the last run failed or was partial: there is nothing
      to hand off yet.
- [ ] After the site is deployed, download each file from the site and compare
      it against `SHA256SUMS`:

      ```sh
      sha256sum -c SHA256SUMS
      ```

## What the audit checks

For each of the rpm, deb and AppImage: the versioned file for this version
exists; it unpacks; its package metadata carries the version; the daemon and
GUI binaries are inside and executable; the daemon contains the license public
key; `grepfocusd --version` prints `grepfocusd X.Y.Z`; the stable-name copy
(`grepfocus.rpm` and so on) is identical to the versioned file; and, when
`release.sh` built it, the file is newer than the start of the run and `HEAD`
did not move while the builds ran.

- rpm: the unit starts `/usr/bin/grepfocusd`, the scriptlets run
  `grepfocusd cleanup` on erase, `LICENSE` is packaged.
- deb: the same unit check, `prerm` runs `grepfocusd cleanup`, `copyright` and
  `LICENSE` are packaged.
- AppImage: no `libwayland-*.so*` is bundled (a bundled copy breaks the window
  on hosts with a newer Mesa), `AppRun` is executable, every daemon payload
  file is present, and the AppImage run with `--version` prints
  `grepfocus-gui X.Y.Z`.

How a line is decided:

- `PASS` only when the check ran and held. If a package does not unpack, every
  check of its contents is a `FAIL` ("not checked: extraction failed").
- A `--version` check is a `FAIL` whenever the binary printed anything other
  than the expected line, exited with an error, or did not start. It is a
  `SKIP` only when the build host demonstrably cannot run the binary: the
  wrong architecture, or a glibc newer than the host's. On a host without
  FUSE the AppImage's extracted `AppRun` is run instead, and the line says so.
- A `SKIP` never counts as a pass: read its reason.

## Continuous integration

`.github/workflows/check.yml` runs `./scripts/bump-version.sh --check` and
`./scripts/check.sh` on every push to `master` and on every pull request. It
builds nothing for release.
