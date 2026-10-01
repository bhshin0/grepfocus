# AUR package (`grepfocus`)

Source-of-truth for the [AUR](https://aur.archlinux.org/packages/grepfocus)
package. The files here (`PKGBUILD`, `grepfocus.install`, `.SRCINFO`) are what
get published; the live AUR package is a **separate git repo**, not this one.

It builds `grepfocus` from source from the tagged GitHub release and installs the
daemon + systemd unit + sysusers/tmpfiles exactly like the RPM, relocated to
`/usr/bin`.

## Per-release update

The version and the checksum are written by `scripts/bump-version.sh`, as
part of the release procedure in [docs/release.md](../../docs/release.md):

1. `./scripts/bump-version.sh X.Y.Z --notes FILE` (release step 1) sets
   `pkgver`, puts `pkgrel` back to 1 and `sha256sums` back to `SKIP`, in
   `PKGBUILD` and in `.SRCINFO` (there the `source` line as well).
2. `./scripts/bump-version.sh --aur-sha` (release step 6, after the
   `vX.Y.Z` tag is pushed) downloads the tag tarball, checks that it is the
   tagged version and writes its sha256 into both files. It changes nothing
   if the tarball cannot be fetched.
3. Commit the two files, smoke-build (below), then publish.

`./scripts/bump-version.sh --check` fails when the two files disagree on
the version, `pkgrel` or the checksum. That is all it compares.

`.SRCINFO` is never regenerated: the script edits those lines in place,
because the machine the releases are cut on has no `makepkg`. Any other
change to `PKGBUILD` — dependencies, `pkgdesc`, the `install` file, a
`pkgrel` bump for a packaging-only fix — has to be copied into `.SRCINFO`
by hand, or the file regenerated on Arch (the container of the smoke build
below has `makepkg`):

```sh
makepkg --printsrcinfo > .SRCINFO
```

## Local smoke build (no Arch box needed — uses podman)

Manual, and not part of `scripts/release.sh`. `makepkg` downloads the tag
tarball named in `PKGBUILD`, so this only works once the tag is on GitHub.
Run it from this directory, and not alongside a release build: the
container mounts this checkout, and `release.sh` refuses to start while
such a container is running.

```sh
podman run --rm -it -v "$PWD":/pkg:Z archlinux:latest bash -c '
  pacman -Syu --noconfirm base-devel git &&
  useradd -m build && chown -R build /pkg &&
  cp -r /pkg /home/build/aur && chown -R build /home/build/aur &&
  su build -c "cd /home/build/aur && makepkg -s --noconfirm"
'
```

(`makepkg` refuses to run as root, hence the throwaway `build` user.)

## Publishing to the AUR

Manual: no script pushes to the AUR. Requires an AUR account with an SSH
key registered (https://aur.archlinux.org/ → My Account → SSH Public Key).
Publish only after `--aur-sha` has replaced `SKIP` with the real checksum.

```sh
git clone ssh://aur@aur.archlinux.org/grepfocus.git aur-grepfocus
cp PKGBUILD grepfocus.install .SRCINFO aur-grepfocus/
cd aur-grepfocus
git add PKGBUILD grepfocus.install .SRCINFO
git commit -m "grepfocus <version>"
git push
```

The first push (new package) uses the same steps; the AUR creates the package
from the initial commit.
