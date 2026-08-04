# AUR package (`grepfocus`)

Source-of-truth for the [AUR](https://aur.archlinux.org/packages/grepfocus)
package. The files here (`PKGBUILD`, `grepfocus.install`, `.SRCINFO`) are what
get published; the live AUR package is a **separate git repo**, not this one.

It builds `grepfocus` from source from the tagged GitHub release and installs the
daemon + systemd unit + sysusers/tmpfiles exactly like the RPM, relocated to
`/usr/bin`.

## Per-release update

1. Bump `pkgver` in `PKGBUILD` to the new version (and reset `pkgrel=1`).
2. Recompute the source hash and update `sha256sums`:
   ```sh
   curl -fsSL "https://github.com/bhshin0/grepfocus/archive/refs/tags/vNEW.tar.gz" | sha256sum
   ```
3. Regenerate `.SRCINFO` **on an Arch machine** (it must match the PKGBUILD):
   ```sh
   makepkg --printsrcinfo > .SRCINFO
   ```
4. Smoke-build (see below), then publish.

## Local smoke build (no Arch box needed — uses podman)

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

Requires an AUR account with an SSH key registered
(https://aur.archlinux.org/ → My Account → SSH Public Key).

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
