# frostbite

A Cold Turkey-style website and application blocker for Linux.

> **Status:** v0.1 in active development. Daemon and Tauri GUI scaffolds
> both compile and run. End-to-end testing on a real install is the next step.

## What it does

When a block is active, frostbite:

- **Blocks websites** by writing entries to `/etc/hosts` that point each
  blocked domain (and its `www.` alias) to `0.0.0.0`, then sets `chattr +i`
  so the file cannot be edited until the block ends.
- **Blocks applications** by polling `/proc` every 500ms and `SIGKILL`ing any
  process whose exe path, basename, or cmdline matches the blocklist.
- **Survives tampering** within the bounds of what's possible on Linux (see
  *Known limits* below). The daemon auto-restarts on kill, re-applies blocks
  on reboot, and persists state with an HMAC seal so hand-edits to
  `state.json` are detected.
- **Will not let you cancel an active block.** That's the entire point.

## Architecture

```
┌──────────────────────┐    Unix socket    ┌─────────────────────────┐
│  Tauri GUI (user)    │   /run/frostbite  │  frostbited (root)      │
│  - Block list editor │ ────────────────► │  - Owns block state     │
│  - Status / timers   │ ◄──────────────── │  - Edits /etc/hosts     │
└──────────────────────┘   length-prefix   │  - Kills blocked procs  │
                              JSON-RPC     │  - systemd-managed      │
                                           └─────────────────────────┘
```

- `frostbited` runs as root via systemd, owns enforcement.
- The GUI is unprivileged. Membership in the `frostbite` group authorizes a
  user to talk to the daemon socket (`/run/frostbite/sock`, mode `0660`).

## Repository layout

```
crates/
  core/      shared types, IPC framing, HMAC helpers
  daemon/    frostbited binary
  gui/       Tauri app (planned)
packaging/
  systemd/   frostbited.service unit
  install.sh dev installer
```

## Build and install (Fedora)

Prerequisites:

```bash
# Rust toolchain (rustup is recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Tauri / WebKit dev headers (install.sh builds the GUI)
sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel javascriptcoregtk4.1-devel

# pnpm — the UI is built and embedded into the GUI binary at compile time
# https://pnpm.io/installation
```

Build and install the full product — daemon + systemd unit, GUI binary,
app-grid launcher, icon, and login autostart entry:

```bash
git clone <repo> frostbite && cd frostbite
sudo ./packaging/install.sh
# log out and back in for `frostbite` group membership to take effect
```

To remove it later, use `sudo ./packaging/uninstall.sh` (see *Recovery*
below).

Verify it's running:

```bash
systemctl status frostbited
journalctl -u frostbited -f
```

## Running the GUI (dev mode)

The Tauri app needs the daemon running and you in the `frostbite` group.

```bash
# one-time: install JS deps
pnpm --dir crates/gui/ui install

# build the frontend (needed because Tauri doesn't run beforeDevCommand
# automatically when you launch the binary directly)
pnpm --dir crates/gui/ui build

# run the GUI
cargo run -p frostbite-gui
```

For an iterative dev loop, install Tauri's CLI and use `tauri dev`:

```bash
cargo install tauri-cli --version "^2.0"
cd crates/gui && cargo tauri dev
```

## Development

Run the full pre-flight suite before committing:

```bash
./scripts/check.sh
```

It runs, stopping on the first failure:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `pnpm --dir crates/gui/ui build` (`tsc -noEmit` + `vite build`)

Requirements: the `rustfmt` and `clippy` components
(`rustup component add rustfmt clippy`), `pnpm`, and — for the workspace-wide
clippy/test that include the GUI crate — the webkit2gtk-4.1 + gtk-3 dev libs.
On a headless box without those, scope the Rust steps to
`-p frostbite-core -p frostbited`.

You can wire it up as a pre-commit hook if you like (not installed
automatically):

```bash
ln -s ../../scripts/check.sh .git/hooks/pre-commit
```

To rebuild and redeploy onto the local machine in one step (installs the
daemon/GUI binaries, restarts the service, and installs the launcher + login
autostart entry), use the upgrade loop:

```bash
./packaging/upgrade.sh   # run as your normal user; uses sudo for system steps
```

## Wire protocol

The daemon listens on a Unix socket. Each frame is a 4-byte big-endian
unsigned length followed by JSON. Methods:

| Method            | Params                                | Notes                                        |
| ----------------- | ------------------------------------- | -------------------------------------------- |
| `list_blocks`     | —                                     |                                              |
| `add_block`       | `{ block: Block }`                    | Returns `{ result: "added", id }`            |
| `update_block`    | `{ block: Block }`                    | Rejected during an active block              |
| `delete_block`    | `{ id: u64 }`                         | Rejected if block is currently active        |
| `start_block`     | `{ id: u64, duration_secs: u64 }`     | Rejected if any block is already active      |
| `cancel_block`    | —                                     | Always rejected while a block is active      |
| `get_status`      | —                                     | Returns active block (if any) + server time  |

A `Block` is `{ id, name, domains: [..], apps: [AppMatcher, ..] }` where
`AppMatcher` is one of `{kind: "exe_path", path}`, `{kind: "basename", name}`,
or `{kind: "cmdline", contains}`.

## Recovery

Frostbite must never brick a machine, so every enforcement artifact has a
supported teardown path — and a manual escape hatch for when the binaries
are already gone.

Supported paths (both idempotent; running them twice is safe):

```bash
# Full uninstall. Tears down enforcement FIRST, then removes the binaries,
# systemd unit, launcher/autostart files, and /run/frostbite. --purge
# additionally deletes saved blocks, the password, the HMAC secret, and
# the frostbite group.
sudo ./packaging/uninstall.sh [--purge]

# Offline teardown without uninstalling: clears the immutable bit, strips
# the managed /etc/hosts region, removes stale atomic-write temp files,
# drops the nftables table, and clears persisted active blocks so a later
# `systemctl start` won't re-apply them. Refuses to run while the daemon
# is up (its 1s reconcile tick would re-apply enforcement right behind
# it) unless you pass --force. --purge deletes /var/lib/frostbite and
# /etc/frostbite; binaries, unit, and the frostbite group are
# uninstall.sh's job.
sudo frostbited cleanup [--purge] [--force]
```

If the binaries are already gone, everything Frostbite enforces can be
undone by hand:

```bash
sudo chattr -i /etc/hosts
sudo sed -i '/# frostbite-begin/,/# frostbite-end/d' /etc/hosts
sudo nft delete table inet frostbite_doh
sudo rm -f /etc/hosts.frostbite.tmp
```

`/var/lib/frostbite/hosts.orig` is a root-only snapshot of the *unmanaged*
`/etc/hosts` content (everything outside the marker region), refreshed
before every managed edit. You normally never need it — the `sed` above
removes the managed region and leaves the rest untouched. Copy it over
`/etc/hosts` only if the file is mangled *beyond* the marker region —
with `install`, not `cp`, since the snapshot is 0600 and `/etc/hosts`
must be world-readable for the resolver in non-root processes:

```bash
sudo install -m 644 /var/lib/frostbite/hosts.orig /etc/hosts
```

## Known limits

We're honest about what we don't defend against. None of these are bypasses
that Cold Turkey beats either.

- **Determined root user.** Anyone with root can boot to recovery mode,
  unmask the unit from initrd, run `chattr -i /etc/hosts`, or load a kernel
  module. Linux gives root unrestricted power; we cannot revoke it. The
  realistic goal is friction high enough to defeat in-the-moment akrasia.
- **Live USB.** Anyone with physical access can boot a USB and edit the
  disk. Out of scope.
- **Custom DoH/DoT endpoints.** An `nftables` table drops DoH (TCP 443)
  and DNS-over-TLS (TCP/UDP 853) to known public resolver IPs, so stock
  Firefox/Chrome DoH can't bypass `/etc/hosts` — but unlisted or
  self-hosted endpoints are allowed by design.
- **System resolvers doing DoT to a listed IP.** The flip side of that
  table: if your system resolver does DNS-over-TLS to one of the listed
  public resolver IPs (e.g. systemd-resolved with `DNSOverTLS=yes`
  pointed at `1.1.1.1`), DNS breaks entirely during active blocks. Use
  plain DNS or an unlisted resolver.
- **Systems that forbid the immutable flag.** Where policy (e.g. SELinux)
  or the filesystem denies `chattr +i`, blocks still work — the hosts
  *content* is the enforcement — but tamper protection is degraded. The
  daemon logs a warning when this happens.
- **VPNs over IP literals.** If the user knows the IP address of a blocked
  site and types it directly, hosts-file blocking won't catch them.
- **Uninstalling works even mid-block — by design.** A Cold Turkey-style
  uninstall lockout was considered and deliberately rejected: root is out
  of the threat model (see above), and never bricking a machine beats
  fighting root. `uninstall.sh` and `frostbited cleanup` tear down
  enforcement during an active block without complaint.
- **No tray icon on stock GNOME.** GNOME ships no StatusNotifier host, so
  the tray icon needs an extension such as "AppIndicator and
  KStatusNotifierItem Support". Without one, closing the window quits the
  app — enforcement is daemon-side and unaffected; minimize instead of
  closing to keep getting block start/end notifications. With one, closing
  hides to the tray; if the tray host
  vanishes while the window is hidden, the window reappears within ~5
  seconds. Launching Frostbite again always surfaces the existing instance.

## License

PolyForm Shield 1.0.0 (source-available; see LICENSE).
