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

# Tauri / WebKit dev headers (only needed for the GUI later)
sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel javascriptcoregtk4.1-devel
```

Build and install the daemon:

```bash
git clone <repo> frostbite && cd frostbite
sudo ./packaging/install.sh
# log out and back in for `frostbite` group membership to take effect
```

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

## Known limits

We're honest about what we don't defend against. None of these are bypasses
that Cold Turkey beats either.

- **Determined root user.** Anyone with root can boot to recovery mode,
  unmask the unit from initrd, run `chattr -i /etc/hosts`, or load a kernel
  module. Linux gives root unrestricted power; we cannot revoke it. The
  realistic goal is friction high enough to defeat in-the-moment akrasia.
- **Live USB.** Anyone with physical access can boot a USB and edit the
  disk. Out of scope.
- **Firefox DoH (DNS-over-HTTPS).** Browsers configured to use DoH bypass
  `/etc/hosts`. v0.2 plans to add an `nftables` rule blocking outbound DNS
  to known DoH endpoints.
- **VPNs over IP literals.** If the user knows the IP address of a blocked
  site and types it directly, hosts-file blocking won't catch them.
- **Uninstalling the package** while a block is active is currently allowed.
  v0.2 will add a postrm hook that refuses uninstall during enforcement.

## License

PolyForm Shield 1.0.0 (source-available; see LICENSE).
