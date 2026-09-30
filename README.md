# GrepFocus

A Cold Turkey-style website and application blocker for Linux.

> **Status:** v0.1 in active development. Daemon and Tauri GUI scaffolds
> both compile and run. End-to-end testing on a real install is the next step.

## What it does

When a block is active, GrepFocus:

- **Blocks websites** by writing entries to `/etc/hosts` that point each
  blocked domain (and its `www.` alias) to `0.0.0.0`, then sets `chattr +i`
  so the file cannot be edited until the block ends.
- **Blocks applications** by polling `/proc` every 500ms and `SIGKILL`ing any
  process whose exe path, basename, or cmdline matches the blocklist and
  that is not running as root (see *Known limits*).
- **Turns browser DNS-over-HTTPS off** through enterprise-policy files
  (Firefox, Mullvad Browser, Chromium including the Ubuntu snap, Chrome,
  Brave) so the `/etc/hosts` block applies in them — those browsers say they
  are "managed by your organization". Written at daemon start and re-checked
  every minute, not only during blocks; Firefox-based browsers pick it up at
  their next start, Chromium immediately.
- **Survives tampering** within the bounds of what's possible on Linux (see
  *Known limits* below). The daemon auto-restarts on kill, re-applies blocks
  on reboot, and persists state with an HMAC seal so hand-edits to
  `state.json` are detected.
- **Will not let you cancel an active block.** That's the entire point.

## Architecture

```
┌──────────────────────┐    Unix socket    ┌─────────────────────────┐
│  Tauri GUI (user)    │   /run/grepfocus  │  grepfocusd (root)      │
│  - Block list editor │ ────────────────► │  - Owns block state     │
│  - Status / timers   │ ◄──────────────── │  - Edits /etc/hosts     │
└──────────────────────┘   length-prefix   │  - Kills blocked procs  │
                              JSON-RPC     │  - systemd-managed      │
                                           └─────────────────────────┘
```

- `grepfocusd` runs as root via systemd, owns enforcement.
- The GUI is unprivileged. Membership in the `grepfocus` group authorizes a
  user to talk to the daemon socket (`/run/grepfocus/sock`, mode `0660`).

## Repository layout

```
crates/
  core/      shared types, IPC framing, HMAC helpers
  daemon/    grepfocusd binary
  gui/       Tauri app (planned)
packaging/
  systemd/   grepfocusd.service unit
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
git clone <repo> grepfocus && cd grepfocus
sudo ./packaging/install.sh
# log out and back in for `grepfocus` group membership to take effect
```

To remove it later, use `sudo ./packaging/uninstall.sh` (see *Recovery*
below).

Verify it's running:

```bash
systemctl status grepfocusd
journalctl -u grepfocusd -f
grepfocusd --version     # prints "grepfocusd <version>"
grepfocus-gui --version  # prints "grepfocus-gui <version>", no window
```

The GUI's Settings tab shows both versions (`GrepFocus <gui> · daemon <ver>
(<path>)`) and, below them, an enforcement diagnostics line — the nft and
`/etc/hosts` lock state, the instant-break proxy, and the re-apply counters
since the daemon started. Enforcement problems themselves show on the Status
tab (see *Known limits*).

## Running the GUI (dev mode)

The Tauri app needs the daemon running and you in the `grepfocus` group.

```bash
# one-time: install JS deps
pnpm --dir crates/gui/ui install

# build the frontend (needed because Tauri doesn't run beforeDevCommand
# automatically when you launch the binary directly)
pnpm --dir crates/gui/ui build

# run the GUI
cargo run -p grepfocus-gui
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
`-p grepfocus-core -p grepfocusd`.

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
| `get_status`      | —                                     | Active blocks, server time, license, settings, plus `health` (daemon version, install kind, nft/hosts/proxy state, browser DoH policies, drift counters, last error) |

A `Block` is `{ id, name, domains: [..], apps: [AppMatcher, ..] }` where
`AppMatcher` is one of `{kind: "exe_path", path}`, `{kind: "basename", name}`,
or `{kind: "cmdline", contains}`.

`add_block` and `update_block` validate the content and refuse the frame with
a plain-language `{ result: "error", message }` when it fails; the GUI runs
the same validator (`grepfocus_core::validate`) so it shows the same text
without a round trip. The rules:

- `domains`: hostnames only, one per entry. A pasted URL is trimmed to its
  host — scheme, path, query, port and one trailing dot are stripped — and
  the result is lowercased. IP literals, wildcards (`*.example.com`) and
  single labels (`localhost`) are refused, as is anything that is not
  letters, digits, dots and hyphens (so a newline or a space can never
  become a second `/etc/hosts` line). International names go in as punycode
  (`xn--…`). A name may be at most 249 characters unless it already starts
  with `www.`, so the alias the daemon adds still fits the 253-character DNS
  limit. At most 5000 per block.
- `apps`: an `exe_path` must be absolute and resolved (no `.`, `..` or `//`
  components — it is compared byte-for-byte with `/proc/<pid>/exe`); a
  `basename` may not contain `/`; a `cmdline` pattern must be at least 3
  characters. Nothing may target GrepFocus itself (any matcher containing
  `grepfocus`, case-insensitively). At most 500 per block.
- A block needs at least one domain or app, and a name of at most 200
  characters with no control characters.

Entries are canonicalized on save, and the daemon applies the same rules to
its stored state at every start: an entry it can normalize is rewritten in
place, one it cannot is dropped, and each change is one journal line
(`journalctl -u grepfocusd | grep sanitized`). A block that was saved by an
older version with more entries than the caps allow keeps working but cannot
be re-saved until it is trimmed.

`get_status` carries a `health` object: every enforcement outcome the daemon
used to log and forget, plus its identity. What a healthy daemon emits:

```json
"health": {
  "daemon_version": "0.5.1",
  "daemon_exe": "/usr/local/bin/grepfocusd",
  "install_kind": "local",
  "nft":   {"kind": "ok"},
  "hosts": {"kind": "locked"},
  "hosts_reapplies": 0,
  "nft_reinstalls": 0,
  "proxy": "holding",
  "browser_policies": [
    {"browser": "firefox", "path": "/etc/firefox/policies/policies.json", "state": {"kind": "written"}, "since_unix": 1790000000},
    {"browser": "mullvad-browser", "path": "/usr/lib/mullvad-browser/distribution/policies.json", "state": {"kind": "failed", "fail_kind": "read_only_fs", "reason": "opening …grepfocus.tmp: Read-only file system (os error 30)"}, "since_unix": 1790000000}
  ],
  "startup_notes": [],
  "last_error": null,
  "last_error_unix": null
}
```

`install_kind` is `package` (`/usr/bin`), `local` (`/usr/local/bin`: the
AppImage installer or the dev scripts) or `unknown`. `nft` is `ok`, `failed`
(`nft` could not install the table — the hosts block is live, DoH is open),
`stale_table` (a block ended but the table could not be removed; the daemon
retries every 30 s), `not_applicable` (nothing enforced) or `unknown`.
`hosts` is `locked`, `unlocked` (tamper protection licensed but `chattr +i`
refused), `not_applicable` or `unknown`. `proxy` is `holding`, `degraded`
(a loopback port would not bind, so breaks lag) or `off`. `failed`,
`stale_table` and `unlocked` carry a `reason`. `hosts_reapplies` counts
re-probes that found the managed region missing (a tamper signal),
`nft_reinstalls` counts the table vanishing while `nft` worked (a firewall
reload). `startup_notes` is what the startup sanitize changed or flagged.
`last_error` is the last failed `/etc/hosts` write, cleared by the next
success. Every enum accepts a tag it does not know as `unknown`, and a client
says nothing for `unknown`: a newer daemon may add a variant without an older
GUI failing the whole frame. An older daemon never emits `health` at all; the
client then reads the default, whose empty `daemon_version` is the tell. The
older `instant_breaks_degraded` flag stays on the wire, derived from
`health.proxy`.

## Recovery

GrepFocus must never brick a machine, so every enforcement artifact has a
supported teardown path — and a manual escape hatch for when the binaries
are already gone.

Supported paths (both idempotent; running them twice is safe):

```bash
# Full uninstall. Tears down enforcement FIRST, then removes the binaries,
# systemd unit, launcher/autostart files, and /run/grepfocus. --purge
# additionally deletes saved blocks, the password, the HMAC secret, and
# the grepfocus group.
sudo ./packaging/uninstall.sh [--purge]

# Offline teardown without uninstalling: clears the immutable bit, strips
# the managed /etc/hosts region, removes stale atomic-write temp files,
# drops the nftables table, removes or restores the browser DoH policy
# files, and clears persisted active blocks so a later `systemctl start`
# won't re-apply them. Refuses to run while the daemon is up (its 1 s
# enforcement tick and 60 s browser-policy pass would re-apply everything
# right behind it) unless you pass --force. --purge deletes
# /var/lib/grepfocus and /etc/grepfocus; binaries, unit, and the grepfocus
# group are uninstall.sh's job.
sudo grepfocusd cleanup [--purge] [--force]
```

**Stopping or disabling the daemon does not restore browsers.** The DoH
policy files stay in place until `grepfocusd cleanup` or an uninstall
removes them, so a stopped daemon still leaves Firefox and Chromium saying
"managed by your organization" with DoH off. Downgrading to a release that
predates the policies (0.5.x) has the same effect: that daemon's `cleanup`
does not know the files, so run the manual commands below first.

If the binaries are already gone, everything GrepFocus enforces can be
undone by hand:

```bash
sudo chattr -i /etc/hosts
sudo sed -i '/# grepfocus-begin/,/# grepfocus-end/d' /etc/hosts
sudo nft delete table inet grepfocus_doh
sudo rm -f /etc/hosts.grepfocus.tmp
# Browser DoH policies. The Chromium-family files are GrepFocus's own:
sudo rm -f /etc/chromium/policies/managed/grepfocus.json \
    /var/snap/chromium/current/policies/managed/grepfocus.json \
    /etc/opt/chrome/policies/managed/grepfocus.json \
    /etc/brave/policies/managed/grepfocus.json
# The Firefox-family files are shared. Delete one only if it carries a
# top-level "grepfocus" key with "created": true (GrepFocus made it); if
# instead a recovery copy exists under /var/lib/grepfocus/policies, that is
# the pre-existing file — put it back, e.g.:
sudo install -m 644 /var/lib/grepfocus/policies/_etc_firefox_policies_policies.json.orig \
    /etc/firefox/policies/policies.json
# (the Mullvad Browser pair is /usr/lib/mullvad-browser/distribution/policies.json
# and .../_usr_lib_mullvad-browser_distribution_policies.json.orig). A file
# with the marker but "created": false and no recovery copy was merged into:
# remove its "DNSOverHTTPS" and "grepfocus" keys by hand and keep the rest.
```

`/var/lib/grepfocus/hosts.orig` is a root-only snapshot of the *unmanaged*
`/etc/hosts` content (everything outside the marker region), refreshed
before every managed edit. You normally never need it — the `sed` above
removes the managed region and leaves the rest untouched. Copy it over
`/etc/hosts` only if the file is mangled *beyond* the marker region —
with `install`, not `cp`, since the snapshot is 0600 and `/etc/hosts`
must be world-readable for the resolver in non-root processes:

```bash
sudo install -m 644 /var/lib/grepfocus/hosts.orig /etc/hosts
```

A `cmdline:` matcher broad enough to hit your desktop session (say,
`cmdline:bin`) kills it again within half a second of every login, and the
GUI cannot delete an active block. Switch to a text console (`Ctrl+Alt+F3`),
log in, then run `sudo systemctl stop grepfocusd && sudo grepfocusd cleanup`
and start the daemon again: cleanup clears the persisted active blocks, so
the block is not re-applied and the saved block can be edited or deleted
from the GUI. Root processes are never killed, so the console login itself
is safe.

## Known limits

We're honest about what we don't defend against. None of these are bypasses
that Cold Turkey beats either.

- **Determined root user.** Anyone with root can boot to recovery mode,
  unmask the unit from initrd, run `chattr -i /etc/hosts`, or load a kernel
  module. Linux gives root unrestricted power; we cannot revoke it. The
  realistic goal is friction high enough to defeat in-the-moment akrasia.
- **Live USB.** Anyone with physical access can boot a USB and edit the
  disk. Out of scope.
- **Custom DoH/DoT endpoints.** Browser policies turn DoH off at the
  source (next bullet); behind them an `nftables` table drops DoH (TCP
  443) and DNS-over-TLS (TCP/UDP 853) to known public resolver IPs during
  blocks, catching a browser that has not restarted since the policy was
  written or that has no policy at all — but unlisted or self-hosted
  endpoints are allowed by design. A system resolver doing DoT to
  `dns.mullvad.net` hits the same documented case as `1.1.1.1` below.
- **Browser DoH policies.** Covered: Firefox (rpm/deb, `/usr/lib*`,
  `/opt`, and the snap — all read `/etc/firefox/policies/policies.json`),
  Mullvad Browser (`/usr/lib/mullvad-browser/distribution/policies.json`,
  the only file it reads), Chromium (rpm/deb; the snap under
  `/var/snap/chromium/current/policies/managed` is not live-tested), Chrome
  and Brave (`/etc/opt/chrome` and `/etc/brave`, not live-tested). Not
  covered: Flatpak Firefox (reported as unsupported), Vivaldi, Edge, Opera,
  and per-user installs under `~`. The Chromium-family file is GrepFocus's
  own; Chromium applies managed files alphabetically, so a later-sorting
  admin file wins. The Firefox-family file is shared: a pre-existing one
  gets only `DNSOverHTTPS` added, its exact bytes are kept under
  `/var/lib/grepfocus/policies` and put back on cleanup or uninstall; a
  fresh `/etc` file is seeded from `distribution/policies.json`, which it
  shadows until uninstall. **DoH stays off while GrepFocus is installed,
  not only during blocks** — Mullvad Browser's DNS goes to the OS resolver
  instead of Mullvad's. A Firefox already running keeps DoH until it is
  restarted. Uninstalling a browser may warn "directory not empty" about
  its policy directory; the daemon removes the file and the empty
  directories within a minute.
- **System resolvers doing DoT to a listed IP.** The flip side of that
  table: if your system resolver does DNS-over-TLS to one of the listed
  public resolver IPs (e.g. systemd-resolved with `DNSOverTLS=yes`
  pointed at `1.1.1.1`), DNS breaks entirely during active blocks. Use
  plain DNS or an unlisted resolver. If the DoH table is ever left behind
  after a block ends, the Status tab says so and the daemon retries
  removing it.
- **Systems that forbid the immutable flag.** Where policy (e.g. SELinux)
  or the filesystem denies `chattr +i`, blocks still work — the hosts
  *content* is the enforcement — but tamper protection is degraded. The
  daemon logs a warning when this happens, the Status tab shows a yellow
  "Tamper protection off" notice and the Settings diagnostics line says
  so.
- **VPNs over IP literals.** If the user knows the IP address of a blocked
  site and types it directly, hosts-file blocking won't catch them.
- **Root processes are never killed.** App blocking skips pid 0 and 1,
  kernel threads, the daemon itself, and every process whose effective uid
  is root: system services, setuid helpers, and — the cost — an app you
  launch through `sudo` or `pkexec`. The boundary is uid 0, not the distro's
  `UID_MIN`, because a wrong boundary would silently stop blocking your own
  apps.
- **Other users' desktop processes ARE killed.** On a shared machine an app
  matcher applies to every non-root process, whoever owns it; blocks are
  not scoped to the user who started them.
- **The `www.` alias is one-directional.** Blocking `reddit.com` also blocks
  `www.reddit.com`; blocking `www.reddit.com` blocks only that name. Other
  subdomains (`old.reddit.com`) must be listed explicitly — wildcards are
  refused.
- **Uninstalling works even mid-block — by design.** A Cold Turkey-style
  uninstall lockout was considered and deliberately rejected: root is out
  of the threat model (see above), and never bricking a machine beats
  fighting root. `uninstall.sh` and `grepfocusd cleanup` tear down
  enforcement during an active block without complaint.
- **No tray icon on stock GNOME.** GNOME ships no StatusNotifier host, so
  the tray icon needs an extension such as "AppIndicator and
  KStatusNotifierItem Support". Without one, closing the window quits the
  app — enforcement is daemon-side and unaffected; minimize instead of
  closing to keep getting block start/end notifications. With one, closing
  hides to the tray; if the tray host
  vanishes while the window is hidden, the window reappears within ~5
  seconds. Launching GrepFocus again always surfaces the existing instance.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE): you may
read, audit, run, modify, and redistribute GrepFocus for any purpose **except**
providing a product that competes with it. Note this is deliberately *not* an
OSI-approved open source licence — "source available" is the accurate term.

Contributions are welcome — issues and pull requests are unaffected by the
licence being source-available rather than open source.
