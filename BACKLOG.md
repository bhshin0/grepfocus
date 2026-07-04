# Known issues / backlog

Low-severity findings from the 2026-07-04 adversarial code review, deferred
deliberately. Each was independently verified as real. File:line references
are as of commit `77a2e92` (pre-fix-wave; may have shifted since).

## Daemon

- **Gated config arms mutate before save without rollback** —
  `crates/daemon/src/ipc.rs` (AddBlock/UpdateBlock/DeleteBlock/AddSchedule/
  UpdateSchedule/DeleteSchedule). On `state::save` failure the in-memory
  mutation survives while disk keeps the old state; a later unrelated save
  silently commits it. StartBlock/TakeBreak/SetPassword now roll back — apply
  the same snapshot-and-restore pattern to the six config arms.
- **Argon2 runs synchronously under the state mutex** —
  `crates/daemon/src/ipc.rs` (Unlock/SetPassword). Each verify/hash stalls the
  scheduler tick, procwatch, and all IPC for the hash duration. Fix: clone the
  PHC string, drop the lock, run verify in `tokio::task::spawn_blocking`.
- **Responses can exceed MAX_FRAME (1 MiB)** — `crates/core/src/wire.rs`.
  A very large block list makes `write_json` fail and drops the connection
  with no Response; the GUI sees only "read: eof". Fix: raise the limit for
  responses or return a proper error before serializing.
- **Crash window between the two renames in `state::save`** —
  `crates/daemon/src/state.rs`. If the daemon dies after `state.json` is
  renamed but before `state.json.mac`, the next startup treats state as
  corrupted and starts fresh (wiping blocks/schedules/password). Fix: write a
  single file containing payload+MAC, or fsync+rename in one step.
- **TakeBreak residual: persistent enforce failure keeps the ledger charge** —
  `crates/daemon/src/ipc.rs`. Save-path rollback and retrying `enforce::sync`
  (scheduler self-heal) are in place, so this now only matters if applies fail
  persistently for the whole break. Fix would be refunding the ledger when a
  break never took effect; probably not worth it.

## GUI

- **Concurrent `ensureUnlocked()` calls clobber `unlockResolver`** —
  `crates/gui/ui/src/main.ts`. Two gated actions racing each other leak the
  first promise (its action silently never runs). Fix: queue prompts or share
  one in-flight promise.
- **Stale tray tooltip while the daemon is down** —
  `crates/gui/src/main.rs` (status watcher `continue` on poll failure). The
  tooltip keeps reporting the last-known "N active". Fix: set a
  "daemon unreachable" tooltip on poll failure.
