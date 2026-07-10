//! Unix-socket JSON-RPC server for the GUI/CLI.
//!
//! Socket lives at /run/grepfocus/sock with mode 0660 and group `grepfocus`.
//! Membership in that group is what authorizes a user to manage blocks.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::Context;
use grepfocus_core::{
    now_unix, ActiveBlock, AllowanceLedger, Originator, Request, Response, Schedule, State,
};
use nix::unistd::Group;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::{auth, enforce, paths, scheduler, state, Daemon};

/// How long an `Unlock` keeps configuration changes permitted.
const UNLOCK_SECS: u64 = 300;

/// Group whose members are authorized to talk to the socket.
pub(crate) const GROUP: &str = "grepfocus";

pub async fn serve(daemon: Arc<Daemon>) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(paths::SOCK);
    let listener = UnixListener::bind(paths::SOCK).context("binding socket")?;
    apply_socket_perms(paths::SOCK)?;
    info!(path = paths::SOCK, "listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let d = daemon.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, d).await {
                        warn!(?e, "client error");
                    }
                });
            }
            Err(e) => {
                error!(?e, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

fn apply_socket_perms(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::chown;
    let gid = match Group::from_name(GROUP)? {
        Some(g) => Some(g.gid.as_raw()),
        None => {
            warn!("group `{GROUP}` not found — socket will be root-only");
            None
        }
    };
    chown(path, None, gid).context("chown socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(())
}

async fn handle(mut stream: UnixStream, daemon: Arc<Daemon>) -> anyhow::Result<()> {
    loop {
        let req: Request = match grepfocus_core::wire::read_json(&mut stream).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let resp = dispatch(req, &daemon).await;
        if let Err(e) = grepfocus_core::wire::write_json(&mut stream, &resp).await {
            if e.kind() == std::io::ErrorKind::InvalidData {
                // The response was too large (or unserializable) to frame.
                // write_json serializes and size-checks before writing any
                // bytes, so the stream is still intact — report a small error
                // and keep the connection open instead of dropping it.
                warn!(?e, "response could not be framed; sending error instead");
                grepfocus_core::wire::write_json(&mut stream, &err("response too large")).await?;
            } else {
                return Err(e.into());
            }
        }
    }
}

async fn dispatch(req: Request, daemon: &Arc<Daemon>) -> Response {
    match req {
        Request::ListBlocks {} => {
            let st = daemon.state.lock().await;
            Response::Blocks {
                blocks: st.blocks.clone(),
            }
        }

        Request::GetStatus {} => {
            let st = daemon.state.lock().await;
            let now = now_unix();
            let password_set = st.password_hash.is_some();
            let unlocked = !password_set || *daemon.unlocked_until.lock().await >= now;
            let today = scheduler::local_day();
            let active_ids: std::collections::HashSet<u64> =
                st.active.iter().map(|a| a.block.id).collect();
            let allowance_used: Vec<AllowanceLedger> = st
                .allowance
                .iter()
                .filter(|l| l.day == today && active_ids.contains(&l.block_id))
                .cloned()
                .collect();
            Response::Status {
                active: st.active.clone(),
                now_unix: now,
                password_set,
                unlocked,
                allowance_used,
            }
        }

        Request::AddBlock { mut block } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            let prev_blocks = st.blocks.clone();
            let prev_next_id = st.next_id;
            block.id = st.next_id;
            st.next_id += 1;
            let id = block.id;
            st.blocks.push(block);
            if let Err(e) = state::save(&st, &daemon.key) {
                st.blocks = prev_blocks;
                st.next_id = prev_next_id;
                return err(format!("save failed: {e}"));
            }
            Response::Added { id }
        }

        Request::UpdateBlock { block } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            if st.active.iter().any(|a| a.block.id == block.id) {
                return err("cannot edit a block while it is active");
            }
            let prev_blocks = st.blocks.clone();
            match st.blocks.iter_mut().find(|b| b.id == block.id) {
                Some(slot) => *slot = block,
                None => return err(format!("no block with id {}", block.id)),
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                st.blocks = prev_blocks;
                return err(format!("save failed: {e}"));
            }
            Response::Ok {}
        }

        Request::DeleteBlock { id } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            if st.active.iter().any(|a| a.block.id == id) {
                return err("cannot delete a block while it is active");
            }
            if st.schedules.iter().any(|s| s.block_id == id) {
                return err("cannot delete a block referenced by a schedule");
            }
            let prev_blocks = st.blocks.clone();
            let before = st.blocks.len();
            st.blocks.retain(|b| b.id != id);
            if st.blocks.len() == before {
                return err(format!("no block with id {id}"));
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                st.blocks = prev_blocks;
                return err(format!("save failed: {e}"));
            }
            Response::Ok {}
        }

        Request::StartBlock { id, duration_secs } => {
            {
                let mut st = daemon.state.lock().await;
                if st.active.iter().any(|a| a.block.id == id) {
                    return err(format!("block {id} is already active"));
                }
                let block = match st.blocks.iter().find(|b| b.id == id) {
                    Some(b) => b.clone(),
                    None => return err(format!("no block with id {id}")),
                };
                let now = now_unix();
                st.active.push(ActiveBlock {
                    block,
                    started_at_unix: now,
                    ends_at_unix: now.saturating_add(duration_secs),
                    originator: Originator::Manual,
                    break_until_unix: None,
                });
                if let Err(e) = state::save(&st, &daemon.key) {
                    st.active.pop();
                    return err(format!("save failed: {e}"));
                }
            }
            if let Err(e) = enforce::sync(daemon).await {
                error!(?e, "failed to apply enforcement after start_block");
                return err(format!(
                    "block started, but enforcement failed to apply (will retry): {e}"
                ));
            }
            info!(id, duration_secs, "block started (manual)");
            Response::Ok {}
        }

        Request::CancelBlock {} => {
            // Strict mode: never cancellable while anything is active.
            let st = daemon.state.lock().await;
            if !st.active.is_empty() {
                err("active blocks cannot be cancelled (strict mode)")
            } else {
                Response::Ok {}
            }
        }

        Request::TakeBreak { block_id, secs } => {
            let now = now_unix();
            let today = scheduler::local_day();
            {
                let mut st = daemon.state.lock().await;

                let (allowance, ends_at) = match st.active.iter().find(|a| a.block.id == block_id) {
                    Some(a) => {
                        if a.break_until_unix.is_some_and(|t| t > now) {
                            return err("this block is already on a break");
                        }
                        (a.block.allowance_secs_per_day, a.ends_at_unix)
                    }
                    None => return err(format!("block {block_id} is not active")),
                };

                // How much has already been spent today on this block.
                let used: u64 = st
                    .allowance
                    .iter()
                    .filter(|l| l.block_id == block_id && l.day == today)
                    .map(|l| l.used_secs)
                    .sum();
                let grant = match compute_grant(allowance, used, ends_at, now, secs) {
                    Ok(g) => g,
                    Err(msg) => return err(msg),
                };

                // Mutate break state + ledger, keeping enough to roll back if
                // the save fails. Every active entry for the block is flagged
                // so a duplicate entry (however it arose) can't keep enforcing.
                let prev_ledger = st.allowance.clone();
                for a in st.active.iter_mut().filter(|a| a.block.id == block_id) {
                    a.break_until_unix = Some(now + grant);
                }
                record_break(&mut st.allowance, block_id, today, grant);

                if let Err(e) = state::save(&st, &daemon.key) {
                    for a in st.active.iter_mut().filter(|a| a.block.id == block_id) {
                        a.break_until_unix = None;
                    }
                    st.allowance = prev_ledger;
                    return err(format!("save failed: {e}"));
                }
                info!(block_id, grant, "break started");
            }
            if let Err(e) = enforce::sync(daemon).await {
                error!(?e, "failed to lift enforcement after take_break");
                return err(format!(
                    "break recorded, but lifting enforcement failed (will retry): {e}"
                ));
            }
            Response::Ok {}
        }

        Request::AddSchedule { mut schedule } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            if !st.blocks.iter().any(|b| b.id == schedule.block_id) {
                return err(format!("no block with id {}", schedule.block_id));
            }
            if let Some(msg) = validate_schedule(&schedule) {
                return err(msg);
            }
            if st
                .schedules
                .iter()
                .any(|s| schedules_equivalent(s, &schedule))
            {
                return err("an identical schedule already exists");
            }
            let prev_schedules = st.schedules.clone();
            let prev_next = st.next_schedule_id;
            schedule.id = st.next_schedule_id;
            st.next_schedule_id += 1;
            let id = schedule.id;
            st.schedules.push(schedule);
            if let Err(e) = state::save(&st, &daemon.key) {
                st.schedules = prev_schedules;
                st.next_schedule_id = prev_next;
                return err(format!("save failed: {e}"));
            }
            Response::Added { id }
        }

        Request::UpdateSchedule { schedule } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            if !st.blocks.iter().any(|b| b.id == schedule.block_id) {
                return err(format!("no block with id {}", schedule.block_id));
            }
            if let Some(msg) = validate_schedule(&schedule) {
                return err(msg);
            }
            if st
                .schedules
                .iter()
                .any(|s| s.id != schedule.id && schedules_equivalent(s, &schedule))
            {
                return err("an identical schedule already exists");
            }
            let prev_schedules = st.schedules.clone();
            match st.schedules.iter_mut().find(|s| s.id == schedule.id) {
                Some(slot) => *slot = schedule,
                None => return err(format!("no schedule with id {}", schedule.id)),
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                st.schedules = prev_schedules;
                return err(format!("save failed: {e}"));
            }
            Response::Ok {}
        }

        Request::DeleteSchedule { id } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            let prev_schedules = st.schedules.clone();
            let before = st.schedules.len();
            st.schedules.retain(|s| s.id != id);
            if st.schedules.len() == before {
                return err(format!("no schedule with id {id}"));
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                st.schedules = prev_schedules;
                return err(format!("save failed: {e}"));
            }
            Response::Ok {}
        }

        Request::ListSchedules {} => {
            let st = daemon.state.lock().await;
            Response::Schedules {
                schedules: st.schedules.clone(),
            }
        }

        Request::Unlock { password } => {
            // Snapshot the stored hash, then release the state lock before the
            // CPU-heavy Argon2 verify so the scheduler, procwatch, and other
            // IPC clients aren't stalled for the hash duration.
            let phc = {
                let st = daemon.state.lock().await;
                match &st.password_hash {
                    None => return Response::Ok {}, // nothing to unlock
                    Some(phc) => phc.clone(),
                }
            };
            let ok = match tokio::task::spawn_blocking(move || auth::verify(&password, &phc)).await
            {
                Ok(ok) => ok,
                Err(e) => return err(format!("verify task failed: {e}")),
            };
            if ok {
                *daemon.unlocked_until.lock().await = now_unix() + UNLOCK_SECS;
                info!("settings unlocked");
                Response::Ok {}
            } else {
                err("incorrect password")
            }
        }

        Request::SetPassword { old, new } => {
            // Snapshot the current hash and unlock state, then do all Argon2
            // work (verify old + hash new) off the state lock so the scheduler,
            // procwatch, and other IPC clients keep running during the hash.
            let snapshot = daemon.state.lock().await.password_hash.clone();
            let unlocked = *daemon.unlocked_until.lock().await >= now_unix();

            let snap_for_task = snapshot.clone();
            let task = tokio::task::spawn_blocking(move || {
                // Changing or clearing an existing password requires proof:
                // either the old password, or a currently-active unlock window.
                if let Some(phc) = &snap_for_task {
                    let old_ok = old.as_deref().is_some_and(|o| auth::verify(o, phc));
                    if !old_ok && !unlocked {
                        return Err("current password required to change it".to_string());
                    }
                }
                match new.as_deref() {
                    Some("") => Err("new password cannot be empty".to_string()),
                    Some(p) => auth::hash(p)
                        .map(Some)
                        .map_err(|e| format!("hashing failed: {e}")),
                    None => Ok(None),
                }
            })
            .await;
            let new_hash = match task {
                Ok(Ok(h)) => h,
                Ok(Err(msg)) => return err(msg),
                Err(e) => return err(format!("password task failed: {e}")),
            };
            let cleared = new_hash.is_none();

            // Re-acquire the lock and guard against a concurrent password change
            // during the hash: if the stored hash moved, the caller's decision
            // was based on stale state, so make them retry.
            let mut st = daemon.state.lock().await;
            if st.password_hash != snapshot {
                return err("password changed concurrently; please retry");
            }
            let prev = std::mem::replace(&mut st.password_hash, new_hash);
            if let Err(e) = state::save(&st, &daemon.key) {
                // Roll back so we never end up requiring a password the user
                // was just told failed to apply.
                st.password_hash = prev;
                return err(format!("save failed: {e}"));
            }
            drop(st);
            // Opening an unlock window after a change lets the user keep editing
            // without an immediate re-prompt; after a clear it is harmless.
            *daemon.unlocked_until.lock().await = now_unix() + UNLOCK_SECS;
            info!(cleared, "settings password updated");
            Response::Ok {}
        }
    }
}

/// Returns `Some(error)` when a settings password is set and no unlock window
/// is currently active — used to gate configuration-changing requests.
async fn gate_config(daemon: &Arc<Daemon>, st: &State) -> Option<Response> {
    st.password_hash.as_ref()?; // no password set → nothing to gate
    if *daemon.unlocked_until.lock().await >= now_unix() {
        None
    } else {
        Some(err(
            "settings are locked — unlock with your password to change configuration",
        ))
    }
}

fn err(message: impl Into<String>) -> Response {
    Response::Error {
        message: message.into(),
    }
}

/// Two schedules are "the same" if they drive the same block over the same
/// days and time window. Names may differ — only the effect matters.
fn schedules_equivalent(a: &Schedule, b: &Schedule) -> bool {
    a.block_id == b.block_id
        && a.days == b.days
        && a.start_minute == b.start_minute
        && a.duration_minutes == b.duration_minutes
}

fn validate_schedule(s: &Schedule) -> Option<String> {
    if s.name.trim().is_empty() {
        return Some("schedule name cannot be empty".into());
    }
    if s.days == 0 {
        return Some("at least one weekday must be selected".into());
    }
    if s.days & !grepfocus_core::DAYS_ALL != 0 {
        return Some("days bitmask has unknown bits set".into());
    }
    if s.start_minute >= 1440 {
        return Some("start_minute must be 0..1440".into());
    }
    if s.duration_minutes == 0 {
        return Some("duration_minutes must be >= 1".into());
    }
    if s.start_minute as u32 + s.duration_minutes as u32 > 1440 {
        return Some("schedule cannot span midnight; split into two schedules instead".into());
    }
    None
}

/// Compute the grantable break length (seconds) for a TakeBreak request, capped
/// by both the remaining daily allowance and the block's remaining time. Pure,
/// so the accounting can be unit-tested without a live daemon.
///
/// Returns a user-facing error string when: no allowance is configured, the
/// allowance is exhausted for today, the block has already ended, or the
/// computed grant is zero.
fn compute_grant(
    allowance: u64,
    used_today: u64,
    ends_at: u64,
    now: u64,
    requested: u64,
) -> Result<u64, &'static str> {
    if allowance == 0 {
        return Err("this block has no break allowance");
    }
    let remaining = allowance.saturating_sub(used_today);
    if remaining == 0 {
        return Err("no break allowance left today");
    }
    // A break can never outlive the block, so never charge for time past its end.
    if ends_at <= now {
        return Err("this block has already ended");
    }
    let grant = requested.min(remaining).min(ends_at - now);
    if grant == 0 {
        return Err("break length must be at least 1 second");
    }
    Ok(grant)
}

/// Record `grant` seconds of break against `block_id` for `today`, first
/// dropping ledger rows from other days (the daily allowance reset).
fn record_break(ledger: &mut Vec<AllowanceLedger>, block_id: u64, today: i64, grant: u64) {
    ledger.retain(|l| l.day == today);
    match ledger
        .iter_mut()
        .find(|l| l.block_id == block_id && l.day == today)
    {
        Some(l) => l.used_secs += grant,
        None => ledger.push(AllowanceLedger {
            block_id,
            day: today,
            used_secs: grant,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_errors_without_allowance() {
        assert_eq!(
            compute_grant(0, 0, 2000, 1000, 60),
            Err("this block has no break allowance")
        );
    }

    #[test]
    fn grant_errors_when_exhausted() {
        assert_eq!(
            compute_grant(600, 600, 2000, 1000, 60),
            Err("no break allowance left today")
        );
        // Saturating: used beyond allowance still reads as exhausted.
        assert_eq!(
            compute_grant(600, 700, 2000, 1000, 60),
            Err("no break allowance left today")
        );
    }

    #[test]
    fn grant_errors_when_block_ended() {
        assert_eq!(
            compute_grant(600, 0, 1000, 1000, 60),
            Err("this block has already ended")
        );
        assert_eq!(
            compute_grant(600, 0, 999, 1000, 60),
            Err("this block has already ended")
        );
    }

    #[test]
    fn grant_errors_on_zero_request() {
        assert_eq!(
            compute_grant(600, 0, 2000, 1000, 0),
            Err("break length must be at least 1 second")
        );
    }

    #[test]
    fn grant_capped_by_remaining_allowance() {
        // remaining = 600 - 590 = 10; block time is ample.
        assert_eq!(compute_grant(600, 590, 1_000_000, 1000, 100), Ok(10));
    }

    #[test]
    fn grant_capped_by_remaining_block_time() {
        // block ends in 5s; allowance is ample.
        assert_eq!(compute_grant(600, 0, 1005, 1000, 100), Ok(5));
    }

    #[test]
    fn grant_uses_request_when_smallest() {
        assert_eq!(compute_grant(600, 0, 1_000_000, 1000, 30), Ok(30));
    }

    #[test]
    fn record_break_adds_new_row() {
        let mut ledger = vec![];
        record_break(&mut ledger, 7, 42, 60);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].block_id, 7);
        assert_eq!(ledger[0].day, 42);
        assert_eq!(ledger[0].used_secs, 60);
    }

    #[test]
    fn record_break_increments_existing_row() {
        let mut ledger = vec![AllowanceLedger {
            block_id: 7,
            day: 42,
            used_secs: 60,
        }];
        record_break(&mut ledger, 7, 42, 30);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].used_secs, 90);
    }

    #[test]
    fn record_break_prunes_other_days_keeps_other_blocks() {
        let mut ledger = vec![
            // yesterday → pruned
            AllowanceLedger {
                block_id: 7,
                day: 41,
                used_secs: 60,
            },
            // today, different block → kept
            AllowanceLedger {
                block_id: 9,
                day: 42,
                used_secs: 15,
            },
        ];
        record_break(&mut ledger, 7, 42, 30);
        assert_eq!(ledger.len(), 2);
        assert!(ledger
            .iter()
            .any(|l| l.block_id == 9 && l.day == 42 && l.used_secs == 15));
        assert!(ledger
            .iter()
            .any(|l| l.block_id == 7 && l.day == 42 && l.used_secs == 30));
        assert!(!ledger.iter().any(|l| l.day == 41));
    }
}
