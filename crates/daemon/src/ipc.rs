//! Unix-socket JSON-RPC server for the GUI/CLI.
//!
//! Socket lives at /run/frostbite/sock with mode 0660 and group `frostbite`.
//! Membership in that group is what authorizes a user to manage blocks.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::Context;
use frostbite_core::{
    now_unix, ActiveBlock, AllowanceLedger, Originator, Request, Response, Schedule, State,
};
use nix::unistd::Group;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::{auth, enforce, paths, scheduler, state, Daemon};

/// How long an `Unlock` keeps configuration changes permitted.
const UNLOCK_SECS: u64 = 300;

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
    let gid = match Group::from_name("frostbite")? {
        Some(g) => Some(g.gid.as_raw()),
        None => {
            warn!("group `frostbite` not found — socket will be root-only");
            None
        }
    };
    chown(path, None, gid).context("chown socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(())
}

async fn handle(mut stream: UnixStream, daemon: Arc<Daemon>) -> anyhow::Result<()> {
    loop {
        let req: Request = match frostbite_core::wire::read_json(&mut stream).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let resp = dispatch(req, &daemon).await;
        frostbite_core::wire::write_json(&mut stream, &resp).await?;
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
            block.id = st.next_id;
            st.next_id += 1;
            let id = block.id;
            st.blocks.push(block);
            if let Err(e) = state::save(&st, &daemon.key) {
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
            match st.blocks.iter_mut().find(|b| b.id == block.id) {
                Some(slot) => *slot = block,
                None => return err(format!("no block with id {}", block.id)),
            }
            if let Err(e) = state::save(&st, &daemon.key) {
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
            let before = st.blocks.len();
            st.blocks.retain(|b| b.id != id);
            if st.blocks.len() == before {
                return err(format!("no block with id {id}"));
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                return err(format!("save failed: {e}"));
            }
            Response::Ok {}
        }

        Request::StartBlock { id, duration_secs } => {
            let domains = {
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
                    ends_at_unix: now + duration_secs,
                    originator: Originator::Manual,
                    break_until_unix: None,
                });
                if let Err(e) = state::save(&st, &daemon.key) {
                    st.active.pop();
                    return err(format!("save failed: {e}"));
                }
                enforce::union_domains(&st.active, now)
            };
            if let Err(e) = enforce::apply(&domains) {
                error!(?e, "failed to apply hosts after start_block");
                return err(format!("apply failed: {e}"));
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
            let domains = {
                let mut st = daemon.state.lock().await;

                let allowance = match st.active.iter().find(|a| a.block.id == block_id) {
                    Some(a) => a.block.allowance_secs_per_day,
                    None => return err(format!("block {block_id} is not active")),
                };
                if allowance == 0 {
                    return err("this block has no break allowance");
                }

                // How much has already been spent today on this block.
                let used: u64 = st
                    .allowance
                    .iter()
                    .filter(|l| l.block_id == block_id && l.day == today)
                    .map(|l| l.used_secs)
                    .sum();
                let remaining = allowance.saturating_sub(used);
                if remaining == 0 {
                    return err("no break allowance left today");
                }
                let grant = secs.min(remaining);
                if grant == 0 {
                    return err("break length must be at least 1 second");
                }

                // Apply the break to the active block.
                if let Some(a) = st.active.iter_mut().find(|a| a.block.id == block_id) {
                    a.break_until_unix = Some(now + grant);
                }

                // Record consumption; drop stale (other-day) entries.
                st.allowance.retain(|l| l.day == today);
                match st
                    .allowance
                    .iter_mut()
                    .find(|l| l.block_id == block_id && l.day == today)
                {
                    Some(l) => l.used_secs += grant,
                    None => st.allowance.push(AllowanceLedger {
                        block_id,
                        day: today,
                        used_secs: grant,
                    }),
                }

                if let Err(e) = state::save(&st, &daemon.key) {
                    return err(format!("save failed: {e}"));
                }
                info!(block_id, grant, "break started");
                enforce::union_domains(&st.active, now)
            };
            if let Err(e) = enforce::apply(&domains) {
                error!(?e, "failed to apply hosts after take_break");
                return err(format!("apply failed: {e}"));
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
            if st.schedules.iter().any(|s| schedules_equivalent(s, &schedule)) {
                return err("an identical schedule already exists");
            }
            schedule.id = st.next_schedule_id;
            st.next_schedule_id += 1;
            let id = schedule.id;
            st.schedules.push(schedule);
            if let Err(e) = state::save(&st, &daemon.key) {
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
            match st.schedules.iter_mut().find(|s| s.id == schedule.id) {
                Some(slot) => *slot = schedule,
                None => return err(format!("no schedule with id {}", schedule.id)),
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                return err(format!("save failed: {e}"));
            }
            Response::Ok {}
        }

        Request::DeleteSchedule { id } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            let before = st.schedules.len();
            st.schedules.retain(|s| s.id != id);
            if st.schedules.len() == before {
                return err(format!("no schedule with id {id}"));
            }
            if let Err(e) = state::save(&st, &daemon.key) {
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
            let st = daemon.state.lock().await;
            match &st.password_hash {
                None => Response::Ok {}, // nothing to unlock
                Some(phc) => {
                    let ok = auth::verify(&password, phc);
                    drop(st);
                    if ok {
                        *daemon.unlocked_until.lock().await = now_unix() + UNLOCK_SECS;
                        info!("settings unlocked");
                        Response::Ok {}
                    } else {
                        err("incorrect password")
                    }
                }
            }
        }

        Request::SetPassword { old, new } => {
            let mut st = daemon.state.lock().await;
            // Changing or clearing an existing password requires proof: either
            // the old password, or a currently-active unlock window.
            if let Some(phc) = &st.password_hash {
                let unlocked = *daemon.unlocked_until.lock().await >= now_unix();
                let old_ok = old.as_deref().is_some_and(|o| auth::verify(o, phc));
                if !old_ok && !unlocked {
                    return err("current password required to change it");
                }
            }
            let new_hash = match new.as_deref() {
                Some("") => return err("new password cannot be empty"),
                Some(p) => match auth::hash(p) {
                    Ok(h) => Some(h),
                    Err(e) => return err(format!("hashing failed: {e}")),
                },
                None => None,
            };
            let cleared = new_hash.is_none();
            st.password_hash = new_hash;
            if let Err(e) = state::save(&st, &daemon.key) {
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
    if st.password_hash.is_none() {
        return None;
    }
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
    if s.days & !frostbite_core::DAYS_ALL != 0 {
        return Some("days bitmask has unknown bits set".into());
    }
    if s.start_minute >= 1440 {
        return Some("start_minute must be 0..1440".into());
    }
    if s.duration_minutes == 0 {
        return Some("duration_minutes must be >= 1".into());
    }
    if s.start_minute as u32 + s.duration_minutes as u32 > 1440 {
        return Some(
            "schedule cannot span midnight; split into two schedules instead".into(),
        );
    }
    None
}
