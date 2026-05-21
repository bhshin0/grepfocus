//! Unix-socket JSON-RPC server for the GUI/CLI.
//!
//! Socket lives at /run/frostbite/sock with mode 0660 and group `frostbite`.
//! Membership in that group is what authorizes a user to manage blocks.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::Context;
use frostbite_core::{
    now_unix, ActiveBlock, Originator, Request, Response, Schedule,
};
use nix::unistd::Group;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::{enforce, paths, state, Daemon};

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
            Response::Status {
                active: st.active.clone(),
                now_unix: now_unix(),
            }
        }

        Request::AddBlock { mut block } => {
            let mut st = daemon.state.lock().await;
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
                });
                if let Err(e) = state::save(&st, &daemon.key) {
                    st.active.pop();
                    return err(format!("save failed: {e}"));
                }
                enforce::union_domains(&st.active)
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

        Request::AddSchedule { mut schedule } => {
            let mut st = daemon.state.lock().await;
            if !st.blocks.iter().any(|b| b.id == schedule.block_id) {
                return err(format!("no block with id {}", schedule.block_id));
            }
            if let Some(msg) = validate_schedule(&schedule) {
                return err(msg);
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
            if !st.blocks.iter().any(|b| b.id == schedule.block_id) {
                return err(format!("no block with id {}", schedule.block_id));
            }
            if let Some(msg) = validate_schedule(&schedule) {
                return err(msg);
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
    }
}

fn err(message: impl Into<String>) -> Response {
    Response::Error {
        message: message.into(),
    }
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
