//! Unix-socket JSON-RPC server for the GUI/CLI.
//!
//! Socket lives at /run/frostbite/sock with mode 0660 and group `frostbite`.
//! Membership in that group is what authorizes a user to manage blocks.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::Context;
use frostbite_core::{now_unix, ActiveBlock, Request, Response};
use nix::unistd::Group;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::{hosts, paths, state, Daemon};

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
                return Response::Error {
                    message: format!("save failed: {e}"),
                };
            }
            Response::Added { id }
        }
        Request::UpdateBlock { block } => {
            let mut st = daemon.state.lock().await;
            if st.active.is_some() {
                return Response::Error {
                    message: "cannot edit blocks while a block is active".into(),
                };
            }
            match st.blocks.iter_mut().find(|b| b.id == block.id) {
                Some(slot) => *slot = block,
                None => {
                    return Response::Error {
                        message: format!("no block with id {}", block.id),
                    }
                }
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                return Response::Error {
                    message: format!("save failed: {e}"),
                };
            }
            Response::Ok {}
        }
        Request::DeleteBlock { id } => {
            let mut st = daemon.state.lock().await;
            if st.active.as_ref().map(|a| a.block.id) == Some(id) {
                return Response::Error {
                    message: "cannot delete the currently active block".into(),
                };
            }
            let before = st.blocks.len();
            st.blocks.retain(|b| b.id != id);
            if st.blocks.len() == before {
                return Response::Error {
                    message: format!("no block with id {id}"),
                };
            }
            if let Err(e) = state::save(&st, &daemon.key) {
                return Response::Error {
                    message: format!("save failed: {e}"),
                };
            }
            Response::Ok {}
        }
        Request::StartBlock { id, duration_secs } => {
            let mut st = daemon.state.lock().await;
            if st.active.is_some() {
                return Response::Error {
                    message: "a block is already active".into(),
                };
            }
            let block = match st.blocks.iter().find(|b| b.id == id) {
                Some(b) => b.clone(),
                None => {
                    return Response::Error {
                        message: format!("no block with id {id}"),
                    }
                }
            };
            let now = now_unix();
            let active = ActiveBlock {
                block: block.clone(),
                started_at_unix: now,
                ends_at_unix: now + duration_secs,
            };
            st.active = Some(active);
            if let Err(e) = state::save(&st, &daemon.key) {
                st.active = None;
                return Response::Error {
                    message: format!("save failed: {e}"),
                };
            }
            drop(st);
            if let Err(e) = hosts::apply_block(&block.domains) {
                error!(?e, "failed to apply hosts block");
                return Response::Error {
                    message: format!("apply failed: {e}"),
                };
            }
            info!(id, duration_secs, "block started");
            Response::Ok {}
        }
        Request::CancelBlock {} => {
            // Strict mode: never cancellable while active.
            let st = daemon.state.lock().await;
            if st.active.is_some() {
                Response::Error {
                    message: "active blocks cannot be cancelled (strict mode)".into(),
                }
            } else {
                Response::Ok {}
            }
        }
    }
}

