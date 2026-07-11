//! Unix-socket JSON-RPC server for the GUI/CLI.
//!
//! Socket lives at /run/grepfocus/sock with mode 0660 and group `grepfocus`.
//! Membership in that group is what authorizes a user to manage blocks.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::Context;
use grepfocus_core::license::{self, LicenseClaims};
use grepfocus_core::{
    now_unix, ActiveBlock, AllowanceLedger, AppMatcher, Originator, Request, Response, Schedule,
    State,
};
use nix::unistd::Group;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::{auth, effective_now, enforce, has_feature, paths, scheduler, state, Daemon};

/// How long an `Unlock` keeps configuration changes permitted.
const UNLOCK_SECS: u64 = 300;

// Verbatim premium-gate copy from the approved plan: actionable (says what to
// do about it), no nagging. Do not reword without going back through the plan.
const MSG_BLOCK_CAP: &str = "Saving more than one block is a premium feature. \
     Enter a license key in Settings, or get one from the GrepFocus store.";
const MSG_APP_BLOCKING: &str = "App blocking is a premium feature. \
     Enter a license key in Settings, or get one from the GrepFocus store.";
const MSG_SCHEDULES: &str = "Schedules are a premium feature. \
     Enter a license key in Settings, or get one from the GrepFocus store.";

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
            let cached = daemon.license.lock().await;
            let lic = license_status_fields(
                cached.as_ref(),
                st.license_token.is_some(),
                effective_now(&st),
            );
            drop(cached);
            Response::Status {
                active: st.active.clone(),
                now_unix: now,
                password_set,
                unlocked,
                allowance_used,
                license_present: lic.present,
                license_valid: lic.valid,
                license_kind: lic.kind,
                license_email: lic.email,
                license_expires_at: lic.expires_at,
                licensed_features: lic.features,
            }
        }

        Request::AddBlock { mut block } => {
            let mut st = daemon.state.lock().await;
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            {
                let lic = daemon.license.lock().await;
                if let Some(msg) = gate_add_block(
                    has_feature(lic.as_ref(), &st, license::features::UNLIMITED_BLOCKS),
                    has_feature(lic.as_ref(), &st, license::features::APP_BLOCKING),
                    st.blocks.len(),
                    &block.apps,
                ) {
                    return err(msg);
                }
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
            // License gate for the app list, against the SAVED block (see
            // update_needs_app_license for the grandfathering rationale:
            // editing e.g. the domains of a premium-era block after a
            // downgrade must not brick the block).
            {
                let saved = match st.blocks.iter().find(|b| b.id == block.id) {
                    Some(b) => b,
                    None => return err(format!("no block with id {}", block.id)),
                };
                if update_needs_app_license(&saved.apps, &block.apps) {
                    let lic = daemon.license.lock().await;
                    if !has_feature(lic.as_ref(), &st, license::features::APP_BLOCKING) {
                        return err(MSG_APP_BLOCKING);
                    }
                }
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

        // Deliberately UNGATED by license: saved blocks always stay startable,
        // even after a downgrade (downgrade deletes nothing and blocks nothing
        // the user already configured).
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
                // Snapshot app enforcement at activation: a license change
                // while the block runs — either direction — must not alter it.
                let apps_enforced = {
                    let lic = daemon.license.lock().await;
                    has_feature(lic.as_ref(), &st, license::features::APP_BLOCKING)
                };
                let now = now_unix();
                st.active.push(ActiveBlock {
                    block,
                    started_at_unix: now,
                    ends_at_unix: now.saturating_add(duration_secs),
                    originator: Originator::Manual,
                    break_until_unix: None,
                    apps_enforced,
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
            {
                let lic = daemon.license.lock().await;
                if !has_feature(lic.as_ref(), &st, license::features::SCHEDULES) {
                    return err(MSG_SCHEDULES);
                }
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
            {
                let lic = daemon.license.lock().await;
                if !has_feature(lic.as_ref(), &st, license::features::SCHEDULES) {
                    return err(MSG_SCHEDULES);
                }
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

        // No license gate: removing configuration is always allowed.
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

        Request::SetLicense { token } => {
            let mut st = daemon.state.lock().await;
            // Gate FIRST, exactly like SetPassword: installing AND clearing a
            // license obey the password/unlock discipline. Without this,
            // clearing the license mid-block would be a self-service
            // downgrade lever — drop back to the free tier to loosen the
            // very limits the user password-locked themselves into.
            if let Some(resp) = gate_config(daemon, &st).await {
                return resp;
            }
            // Verify BEFORE storing: an unverifiable token is rejected
            // outright and nothing changes.
            let new_claims = match &token {
                Some(t) => match license::verify_token(t, effective_now(&st)) {
                    Ok(claims) => Some(claims),
                    Err(e) => return err(e.to_string()),
                },
                None => None,
            };
            let installed = new_claims.is_some();
            let prev = std::mem::replace(&mut st.license_token, token);
            if let Err(e) = state::save(&st, &daemon.key) {
                st.license_token = prev;
                return err(format!("save failed: {e}"));
            }
            *daemon.license.lock().await = new_claims;
            info!(installed, "license updated");
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

/// The license-related fields of a `Status` response. Mirrors the
/// `license_*` fields on `Response::Status`; kept as a named struct so the
/// derivation below stays a pure, unit-testable function.
struct LicenseStatus {
    present: bool,
    valid: bool,
    kind: Option<String>,
    email: Option<String>,
    expires_at: Option<i64>,
    features: Vec<String>,
}

/// Derive the license fields for a `Status` response from the daemon's
/// cached claims (verified at startup or `SetLicense`).
///
/// Validity re-checks expiry against `now` (the caller passes
/// `effective_now`), so a trial that lapses while the daemon is running
/// reports invalid without a restart. `kind`/`email`/`expires_at` are
/// reported whenever claims exist — even expired — so the GUI can render
/// "trial expired" from `present && !valid` plus `expires_at`. `features`
/// is only populated while valid: it drives gating display.
fn license_status_fields(
    claims: Option<&LicenseClaims>,
    token_present: bool,
    now: i64,
) -> LicenseStatus {
    let valid = claims.is_some_and(|c| c.expires_at.is_none_or(|t| t >= now));
    LicenseStatus {
        present: token_present,
        valid,
        kind: claims.map(|c| c.kind.clone()),
        email: claims.map(|c| c.email.clone()),
        expires_at: claims.and_then(|c| c.expires_at),
        features: match claims {
            Some(c) if valid => c.features.clone(),
            _ => Vec::new(),
        },
    }
}

/// Premium gate for `AddBlock`. Pure so the free/licensed matrix is
/// unit-testable without a live daemon (the happy path saves state, which
/// needs the real state dir).
///
/// The 1-block cap counts SAVED blocks and gates only NEW adds — a downgrade
/// deletes nothing and existing blocks stay startable, there is just no room
/// for more. Saving app matchers additionally needs `app_blocking`. The cap
/// error wins when both apply: it is the one the user must resolve first.
fn gate_add_block(
    unlimited: bool,
    app_blocking: bool,
    saved_blocks: usize,
    new_apps: &[AppMatcher],
) -> Option<&'static str> {
    if !unlimited && saved_blocks >= 1 {
        return Some(MSG_BLOCK_CAP);
    }
    if !app_blocking && !new_apps.is_empty() {
        return Some(MSG_APP_BLOCKING);
    }
    None
}

/// Whether a block update's app list requires the `app_blocking` feature.
///
/// Grandfathering rule (a downgrade deletes nothing): after a license
/// lapses, a premium-era block with saved app matchers must stay editable in
/// every OTHER respect — rejecting an update that merely passes the saved
/// apps through unchanged would brick the block the moment the user renames
/// it or edits its domains. Clearing apps is likewise always allowed
/// (removing configuration is free). Only INTRODUCING apps where none were
/// saved, or CHANGING a saved list into a different non-empty one, is a
/// premium action.
fn update_needs_app_license(saved: &[AppMatcher], updated: &[AppMatcher]) -> bool {
    !updated.is_empty() && updated != saved
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

    // ── license_status_fields() ─────────────────────────────────────────────

    fn claims(kind: &str, expires_at: Option<i64>) -> LicenseClaims {
        LicenseClaims {
            license_id: "GF-TEST-0001".into(),
            email: "kat@example.com".into(),
            tier: "premium".into(),
            kind: kind.into(),
            features: license::features::ALL
                .iter()
                .map(|s| s.to_string())
                .collect(),
            issued_at: 1_752_192_000,
            expires_at,
            max_devices: 3,
        }
    }

    #[test]
    fn status_fields_unlicensed() {
        let s = license_status_fields(None, false, 1_752_192_000);
        assert!(!s.present);
        assert!(!s.valid);
        assert_eq!(s.kind, None);
        assert_eq!(s.email, None);
        assert_eq!(s.expires_at, None);
        assert!(s.features.is_empty());
    }

    #[test]
    fn status_fields_token_present_but_unverified() {
        // A stored token that failed startup verification: present, but no
        // cached claims → invalid with no metadata to report.
        let s = license_status_fields(None, true, 1_752_192_000);
        assert!(s.present);
        assert!(!s.valid);
        assert_eq!(s.kind, None);
        assert!(s.features.is_empty());
    }

    #[test]
    fn status_fields_valid_perpetual() {
        let c = claims("perpetual", None);
        // Perpetual: valid at any clock value.
        for now in [i64::MIN, 0, 4_102_444_800, i64::MAX] {
            let s = license_status_fields(Some(&c), true, now);
            assert!(s.present);
            assert!(s.valid);
            assert_eq!(s.kind.as_deref(), Some("perpetual"));
            assert_eq!(s.email.as_deref(), Some("kat@example.com"));
            assert_eq!(s.expires_at, None);
            assert_eq!(s.features, license::features::ALL);
        }
    }

    #[test]
    fn status_fields_valid_trial_before_expiry() {
        let c = claims("trial", Some(2_000));
        let s = license_status_fields(Some(&c), true, 1_000);
        assert!(s.valid);
        assert_eq!(s.kind.as_deref(), Some("trial"));
        assert_eq!(s.expires_at, Some(2_000));
        assert_eq!(s.features, license::features::ALL);
        // Frozen boundary rule: expires_at == now is still valid.
        assert!(license_status_fields(Some(&c), true, 2_000).valid);
    }

    #[test]
    fn status_fields_trial_expired_at_status_time() {
        // The claims verified fine when cached, but the trial has since
        // lapsed: status must flip to invalid without a daemon restart,
        // while still reporting present + kind + expires_at so the GUI can
        // say "trial expired". Features are withheld — they drive gating.
        let c = claims("trial", Some(2_000));
        let s = license_status_fields(Some(&c), true, 2_001);
        assert!(s.present);
        assert!(!s.valid);
        assert_eq!(s.kind.as_deref(), Some("trial"));
        assert_eq!(s.email.as_deref(), Some("kat@example.com"));
        assert_eq!(s.expires_at, Some(2_000));
        assert!(s.features.is_empty());
    }

    // ── SetLicense dispatch arm ─────────────────────────────────────────────

    fn test_daemon() -> Arc<Daemon> {
        Arc::new(Daemon {
            state: tokio::sync::Mutex::new(State::default()),
            key: b"ipc-test-key-0123456789abcdef012".to_vec(),
            unlocked_until: tokio::sync::Mutex::new(0),
            applied: tokio::sync::Mutex::new(None),
            license: tokio::sync::Mutex::new(None),
        })
    }

    /// The KAT fixture minted by the real web-side signer (see
    /// crates/core/tests/license_kat.rs for provenance/regeneration).
    fn kat() -> serde_json::Value {
        serde_json::from_str(include_str!("../../core/tests/fixtures/license_kat.json")).unwrap()
    }

    #[tokio::test]
    async fn set_license_verifies_before_storing() {
        let daemon = test_daemon();
        let fx = kat();
        let token = fx["valid_perpetual"]["token"].as_str().unwrap();

        // The token is genuine — it verifies under the KAT test key…
        license::verify_token_with_key(fx["test_pubkey_b64url"].as_str().unwrap(), token, 0)
            .expect("KAT token must verify under its own key");

        // …but the arm verifies against the EMBEDDED production key (filled
        // at the 2026-07-11 ceremony), so a token signed by the throwaway
        // test key is rejected as BadSignature — proving the
        // verify-before-store order: nothing may be persisted or cached on
        // any verification failure. A happy-path arm test would need a token
        // minted by the production private key, which is vaulted with the
        // store and rightly unavailable here; the valid path is covered by
        // the core KATs (verify_token_with_key) plus the pure
        // license_status_fields tests above.
        let resp = dispatch(
            Request::SetLicense {
                token: Some(token.to_string()),
            },
            &daemon,
        )
        .await;
        match resp {
            Response::Error { message } => {
                assert_eq!(message, "license signature is invalid")
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert_eq!(
            daemon.state.lock().await.license_token,
            None,
            "a rejected token must never be stored"
        );
        assert!(daemon.license.lock().await.is_none());
    }

    #[tokio::test]
    async fn set_license_is_gated_by_the_settings_lock() {
        // With a password set and no unlock window, SetLicense — including a
        // CLEAR — must be refused before any verify/store work happens:
        // clearing the license mid-block is a self-service downgrade lever.
        let daemon = test_daemon();
        daemon.state.lock().await.password_hash =
            Some("$argon2id$v=19$m=19456,t=2,p=1$abc$def".to_string());
        let resp = dispatch(Request::SetLicense { token: None }, &daemon).await;
        match resp {
            Response::Error { message } => assert!(
                message.contains("locked"),
                "expected the settings-lock error, got: {message}"
            ),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── license gates ───────────────────────────────────────────────────────
    //
    // Rejections return before `state::save`, so they are fully testable
    // through `dispatch`. Accept paths would hit the real state dir, so their
    // matrices live on the pure helpers (`gate_add_block`,
    // `update_needs_app_license`) instead — except where a later,
    // environment-independent error proves the gate was passed.

    use grepfocus_core::{Block, DAY_MON};

    fn blk(id: u64, apps: Vec<AppMatcher>) -> Block {
        Block {
            id,
            name: format!("block-{id}"),
            domains: vec!["example.com".into()],
            apps,
            allowance_secs_per_day: 0,
        }
    }

    fn steam() -> AppMatcher {
        AppMatcher::Basename {
            name: "steam".into(),
        }
    }

    fn discord() -> AppMatcher {
        AppMatcher::Basename {
            name: "discord".into(),
        }
    }

    fn sched(block_id: u64) -> Schedule {
        Schedule {
            id: 0,
            name: "mornings".into(),
            block_id,
            days: DAY_MON,
            start_minute: 540,
            duration_minutes: 60,
            enabled: true,
        }
    }

    fn err_msg(resp: Response) -> String {
        match resp {
            Response::Error { message } => message,
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// The response may be Ok, or an unrelated error (in tests, `save` fails
    /// against the real state dir) — but it must not be a premium gate.
    fn assert_not_premium_gated(resp: &Response) {
        if let Response::Error { message } = resp {
            assert!(
                !message.contains("premium feature"),
                "unexpected premium gate: {message}"
            );
        }
    }

    #[test]
    fn gate_add_block_matrix() {
        let apps = vec![steam()];
        // Free tier: the FIRST block is fine…
        assert_eq!(gate_add_block(false, false, 0, &[]), None);
        // …the second (and any later) add hits the cap, with the exact copy.
        assert_eq!(gate_add_block(false, false, 1, &[]), Some(MSG_BLOCK_CAP));
        assert_eq!(gate_add_block(false, false, 7, &[]), Some(MSG_BLOCK_CAP));
        // Licensed: many adds fine, apps fine.
        assert_eq!(gate_add_block(true, true, 100, &apps), None);
        // Free tier: apps rejected even on the very first block.
        assert_eq!(
            gate_add_block(false, false, 0, &apps),
            Some(MSG_APP_BLOCKING)
        );
        // Both violations at once: the cap error wins.
        assert_eq!(gate_add_block(false, false, 1, &apps), Some(MSG_BLOCK_CAP));
        // The two features gate independently.
        assert_eq!(gate_add_block(false, true, 1, &apps), Some(MSG_BLOCK_CAP));
        assert_eq!(
            gate_add_block(true, false, 1, &apps),
            Some(MSG_APP_BLOCKING)
        );
        assert_eq!(gate_add_block(true, false, 1, &[]), None);
    }

    #[test]
    fn update_app_license_grandfather_matrix() {
        let a = vec![steam()];
        let b = vec![discord()];
        let ab = vec![steam(), discord()];
        // Keeping the identical saved list passes through.
        assert!(!update_needs_app_license(&a, &a));
        // Clearing is always allowed, as is staying empty.
        assert!(!update_needs_app_license(&a, &[]));
        assert!(!update_needs_app_license(&[], &[]));
        // Introducing apps where none were saved needs the license.
        assert!(update_needs_app_license(&[], &a));
        // So does changing a saved list — including adding to or shrinking it.
        assert!(update_needs_app_license(&a, &b));
        assert!(update_needs_app_license(&a, &ab));
        assert!(update_needs_app_license(&ab, &a));
    }

    #[tokio::test]
    async fn add_block_second_free_add_rejected_with_exact_copy() {
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![]));
        let resp = dispatch(
            Request::AddBlock {
                block: blk(0, vec![]),
            },
            &daemon,
        )
        .await;
        assert_eq!(err_msg(resp), MSG_BLOCK_CAP);
        assert_eq!(daemon.state.lock().await.blocks.len(), 1);
    }

    #[tokio::test]
    async fn add_block_with_apps_rejected_free_with_exact_copy() {
        let daemon = test_daemon(); // zero saved blocks: the cap can't trip first
        let resp = dispatch(
            Request::AddBlock {
                block: blk(0, vec![steam()]),
            },
            &daemon,
        )
        .await;
        assert_eq!(err_msg(resp), MSG_APP_BLOCKING);
        assert!(daemon.state.lock().await.blocks.is_empty());
    }

    #[tokio::test]
    async fn update_block_cannot_introduce_apps_free() {
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![]));
        let resp = dispatch(
            Request::UpdateBlock {
                block: blk(1, vec![steam()]),
            },
            &daemon,
        )
        .await;
        assert_eq!(err_msg(resp), MSG_APP_BLOCKING);
        assert!(daemon.state.lock().await.blocks[0].apps.is_empty());
    }

    #[tokio::test]
    async fn update_block_cannot_modify_apps_free() {
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![steam()]));
        let resp = dispatch(
            Request::UpdateBlock {
                block: blk(1, vec![discord()]),
            },
            &daemon,
        )
        .await;
        assert_eq!(err_msg(resp), MSG_APP_BLOCKING);
        assert_eq!(daemon.state.lock().await.blocks[0].apps, vec![steam()]);
    }

    #[tokio::test]
    async fn update_block_grandfathered_apps_pass_through_ungated() {
        // Free tier, premium-era block with apps: an update that keeps the
        // apps verbatim (here: editing domains) must not hit the premium
        // gate — that would brick the block after a downgrade.
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![steam()]));
        let mut update = blk(1, vec![steam()]);
        update.domains = vec!["news.ycombinator.com".into()];
        let resp = dispatch(Request::UpdateBlock { block: update }, &daemon).await;
        assert_not_premium_gated(&resp);
    }

    #[tokio::test]
    async fn update_block_clearing_apps_ungated() {
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![steam()]));
        let resp = dispatch(
            Request::UpdateBlock {
                block: blk(1, vec![]),
            },
            &daemon,
        )
        .await;
        assert_not_premium_gated(&resp);
    }

    #[tokio::test]
    async fn add_schedule_rejected_free_with_exact_copy() {
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![]));
        let resp = dispatch(Request::AddSchedule { schedule: sched(1) }, &daemon).await;
        assert_eq!(err_msg(resp), MSG_SCHEDULES);
        assert!(daemon.state.lock().await.schedules.is_empty());
    }

    #[tokio::test]
    async fn update_schedule_rejected_free_with_exact_copy() {
        let daemon = test_daemon();
        daemon.state.lock().await.blocks.push(blk(1, vec![]));
        let resp = dispatch(Request::UpdateSchedule { schedule: sched(1) }, &daemon).await;
        assert_eq!(err_msg(resp), MSG_SCHEDULES);
    }

    #[tokio::test]
    async fn licensed_add_schedule_passes_the_gate() {
        // With a valid license cached, AddSchedule gets past the premium gate
        // and fails on the NEXT check (missing block) — an assertion that
        // works without touching the real state dir.
        let daemon = test_daemon();
        *daemon.license.lock().await = Some(claims("perpetual", None));
        let resp = dispatch(Request::AddSchedule { schedule: sched(5) }, &daemon).await;
        assert_eq!(err_msg(resp), "no block with id 5");
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
