// Prevent additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;
mod tray;
mod update;
mod version;

use std::collections::HashMap;
use std::time::Duration;

use grepfocus_core::{
    ActiveBlock, AllowanceLedger, AllowanceStatus, Block, DayStat, FocusSession, Health,
    LifetimeTotals, NftStatus, PomodoroStatus, Request, Response, Schedule, Settings,
};
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

/// The workspace version: what `--version` prints and what the Settings about
/// line shows beside the daemon's. `tauri.conf.json` carries its own copy
/// (Tauri reads that one for the bundle), pinned to this by a test.
const GUI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where a package install (rpm/deb/AUR) puts the daemon; also hardcoded in
/// `debian/grepfocus.prerm` and the installer's `PACKAGED_BIN`.
const PACKAGED_DAEMON_BIN: &str = "/usr/bin/grepfocusd";
/// Where the AppImage's pkexec installer AND the dev scripts put it — its
/// presence alone is not evidence of an AppImage install.
const LOCAL_DAEMON_BIN: &str = "/usr/local/bin/grepfocusd";

#[tauri::command]
async fn list_blocks() -> Result<Vec<Block>, String> {
    match client::call(Request::ListBlocks {}).await? {
        Response::Blocks { blocks } => Ok(blocks),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Save a new block. The content validator is core's — the same one the
/// daemon runs — so a refusal reaches the user with the daemon's exact text
/// and no round trip; the daemon stays authoritative and re-validates.
#[tauri::command]
async fn add_block(block: Block) -> Result<u64, String> {
    let mut block = block;
    grepfocus_core::validate::validate_block(&mut block)?;
    match client::call(Request::AddBlock { block }).await? {
        Response::Added { id } => Ok(id),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Save an edited block. The daemon refuses this while the block is ACTIVE
/// ("cannot edit a block while it is active") so that a running block's
/// allowance and lock cannot be softened mid-flight; the frontend disables its
/// edit form for active blocks rather than inviting that refusal. It also
/// normalizes the allowance policy and its legacy mirror on save, so a client
/// frame need only be coherent, not canonical. Domains and app matchers are
/// validated here first, as in `add_block`.
#[tauri::command]
async fn update_block(block: Block) -> Result<(), String> {
    let mut block = block;
    grepfocus_core::validate::validate_block(&mut block)?;
    match client::call(Request::UpdateBlock { block }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn delete_block(id: u64) -> Result<(), String> {
    match client::call(Request::DeleteBlock { id }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn start_block(id: u64, duration_secs: u64) -> Result<(), String> {
    match client::call(Request::StartBlock { id, duration_secs }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Start a pomodoro session driving a saved block through alternating
/// focus/break intervals. Gated by the daemon on the `pomodoro` feature — an
/// unlicensed request comes back as `Response::Error` and surfaces to JS as the
/// thrown feature-gate string, same as the other premium commands.
#[tauri::command]
async fn start_pomodoro(
    block_id: u64,
    focus_secs: u64,
    break_secs: u64,
    cycles: u32,
) -> Result<(), String> {
    match client::call(Request::StartPomodoro {
        block_id,
        focus_secs,
        break_secs,
        cycles,
    })
    .await?
    {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Stop the running pomodoro session. Hybrid commitment model: the daemon
/// allows this only during a break and refuses it mid-focus, returning its
/// refusal verbatim for the frontend to surface.
#[tauri::command]
async fn stop_pomodoro() -> Result<(), String> {
    match client::call(Request::StopPomodoro {}).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[derive(serde::Serialize)]
struct StatusOut {
    active: Vec<ActiveBlock>,
    now_unix: u64,
    password_set: bool,
    unlocked: bool,
    /// Per-active-block allowance: the policy plus the reduction of break
    /// history under it. The path the frontend reads.
    allowance: Vec<AllowanceStatus>,
    /// DEPRECATED, still carried: a bare per-day counter that cannot express a
    /// rolling window. Kept so the frontend has a fallback when talking to a
    /// daemon old enough not to emit `allowance` at all.
    allowance_used: Vec<AllowanceLedger>,
    license_present: bool,
    license_valid: bool,
    license_kind: Option<String>,
    license_email: Option<String>,
    license_expires_at: Option<i64>,
    licensed_features: Vec<String>,
    pomodoro: Option<PomodoroStatus>,
    /// Current cross-cutting preferences, so the frontend can render toggles
    /// (e.g. the notifications checkbox) off the same status poll.
    settings: Settings,
    /// DEPRECATED, still carried: equal to `health.proxy == "degraded"`.
    /// The frontend's "port in use" notice reads this until it moves to
    /// `health.proxy`.
    instant_breaks_degraded: bool,
    /// Enforcement health and daemon identity, passed through untouched. An
    /// old daemon never emits it, in which case core's default arrives here
    /// with an empty `daemon_version`.
    health: Health,
    /// GUI/daemon version skew advice (see `version::advise`). Computed
    /// here, on every poll, so the banner tracks an install the moment it
    /// lands; never license-gated.
    update: version::UpdateAdvice,
}

#[tauri::command]
async fn get_status() -> Result<StatusOut, String> {
    match client::call(Request::GetStatus {}).await? {
        Response::Status {
            active,
            now_unix,
            password_set,
            unlocked,
            allowance,
            allowance_used,
            license_present,
            license_valid,
            license_kind,
            license_email,
            license_expires_at,
            licensed_features,
            pomodoro,
            settings,
            instant_breaks_degraded,
            health,
        } => {
            let env = probe_app_env();
            let update = version::advise(version::Probe {
                gui: GUI_VERSION,
                daemon: (!health.daemon_version.is_empty())
                    .then_some(health.daemon_version.as_str()),
                install_kind: health.install_kind,
                appimage: env.appimage,
                packaged_binary: env.packaged_daemon,
                local_binary: env.local_daemon,
            });
            Ok(StatusOut {
                active,
                now_unix,
                password_set,
                unlocked,
                allowance,
                allowance_used,
                license_present,
                license_valid,
                license_kind,
                license_email,
                license_expires_at,
                licensed_features,
                pomodoro,
                settings,
                instant_breaks_degraded,
                health: *health,
                update,
            })
        }
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn set_password(old: Option<String>, new: Option<String>) -> Result<(), String> {
    match client::call(Request::SetPassword { old, new }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn set_license(token: Option<String>) -> Result<(), String> {
    match client::call(Request::SetLicense { token }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Replace the cross-cutting preferences. The daemon gates this behind the
/// settings lock (so a locked user must unlock first) but never behind a
/// license — preferences are free. A refusal surfaces to JS verbatim.
#[tauri::command]
async fn set_settings(settings: Settings) -> Result<(), String> {
    match client::call(Request::SetSettings { settings }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn unlock(password: String) -> Result<(), String> {
    match client::call(Request::Unlock { password }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Take a break on an active block. `challenge` is the user's typed response
/// for a `ChallengeBreaks` block and `None` for every other mode — the daemon
/// decides whether one was required, and verifies it. The frontend omits the
/// argument entirely for unlocked breaks (Tauri maps a missing arg to `None`).
#[tauri::command]
async fn take_break(block_id: u64, secs: u64, challenge: Option<String>) -> Result<(), String> {
    match client::call(Request::TakeBreak {
        block_id,
        secs,
        challenge,
    })
    .await?
    {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Ask the daemon for a fresh break challenge. The daemon issues AND verifies
/// the string (it never originates here), so this is a pure pass-through.
#[tauri::command]
async fn get_break_challenge(block_id: u64) -> Result<String, String> {
    match client::call(Request::GetBreakChallenge { block_id }).await? {
        Response::BreakChallenge { text } => Ok(text),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Usage-stats payload, mirroring `Response::UsageStats`. The nested core types
/// already derive `Serialize`, so they cross to the frontend as-is. Gated by the
/// daemon on the `usage_stats` feature — an unlicensed request comes back as
/// `Response::Error` and surfaces to JS as the thrown feature-gate string.
#[derive(serde::Serialize)]
struct UsageStatsOut {
    totals: LifetimeTotals,
    sessions: Vec<FocusSession>,
    days: Vec<DayStat>,
    current_streak: u32,
    longest_streak: u32,
}

#[tauri::command]
async fn get_usage_stats() -> Result<UsageStatsOut, String> {
    match client::call(Request::GetUsageStats {}).await? {
        Response::UsageStats {
            totals,
            sessions,
            days,
            current_streak,
            longest_streak,
        } => Ok(UsageStatsOut {
            totals,
            sessions,
            days,
            current_streak,
            longest_streak,
        }),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn list_schedules() -> Result<Vec<Schedule>, String> {
    match client::call(Request::ListSchedules {}).await? {
        Response::Schedules { schedules } => Ok(schedules),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn add_schedule(schedule: Schedule) -> Result<u64, String> {
    match client::call(Request::AddSchedule { schedule }).await? {
        Response::Added { id } => Ok(id),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn update_schedule(schedule: Schedule) -> Result<(), String> {
    match client::call(Request::UpdateSchedule { schedule }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn delete_schedule(id: u64) -> Result<(), String> {
    match client::call(Request::DeleteSchedule { id }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// What the frontend needs to know about how the app is running: whether
/// we're an AppImage — which gates the first-run "install the system service"
/// flow, since the pkexec installer only makes sense from an AppImage (package
/// installs already set the daemon up; AppRun sets $APPIMAGE) — our own
/// version, shown beside the daemon's on the Settings tab, and which daemon
/// binaries exist, which picks the first-run dialog's mode when the daemon is
/// down (a package install is started, not installed) and feeds the skew
/// advice.
#[derive(serde::Serialize)]
struct AppEnv {
    appimage: bool,
    gui_version: String,
    /// `/usr/bin/grepfocusd` exists.
    packaged_daemon: bool,
    /// `/usr/local/bin/grepfocusd` exists.
    local_daemon: bool,
}

/// Re-probed on every call (two stats): the binaries change under a running
/// GUI exactly when it matters — the installer just put one there.
fn probe_app_env() -> AppEnv {
    AppEnv {
        appimage: std::env::var_os("APPIMAGE").is_some(),
        gui_version: GUI_VERSION.to_string(),
        packaged_daemon: std::path::Path::new(PACKAGED_DAEMON_BIN).exists(),
        local_daemon: std::path::Path::new(LOCAL_DAEMON_BIN).exists(),
    }
}

#[tauri::command]
fn app_env() -> AppEnv {
    probe_app_env()
}

/// Install or update the system service from inside an AppImage by running
/// the bundled installer as root via pkexec. The daemon binary + unit/config
/// files ride along in the AppImage as Tauri resources (bundle.resources ->
/// resource_dir()/payload/); the script relocates them and enables the unit.
/// A re-run is an update: the script refuses to run over a package install
/// (exit 98) and to downgrade (exit 99) — see `installer_error` and
/// packaging/appimage/appimage-install.sh. Called by the first-run dialog and
/// the Status tab's skew banner.
#[tauri::command]
async fn install_service(app: AppHandle) -> Result<(), String> {
    // Resolve the target user in-process (the desktop user running the GUI),
    // not from the frontend — the script usermod's them into the grepfocus group.
    let user = std::env::var("USER").unwrap_or_default();
    run_service_script(&app, ServiceAction::Install, Some(user)).await
}

/// Remove the system service the AppImage's installer put there: the script
/// stops and disables the unit, runs `grepfocusd cleanup` (hosts region,
/// nftables, browser DoH policies) and deletes the binary and unit. Saved
/// data in /var/lib/grepfocus and /etc/grepfocus stays. Called by the
/// Settings tab's "Remove system service".
///
/// The daemon is asked first, here and not only in the frontend: a block or
/// a pomodoro session refuses the removal (from the GUI this would be the
/// cancel the daemon never grants) even when it started while the
/// confirmation dialog was open, and so does a daemon that cannot be asked.
/// A schedule that fires while the polkit prompt is up is not caught.
#[tauri::command]
async fn uninstall_service(app: AppHandle) -> Result<(), String> {
    let status = client::call(Request::GetStatus {}).await.map_err(|e| {
        format!(
            "The service is not answering, so GrepFocus cannot tell whether a block is running — nothing was removed.\n({e})"
        )
    })?;
    match status {
        Response::Status {
            active,
            pomodoro,
            password_set,
            unlocked,
            ..
        } => {
            let locked = password_set && !unlocked;
            if let Some(why) = removal_refusal(!active.is_empty(), pomodoro.is_some(), locked) {
                return Err(why.to_string());
            }
        }
        Response::Error { message } => return Err(message),
        other => return Err(format!("unexpected response: {other:?}")),
    }
    run_service_script(&app, ServiceAction::Uninstall, None).await
}

/// Why the system service may not be removed right now, `None` when it may.
/// The two running-block sentences are also `serviceRemovalRefusal` in
/// ui/src/main.ts, which asks before it opens the confirmation dialog —
/// change together. The settings lock is prompted for there
/// (`ensureUnlocked`); here it only catches an unlock that lapsed since.
fn removal_refusal(block_active: bool, pomodoro: bool, locked: bool) -> Option<&'static str> {
    if pomodoro {
        Some("A pomodoro session is running — the service cannot be removed until it ends.")
    } else if block_active {
        Some("A block is running — the service cannot be removed until it ends.")
    } else if locked {
        Some("Settings are locked — unlock them, then remove the service.")
    } else {
        None
    }
}

/// What the privileged installer script is asked to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceAction {
    Install,
    Uninstall,
}

impl ServiceAction {
    /// The script's first argument (its `case "$ACTION"` arms).
    fn arg(self) -> &'static str {
        match self {
            ServiceAction::Install => "install",
            ServiceAction::Uninstall => "uninstall",
        }
    }
}

// The daily release check (see update.rs). Every command but `open_url`
// returns the fresh `UpdateInfo` so the frontend renders what it just
// changed without a second round trip.

#[tauri::command]
fn get_update_info(store: tauri::State<'_, update::Store>) -> update::UpdateInfo {
    store.info(update::now_unix())
}

/// The frontend calls this after the disclosure strip has been rendered
/// once; only then may the checker make its first network contact.
#[tauri::command]
fn acknowledge_update_check(app: AppHandle) -> update::UpdateInfo {
    update::acknowledge_then_check(&app)
}

/// The Settings button: a check now, whatever the cadence says. `Err`
/// only when checks are turned off.
#[tauri::command]
async fn check_for_update(app: AppHandle) -> Result<update::UpdateInfo, String> {
    update::check_now(&app).await
}

/// GUI-local, per user, no password gate: it is a privacy preference, not
/// a blocking one.
#[tauri::command]
fn set_update_check_enabled(
    store: tauri::State<'_, update::Store>,
    enabled: bool,
) -> update::UpdateInfo {
    store.set_enabled(enabled, update::now_unix())
}

/// Dismisses the release currently known; no argument, so a stale
/// frontend cannot dismiss a version it never showed.
#[tauri::command]
fn dismiss_update(store: tauri::State<'_, update::Store>) -> update::UpdateInfo {
    store.dismiss(update::now_unix())
}

/// Open a grepfocus.com link in the user's browser via `xdg-open`
/// (allowlisted in `update::link_allowed`; the AppImage's environment is
/// scrubbed first so the browser does not load the bundled GTK).
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    update::open_link(&url)
}

/// The payload files the privileged installer needs. The script must be first —
/// the bootstrap executes `$tmp/appimage-install.sh` after verifying everything.
const PAYLOAD_FILES: [&str; 5] = [
    "appimage-install.sh",
    "grepfocusd",
    "grepfocusd.service",
    "grepfocus.sysusers.conf",
    "grepfocus.tmpfiles.conf",
];

/// Runs as root under `pkexec /bin/sh -c BOOTSTRAP sh <action> <user> [<staged
/// path> <sha256>]...`. Copies each staged file into a fresh ROOT-owned temp
/// dir, verifies the sha256 of the root-owned copy, and only then executes the
/// installer from that dir. Exit 97 = integrity mismatch.
///
/// This text itself must stay POSIX: `/bin/sh` is dash on Debian/Ubuntu (the
/// AppImage's audience). The installer is bash and is run as such — not
/// `exec`ed, so the EXIT trap still removes `$tmp`. `--force` (the installer's
/// downgrade override) is deliberately never forwarded from here.
const BOOTSTRAP: &str = r#"
set -eu
action="$1"; tgt_user="$2"; shift 2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
while [ "$#" -ge 2 ]; do
    src="$1"; sha="$2"; shift 2
    base=${src##*/}
    cp -- "$src" "$tmp/$base"
    printf '%s  %s\n' "$sha" "$tmp/$base" | sha256sum -c - >/dev/null 2>&1 \
        || { printf 'integrity check failed: %s\n' "$base" >&2; exit 97; }
done
bash "$tmp/appimage-install.sh" "$action" "$tgt_user"
"#;

/// Run the bundled appimage-install.sh as root via pkexec.
///
/// This CANNOT execute the script straight from the AppImage mount: the mount
/// is user-private FUSE (no allow_other), which the kernel makes unreadable to
/// every other uid INCLUDING root — pkexec would authorize fine and then root's
/// shell would fail to even open the script. So instead: we (the mounting user)
/// stage the payload into a private temp dir and hash it, then the pkexec'd
/// BOOTSTRAP re-copies the files into a root-owned temp dir and re-verifies the
/// hashes there before executing. The expected hashes travel in pkexec's argv,
/// which no other process can alter, and root hashes its own copies — so a
/// same-user process swapping staged files between the auth prompt and root
/// execution is caught, closing the classic user-writable-path race.
async fn run_service_script(
    app: &AppHandle,
    action: ServiceAction,
    user: Option<String>,
) -> Result<(), String> {
    let payload_dir = app
        .path()
        .resource_dir()
        .map_err(|e| format!("cannot locate bundled resources: {e}"))?
        .join("payload");
    if !payload_dir.join(PAYLOAD_FILES[0]).exists() {
        return Err(format!(
            "installer payload not found under {} — is this the AppImage build?",
            payload_dir.display()
        ));
    }

    let output =
        tauri::async_runtime::spawn_blocking(move || -> Result<std::process::Output, String> {
            use std::os::unix::fs::PermissionsExt;

            let stage =
                std::env::temp_dir().join(format!("grepfocus-stage-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&stage);
            std::fs::create_dir(&stage).map_err(|e| format!("cannot create staging dir: {e}"))?;
            std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot restrict staging dir: {e}"))?;

            let run = (|| -> Result<std::process::Output, String> {
                let mut pairs: Vec<(std::path::PathBuf, String)> = Vec::new();
                for name in PAYLOAD_FILES {
                    let dst = stage.join(name);
                    std::fs::copy(payload_dir.join(name), &dst)
                        .map_err(|e| format!("cannot stage {name}: {e}"))?;
                    let out = std::process::Command::new("sha256sum")
                        .arg(&dst)
                        .output()
                        .map_err(|e| format!("cannot hash {name}: {e}"))?;
                    if !out.status.success() {
                        return Err(format!("sha256sum failed for {name}"));
                    }
                    let hash = String::from_utf8_lossy(&out.stdout)
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    if hash.len() != 64 {
                        return Err(format!("unexpected sha256 output for {name}"));
                    }
                    pairs.push((dst, hash));
                }

                let mut cmd = std::process::Command::new("pkexec");
                cmd.arg("/bin/sh")
                    .arg("-c")
                    .arg(BOOTSTRAP)
                    .arg("sh")
                    .arg(action.arg())
                    .arg(user.as_deref().unwrap_or(""));
                for (path, hash) in &pairs {
                    cmd.arg(path).arg(hash);
                }
                cmd.output()
                    .map_err(|e| format!("failed to launch pkexec: {e}"))
            })();

            let _ = std::fs::remove_dir_all(&stage);
            run
        })
        .await
        .map_err(|e| format!("failed to launch installer: {e}"))??;

    if output.status.success() {
        return Ok(());
    }
    Err(installer_error(
        action,
        output.status.code(),
        &String::from_utf8_lossy(&output.stderr),
    ))
}

/// How pkexec opens the one stderr line it prints when it refuses before
/// running anything; the rest of the line is the reason.
const PKEXEC_REFUSAL: &str = "Error executing command as another user:";

/// pkexec's reason for refusing, when `stderr` opens with its own line.
fn pkexec_refusal(stderr: &str) -> Option<&str> {
    let reason = stderr.lines().next()?.strip_prefix(PKEXEC_REFUSAL)?;
    Some(reason.trim())
}

/// The user-facing text for a failed installer run. pkexec itself: 126 = auth
/// dialog dismissed, 127 = not authorized — but once the program runs, the
/// exit code is the program's, so those meanings are only trusted when the
/// run left stderr empty or opening with pkexec's own refusal line (it
/// prints one for both). Any other pkexec reason — no authentication agent
/// — falls through with its text. 97/98/99 are the bootstrap's and the
/// script's own codes (integrity, package install present, downgrade); the
/// script raises 99 for `install` only. `action` picks the wording where
/// "update it" or "installer" would be wrong for a removal.
fn installer_error(action: ServiceAction, code: Option<i32>, stderr: &str) -> String {
    let stderr = stderr.trim();
    let pkexec = pkexec_refusal(stderr);
    let detail = |msg: &str| {
        if stderr.is_empty() {
            msg.to_string()
        } else {
            format!("{msg}\n({stderr})")
        }
    };
    match (code, action) {
        (Some(126), _) if stderr.is_empty() || pkexec == Some("Request dismissed") => {
            "Authorization was dismissed.".to_string()
        }
        (Some(127), _) if stderr.is_empty() || pkexec == Some("Not authorized") => {
            "Authentication failed or not authorized.".to_string()
        }
        (Some(97), _) => {
            "Installer bundle failed its integrity check — re-download the AppImage.".to_string()
        }
        (Some(98), ServiceAction::Install) => detail(
            "A package install of GrepFocus owns /usr/bin/grepfocusd — update it with your package manager instead of from this app.",
        ),
        (Some(98), ServiceAction::Uninstall) => detail(
            "A package install of GrepFocus owns /usr/bin/grepfocusd — remove it with your package manager instead of from this app.",
        ),
        (Some(99), _) => detail(
            "The installed service is newer than the one bundled in this app, so the installer refused to downgrade it. Use a newer AppImage.",
        ),
        (code, action) => format!(
            "{} (exit {}): {}",
            match action {
                ServiceAction::Install => "Installer failed",
                ServiceAction::Uninstall => "Removing the service failed",
            },
            code.unwrap_or(-1),
            stderr
        ),
    }
}

/// Fire a desktop notification. Best-effort — failures are ignored so a
/// missing notification daemon never disrupts the app.
fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

/// The notification body while enforcement is in a RED state, `None`
/// otherwise. Mirrors exactly the two RED rules of `healthNotices` in
/// ui/src/main.ts — change together: a state the banner paints red that this
/// does not (or the reverse) is a notification the window cannot explain.
/// Silent on a daemon too old to report (empty `daemon_version`).
fn enforcement_red(health: &Health, domain_block_active: bool) -> Option<&'static str> {
    if health.daemon_version.is_empty() {
        return None;
    }
    if health.last_error.is_some() {
        return Some(
            "The /etc/hosts change could not be applied — website blocking may not be enforced. Open GrepFocus for details.",
        );
    }
    if domain_block_active && matches!(health.nft, NftStatus::Failed { .. }) {
        return Some(
            "DoH protection (nftables) failed — browsers using DNS-over-HTTPS can bypass the active block. Open GrepFocus for details.",
        );
    }
    None
}

/// Show + focus the main window. Every un-hide path must go through here:
/// tao 0.35's Wayland client-side decorations go stale across hide()/show() —
/// the titlebar buttons render but ignore clicks until something forces a
/// re-layout (tauri#11856, root cause tao#1046; fixed upstream, drop this
/// when tauri ships it). Toggling `resizable` forces that re-layout without
/// going through set_size, which is itself unreliable under Wayland CSD.
/// WebviewWindow methods are thread-safe, so this is callable from the
/// status watcher's async runtime thread too.
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        #[cfg(target_os = "linux")]
        {
            let _ = window.set_resizable(false);
            let _ = window.set_resizable(true);
        }
        let _ = window.set_focus();
    }
}

/// Background task: poll the daemon every 5s, keep the tray tooltip in sync,
/// and fire a notification whenever a block starts or ends, or enforcement
/// newly goes RED (see `enforcement_red`). Runs for the life of the process
/// (when a tray host is present, the window hides to tray rather than
/// closing), so notifications keep flowing even with no window open. Also
/// re-shows a hidden window if its tray host vanishes.
fn spawn_status_watcher(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // id -> block name. `None` until the first successful poll so we
        // establish a baseline without notifying for already-active blocks.
        let mut prev: Option<HashMap<u64, String>> = None;
        // Whether the last successful poll was RED; `None` until the first
        // one, for the same baseline reason. Only the false→true edge
        // notifies: the fault stays up until it clears, so repeating it every
        // poll would be noise.
        let mut prev_red: Option<bool> = None;
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;

            // Hidden-window rescue: a hidden window never gets a close event,
            // so a tray that vanishes underneath it (extension disabled
            // mid-session) would strand the app without this.
            if let Some(window) = app.get_webview_window("main") {
                if matches!(window.is_visible(), Ok(false)) {
                    let present =
                        tauri::async_runtime::spawn_blocking(tray::status_notifier_host_present)
                            .await
                            .unwrap_or(false);
                    if !present {
                        show_main_window(&app);
                    }
                }
            }

            let (active, settings, health) = match client::call(Request::GetStatus {}).await {
                Ok(Response::Status {
                    active,
                    settings,
                    health,
                    ..
                }) => (active, settings, health),
                _ => {
                    // Daemon down / transient error. Surface it in the tooltip
                    // instead of leaving the stale "N active" text, but do NOT
                    // touch `prev` or `prev_red`: keeping the notification
                    // baselines avoids a spurious burst of "block started/
                    // ended" (or a repeated RED) when it recovers.
                    if let Some(tray) = app.tray_by_id("grepfocus-tray") {
                        let _ = tray.set_tooltip(Some("GrepFocus — daemon unreachable"));
                    }
                    continue;
                }
            };
            let cur: HashMap<u64, String> = active
                .iter()
                .map(|a| (a.block.id, a.block.name.clone()))
                .collect();
            let domain_block_active = active.iter().any(|a| !a.block.domains.is_empty());
            let red = enforcement_red(&health, domain_block_active);

            if let Some(tray) = app.tray_by_id("grepfocus-tray") {
                let tip = if cur.is_empty() {
                    "GrepFocus — no active blocks".to_string()
                } else {
                    format!("GrepFocus — {} active", cur.len())
                };
                let _ = tray.set_tooltip(Some(&tip));
            }

            // Gate on the preference, but always update the baseline below —
            // toggling notifications back on must not then replay every block
            // that started or ended while they were off.
            if settings.notifications {
                if let Some(prev_map) = &prev {
                    for (id, name) in &cur {
                        if !prev_map.contains_key(id) {
                            notify(&app, "Block started", name);
                        }
                    }
                    for (id, name) in prev_map {
                        if !cur.contains_key(id) {
                            notify(&app, "Block ended", name);
                        }
                    }
                }
                if let (Some(false), Some(body)) = (prev_red, red) {
                    notify(&app, "GrepFocus: blocking problem", body);
                }
            }
            prev = Some(cur);
            prev_red = Some(red.is_some());
        }
    });
}

/// When running from an AppImage, point the bundled libwebkit2gtk at its own
/// helper processes. It looks for WebKitWebProcess / WebKitNetworkProcess and
/// the injected bundle at a compiled-in absolute path (the Ubuntu build
/// host's), which doesn't exist on other distros -> the page never loads.
/// WEBKIT_EXEC_PATH / WEBKIT_INJECTED_BUNDLE_PATH redirect it to the copies
/// under $APPDIR. Must run before GTK/webkit initialize (before
/// tauri::Builder::run) and only under $APPIMAGE, so native installs
/// (rpm/deb/AUR — no $APPIMAGE) are untouched. Set only if unset, so a user
/// can still override.
///
/// The other half of "renders on an arbitrary host" is handled at build time:
/// build-appimage.sh strips every bundled libwayland-*.so so the HOST copy is
/// used — the host's Mesa EGL stack hard-requires its own libwayland version
/// (e.g. wl_fixes_interface, wayland 1.23), and a shadowing older copy makes
/// EGL fail entirely, SIGABRTing the web process.
fn configure_appimage_webview_env() {
    if std::env::var_os("APPIMAGE").is_none() {
        return;
    }
    if let Some(appdir) = std::env::var_os("APPDIR") {
        let base = std::path::Path::new(&appdir).join("usr/lib/x86_64-linux-gnu/webkit2gtk-4.1");
        set_env_if_unset("WEBKIT_EXEC_PATH", base.as_os_str());
        set_env_if_unset(
            "WEBKIT_INJECTED_BUNDLE_PATH",
            base.join("injected-bundle").as_os_str(),
        );
    }
}

fn set_env_if_unset(key: &str, val: &std::ffi::OsStr) {
    if std::env::var_os(key).is_none() {
        std::env::set_var(key, val);
    }
}

fn main() {
    // Answered before any Tauri init: the single-instance plugin would
    // otherwise surface an already-running window instead of printing.
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--version") | Some("-V")
    ) {
        println!("grepfocus-gui {GUI_VERSION}");
        return;
    }

    // AppImage-only webview env fixes; must precede any GTK/webkit init below.
    configure_appimage_webview_env();

    // wry's custom URI scheme handler is unreliable on this webkit2gtk-4.1
    // build (2.52). Serve embedded assets via a real localhost HTTP server
    // instead. Note: this URL is treated as "remote" by Tauri 2's ACL, so
    // our app commands need explicit allow-* entries in capabilities/default.json.
    let port = portpicker::pick_unused_port().expect("no free port");

    tauri::Builder::default()
        // Must be the first plugin: a second launch surfaces the existing
        // window (likely hidden in the tray) instead of spawning a duplicate
        // process with its own tray icon and notification stream.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_localhost::Builder::new(port).build())
        .plugin(tauri_plugin_notification::init())
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide to tray only when a tray can actually bring us back.
                // NB: if the frontend ever adds a JS tauri://close-requested
                // listener, tauri auto-prevents close and this branch stops
                // mattering — don't.
                if tray::status_notifier_host_present() {
                    api.prevent_close();
                    let _ = window.hide();
                }
                // else: allow the close; the app exits with its last window.
                // No goodbye notification — it was tried and removed: the
                // plugin delivers on a spawned task that process exit races
                // and loses, a blocking send can stall the main thread for
                // the D-Bus method timeout (the window freezes mid-close),
                // and GNOME suppresses the banner anyway (focused-app
                // heuristic, source teardown on exit).
            }
        })
        .setup(move |app| {
            // The release-check store is managed before the window exists,
            // so the first `get_update_info` from the page never races it.
            let update_url = std::env::var("GREPFOCUS_UPDATE_URL")
                .ok()
                .filter(|u| !u.trim().is_empty())
                .unwrap_or_else(|| update::DEFAULT_URL.to_string());
            app.manage(update::Store::open(
                update::config_path(
                    std::env::var_os("XDG_CONFIG_HOME").as_deref(),
                    std::env::var_os("HOME").as_deref(),
                ),
                update_url,
                GUI_VERSION,
                std::env::var_os("APPIMAGE").is_some(),
            ));

            let url = format!("http://localhost:{port}/index.html")
                .parse()
                .unwrap();
            let _win = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("GrepFocus")
                .inner_size(900.0, 640.0)
                .min_inner_size(600.0, 480.0)
                .build()?;

            let menu = MenuBuilder::new(app)
                .text("show", "Show GrepFocus")
                .separator()
                .text("quit", "Quit")
                .build()?;

            TrayIconBuilder::with_id("grepfocus-tray")
                .icon(app.default_window_icon().expect("bundled icon").clone())
                .tooltip("GrepFocus — no active blocks")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            if w.is_visible().unwrap_or(false) {
                                let _ = w.hide();
                            } else {
                                show_main_window(app);
                            }
                        }
                    }
                })
                .build(app)?;

            // Workaround for muda/appindicator on GNOME (tauri#8825): the
            // StatusNotifier host can render the initial tray menu BLANK even
            // though the exported DBusMenu is correct (verified: identical
            // structure to apps that render fine). Re-setting the menu shortly
            // after startup emits a fresh LayoutUpdated, forcing the host to
            // re-read a populated layout. A freshly built menu (new internal
            // ids → bumped revision) is a genuine "second menu", not a no-op
            // re-assign. The tray icon and its `on_menu_event` handler (matched
            // by item id, which we keep identical) persist across the swap.
            let menu_reset_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                if let Some(tray) = menu_reset_app.tray_by_id("grepfocus-tray") {
                    if let Ok(fresh) = MenuBuilder::new(&menu_reset_app)
                        .text("show", "Show GrepFocus")
                        .separator()
                        .text("quit", "Quit")
                        .build()
                    {
                        let _ = tray.set_menu(Some(fresh));
                    }
                }
            });

            spawn_status_watcher(app.handle().clone());
            update::spawn_checker(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_blocks,
            add_block,
            update_block,
            delete_block,
            start_block,
            get_status,
            get_usage_stats,
            list_schedules,
            add_schedule,
            update_schedule,
            delete_schedule,
            set_password,
            set_license,
            set_settings,
            unlock,
            take_break,
            get_break_challenge,
            start_pomodoro,
            stop_pomodoro,
            app_env,
            install_service,
            uninstall_service,
            get_update_info,
            acknowledge_update_check,
            check_for_update,
            set_update_check_enabled,
            dismiss_update,
            open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{
        enforcement_red, installer_error, removal_refusal, version, ServiceAction, BOOTSTRAP,
        GUI_VERSION, LOCAL_DAEMON_BIN, PACKAGED_DAEMON_BIN, PAYLOAD_FILES,
    };
    use grepfocus_core::{Health, NftStatus};

    // The packaging files this binary's constants must agree with. Test-only:
    // the release binary must not embed them.
    const STAGE_SCRIPT: &str = include_str!("../../../packaging/appimage/stage-payload.sh");
    const INSTALL_SCRIPT: &str = include_str!("../../../packaging/appimage/appimage-install.sh");
    const DEBIAN_PRERM: &str = include_str!("../../../debian/grepfocus.prerm");

    /// A daemon new enough to report health, everything else at rest.
    fn reporting() -> Health {
        Health {
            daemon_version: "0.5.1".to_string(),
            ..Health::default()
        }
    }

    #[test]
    fn enforcement_red_mirrors_frontend_rules() {
        // A daemon too old to report says nothing, whatever the fields hold.
        let old = Health {
            last_error: Some("hosts: read-only file system".to_string()),
            ..Health::default()
        };
        assert_eq!(enforcement_red(&old, true), None);

        // last_error is RED with or without a domain block.
        let hosts = Health {
            last_error: Some("hosts: read-only file system".to_string()),
            ..reporting()
        };
        assert!(enforcement_red(&hosts, true).is_some());
        assert!(enforcement_red(&hosts, false).is_some());

        // nft Failed is RED only while a domain block is active.
        let nft = Health {
            nft: NftStatus::Failed {
                reason: "nft: command not found".to_string(),
            },
            ..reporting()
        };
        assert!(enforcement_red(&nft, true).is_some());
        assert_eq!(enforcement_red(&nft, false), None);

        // StaleTable is the banner's YELLOW, never a notification.
        let stale = Health {
            nft: NftStatus::StaleTable {
                reason: "table busy".to_string(),
            },
            ..reporting()
        };
        assert_eq!(enforcement_red(&stale, true), None);
        assert_eq!(enforcement_red(&reporting(), true), None);
    }

    #[test]
    fn tauri_conf_version_matches_cargo() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("valid JSON");
        assert_eq!(conf["version"], GUI_VERSION);
    }

    /// The skew advice compares `GUI_VERSION` through `version::parse_version`;
    /// a workspace version it cannot parse would silence the banner for good.
    #[test]
    fn gui_version_parses() {
        let v = version::parse_version(GUI_VERSION).expect("MAJOR.MINOR.PATCH");
        assert!(
            v.pre.is_empty() && v.build.is_empty(),
            "plain release: {GUI_VERSION}"
        );
    }

    #[test]
    fn installer_error_maps_pkexec_codes() {
        for action in [ServiceAction::Install, ServiceAction::Uninstall] {
            assert_eq!(
                installer_error(action, Some(126), ""),
                "Authorization was dismissed."
            );
            assert_eq!(
                installer_error(action, Some(127), "  \n"),
                "Authentication failed or not authorized."
            );
        }
        // Once the program ran, 126 is its own exit code, not pkexec's.
        let generic = installer_error(ServiceAction::Install, Some(126), "bash: permission denied");
        assert!(generic.starts_with("Installer failed (exit 126): bash: permission denied"));
        assert!(!generic.contains("dismissed"));
    }

    /// pkexec does not refuse silently: the strings are the ones in polkit's
    /// pkexec, newline and "incident" trailer included.
    #[test]
    fn installer_error_reads_pkexec_refusal_lines() {
        const DISMISSED: &str = "Error executing command as another user: Request dismissed\n";
        const NOT_AUTHORIZED: &str =
            "Error executing command as another user: Not authorized\n\nThis incident has been reported.\n";
        const NO_AGENT: &str =
            "Error executing command as another user: No authentication agent found.\n";
        for action in [ServiceAction::Install, ServiceAction::Uninstall] {
            assert_eq!(
                installer_error(action, Some(126), DISMISSED),
                "Authorization was dismissed."
            );
            assert_eq!(
                installer_error(action, Some(127), NOT_AUTHORIZED),
                "Authentication failed or not authorized."
            );
            // A reason with no sentence of its own keeps pkexec's text.
            let no_agent = installer_error(action, Some(127), NO_AGENT);
            assert!(no_agent.contains("(exit 127)"), "{no_agent}");
            assert!(
                no_agent.ends_with("No authentication agent found."),
                "{no_agent}"
            );
        }
        // The script's own output that merely mentions the phrase is not
        // pkexec's line.
        let own = installer_error(
            ServiceAction::Uninstall,
            Some(126),
            "rm: Error executing command as another user: Request dismissed",
        );
        assert!(
            own.starts_with("Removing the service failed (exit 126)"),
            "{own}"
        );
    }

    #[test]
    fn installer_error_97_integrity() {
        for action in [ServiceAction::Install, ServiceAction::Uninstall] {
            let msg = installer_error(action, Some(97), "integrity check failed: grepfocusd");
            assert!(msg.contains("integrity check"));
            assert!(msg.contains("re-download"));
        }
    }

    #[test]
    fn installer_error_98_package_present() {
        let msg = installer_error(
            ServiceAction::Install,
            Some(98),
            "error: /usr/bin/grepfocusd exists",
        );
        assert!(msg.contains("update it with your package manager"));
        assert!(msg.ends_with("(error: /usr/bin/grepfocusd exists)"));
        // Without stderr the message stands alone.
        assert!(!installer_error(ServiceAction::Install, Some(98), "").contains('('));
    }

    /// A removal never tells the user to "update" the package.
    #[test]
    fn installer_error_98_on_uninstall_says_remove() {
        let msg = installer_error(
            ServiceAction::Uninstall,
            Some(98),
            "error: /usr/bin/grepfocusd exists",
        );
        assert!(msg.contains("remove it with your package manager"));
        assert!(!msg.contains("update"));
        assert!(msg.ends_with("(error: /usr/bin/grepfocusd exists)"));
    }

    #[test]
    fn installer_error_99_downgrade() {
        let msg = installer_error(
            ServiceAction::Install,
            Some(99),
            "refusing to downgrade grepfocusd 0.6.1 -> 0.6.0",
        );
        assert!(msg.contains("refused to downgrade"));
        assert!(msg.contains("0.6.1 -> 0.6.0"));
    }

    #[test]
    fn installer_error_other_includes_code_and_stderr() {
        assert_eq!(
            installer_error(
                ServiceAction::Install,
                Some(2),
                "usage: install <user> [--force] | uninstall"
            ),
            "Installer failed (exit 2): usage: install <user> [--force] | uninstall"
        );
        assert_eq!(
            installer_error(ServiceAction::Install, None, "killed"),
            "Installer failed (exit -1): killed"
        );
        assert_eq!(
            installer_error(ServiceAction::Uninstall, Some(1), "rm: cannot remove"),
            "Removing the service failed (exit 1): rm: cannot remove"
        );
    }

    #[test]
    fn removal_refused_while_a_block_or_pomodoro_runs() {
        assert_eq!(removal_refusal(false, false, false), None);
        assert_eq!(
            removal_refusal(true, false, false),
            Some("A block is running — the service cannot be removed until it ends.")
        );
        // A pomodoro session holds its block active through its breaks; it
        // is named as what has to end.
        for block_active in [false, true] {
            assert_eq!(
                removal_refusal(block_active, true, false),
                Some(
                    "A pomodoro session is running — the service cannot be removed until it ends."
                )
            );
        }
    }

    /// The running block is the reason given even when settings are locked
    /// too: unlocking would not help.
    #[test]
    fn removal_refused_while_settings_are_locked() {
        let locked = removal_refusal(false, false, true).expect("refused");
        assert!(locked.contains("locked"), "{locked}");
        assert!(removal_refusal(true, false, true)
            .expect("refused")
            .contains("block is running"));
    }

    /// The bootstrap runs under `pkexec /bin/sh -c`, which is dash on
    /// Debian/Ubuntu, so it must stay POSIX; the installer is bash and must
    /// be run as such (bash arrays and `[[` die under dash).
    #[test]
    fn bootstrap_runs_installer_under_bash_and_is_posix() {
        let last = BOOTSTRAP
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .expect("non-empty bootstrap");
        assert!(
            last.starts_with("bash \"$tmp/appimage-install.sh\""),
            "last line: {last}"
        );
        assert!(!last.starts_with("exec"), "the EXIT trap must still run");
        assert!(!BOOTSTRAP.contains("[["));
        assert!(!BOOTSTRAP.contains("pipefail"));
        assert!(!BOOTSTRAP.contains("--force"));
    }

    /// Every file `run_service_script` stages must be one `stage-payload.sh`
    /// bundles, or the AppImage build ships an installer that cannot run.
    #[test]
    fn payload_files_are_staged() {
        for name in PAYLOAD_FILES {
            assert!(
                STAGE_SCRIPT.contains(&format!("\"$DEST/{name}\"")),
                "{name} is not staged by stage-payload.sh"
            );
        }
    }

    /// The paths and exit codes `installer_error` and the skew advice rely
    /// on are spelled out in the script and the deb maintainer script.
    #[test]
    fn installer_script_agrees_on_paths_and_codes() {
        assert!(INSTALL_SCRIPT.contains(&format!("\nPACKAGED_BIN={PACKAGED_DAEMON_BIN}\n")));
        assert!(INSTALL_SCRIPT.contains(&format!("\nBIN={LOCAL_DAEMON_BIN}\n")));
        assert!(INSTALL_SCRIPT.contains("exit 98"));
        assert!(INSTALL_SCRIPT.contains("exit 99"));
        assert!(INSTALL_SCRIPT.contains("sort -V"));
        // A payload dir that forbids execution (noexec /tmp) skips the
        // downgrade guard; it must not fail the install.
        assert!(INSTALL_SCRIPT.contains("rc == 126"));
        assert!(INSTALL_SCRIPT.contains("downgrade check skipped"));
        // A failed teardown must fail the removal: exit 0 is what the GUI
        // reports as "Service removed".
        assert!(!INSTALL_SCRIPT.contains("cleanup || true"));
        assert!(INSTALL_SCRIPT.starts_with("#!/usr/bin/env bash\n"));
        for action in [ServiceAction::Install, ServiceAction::Uninstall] {
            assert!(
                INSTALL_SCRIPT.contains(&format!("\n    {})\n", action.arg())),
                "no `{}` arm in the script's case",
                action.arg()
            );
        }
        assert!(DEBIAN_PRERM.contains(PACKAGED_DAEMON_BIN));
    }
}
