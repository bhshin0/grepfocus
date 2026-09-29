// Prevent additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;
mod tray;

use std::collections::HashMap;
use std::time::Duration;

use grepfocus_core::{
    ActiveBlock, AllowanceLedger, AllowanceStatus, Block, DayStat, FocusSession, LifetimeTotals,
    PomodoroStatus, Request, Response, Schedule, Settings,
};
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

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
    /// Instant breaks wanted but a loopback port would not bind, so the
    /// frontend can explain why breaks lag on this machine.
    instant_breaks_degraded: bool,
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
        } => Ok(StatusOut {
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
        }),
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

/// What the frontend needs to know about how the app is running. Today only
/// whether we're an AppImage — which gates the first-run "install the system
/// service" flow: the pkexec installer only makes sense from an AppImage
/// (package installs already set the daemon up). AppRun sets $APPIMAGE.
#[derive(serde::Serialize)]
struct AppEnv {
    appimage: bool,
}

#[tauri::command]
fn app_env() -> AppEnv {
    AppEnv {
        appimage: std::env::var_os("APPIMAGE").is_some(),
    }
}

/// Install the system service from inside an AppImage by running the bundled
/// installer as root via pkexec. The daemon binary + unit/config files ride
/// along in the AppImage as Tauri resources (bundle.resources ->
/// resource_dir()/payload/); the script relocates them and enables the unit.
/// See packaging/appimage/appimage-install.sh.
#[tauri::command]
async fn install_service(app: AppHandle) -> Result<(), String> {
    // Resolve the target user in-process (the desktop user running the GUI),
    // not from the frontend — the script usermod's them into the grepfocus group.
    let user = std::env::var("USER").unwrap_or_default();
    run_service_script(&app, "install", Some(user)).await
}

#[tauri::command]
async fn uninstall_service(app: AppHandle) -> Result<(), String> {
    run_service_script(&app, "uninstall", None).await
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
/bin/sh "$tmp/appimage-install.sh" "$action" "$tgt_user"
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
    action: &str,
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

    let action = action.to_string();
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
                    .arg(&action)
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
    // pkexec itself: 126 = auth dialog dismissed, 127 = not authorized — but
    // once the program runs, the exit code is the program's, so only trust
    // those meanings when the run produced no stderr of its own.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    match output.status.code() {
        Some(126) if stderr.is_empty() => Err("Authorization was dismissed.".to_string()),
        Some(127) if stderr.is_empty() => {
            Err("Authentication failed or not authorized.".to_string())
        }
        Some(97) => Err(
            "Installer bundle failed its integrity check — re-download the AppImage.".to_string(),
        ),
        code => Err(format!(
            "Installer failed (exit {}): {}",
            code.unwrap_or(-1),
            stderr
        )),
    }
}

/// Fire a desktop notification. Best-effort — failures are ignored so a
/// missing notification daemon never disrupts the app.
fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
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
/// and fire a notification whenever a block starts or ends. Runs for the life
/// of the process (when a tray host is present, the window hides to tray
/// rather than closing), so notifications keep flowing even with no window
/// open. Also re-shows a hidden window if its tray host vanishes.
fn spawn_status_watcher(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // id -> block name. `None` until the first successful poll so we
        // establish a baseline without notifying for already-active blocks.
        let mut prev: Option<HashMap<u64, String>> = None;
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

            let (active, settings) = match client::call(Request::GetStatus {}).await {
                Ok(Response::Status {
                    active, settings, ..
                }) => (active, settings),
                _ => {
                    // Daemon down / transient error. Surface it in the tooltip
                    // instead of leaving the stale "N active" text, but do NOT
                    // touch `prev`: keeping the notification baseline avoids a
                    // spurious burst of "block started/ended" when it recovers.
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
            }
            prev = Some(cur);
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
