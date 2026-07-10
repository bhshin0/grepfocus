// Prevent additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;
mod tray;

use std::collections::HashMap;
use std::time::Duration;

use frostbite_core::{ActiveBlock, AllowanceLedger, Block, Request, Response, Schedule};
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

#[tauri::command]
async fn add_block(block: Block) -> Result<u64, String> {
    match client::call(Request::AddBlock { block }).await? {
        Response::Added { id } => Ok(id),
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

#[derive(serde::Serialize)]
struct StatusOut {
    active: Vec<ActiveBlock>,
    now_unix: u64,
    password_set: bool,
    unlocked: bool,
    allowance_used: Vec<AllowanceLedger>,
}

#[tauri::command]
async fn get_status() -> Result<StatusOut, String> {
    match client::call(Request::GetStatus {}).await? {
        Response::Status {
            active,
            now_unix,
            password_set,
            unlocked,
            allowance_used,
        } => Ok(StatusOut {
            active,
            now_unix,
            password_set,
            unlocked,
            allowance_used,
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
async fn unlock(password: String) -> Result<(), String> {
    match client::call(Request::Unlock { password }).await? {
        Response::Ok {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn take_break(block_id: u64, secs: u64) -> Result<(), String> {
    match client::call(Request::TakeBreak { block_id, secs }).await? {
        Response::Ok {} => Ok(()),
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

/// Fire a desktop notification. Best-effort — failures are ignored so a
/// missing notification daemon never disrupts the app.
fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
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
                        let _ = window.show();
                    }
                }
            }

            let active = match client::call(Request::GetStatus {}).await {
                Ok(Response::Status { active, .. }) => active,
                _ => {
                    // Daemon down / transient error. Surface it in the tooltip
                    // instead of leaving the stale "N active" text, but do NOT
                    // touch `prev`: keeping the notification baseline avoids a
                    // spurious burst of "block started/ended" when it recovers.
                    if let Some(tray) = app.tray_by_id("frostbite-tray") {
                        let _ = tray.set_tooltip(Some("Frostbite — daemon unreachable"));
                    }
                    continue;
                }
            };
            let cur: HashMap<u64, String> = active
                .iter()
                .map(|a| (a.block.id, a.block.name.clone()))
                .collect();

            if let Some(tray) = app.tray_by_id("frostbite-tray") {
                let tip = if cur.is_empty() {
                    "Frostbite — no active blocks".to_string()
                } else {
                    format!("Frostbite — {} active", cur.len())
                };
                let _ = tray.set_tooltip(Some(&tip));
            }

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
            prev = Some(cur);
        }
    });
}

fn main() {
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
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
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
                } else {
                    // Quit path: surface the tradeoff at the moment it bites —
                    // notifications work on stock GNOME even though the tray
                    // doesn't.
                    notify(
                        window.app_handle(),
                        "Frostbite closed",
                        "No block start/end notifications until you reopen it.",
                    );
                }
            }
        })
        .setup(move |app| {
            let url = format!("http://localhost:{port}/index.html")
                .parse()
                .unwrap();
            let _win = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("Frostbite")
                .inner_size(900.0, 640.0)
                .min_inner_size(600.0, 480.0)
                .build()?;

            let menu = MenuBuilder::new(app)
                .text("show", "Show Frostbite")
                .separator()
                .text("quit", "Quit")
                .build()?;

            TrayIconBuilder::with_id("frostbite-tray")
                .icon(app.default_window_icon().expect("bundled icon").clone())
                .tooltip("Frostbite — no active blocks")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
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
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            spawn_status_watcher(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_blocks,
            add_block,
            delete_block,
            start_block,
            get_status,
            list_schedules,
            add_schedule,
            update_schedule,
            delete_schedule,
            set_password,
            unlock,
            take_break,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
