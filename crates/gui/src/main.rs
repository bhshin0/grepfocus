// Prevent additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;

use frostbite_core::{ActiveBlock, Block, Request, Response, Schedule};
use tauri::{WebviewUrl, WebviewWindowBuilder};

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
}

#[tauri::command]
async fn get_status() -> Result<StatusOut, String> {
    match client::call(Request::GetStatus {}).await? {
        Response::Status { active, now_unix } => Ok(StatusOut { active, now_unix }),
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

fn main() {
    // wry's custom URI scheme handler is unreliable on this webkit2gtk-4.1
    // build (2.52). Serve embedded assets via a real localhost HTTP server
    // instead. Note: this URL is treated as "remote" by Tauri 2's ACL, so
    // our app commands need explicit allow-* entries in capabilities/default.json.
    let port = portpicker::pick_unused_port().expect("no free port");

    tauri::Builder::default()
        .plugin(tauri_plugin_localhost::Builder::new(port).build())
        .setup(move |app| {
            let url = format!("http://localhost:{port}/index.html").parse().unwrap();
            let _win = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
                .title("Frostbite")
                .inner_size(900.0, 640.0)
                .min_inner_size(600.0, 480.0)
                .build()?;
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
