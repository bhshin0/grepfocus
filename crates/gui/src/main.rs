// Prevent additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;

use frostbite_core::{ActiveBlock, Block, Request, Response};

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
    active: Option<ActiveBlock>,
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_blocks,
            add_block,
            delete_block,
            start_block,
            get_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
