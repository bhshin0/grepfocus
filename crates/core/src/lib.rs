//! Shared types and helpers for the frostbite daemon and clients.
//!
//! The wire protocol is length-prefixed JSON: a 4-byte big-endian u32 holding
//! the byte length of the payload, followed by the JSON payload itself.
//! Both directions use the same framing.

use serde::{Deserialize, Serialize};

pub mod hmac_sig;
pub mod wire;

/// A named bundle of things to block.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Block {
    pub id: u64,
    pub name: String,
    pub domains: Vec<String>,
    pub apps: Vec<AppMatcher>,
}

/// How to identify a process to kill.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppMatcher {
    /// Match `/proc/<pid>/exe` resolved path exactly.
    ExePath { path: String },
    /// Match the basename of `/proc/<pid>/exe` (e.g. "steam").
    Basename { name: String },
    /// Match a substring inside `/proc/<pid>/cmdline` (for flatpak/snap wrappers).
    Cmdline { contains: String },
}

/// A block that is currently being enforced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveBlock {
    pub block: Block,
    pub started_at_unix: u64,
    pub ends_at_unix: u64,
}

/// Daemon-side persisted state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub next_id: u64,
    pub blocks: Vec<Block>,
    pub active: Option<ActiveBlock>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    AddBlock { block: Block },
    UpdateBlock { block: Block },
    DeleteBlock { id: u64 },
    ListBlocks {},
    GetStatus {},
    StartBlock { id: u64, duration_secs: u64 },
    /// Rejected while a block is active in strict mode.
    CancelBlock {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok {},
    Blocks { blocks: Vec<Block> },
    Status { active: Option<ActiveBlock>, now_unix: u64 },
    Added { id: u64 },
    Error { message: String },
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
