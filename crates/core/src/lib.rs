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

/// What caused a block to become active. Affects how it's ended.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Originator {
    /// Started by an explicit `start_block` IPC call.
    Manual,
    /// Started by the recurring-schedule engine.
    Schedule { schedule_id: u64 },
}

/// A block that is currently being enforced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveBlock {
    pub block: Block,
    pub started_at_unix: u64,
    pub ends_at_unix: u64,
    #[serde(default = "default_originator")]
    pub originator: Originator,
}

fn default_originator() -> Originator {
    Originator::Manual
}

/// A recurring weekly schedule that automatically activates a block during a
/// daily time window on selected weekdays.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Schedule {
    pub id: u64,
    pub name: String,
    pub block_id: u64,
    /// Bitmask of days. Bit 0 = Sunday, bit 1 = Monday, ..., bit 6 = Saturday.
    pub days: u8,
    /// Minute of the day (local time) when the window opens, 0..1440.
    pub start_minute: u16,
    /// Window duration in minutes. Must satisfy `start_minute + duration <= 1440`.
    /// Schedules that would span midnight should be split into two schedules.
    pub duration_minutes: u16,
    pub enabled: bool,
}

/// Daemon-side persisted state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub next_id: u64,
    pub blocks: Vec<Block>,
    /// On-disk format may be `null` (pre-multi-block), `{ ... }` (single
    /// active block, pre-multi-block), or `[ ... ]` (current). All three
    /// are accepted on read; we always write the array form.
    #[serde(default, deserialize_with = "deserialize_active")]
    pub active: Vec<ActiveBlock>,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
    #[serde(default)]
    pub next_schedule_id: u64,
}

fn deserialize_active<'de, D>(d: D) -> Result<Vec<ActiveBlock>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OldOrNew {
        Many(Vec<ActiveBlock>),
        Single(ActiveBlock),
    }
    let v: Option<OldOrNew> = Option::deserialize(d)?;
    Ok(match v {
        Some(OldOrNew::Many(v)) => v,
        Some(OldOrNew::Single(s)) => vec![s],
        None => Vec::new(),
    })
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
    /// Rejected while any block is active in strict mode.
    CancelBlock {},
    AddSchedule { schedule: Schedule },
    UpdateSchedule { schedule: Schedule },
    DeleteSchedule { id: u64 },
    ListSchedules {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok {},
    Blocks { blocks: Vec<Block> },
    Status { active: Vec<ActiveBlock>, now_unix: u64 },
    Added { id: u64 },
    Schedules { schedules: Vec<Schedule> },
    Error { message: String },
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Day-bitmask helpers. Bit 0 = Sunday, 6 = Saturday.
pub const DAY_SUN: u8 = 1 << 0;
pub const DAY_MON: u8 = 1 << 1;
pub const DAY_TUE: u8 = 1 << 2;
pub const DAY_WED: u8 = 1 << 3;
pub const DAY_THU: u8 = 1 << 4;
pub const DAY_FRI: u8 = 1 << 5;
pub const DAY_SAT: u8 = 1 << 6;
pub const DAYS_WEEKDAYS: u8 = DAY_MON | DAY_TUE | DAY_WED | DAY_THU | DAY_FRI;
pub const DAYS_ALL: u8 = 0b0111_1111;

/// True if `days` includes weekday `n` (0=Sun..6=Sat).
pub fn day_set(days: u8, n: u8) -> bool {
    n < 7 && (days & (1 << n)) != 0
}
