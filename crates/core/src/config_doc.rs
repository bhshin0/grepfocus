//! The portable export/import document: blocks and schedules as plain JSON.
//!
//! Pure — no I/O, no clock, no license checks. The daemon's import handler
//! applies the license gates to the [`ImportPlan`] this module returns and
//! performs the swap; the GUI runs [`parse`] first so a bad file gets its
//! error without a round trip. [`build`] takes ONLY blocks and schedules, so
//! the password hash, license, high-water mark, stats, break history, active
//! blocks, pomodoro and settings are excluded by construction.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::validate::{
    excerpt, schedules_equivalent, validate_block, validate_schedule, MAX_BLOCK_NAME_CHARS,
};
use crate::{validate_policy, Block, Schedule};

/// Document format version. Readers refuse anything newer than this; bump it
/// when an older build could misread a newer file.
pub const SCHEMA: u32 = 1;
/// Largest text [`parse`] accepts. Under `wire::MAX_FRAME` (16 MiB) with
/// room for the request envelope, so a parsed document always fits a frame.
pub const MAX_DOC_BYTES: usize = 8 << 20;
/// Most blocks a document may hold. [`parse`] and [`plan_import`] both
/// refuse more, so the per-block validation and rename bookkeeping an import
/// does is bounded whichever way a document reaches it.
pub const MAX_DOC_BLOCKS: usize = 1000;
/// Most schedules a document may hold; see [`MAX_DOC_BLOCKS`].
pub const MAX_DOC_SCHEDULES: usize = 2000;

/// What an export file holds. Unknown top-level keys are tolerated (a newer
/// build may add some); `blocks`/`schedules` default so a hand-trimmed file
/// still parses. An unknown allowance-policy kind inside a block degrades
/// rather than fails, via `Block`'s `lenient_policy`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigDoc {
    pub schema: u32,
    pub exported_at_unix: u64,
    pub app_version: String,
    #[serde(default)]
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
}

/// How an import combines with what is already saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportMode {
    /// Add the file's blocks and schedules next to the existing ones.
    Merge,
    /// Drop every saved block and schedule first.
    Replace,
}

/// The new configuration an import would produce, computed without touching
/// state so the caller can gate it and swap it in all-or-nothing.
#[derive(Clone, Debug)]
pub struct ImportPlan {
    /// The full block list after the import (existing ones first on Merge).
    pub blocks: Vec<Block>,
    /// The full schedule list after the import.
    pub schedules: Vec<Schedule>,
    /// The counters after assigning every imported record a fresh id.
    pub next_id: u64,
    pub next_schedule_id: u64,
    /// `(name in the file, name saved)` for every block renamed to avoid a
    /// collision.
    pub renamed: Vec<(String, String)>,
    /// Schedules in the file dropped as duplicates of one earlier in the
    /// file (same block, days and window).
    pub skipped_schedules: usize,
}

/// The export document for `blocks` and `schedules` as they are saved.
pub fn build(
    blocks: &[Block],
    schedules: &[Schedule],
    now_unix: u64,
    app_version: &str,
) -> ConfigDoc {
    ConfigDoc {
        schema: SCHEMA,
        exported_at_unix: now_unix,
        app_version: app_version.to_string(),
        blocks: blocks.to_vec(),
        schedules: schedules.to_vec(),
    }
}

/// Parse an export file. `Err` is the user-facing text; the schema check is
/// repeated by the daemon, which is the authority.
pub fn parse(json: &str) -> Result<ConfigDoc, String> {
    if json.len() > MAX_DOC_BYTES {
        return Err(format!(
            "file is too large (max {} MiB)",
            MAX_DOC_BYTES >> 20
        ));
    }
    let doc: ConfigDoc =
        serde_json::from_str(json).map_err(|e| format!("not a GrepFocus export: {e}"))?;
    if doc.schema == 0 {
        return Err("not a GrepFocus export: missing schema".into());
    }
    if doc.schema > SCHEMA {
        return Err(format!(
            "exported by a newer GrepFocus (schema {}) — update first",
            doc.schema
        ));
    }
    check_counts(&doc)?;
    Ok(doc)
}

/// The record caps, shared by [`parse`] and [`plan_import`] so a document
/// built in memory gets the same refusal as one read from disk.
fn check_counts(doc: &ConfigDoc) -> Result<(), String> {
    if doc.blocks.len() > MAX_DOC_BLOCKS {
        return Err(format!("file holds too many blocks (max {MAX_DOC_BLOCKS})"));
    }
    if doc.schedules.len() > MAX_DOC_SCHEDULES {
        return Err(format!(
            "file holds too many schedules (max {MAX_DOC_SCHEDULES})"
        ));
    }
    Ok(())
}

/// Plan an import of `doc` over the saved configuration.
///
/// Ids always continue from the current counters and are never reused, even
/// on Replace, because `stats.sessions` and `breaks` reference block ids.
/// Blocks get the same validation and policy normalization as `AddBlock`,
/// with the error prefixed by the block's name; a name already in the result
/// becomes `"{name} (imported)"`, then `"{name} (imported 2)"` and so on,
/// cut back so it never exceeds the name cap. Schedules are remapped onto
/// the imported blocks and validated; a duplicate of one earlier in the file
/// (same block, days and window) is skipped and counted, not refused. Since
/// every imported block gets a fresh id, an imported schedule can never be
/// equivalent to a saved one. Nothing here is license-gated — the caller
/// gates the plan.
pub fn plan_import(
    doc: ConfigDoc,
    existing_blocks: &[Block],
    existing_schedules: &[Schedule],
    next_id: u64,
    next_schedule_id: u64,
    mode: ImportMode,
) -> Result<ImportPlan, String> {
    if doc.blocks.is_empty() && doc.schedules.is_empty() {
        return Err("the file contains no blocks or schedules".into());
    }
    check_counts(&doc)?;
    let (mut blocks, mut schedules) = match mode {
        ImportMode::Merge => (existing_blocks.to_vec(), existing_schedules.to_vec()),
        ImportMode::Replace => (Vec::new(), Vec::new()),
    };
    let mut next_id = next_id;
    let mut next_schedule_id = next_schedule_id;
    let mut id_map: HashMap<u64, u64> = HashMap::with_capacity(doc.blocks.len());
    let mut renamed = Vec::new();
    let mut names = NameAllocator::seeded(blocks.iter().map(|b| b.name.as_str()));

    for mut block in doc.blocks {
        let label = excerpt(&block.name);
        if id_map.contains_key(&block.id) {
            return Err(format!(
                "block {label:?}: id {} appears twice in the file",
                block.id
            ));
        }
        validate_block(&mut block).map_err(|e| format!("block {label:?}: {e}"))?;
        if let Some(msg) = validate_policy(&block.policy()) {
            return Err(format!("block {label:?}: {msg}"));
        }
        block.set_policy(block.policy());
        let name = names.claim(&block.name);
        if name != block.name {
            renamed.push((block.name.clone(), name.clone()));
            block.name = name;
        }
        id_map.insert(block.id, next_id);
        block.id = next_id;
        next_id = next_id.checked_add(1).ok_or("id counter exhausted")?;
        blocks.push(block);
    }

    let mut skipped_schedules = 0;
    for mut s in doc.schedules {
        let label = excerpt(&s.name);
        let Some(&block_id) = id_map.get(&s.block_id) else {
            return Err(format!(
                "schedule {label:?}: refers to block id {} which is not in the file",
                s.block_id
            ));
        };
        s.block_id = block_id;
        validate_schedule(&s).map_err(|e| format!("schedule {label:?}: {e}"))?;
        // A linear scan per schedule: the caps bound it at a few million
        // four-field compares, and `schedules_equivalent` stays the one
        // definition of "the same schedule".
        if schedules.iter().any(|t| schedules_equivalent(t, &s)) {
            skipped_schedules += 1;
            continue;
        }
        s.id = next_schedule_id;
        next_schedule_id = next_schedule_id
            .checked_add(1)
            .ok_or("id counter exhausted")?;
        schedules.push(s);
    }

    Ok(ImportPlan {
        blocks,
        schedules,
        next_id,
        next_schedule_id,
        renamed,
        skipped_schedules,
    })
}

/// Hands out block names that are unique within one import: `name` itself
/// when free, else the first free `"{name} (imported)"`,
/// `"{name} (imported 2)"`, … so an import is lossless and the copies are
/// visible. Linear over the file: membership is a set lookup and each base
/// name remembers the next suffix to try, so a thousand blocks sharing one
/// name cost a thousand steps, not a million. A suffixed name is cut back by
/// characters to stay within [`MAX_BLOCK_NAME_CHARS`].
struct NameAllocator {
    taken: HashSet<String>,
    next_suffix: HashMap<String, u32>,
}

impl NameAllocator {
    fn seeded<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            taken: names.into_iter().map(str::to_string).collect(),
            next_suffix: HashMap::new(),
        }
    }

    /// The name to save `name` under; marked taken for the rest of the import.
    fn claim(&mut self, name: &str) -> String {
        if !self.taken.contains(name) {
            self.taken.insert(name.to_string());
            return name.to_string();
        }
        let n = self.next_suffix.entry(name.to_string()).or_insert(1);
        loop {
            let suffix = if *n == 1 {
                " (imported)".to_string()
            } else {
                format!(" (imported {n})")
            };
            *n += 1;
            let candidate = format!("{}{suffix}", fit(name, &suffix));
            if !self.taken.contains(&candidate) {
                self.taken.insert(candidate.clone());
                return candidate;
            }
        }
    }
}

/// `base` cut back by characters so `base + suffix` fits
/// [`MAX_BLOCK_NAME_CHARS`].
fn fit(base: &str, suffix: &str) -> String {
    let room = MAX_BLOCK_NAME_CHARS.saturating_sub(suffix.chars().count());
    base.chars().take(room).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowancePolicy, AppMatcher, LockMode, DAYS_WEEKDAYS};

    fn block(id: u64, name: &str, domains: &[&str]) -> Block {
        Block {
            id,
            name: name.into(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
            apps: vec![],
            allowance_secs_per_day: 0,
            allowance: None,
            lock: LockMode::Unlocked,
        }
    }

    fn sched(id: u64, block_id: u64, start: u16, dur: u16) -> Schedule {
        Schedule {
            id,
            name: format!("s{id}"),
            block_id,
            days: DAYS_WEEKDAYS,
            start_minute: start,
            duration_minutes: dur,
            enabled: true,
        }
    }

    fn doc(blocks: Vec<Block>, schedules: Vec<Schedule>) -> ConfigDoc {
        build(&blocks, &schedules, 1_752_192_000, "0.7.0")
    }

    fn names(blocks: &[Block]) -> Vec<&str> {
        blocks.iter().map(|b| b.name.as_str()).collect()
    }

    #[test]
    fn build_then_parse_round_trips() {
        let mut b = block(4, "Social", &["reddit.com"]);
        b.set_policy(AllowancePolicy::RollingWindow {
            secs: 300,
            window_secs: 3600,
        });
        b.lock = LockMode::ChallengeBreaks;
        b.apps.push(AppMatcher::Basename {
            name: "steam".into(),
        });
        let d = doc(vec![b], vec![sched(9, 4, 23 * 60, 120)]);
        let json = serde_json::to_string_pretty(&d).unwrap();
        let back = parse(&json).unwrap();
        assert_eq!(back.schema, SCHEMA);
        assert_eq!(back.exported_at_unix, 1_752_192_000);
        assert_eq!(back.app_version, "0.7.0");
        assert_eq!(back.blocks.len(), 1);
        assert_eq!(back.blocks[0].id, 4);
        assert_eq!(back.blocks[0].name, "Social");
        assert_eq!(back.blocks[0].domains, ["reddit.com"]);
        assert_eq!(back.blocks[0].lock, LockMode::ChallengeBreaks);
        assert_eq!(
            back.blocks[0].policy(),
            AllowancePolicy::RollingWindow {
                secs: 300,
                window_secs: 3600
            }
        );
        assert_eq!(back.blocks[0].apps.len(), 1);
        assert_eq!(back.schedules.len(), 1);
        assert_eq!(back.schedules[0].block_id, 4);
        assert_eq!(back.schedules[0].duration_minutes, 120);
    }

    // The file carries exactly these keys and nothing else — no password,
    // license, stats, breaks, actives, pomodoro or settings can ride along.
    #[test]
    fn doc_has_exactly_five_top_level_keys() {
        let d = doc(vec![block(1, "x", &["reddit.com"])], vec![]);
        let v: serde_json::Value = serde_json::to_value(&d).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "app_version",
                "blocks",
                "exported_at_unix",
                "schedules",
                "schema"
            ]
        );
    }

    #[test]
    fn parse_rejects_garbage_oversize_and_newer_schema() {
        let e = parse("not json").unwrap_err();
        assert!(e.starts_with("not a GrepFocus export: "), "{e}");
        let e = parse(r#"{"blocks": []}"#).unwrap_err();
        assert!(e.starts_with("not a GrepFocus export: "), "{e}");
        assert!(e.contains("schema"), "{e}");
        let e = parse(r#"{"schema": 0, "exported_at_unix": 0, "app_version": "x"}"#).unwrap_err();
        assert_eq!(e, "not a GrepFocus export: missing schema");
        let e = parse(r#"{"schema": 2, "exported_at_unix": 0, "app_version": "x"}"#).unwrap_err();
        assert_eq!(e, "exported by a newer GrepFocus (schema 2) — update first");
        let big = "x".repeat(MAX_DOC_BYTES + 1);
        let e = parse(&big).unwrap_err();
        assert_eq!(e, "file is too large (max 8 MiB)");
        // The cap is on the text, not the parse: a bad file under it still
        // gets the parse error.
        let d = doc(vec![], vec![]);
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            parse(&json).is_ok(),
            "an empty doc parses; plan_import refuses it"
        );
    }

    // Forward/backward tolerance: a missing `schedules` key, an unknown
    // top-level key and an unknown policy kind all parse.
    #[test]
    fn doc_without_schedules_key_parses() {
        let json = r#"{
            "schema": 1,
            "exported_at_unix": 1,
            "app_version": "9.9.9",
            "from_the_future": {"nested": true},
            "blocks": [{
                "id": 1, "name": "x", "domains": ["reddit.com"], "apps": [],
                "allowance_secs_per_day": 60,
                "allowance": {"kind": "lunar", "secs": 1}
            }]
        }"#;
        let d = parse(json).unwrap();
        assert!(d.schedules.is_empty());
        assert_eq!(d.blocks.len(), 1);
        assert_eq!(d.blocks[0].policy(), AllowancePolicy::PerDay { secs: 60 });
    }

    #[test]
    fn plan_reassigns_ids_and_remaps_schedules() {
        let existing = vec![block(1, "Work", &["news.ycombinator.com"])];
        let existing_s = vec![sched(1, 1, 540, 60)];
        // File ids collide with the saved ones on purpose.
        let d = doc(
            vec![
                block(1, "Social", &["Reddit.com"]),
                block(2, "Games", &["store.steampowered.com"]),
            ],
            vec![sched(1, 2, 20 * 60, 120), sched(2, 1, 8 * 60, 30)],
        );
        let p = plan_import(d, &existing, &existing_s, 7, 3, ImportMode::Merge).unwrap();
        assert_eq!(names(&p.blocks), ["Work", "Social", "Games"]);
        let ids: Vec<u64> = p.blocks.iter().map(|b| b.id).collect();
        assert_eq!(ids, [1, 7, 8]);
        assert_eq!(p.next_id, 9);
        // Normalized like AddBlock: domain canonical, policy mirror written.
        assert_eq!(p.blocks[1].domains, ["reddit.com"]);
        assert_eq!(p.blocks[1].allowance, Some(AllowancePolicy::Disabled));
        // Schedules follow their block to its NEW id, in file order, after
        // the existing one, with fresh ids.
        let refs: Vec<(u64, u64)> = p.schedules.iter().map(|s| (s.id, s.block_id)).collect();
        assert_eq!(refs, [(1, 1), (3, 8), (4, 7)]);
        assert_eq!(p.next_schedule_id, 5);
        assert!(p.renamed.is_empty());
        assert_eq!(p.skipped_schedules, 0);
    }

    #[test]
    fn plan_renames_collisions_with_suffix_and_counter() {
        let existing = vec![
            block(1, "Social", &["reddit.com"]),
            block(2, "Social (imported)", &["x.com"]),
        ];
        let d = doc(
            vec![
                block(10, "Social", &["reddit.com"]),
                block(11, "Social", &["reddit.com"]),
                block(12, "Fresh", &["reddit.com"]),
            ],
            vec![],
        );
        let p = plan_import(d, &existing, &[], 3, 1, ImportMode::Merge).unwrap();
        assert_eq!(
            names(&p.blocks),
            [
                "Social",
                "Social (imported)",
                "Social (imported 2)",
                "Social (imported 3)",
                "Fresh"
            ]
        );
        assert_eq!(
            p.renamed,
            [
                ("Social".to_string(), "Social (imported 2)".to_string()),
                ("Social".to_string(), "Social (imported 3)".to_string()),
            ]
        );
    }

    fn many_blocks(n: usize, name: &str) -> Vec<Block> {
        (0..n)
            .map(|i| block(i as u64 + 1, name, &["reddit.com"]))
            .collect()
    }

    /// `n` schedules on block 1, no two with the same window, none past
    /// midnight.
    fn many_schedules(n: usize) -> Vec<Schedule> {
        (0..n)
            .map(|i| sched(i as u64 + 1, 1, (i % 1440) as u16, 1 + (i / 1440) as u16))
            .collect()
    }

    // Exactly the cap parses; one more is refused with the record text, not
    // the byte cap (these files are far under 8 MiB).
    #[test]
    fn parse_rejects_too_many_blocks_and_schedules() {
        let at_cap = doc(
            many_blocks(MAX_DOC_BLOCKS, "b"),
            many_schedules(MAX_DOC_SCHEDULES),
        );
        let json = serde_json::to_string(&at_cap).unwrap();
        assert!(json.len() < MAX_DOC_BYTES);
        let back = parse(&json).unwrap();
        assert_eq!(back.blocks.len(), MAX_DOC_BLOCKS);
        assert_eq!(back.schedules.len(), MAX_DOC_SCHEDULES);

        let json =
            serde_json::to_string(&doc(many_blocks(MAX_DOC_BLOCKS + 1, "b"), vec![])).unwrap();
        assert_eq!(
            parse(&json).unwrap_err(),
            "file holds too many blocks (max 1000)"
        );
        let json =
            serde_json::to_string(&doc(vec![], many_schedules(MAX_DOC_SCHEDULES + 1))).unwrap();
        assert_eq!(
            parse(&json).unwrap_err(),
            "file holds too many schedules (max 2000)"
        );
    }

    // The same caps hold for a document that never went through `parse`.
    // At the cap every block shares one name, so the whole rename sequence
    // runs: "Social", "(imported)", "(imported 2)" … "(imported 999)".
    #[test]
    fn plan_import_rejects_too_many_blocks_and_schedules() {
        let at_cap = doc(
            many_blocks(MAX_DOC_BLOCKS, "Social"),
            many_schedules(MAX_DOC_SCHEDULES),
        );
        let p = plan_import(at_cap, &[], &[], 1, 1, ImportMode::Merge).unwrap();
        assert_eq!(p.blocks.len(), MAX_DOC_BLOCKS);
        assert_eq!(p.schedules.len(), MAX_DOC_SCHEDULES);
        assert_eq!(p.skipped_schedules, 0);
        assert_eq!(p.renamed.len(), MAX_DOC_BLOCKS - 1);
        assert_eq!(p.blocks[0].name, "Social");
        assert_eq!(p.blocks[1].name, "Social (imported)");
        assert_eq!(p.blocks[2].name, "Social (imported 2)");
        assert_eq!(p.blocks[999].name, "Social (imported 999)");
        let distinct: std::collections::HashSet<&str> = names(&p.blocks).into_iter().collect();
        assert_eq!(distinct.len(), MAX_DOC_BLOCKS);

        let d = doc(many_blocks(MAX_DOC_BLOCKS + 1, "b"), vec![]);
        assert_eq!(
            plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err(),
            "file holds too many blocks (max 1000)"
        );
        let d = doc(
            vec![block(1, "b", &["reddit.com"])],
            many_schedules(MAX_DOC_SCHEDULES + 1),
        );
        assert_eq!(
            plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err(),
            "file holds too many schedules (max 2000)"
        );
    }

    // A name at the cap gains its suffix by losing characters, never by
    // exceeding the cap the daemon would then refuse.
    #[test]
    fn plan_rename_never_exceeds_the_name_cap() {
        let long = "n".repeat(MAX_BLOCK_NAME_CHARS);
        let existing = vec![block(1, &long, &["reddit.com"])];
        let d = doc(
            vec![
                block(1, &long, &["reddit.com"]),
                block(2, &long, &["x.com"]),
            ],
            vec![],
        );
        let p = plan_import(d, &existing, &[], 2, 1, ImportMode::Merge).unwrap();
        let a = p.blocks[1].name.as_str();
        let b = p.blocks[2].name.as_str();
        assert_eq!(a.chars().count(), MAX_BLOCK_NAME_CHARS, "{a}");
        assert_eq!(b.chars().count(), MAX_BLOCK_NAME_CHARS, "{b}");
        assert_ne!(a, b);
        assert_ne!(a, long);
        assert!(a.ends_with("n (imported)"), "{a}");
        assert!(b.ends_with("n (imported 2)"), "{b}");
        assert_eq!(p.renamed.len(), 2);

        // Cut by characters, never inside a multi-byte one.
        let wide = "é".repeat(MAX_BLOCK_NAME_CHARS);
        let existing = vec![block(1, &wide, &["reddit.com"])];
        let d = doc(vec![block(1, &wide, &["x.com"])], vec![]);
        let p = plan_import(d, &existing, &[], 2, 1, ImportMode::Merge).unwrap();
        let w = p.blocks[1].name.as_str();
        assert_eq!(w.chars().count(), MAX_BLOCK_NAME_CHARS, "{w}");
        assert!(w.starts_with("éé") && w.ends_with("é (imported)"), "{w}");
    }

    #[test]
    fn plan_skips_equivalent_schedules() {
        let existing = vec![block(1, "Work", &["reddit.com"])];
        let existing_s = vec![sched(1, 1, 540, 60)];
        let mut dup_in_file = sched(3, 5, 20 * 60, 60);
        dup_in_file.name = "same window, other name".into();
        let d = doc(
            vec![block(5, "Imported", &["x.com"])],
            vec![
                sched(2, 5, 20 * 60, 60),
                dup_in_file,
                sched(4, 5, 6 * 60, 30),
            ],
        );
        let p = plan_import(d, &existing, &existing_s, 2, 2, ImportMode::Merge).unwrap();
        assert_eq!(p.schedules.len(), 3, "existing + two distinct imported");
        assert_eq!(p.skipped_schedules, 1);
        assert_eq!(p.next_schedule_id, 4, "a skipped schedule consumes no id");
    }

    #[test]
    fn plan_replace_ignores_existing_but_keeps_counters() {
        let existing = vec![block(1, "Social", &["reddit.com"])];
        let existing_s = vec![sched(1, 1, 540, 60)];
        let d = doc(
            vec![block(1, "Social", &["reddit.com"])],
            vec![sched(1, 1, 540, 60)],
        );
        let p = plan_import(d, &existing, &existing_s, 2, 2, ImportMode::Replace).unwrap();
        assert_eq!(
            names(&p.blocks),
            ["Social"],
            "no rename: the old one is gone"
        );
        assert_eq!(p.blocks[0].id, 2, "ids are never reused");
        assert_eq!(p.next_id, 3);
        assert_eq!(
            p.schedules.len(),
            1,
            "the equivalent OLD schedule is not in the result"
        );
        assert_eq!(p.schedules[0].id, 2);
        assert_eq!(p.schedules[0].block_id, 2);
        assert_eq!(p.next_schedule_id, 3);
        assert_eq!(p.skipped_schedules, 0);
    }

    #[test]
    fn plan_rejects_duplicate_ids_and_dangling_block_refs() {
        let d = doc(
            vec![block(1, "A", &["reddit.com"]), block(1, "B", &["x.com"])],
            vec![],
        );
        assert_eq!(
            plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err(),
            "block \"B\": id 1 appears twice in the file"
        );
        // A schedule must point at a block IN THE FILE — not at a saved one,
        // whose id the file cannot know.
        let existing = vec![block(7, "Saved", &["reddit.com"])];
        let d = doc(vec![block(1, "A", &["x.com"])], vec![sched(1, 7, 540, 60)]);
        assert_eq!(
            plan_import(d, &existing, &[], 8, 1, ImportMode::Merge).unwrap_err(),
            "schedule \"s1\": refers to block id 7 which is not in the file"
        );
    }

    #[test]
    fn plan_rejects_empty_doc() {
        let d = doc(vec![], vec![]);
        assert_eq!(
            plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err(),
            "the file contains no blocks or schedules"
        );
    }

    // Validation runs with AddBlock's exact text, prefixed by the name, and
    // a policy out of range is caught before anything is assigned.
    #[test]
    fn plan_prefixes_validation_errors_with_the_name() {
        let d = doc(
            vec![block(1, "Social", &["reddit.com\n0.0.0.0 evil"])],
            vec![],
        );
        let e = plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err();
        assert!(e.starts_with("block \"Social\": domain "), "{e}");
        let mut b = block(1, "Social", &["reddit.com"]);
        b.set_policy(AllowancePolicy::PerDay { secs: 0 });
        let d = doc(vec![b], vec![]);
        let e = plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err();
        assert!(e.starts_with("block \"Social\": "), "{e}");
        let d = doc(
            vec![block(1, "Social", &["reddit.com"])],
            vec![Schedule {
                days: 0,
                ..sched(1, 1, 540, 60)
            }],
        );
        let e = plan_import(d, &[], &[], 1, 1, ImportMode::Merge).unwrap_err();
        assert_eq!(e, "schedule \"s1\": at least one weekday must be selected");
    }

    #[test]
    fn import_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ImportMode::Merge).unwrap(),
            r#""merge""#
        );
        assert_eq!(
            serde_json::to_string(&ImportMode::Replace).unwrap(),
            r#""replace""#
        );
        let m: ImportMode = serde_json::from_str(r#""replace""#).unwrap();
        assert_eq!(m, ImportMode::Replace);
    }
}
