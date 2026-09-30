use std::process::Command;

/// Id of the one tray icon. Every lookup goes through `tray_by_id` with this
/// rather than holding a handle.
pub const TRAY_ID: &str = "grepfocus-tray";

/// Re-registrations tried while a present host keeps not listing the tray
/// item (or they keep failing on our side), before giving up until the host
/// next goes away and comes back.
const MAX_ATTEMPTS: u8 = 3;

/// What one read of the StatusNotifierWatcher says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostProbe {
    /// A StatusNotifier host (a visible tray) is registered.
    pub host: bool,
    /// Whether the watcher lists our tray item; `None` when the reply carries
    /// no readable listing, which must not be mistaken for "not listed".
    pub item_listed: Option<bool>,
}

/// Reads the StatusNotifierWatcher's properties on the user bus in one
/// process. Any failure (no watcher, timeout, no busctl) reads as "no tray"
/// so the window stays closable. Stock GNOME ships no host, so our tray icon
/// silently never renders even though TrayIconBuilder::build() succeeds.
/// NB: must be the `call` verb — `busctl get-property` silently ignores
/// --timeout/--auto-start (25s default method-call timeout, and it could
/// dbus-activate the name).
pub fn probe_host() -> HostProbe {
    let out = Command::new("busctl")
        .args([
            "--user",
            "--timeout=2",
            "--auto-start=no",
            "call",
            "org.kde.StatusNotifierWatcher",
            "/StatusNotifierWatcher",
            "org.freedesktop.DBus.Properties",
            "GetAll",
            "s",
            "org.kde.StatusNotifierWatcher",
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => parse_watcher_properties(
            &String::from_utf8_lossy(&out.stdout),
            &item_object_name(TRAY_ID),
        ),
        _ => HostProbe::default(),
    }
}

/// True when a StatusNotifier host is registered on the user bus.
pub fn status_notifier_host_present() -> bool {
    probe_host().host
}

/// Last segment of the object path the tray item is exported at. tray-icon
/// names the indicator "tray-icon tray app <tray id>" and libappindicator
/// exports it under that id with every non-alphanumeric byte replaced by `_`.
/// If either ever changes, the item reads as not listed and `TrayWatch`
/// spends its `MAX_ATTEMPTS` once per host appearance — no worse.
fn item_object_name(tray_id: &str) -> String {
    format!("tray-icon tray app {tray_id}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// One token of `busctl call` output: a quoted string or a bare word (a type
/// signature, a count, a boolean). Kept apart so that no string value, e.g.
/// an item another program registered, can pass for a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Str(String),
    Word(String),
}

/// Splits `busctl call` output. busctl C-escapes strings: a backslash keeps
/// the character after it, which undoes `\"` and `\\`; a value with any other
/// escape cannot be one of ours.
fn tokens(stdout: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut chars = stdout.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut s = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => s.extend(chars.next()),
                    _ => s.push(c),
                }
            }
            out.push(Token::Str(s));
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                s.push(c);
                chars.next();
            }
            out.push(Token::Word(s));
        }
    }
    out
}

/// The tokens after property `name` and its type signature `signature` in a
/// `Properties.GetAll` reply (`a{sv} N "Name" <signature> <value> …`).
fn property_value<'a>(toks: &'a [Token], name: &str, signature: &str) -> Option<&'a [Token]> {
    toks.windows(2)
        .position(|w| {
            matches!(&w[0], Token::Str(s) if s == name)
                && matches!(&w[1], Token::Word(s) if s == signature)
        })
        .map(|i| &toks[i + 2..])
}

/// Parses `a{sv} 3 "RegisteredStatusNotifierItems" as 1 ":1.42/org/ayatana/
/// NotificationItem/<name>" "IsStatusNotifierHostRegistered" b true …`.
/// Watchers disagree on the item format (unique bus name + path, or — the
/// GNOME AppIndicator extension — the bare path as it was registered), so
/// only the last path segment is matched.
fn parse_watcher_properties(stdout: &str, object_name: &str) -> HostProbe {
    let toks = tokens(stdout);
    let host = property_value(&toks, "IsStatusNotifierHostRegistered", "b")
        .and_then(<[Token]>::first)
        .is_some_and(|t| matches!(t, Token::Word(s) if s == "true"));
    let item_listed =
        property_value(&toks, "RegisteredStatusNotifierItems", "as").and_then(|value| match value
            .split_first()
        {
            Some((Token::Word(count), items)) => {
                let items = items.get(..count.parse().ok()?)?;
                Some(items.iter().any(|t| {
                    matches!(t, Token::Str(s)
                        if s.strip_suffix(object_name).is_some_and(|rest| rest.ends_with('/')))
                }))
            }
            _ => None,
        });
    HostProbe { host, item_listed }
}

/// What the status watcher does to the tray on one poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    None,
    /// Register the tray item with the host again.
    Reregister,
    /// `MAX_ATTEMPTS` re-registrations did not get the item listed; say so
    /// once and stop trying.
    GiveUp,
}

/// The absent→present edge of the tray host. `prev_host` is `None` until the
/// first poll, which only sets the baseline: startup has just built the tray
/// against whatever was there.
pub fn tray_action(prev_host: Option<bool>, host_now: bool) -> TrayAction {
    match (prev_host, host_now) {
        (Some(false), true) => TrayAction::Reregister,
        _ => TrayAction::None,
    }
}

/// Decides, poll by poll, when the tray item must be registered again: when
/// the host comes (back) up, and while a host that stayed up does not list
/// the item or the last re-registration failed on our side. At most one
/// action per poll, so a flapping host cannot cause more than one
/// re-registration per poll interval.
#[derive(Debug, Default)]
pub struct TrayWatch {
    prev_host: Option<bool>,
    /// Re-registrations since the item was last seen listed.
    attempts: u8,
    gave_up: bool,
}

impl TrayWatch {
    /// `item_listed` is `HostProbe::item_listed`; `last_failed` says the most
    /// recent re-registration could not be carried out. Both are ignored on
    /// the baseline poll (the item registers asynchronously after startup),
    /// on a host edge (that re-registers regardless) and after giving up.
    pub fn poll(
        &mut self,
        host_now: bool,
        item_listed: Option<bool>,
        last_failed: bool,
    ) -> TrayAction {
        let edge = tray_action(self.prev_host, host_now);
        let settled = self.prev_host == Some(true) && !self.gave_up;
        self.prev_host = Some(host_now);
        if !host_now {
            self.attempts = 0;
            self.gave_up = false;
            return TrayAction::None;
        }
        if edge == TrayAction::Reregister {
            self.attempts = 1;
            self.gave_up = false;
            return edge;
        }
        if !settled {
            return TrayAction::None;
        }
        if last_failed || item_listed == Some(false) {
            if self.attempts >= MAX_ATTEMPTS {
                self.gave_up = true;
                TrayAction::GiveUp
            } else {
                self.attempts += 1;
                TrayAction::Reregister
            }
        } else {
            if item_listed == Some(true) {
                self.attempts = 0;
            }
            TrayAction::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        item_object_name, parse_watcher_properties, tokens, tray_action, HostProbe, Token,
        TrayAction, TrayWatch, MAX_ATTEMPTS, TRAY_ID,
    };

    const ITEM: &str = "tray_icon_tray_app_grepfocus_tray";

    fn parse(stdout: &str) -> HostProbe {
        parse_watcher_properties(stdout, ITEM)
    }

    #[test]
    fn item_object_name_matches_the_exported_path() {
        // Observed on the bus: /org/ayatana/NotificationItem/<this>.
        assert_eq!(item_object_name(TRAY_ID), ITEM);
    }

    #[test]
    fn tokens_keep_strings_and_words_apart() {
        assert_eq!(
            tokens("a{sv} 1 \"Is Host\" b true\n"),
            vec![
                Token::Word("a{sv}".into()),
                Token::Word("1".into()),
                Token::Str("Is Host".into()),
                Token::Word("b".into()),
                Token::Word("true".into()),
            ]
        );
        assert_eq!(
            tokens(r#""a \" b true" "c:\\d""#),
            vec![Token::Str("a \" b true".into()), Token::Str("c:\\d".into())]
        );
        assert_eq!(tokens(""), vec![]);
        assert_eq!(
            tokens("\"unterminated"),
            vec![Token::Str("unterminated".into())]
        );
    }

    #[test]
    fn reads_host_and_item_from_one_reply() {
        // As the stub watcher and KDE list it: unique bus name + path.
        assert_eq!(
            parse(
                "a{sv} 3 \"RegisteredStatusNotifierItems\" as 1 \":1.5/org/ayatana/NotificationItem/tray_icon_tray_app_grepfocus_tray\" \"IsStatusNotifierHostRegistered\" b true \"ProtocolVersion\" i 0\n"
            ),
            HostProbe {
                host: true,
                item_listed: Some(true)
            }
        );
        // As the GNOME AppIndicator extension lists it: the bare path, here
        // after another program's item and with the properties reordered.
        assert_eq!(
            parse(
                "a{sv} 3 \"ProtocolVersion\" i 0 \"IsStatusNotifierHostRegistered\" b true \"RegisteredStatusNotifierItems\" as 2 \":1.9/StatusNotifierItem\" \"/org/ayatana/NotificationItem/tray_icon_tray_app_grepfocus_tray\""
            ),
            HostProbe {
                host: true,
                item_listed: Some(true)
            }
        );
    }

    #[test]
    fn host_without_our_item() {
        let empty = HostProbe {
            host: true,
            item_listed: Some(false),
        };
        assert_eq!(
            parse("a{sv} 2 \"RegisteredStatusNotifierItems\" as 0 \"IsStatusNotifierHostRegistered\" b true"),
            empty
        );
        assert_eq!(
            parse("a{sv} 2 \"RegisteredStatusNotifierItems\" as 1 \":1.9/StatusNotifierItem\" \"IsStatusNotifierHostRegistered\" b true"),
            empty
        );
        // A different indicator whose id merely ends the same way.
        assert_eq!(
            parse("a{sv} 2 \"RegisteredStatusNotifierItems\" as 1 \":1.7/org/ayatana/NotificationItem/other_tray_icon_tray_app_grepfocus_tray\" \"IsStatusNotifierHostRegistered\" b true"),
            empty
        );
        // Our name as a prefix of a longer one (a second tray id).
        assert_eq!(
            parse("a{sv} 2 \"RegisteredStatusNotifierItems\" as 1 \":1.7/org/ayatana/NotificationItem/tray_icon_tray_app_grepfocus_tray_2\" \"IsStatusNotifierHostRegistered\" b true"),
            empty
        );
    }

    #[test]
    fn watcher_without_a_host() {
        assert_eq!(
            parse("a{sv} 2 \"RegisteredStatusNotifierItems\" as 0 \"IsStatusNotifierHostRegistered\" b false"),
            HostProbe {
                host: false,
                item_listed: Some(false)
            }
        );
    }

    #[test]
    fn unreadable_listing_is_unknown_not_unlisted() {
        // The listing property failed on the watcher's side and is left out.
        assert_eq!(
            parse("a{sv} 2 \"IsStatusNotifierHostRegistered\" b true \"ProtocolVersion\" i 0"),
            HostProbe {
                host: true,
                item_listed: None
            }
        );
        // Fewer entries than announced.
        assert_eq!(
            parse("a{sv} 2 \"IsStatusNotifierHostRegistered\" b true \"RegisteredStatusNotifierItems\" as 2 \"/x\""),
            HostProbe {
                host: true,
                item_listed: None
            }
        );
    }

    #[test]
    fn anything_else_is_no_tray() {
        for out in ["", "a{sv} 0", "b true", "v b true", "true", "s \"x\""] {
            assert_eq!(parse(out), HostProbe::default(), "{out:?}");
        }
    }

    #[test]
    fn a_string_value_cannot_pass_for_a_property() {
        // Another program's items, named to look like the host flag.
        assert_eq!(
            parse("a{sv} 2 \"RegisteredStatusNotifierItems\" as 2 \"IsStatusNotifierHostRegistered\" \"x \\\"IsStatusNotifierHostRegistered\\\" b true\" \"IsStatusNotifierHostRegistered\" b false"),
            HostProbe {
                host: false,
                item_listed: Some(false)
            }
        );
    }

    #[test]
    fn edge_is_absent_to_present_only() {
        assert_eq!(tray_action(Some(false), true), TrayAction::Reregister);
        assert_eq!(tray_action(Some(true), true), TrayAction::None);
        assert_eq!(tray_action(Some(true), false), TrayAction::None);
        assert_eq!(tray_action(Some(false), false), TrayAction::None);
    }

    #[test]
    fn first_poll_is_a_baseline() {
        assert_eq!(tray_action(None, true), TrayAction::None);
        assert_eq!(tray_action(None, false), TrayAction::None);
    }

    /// One poll whose re-registrations all succeed on our side.
    fn poll(w: &mut TrayWatch, host: bool, listed: bool) -> TrayAction {
        w.poll(host, Some(listed), false)
    }

    #[test]
    fn steady_host_with_listed_item_does_nothing() {
        let mut w = TrayWatch::default();
        for _ in 0..10 {
            assert_eq!(poll(&mut w, true, true), TrayAction::None);
        }
    }

    #[test]
    fn baseline_poll_does_not_act() {
        let mut w = TrayWatch::default();
        // Not listed yet: the item registers asynchronously after startup.
        assert_eq!(poll(&mut w, true, false), TrayAction::None);
    }

    #[test]
    fn host_restart_reregisters_once() {
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
    }

    #[test]
    fn host_restart_reregisters_an_item_that_is_already_listed() {
        // The item registers itself with the returning host; the edge still
        // re-sets the menu for it.
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        assert_eq!(poll(&mut w, true, true), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
    }

    #[test]
    fn host_appearing_after_startup_reregisters() {
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
    }

    #[test]
    fn unlisted_item_is_retried_then_given_up_once() {
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        // The edge is attempt 1; the rest are retries on later polls.
        for _ in 0..MAX_ATTEMPTS {
            assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        }
        assert_eq!(poll(&mut w, true, false), TrayAction::GiveUp);
        for _ in 0..10 {
            assert_eq!(poll(&mut w, true, false), TrayAction::None);
        }
    }

    #[test]
    fn retry_stops_as_soon_as_the_item_is_listed() {
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
    }

    #[test]
    fn item_lost_without_a_visible_host_edge_is_reregistered() {
        // The host restarted between two polls: both saw it present.
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
        // The budget is back to full after a confirmed listing.
        for _ in 0..MAX_ATTEMPTS {
            assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        }
        assert_eq!(poll(&mut w, true, false), TrayAction::GiveUp);
    }

    #[test]
    fn startup_registration_that_never_lands_is_retried() {
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, true, false), TrayAction::None);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        assert_eq!(poll(&mut w, true, true), TrayAction::None);
    }

    #[test]
    fn host_leaving_resets_a_give_up() {
        let mut w = TrayWatch::default();
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        for _ in 0..MAX_ATTEMPTS {
            assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
        }
        assert_eq!(poll(&mut w, true, false), TrayAction::GiveUp);
        assert_eq!(poll(&mut w, false, false), TrayAction::None);
        assert_eq!(poll(&mut w, true, false), TrayAction::Reregister);
    }

    #[test]
    fn flapping_host_acts_at_most_once_per_poll() {
        let mut w = TrayWatch::default();
        let mut actions = 0;
        for i in 0..20 {
            if poll(&mut w, i % 2 == 1, false) != TrayAction::None {
                actions += 1;
            }
        }
        assert_eq!(actions, 10, "one re-registration per appearance");
    }

    #[test]
    fn unknown_listing_is_not_mistaken_for_unlisted() {
        let mut w = TrayWatch::default();
        for _ in 0..10 {
            assert_eq!(w.poll(true, None, false), TrayAction::None);
        }
    }

    #[test]
    fn failed_reregistration_is_retried_on_later_polls_then_given_up() {
        let mut w = TrayWatch::default();
        // The baseline poll runs before the startup re-set has had its turn.
        assert_eq!(w.poll(true, None, false), TrayAction::None);
        // Listed or not, a re-set that failed on our side is tried again.
        assert_eq!(w.poll(true, Some(true), true), TrayAction::Reregister);
        assert_eq!(w.poll(true, None, true), TrayAction::Reregister);
        assert_eq!(w.poll(true, Some(true), true), TrayAction::Reregister);
        assert_eq!(w.poll(true, Some(true), true), TrayAction::GiveUp);
        assert_eq!(w.poll(true, Some(true), true), TrayAction::None);
    }

    #[test]
    fn failed_reregistration_that_then_succeeds_stops_the_retries() {
        let mut w = TrayWatch::default();
        assert_eq!(w.poll(false, None, false), TrayAction::None);
        assert_eq!(w.poll(true, Some(true), false), TrayAction::Reregister);
        assert_eq!(w.poll(true, Some(true), true), TrayAction::Reregister);
        assert_eq!(w.poll(true, Some(true), false), TrayAction::None);
        // The listing confirmed the item: a later failure has the full budget.
        for _ in 0..MAX_ATTEMPTS {
            assert_eq!(w.poll(true, Some(true), true), TrayAction::Reregister);
        }
        assert_eq!(w.poll(true, Some(true), true), TrayAction::GiveUp);
    }

    #[test]
    fn failure_flag_is_ignored_while_the_host_is_away() {
        let mut w = TrayWatch::default();
        assert_eq!(w.poll(true, Some(true), false), TrayAction::None);
        for _ in 0..5 {
            assert_eq!(w.poll(false, None, true), TrayAction::None);
        }
        assert_eq!(w.poll(true, Some(true), true), TrayAction::Reregister);
    }
}
