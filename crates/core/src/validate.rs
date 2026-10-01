//! Block-content validation and canonicalization.
//!
//! The daemon is the authority (it refuses a bad `AddBlock`/`UpdateBlock` and
//! sanitizes stored blocks at startup); the GUI runs the same functions before
//! the round trip so the user sees the same text without one. Everything here
//! is pure — no I/O, no logging, no clock — so both sides agree by
//! construction.
//!
//! Two layers, kept apart on purpose:
//!
//! - [`hostname_shape`] is RFC 1123 *shape* only: what may appear in a
//!   hostname at all. The loopback proxy applies it to names that come off the
//!   network, so it must accept everything a wire hostname can be
//!   (`localhost`, an IPv4 literal, a name with capitals).
//! - [`normalize_domain`] is the *policy* for a stored block entry: canonical
//!   form, no IP literals, no single labels, no wildcards, room for the
//!   `www.` alias.

use std::fmt;

use crate::{AppMatcher, Block};

/// DNS name limit; the hosts writer emits the name verbatim, so nothing longer
/// can ever resolve.
pub const MAX_HOSTNAME_LEN: usize = 253;
/// DNS label limit (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;
/// `render_block` adds a `www.` alias to every name that lacks one, and the
/// alias must itself fit [`MAX_HOSTNAME_LEN`].
pub const WWW_ALIAS_RESERVE: usize = 4;
/// Every domain becomes two `/etc/hosts` lines rewritten on each enforcement
/// change; the cap keeps a hostile client from turning that into a
/// multi-megabyte root write per tick.
pub const MAX_DOMAINS_PER_BLOCK: usize = 5000;
/// Every matcher is compared against every process on every procwatch sweep.
pub const MAX_APPS_PER_BLOCK: usize = 500;
pub const MAX_BLOCK_NAME_CHARS: usize = 200;
/// A one- or two-character `cmdline` substring matches nearly every process
/// on the machine.
pub const MIN_CMDLINE_CHARS: usize = 3;
pub const MAX_MATCHER_BYTES: usize = 4096;
/// `NAME_MAX` on every Linux filesystem that matters.
pub const MAX_BASENAME_BYTES: usize = 255;
/// Case-insensitive substring that marks a matcher as aimed at GrepFocus
/// itself: `grepfocusd`, `grepfocus-gui`, `GrepFocus-0.5.1-x86_64.AppImage`.
pub const SELF_MARKER: &str = "grepfocus";

/// Whether `s` names GrepFocus itself (see [`SELF_MARKER`]).
pub fn is_self_target(s: &str) -> bool {
    let needle = SELF_MARKER.as_bytes();
    s.as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Why a domain entry was refused. `message` is the user-facing text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    Empty,
    NotAscii,
    TooLong,
    EmptyLabel,
    LabelTooLong,
    BadChar,
    HyphenEdge,
    SingleLabel,
    LooksLikeIp,
    Wildcard,
}

impl DomainError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Empty => "hostname is empty",
            Self::NotAscii => {
                "international domain names must be entered in punycode (xn--…) form"
            }
            Self::TooLong => "hostname is too long (max 253 characters including its www. alias)",
            Self::EmptyLabel => "hostname has an empty label (two dots in a row, or a leading dot)",
            Self::LabelTooLong => "a hostname label is too long (max 63 characters between dots)",
            Self::BadChar => {
                "hostname contains an invalid character — only letters, digits, dots and hyphens, one hostname per entry"
            }
            Self::HyphenEdge => "a hostname label cannot start or end with a hyphen",
            Self::SingleLabel => "enter a full hostname with a dot, e.g. reddit.com",
            Self::LooksLikeIp => "IP addresses cannot be blocked — enter a hostname, e.g. reddit.com",
            Self::Wildcard => {
                "wildcards are not supported — reddit.com also blocks www.reddit.com; list other subdomains explicitly"
            }
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DomainError {}

/// Why an app matcher was refused. `message` is the user-facing text, written
/// to follow a `{kind} {text:?}:` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatcherError {
    Empty,
    ControlChar,
    TooLong,
    NotAbsolute,
    BadComponent,
    TrailingSlash,
    ContainsSlash,
    TooShort,
    SelfMatch,
}

impl MatcherError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Empty => "must not be empty",
            Self::ControlChar => "cannot contain control characters",
            Self::TooLong => "is too long",
            Self::NotAbsolute => "must be absolute (start with /), e.g. /usr/bin/steam",
            Self::BadComponent => {
                "cannot contain ., .. or empty (//) components — use the resolved path"
            }
            Self::TrailingSlash => "must name a file, not a directory",
            Self::ContainsSlash => "cannot contain / — use an exe path for a full path",
            Self::TooShort => {
                "must be at least 3 characters — a shorter pattern would match nearly every process"
            }
            Self::SelfMatch => "would match GrepFocus itself, which cannot block itself",
        }
    }
}

impl fmt::Display for MatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for MatcherError {}

/// RFC 1123 hostname shape: ASCII, within the DNS length limits, and a
/// dot-separated run of non-empty labels made of letters, digits and hyphens
/// that neither start nor end with one.
///
/// Shape only — no lowercasing, no trailing-dot tolerance, no policy. This is
/// the rule set the loopback proxy applies to a `Host:` header or SNI, so it
/// must keep accepting `localhost` and IPv4 literals; refusing those for a
/// stored block is [`normalize_domain`]'s job.
pub fn hostname_shape(host: &str) -> Result<(), DomainError> {
    if host.is_empty() {
        return Err(DomainError::Empty);
    }
    if !host.is_ascii() {
        return Err(DomainError::NotAscii);
    }
    if host.len() > MAX_HOSTNAME_LEN {
        return Err(DomainError::TooLong);
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(DomainError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DomainError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainError::HyphenEdge);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(DomainError::BadChar);
        }
    }
    Ok(())
}

/// Strip one leading `http://` or `https://`, ASCII case-insensitively.
fn strip_scheme(s: &str) -> &str {
    for scheme in ["http://", "https://"] {
        // `get` rather than slicing: `s` is untrusted and may hold a
        // multibyte char across the boundary.
        if let Some(head) = s.get(..scheme.len()) {
            if head.eq_ignore_ascii_case(scheme) {
                return &s[scheme.len()..];
            }
        }
    }
    s
}

/// Strip one trailing `:<digits>` (a port), leaving anything else alone so it
/// fails the shape check with a clear error.
fn strip_port(s: &str) -> &str {
    match s.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => s,
    }
}

/// The canonical stored form of a domain entry, or why the entry cannot be
/// one.
///
/// Forgiving about what people paste — a URL, a scheme, a path, a port, a
/// trailing dot, capitals — and strict about what is left: one lowercase
/// hostname in RFC 1123 shape with at least two labels, not an IP literal, not
/// a wildcard, and short enough that its `www.` alias still fits the DNS
/// limit. The `www.` prefix is kept as typed: the hosts writer and the
/// forwardable set own the alias. Idempotent on its own output.
pub fn normalize_domain(raw: &str) -> Result<String, DomainError> {
    let s = strip_scheme(raw.trim());
    let s = &s[..s.find(['/', '?', '#']).unwrap_or(s.len())];
    let s = strip_port(s);
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.contains('*') {
        return Err(DomainError::Wildcard);
    }
    hostname_shape(s)?;
    let host = s.to_ascii_lowercase();
    if !host.starts_with("www.") && host.len() > MAX_HOSTNAME_LEN - WWW_ALIAS_RESERVE {
        return Err(DomainError::TooLong);
    }
    let Some((_, last)) = host.rsplit_once('.') else {
        return Err(DomainError::SingleLabel);
    };
    // Shape guarantees a non-empty last label, so all-digits means a numeric
    // TLD, which does not exist — this is an IPv4 literal.
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DomainError::LooksLikeIp);
    }
    Ok(host)
}

/// The matcher's kind as it appears in user-facing messages.
pub fn matcher_kind_label(m: &AppMatcher) -> &'static str {
    match m {
        AppMatcher::ExePath { .. } => "exe path",
        AppMatcher::Basename { .. } => "basename",
        AppMatcher::Cmdline { .. } => "cmdline pattern",
    }
}

/// The matcher's payload, whatever its kind.
pub fn matcher_text(m: &AppMatcher) -> &str {
    match m {
        AppMatcher::ExePath { path } => path,
        AppMatcher::Basename { name } => name,
        AppMatcher::Cmdline { contains } => contains,
    }
}

/// The canonical form of an app matcher, or why it cannot have one.
///
/// An exe path must be the resolved absolute path procwatch reads from
/// `/proc/<pid>/exe`: `/usr//bin/steam` or `/usr/bin/../bin/steam` can never
/// compare equal to one, so they are refused rather than silently never
/// matching. Nothing may target GrepFocus itself. Idempotent on its own
/// output.
pub fn normalize_matcher(m: &AppMatcher) -> Result<AppMatcher, MatcherError> {
    let text = matcher_text(m).trim();
    if text.is_empty() {
        return Err(MatcherError::Empty);
    }
    if text.chars().any(char::is_control) {
        return Err(MatcherError::ControlChar);
    }
    if text.len() > MAX_MATCHER_BYTES {
        return Err(MatcherError::TooLong);
    }
    match m {
        AppMatcher::ExePath { .. } => {
            let Some(rest) = text.strip_prefix('/') else {
                return Err(MatcherError::NotAbsolute);
            };
            if text.ends_with('/') {
                return Err(MatcherError::TrailingSlash);
            }
            if rest
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return Err(MatcherError::BadComponent);
            }
            let file_name = rest.rsplit('/').next().unwrap_or(rest);
            if is_self_target(file_name) {
                return Err(MatcherError::SelfMatch);
            }
            Ok(AppMatcher::ExePath { path: text.into() })
        }
        AppMatcher::Basename { .. } => {
            if text.contains('/') {
                return Err(MatcherError::ContainsSlash);
            }
            if text.len() > MAX_BASENAME_BYTES {
                return Err(MatcherError::TooLong);
            }
            if is_self_target(text) {
                return Err(MatcherError::SelfMatch);
            }
            Ok(AppMatcher::Basename { name: text.into() })
        }
        AppMatcher::Cmdline { .. } => {
            if text.chars().count() < MIN_CMDLINE_CHARS {
                return Err(MatcherError::TooShort);
            }
            if is_self_target(text) {
                return Err(MatcherError::SelfMatch);
            }
            Ok(AppMatcher::Cmdline {
                contains: text.into(),
            })
        }
    }
}

/// How much of an offending entry an error message or a startup note quotes.
/// Enough to recognise it, never a 4 KiB path or a pasted page.
const EXCERPT_CHARS: usize = 40;

/// The first [`EXCERPT_CHARS`] of `s`, with an ellipsis when that cut
/// anything. Callers Debug-quote the result.
pub(crate) fn excerpt(s: &str) -> String {
    let mut out: String = s.chars().take(EXCERPT_CHARS).collect();
    if s.chars().nth(EXCERPT_CHARS).is_some() {
        out.push('…');
    }
    out
}

/// Validate a block a client wants saved, canonicalizing its domains and app
/// matchers in place. `Err` is the exact user-facing text and leaves the block
/// untouched.
///
/// Does not touch the allowance policy — `validate_policy` and `set_policy`
/// keep their own path in the IPC handler.
pub fn validate_block(block: &mut Block) -> Result<(), String> {
    if block.name.trim().is_empty() {
        return Err("name is required".into());
    }
    if block.name.chars().any(char::is_control) {
        return Err("name cannot contain control characters".into());
    }
    if block.name.chars().count() > MAX_BLOCK_NAME_CHARS {
        return Err(format!(
            "name is too long (max {MAX_BLOCK_NAME_CHARS} characters)"
        ));
    }

    if block.domains.len() > MAX_DOMAINS_PER_BLOCK {
        return Err(format!(
            "a block can hold at most {MAX_DOMAINS_PER_BLOCK} domains"
        ));
    }
    let mut domains: Vec<String> = Vec::with_capacity(block.domains.len());
    for raw in &block.domains {
        let d = normalize_domain(raw).map_err(|e| format!("domain {:?}: {e}", excerpt(raw)))?;
        if !domains.contains(&d) {
            domains.push(d);
        }
    }

    if block.apps.len() > MAX_APPS_PER_BLOCK {
        return Err(format!(
            "a block can hold at most {MAX_APPS_PER_BLOCK} app matchers"
        ));
    }
    let mut apps: Vec<AppMatcher> = Vec::with_capacity(block.apps.len());
    for m in &block.apps {
        let n = normalize_matcher(m).map_err(|e| {
            format!(
                "{} {:?}: {e}",
                matcher_kind_label(m),
                excerpt(matcher_text(m))
            )
        })?;
        if !apps.contains(&n) {
            apps.push(n);
        }
    }

    if domains.is_empty() && apps.is_empty() {
        return Err("a block needs at least one domain or app to block".into());
    }
    block.domains = domains;
    block.apps = apps;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe(p: &str) -> AppMatcher {
        AppMatcher::ExePath { path: p.into() }
    }
    fn base(n: &str) -> AppMatcher {
        AppMatcher::Basename { name: n.into() }
    }
    fn cmd(c: &str) -> AppMatcher {
        AppMatcher::Cmdline { contains: c.into() }
    }

    fn label(n: usize) -> String {
        "a".repeat(n)
    }

    /// A hostname of exactly `len` bytes built from 63-byte labels.
    fn hostname_of_len(len: usize) -> String {
        let mut out = String::new();
        while out.len() < len {
            if !out.is_empty() {
                out.push('.');
            }
            let room = len - out.len();
            out.push_str(&label(room.min(MAX_LABEL_LEN)));
        }
        assert_eq!(out.len(), len);
        out
    }

    // ── hostname_shape ──────────────────────────────────────────────────────

    #[test]
    fn hostname_shape_accepts_wire_shapes() {
        for h in [
            "reddit.com",
            "www.Reddit.COM",
            "localhost",
            "1.2.3.4",
            "xn--bcher-kva.example",
            "a-b.c-d.e",
            "a",
            &hostname_of_len(MAX_HOSTNAME_LEN),
            &format!("{}.x", label(MAX_LABEL_LEN)),
        ] {
            assert_eq!(hostname_shape(h), Ok(()), "{h:?}");
        }
    }

    #[test]
    fn hostname_shape_rejects_each_kind() {
        use DomainError::*;
        for (h, e) in [
            ("", Empty),
            ("bücher.example", NotAscii),
            (hostname_of_len(MAX_HOSTNAME_LEN + 1).as_str(), TooLong),
            (".reddit.com", EmptyLabel),
            ("reddit..com", EmptyLabel),
            ("reddit.com.", EmptyLabel),
            (&format!("{}.x", label(MAX_LABEL_LEN + 1)), LabelTooLong),
            ("-reddit.com", HyphenEdge),
            ("reddit-.com", HyphenEdge),
            ("-", HyphenEdge),
            ("red dit.com", BadChar),
            ("reddit.com\n", BadChar),
            ("reddit.com\r\n", BadChar),
            ("red_dit.com", BadChar),
            ("a@b.com", BadChar),
            ("[::1]", BadChar),
            ("reddit.com#x", BadChar),
            ("reddit.com/", BadChar),
            ("*.reddit.com", BadChar),
            ("reddit.com:443", BadChar),
        ] {
            assert_eq!(hostname_shape(h), Err(e), "{h:?}");
        }
    }

    // ── normalize_domain ────────────────────────────────────────────────────

    #[test]
    fn normalize_domain_canonical_forms_pass_through() {
        for d in [
            "reddit.com",
            "www.reddit.com",
            "old.reddit.com",
            "xn--bcher-kva.example",
            "a-b.example",
            "x.co",
        ] {
            assert_eq!(normalize_domain(d).as_deref(), Ok(d), "{d:?}");
        }
    }

    #[test]
    fn normalize_domain_normalizes() {
        for (raw, want) in [
            ("  reddit.com  ", "reddit.com"),
            ("http://reddit.com", "reddit.com"),
            ("https://reddit.com", "reddit.com"),
            ("HTTPS://reddit.com", "reddit.com"),
            ("https://reddit.com/r/rust", "reddit.com"),
            ("https://reddit.com/r/ünicode", "reddit.com"),
            ("reddit.com/", "reddit.com"),
            ("reddit.com?x=1", "reddit.com"),
            ("reddit.com#frag", "reddit.com"),
            ("reddit.com:443", "reddit.com"),
            ("https://reddit.com:8080/path?q#f", "reddit.com"),
            ("reddit.com.", "reddit.com"),
            ("Reddit.COM", "reddit.com"),
            ("WWW.Reddit.com", "www.reddit.com"),
            ("\thttps://Old.Reddit.com./r/x\n", "old.reddit.com"),
        ] {
            assert_eq!(normalize_domain(raw).as_deref(), Ok(want), "{raw:?}");
        }
    }

    #[test]
    fn normalize_domain_is_idempotent() {
        for raw in [
            "https://Reddit.com:443/r/rust",
            "WWW.example.org.",
            "xn--bcher-kva.example",
            &format!(
                "www.{}",
                hostname_of_len(MAX_HOSTNAME_LEN - WWW_ALIAS_RESERVE)
            ),
        ] {
            let once = normalize_domain(raw).unwrap();
            assert_eq!(normalize_domain(&once).unwrap(), once, "{raw:?}");
        }
    }

    #[test]
    fn normalize_domain_rejects_injection() {
        for raw in [
            "reddit.com\n0.0.0.0 evil.example",
            "reddit.com 0.0.0.0 evil.example",
            "reddit.com\t# comment",
            "reddit.com\0evil",
            "reddit.com\r\n0.0.0.0 evil.example",
        ] {
            assert_eq!(normalize_domain(raw), Err(DomainError::BadChar), "{raw:?}");
        }
    }

    #[test]
    fn normalize_domain_rejects_unicode() {
        for raw in ["bücher.example", "реддит.com", "reddit\u{a0}.com"] {
            assert_eq!(normalize_domain(raw), Err(DomainError::NotAscii), "{raw:?}");
        }
    }

    #[test]
    fn normalize_domain_rejects_shape() {
        use DomainError::*;
        for (raw, e) in [
            ("", Empty),
            ("   ", Empty),
            ("https://", Empty),
            (".", Empty),
            ("https:///path", Empty),
            ("*.reddit.com", Wildcard),
            ("reddit.*", Wildcard),
            ("reddit", SingleLabel),
            ("localhost", SingleLabel),
            ("1.2.3.4", LooksLikeIp),
            ("10.0.0.1:53", LooksLikeIp),
            ("reddit.123", LooksLikeIp),
            ("[::1]", BadChar),
            ("reddit..com", EmptyLabel),
            (".reddit.com", EmptyLabel),
            ("-reddit.com", HyphenEdge),
            ("red_dit.com", BadChar),
            ("user@reddit.com", BadChar),
            ("reddit.com:x", BadChar),
        ] {
            assert_eq!(normalize_domain(raw), Err(e), "{raw:?}");
        }
    }

    #[test]
    fn normalize_domain_length_limits() {
        let fits = hostname_of_len(MAX_HOSTNAME_LEN - WWW_ALIAS_RESERVE);
        assert_eq!(normalize_domain(&fits).as_deref(), Ok(fits.as_str()));

        let over = hostname_of_len(MAX_HOSTNAME_LEN - WWW_ALIAS_RESERVE + 1);
        assert_eq!(normalize_domain(&over), Err(DomainError::TooLong));

        // An entry that already carries the alias may use the whole limit.
        let www = format!("www.{fits}");
        assert_eq!(www.len(), MAX_HOSTNAME_LEN);
        assert_eq!(normalize_domain(&www).as_deref(), Ok(www.as_str()));

        let www_over = format!("www.{}", hostname_of_len(MAX_HOSTNAME_LEN - 3));
        assert_eq!(normalize_domain(&www_over), Err(DomainError::TooLong));
    }

    // ── normalize_matcher ───────────────────────────────────────────────────

    #[test]
    fn normalize_matcher_exe_path() {
        use MatcherError::*;
        assert_eq!(
            normalize_matcher(&exe("  /usr/bin/steam\n")),
            Ok(exe("/usr/bin/steam"))
        );
        assert_eq!(
            normalize_matcher(&exe("/tmp/.mount_x/usr/bin/discord")),
            Ok(exe("/tmp/.mount_x/usr/bin/discord"))
        );
        for (raw, e) in [
            ("", Empty),
            ("   ", Empty),
            ("/usr/bin/st\u{7}eam", ControlChar),
            ("/usr/bin/steam\0", ControlChar),
            ("usr/bin/steam", NotAbsolute),
            ("steam", NotAbsolute),
            ("/usr/bin/", TrailingSlash),
            ("/", TrailingSlash),
            ("/usr//bin/steam", BadComponent),
            ("/usr/bin/./steam", BadComponent),
            ("/usr/bin/../bin/steam", BadComponent),
            ("/usr/bin/grepfocusd", SelfMatch),
            ("/tmp/.mount_x/usr/bin/grepfocus-gui", SelfMatch),
            ("/home/u/GrepFocus-0.5.1-x86_64.AppImage", SelfMatch),
        ] {
            assert_eq!(normalize_matcher(&exe(raw)), Err(e), "{raw:?}");
        }
        let long = format!("/{}", "a".repeat(MAX_MATCHER_BYTES));
        assert_eq!(normalize_matcher(&exe(&long)), Err(TooLong));
        // A directory named after us is not a self target; only the file is.
        assert_eq!(
            normalize_matcher(&exe("/home/grepfocus-fan/bin/steam")),
            Ok(exe("/home/grepfocus-fan/bin/steam"))
        );
    }

    #[test]
    fn normalize_matcher_basename() {
        use MatcherError::*;
        assert_eq!(normalize_matcher(&base(" steam ")), Ok(base("steam")));
        assert_eq!(normalize_matcher(&base("Discord")), Ok(base("Discord")));
        for (raw, e) in [
            ("", Empty),
            ("st\team", ControlChar),
            ("usr/steam", ContainsSlash),
            ("/steam", ContainsSlash),
            ("grepfocusd", SelfMatch),
            ("GrepFocus-gui", SelfMatch),
        ] {
            assert_eq!(normalize_matcher(&base(raw)), Err(e), "{raw:?}");
        }
        assert_eq!(
            normalize_matcher(&base(&"a".repeat(MAX_BASENAME_BYTES))),
            Ok(base(&"a".repeat(MAX_BASENAME_BYTES)))
        );
        assert_eq!(
            normalize_matcher(&base(&"a".repeat(MAX_BASENAME_BYTES + 1))),
            Err(TooLong)
        );
    }

    #[test]
    fn normalize_matcher_cmdline() {
        use MatcherError::*;
        assert_eq!(
            normalize_matcher(&cmd(" com.discordapp.Discord ")),
            Ok(cmd("com.discordapp.Discord"))
        );
        assert_eq!(normalize_matcher(&cmd("abc")), Ok(cmd("abc")));
        // Character count, not bytes: three multibyte chars are enough.
        assert_eq!(normalize_matcher(&cmd("ééé")), Ok(cmd("ééé")));
        for (raw, e) in [
            ("", Empty),
            ("a\nb", ControlChar),
            ("ab", TooShort),
            (" a ", TooShort),
            ("éé", TooShort),
            ("GREPFOCUS", SelfMatch),
            ("/usr/bin/grepfocusd cleanup", SelfMatch),
        ] {
            assert_eq!(normalize_matcher(&cmd(raw)), Err(e), "{raw:?}");
        }
        assert_eq!(
            normalize_matcher(&cmd(&"a".repeat(MAX_MATCHER_BYTES + 1))),
            Err(TooLong)
        );
    }

    #[test]
    fn normalize_matcher_is_idempotent() {
        for m in [
            exe("  /usr/bin/steam "),
            base("\tsteam"),
            cmd(" com.discordapp.Discord\n"),
        ] {
            let once = normalize_matcher(&m).unwrap();
            assert_eq!(normalize_matcher(&once), Ok(once.clone()), "{m:?}");
        }
    }

    // ── validate_block ──────────────────────────────────────────────────────

    fn block(name: &str, domains: &[&str], apps: Vec<AppMatcher>) -> Block {
        Block {
            id: 1,
            name: name.into(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
            apps,
            ..Default::default()
        }
    }

    #[test]
    fn validate_block_normalizes_and_dedupes() {
        let mut b = block(
            "Social",
            &[
                "https://Reddit.com/r/rust",
                "reddit.com",
                "WWW.reddit.com.",
                "twitter.com",
                "reddit.com:443",
            ],
            vec![
                exe(" /usr/bin/steam "),
                base("discord"),
                exe("/usr/bin/steam"),
                cmd(" com.discordapp.Discord "),
                base("discord "),
            ],
        );
        assert_eq!(validate_block(&mut b), Ok(()));
        assert_eq!(b.domains, ["reddit.com", "www.reddit.com", "twitter.com"]);
        assert_eq!(
            b.apps,
            [
                exe("/usr/bin/steam"),
                base("discord"),
                cmd("com.discordapp.Discord")
            ]
        );
        // Already canonical: a second pass changes nothing.
        let again = b.clone();
        assert_eq!(validate_block(&mut b), Ok(()));
        assert_eq!(b.domains, again.domains);
        assert_eq!(b.apps, again.apps);
    }

    #[test]
    fn validate_block_error_text_names_the_entry() {
        let mut b = block("x", &["reddit.com\n0.0.0.0 evil.example"], vec![]);
        assert_eq!(
            validate_block(&mut b),
            Err("domain \"reddit.com\\n0.0.0.0 evil.example\": hostname contains an invalid character — only letters, digits, dots and hyphens, one hostname per entry".into())
        );
        // The offending entry survives untouched for the client to show.
        assert_eq!(b.domains, ["reddit.com\n0.0.0.0 evil.example"]);

        let mut b = block("x", &["1.2.3.4"], vec![]);
        assert_eq!(
            validate_block(&mut b),
            Err("domain \"1.2.3.4\": IP addresses cannot be blocked — enter a hostname, e.g. reddit.com".into())
        );

        let long = format!("{}.com", "a".repeat(MAX_LABEL_LEN + 1));
        let mut b = block("x", &[&long], vec![]);
        assert_eq!(
            validate_block(&mut b),
            Err(format!(
                "domain \"{}…\": a hostname label is too long (max 63 characters between dots)",
                "a".repeat(40)
            ))
        );

        let mut b = block("x", &["reddit.com"], vec![exe("usr/bin/steam")]);
        assert_eq!(
            validate_block(&mut b),
            Err(
                "exe path \"usr/bin/steam\": must be absolute (start with /), e.g. /usr/bin/steam"
                    .into()
            )
        );
        // Domains are checked first but not committed when a matcher fails.
        assert_eq!(b.apps, [exe("usr/bin/steam")]);

        let mut b = block("x", &[], vec![base("a/b")]);
        assert_eq!(
            validate_block(&mut b),
            Err("basename \"a/b\": cannot contain / — use an exe path for a full path".into())
        );

        let mut b = block("x", &[], vec![cmd("ab")]);
        assert_eq!(
            validate_block(&mut b),
            Err("cmdline pattern \"ab\": must be at least 3 characters — a shorter pattern would match nearly every process".into())
        );

        let mut b = block("x", &[], vec![base("grepfocus-gui")]);
        assert_eq!(
            validate_block(&mut b),
            Err("basename \"grepfocus-gui\": would match GrepFocus itself, which cannot block itself".into())
        );

        // Matcher text is excerpted the same way as a domain.
        let mut b = block("x", &[], vec![cmd(&format!("{}grepfocus", "c".repeat(40)))]);
        assert_eq!(
            validate_block(&mut b),
            Err(format!(
                "cmdline pattern \"{}…\": would match GrepFocus itself, which cannot block itself",
                "c".repeat(40)
            ))
        );
    }

    #[test]
    fn validate_block_rejects_name_counts_and_empty() {
        let mut b = block("", &["reddit.com"], vec![]);
        assert_eq!(validate_block(&mut b), Err("name is required".into()));
        let mut b = block("   ", &["reddit.com"], vec![]);
        assert_eq!(validate_block(&mut b), Err("name is required".into()));

        let mut b = block("So\ncial", &["reddit.com"], vec![]);
        assert_eq!(
            validate_block(&mut b),
            Err("name cannot contain control characters".into())
        );

        // 200 characters is fine even at two bytes each; 201 is not.
        let mut b = block(&"é".repeat(200), &["reddit.com"], vec![]);
        assert_eq!(validate_block(&mut b), Ok(()));
        let mut b = block(&"é".repeat(201), &["reddit.com"], vec![]);
        assert_eq!(
            validate_block(&mut b),
            Err("name is too long (max 200 characters)".into())
        );

        let many: Vec<String> = (0..=MAX_DOMAINS_PER_BLOCK)
            .map(|i| format!("d{i}.example"))
            .collect();
        let mut b = block("x", &[], vec![]);
        b.domains = many;
        assert_eq!(
            validate_block(&mut b),
            Err("a block can hold at most 5000 domains".into())
        );
        // The cap counts entries as sent, so duplicates do not sneak past it.
        let mut b = block("x", &[], vec![]);
        b.domains = vec!["reddit.com".into(); MAX_DOMAINS_PER_BLOCK + 1];
        assert_eq!(
            validate_block(&mut b),
            Err("a block can hold at most 5000 domains".into())
        );
        let mut b = block("x", &[], vec![]);
        b.domains = vec!["reddit.com".into(); MAX_DOMAINS_PER_BLOCK];
        assert_eq!(validate_block(&mut b), Ok(()));
        assert_eq!(b.domains, ["reddit.com"]);

        let mut b = block("x", &[], vec![base("steam"); MAX_APPS_PER_BLOCK + 1]);
        assert_eq!(
            validate_block(&mut b),
            Err("a block can hold at most 500 app matchers".into())
        );

        let mut b = block("x", &[], vec![]);
        assert_eq!(
            validate_block(&mut b),
            Err("a block needs at least one domain or app to block".into())
        );
    }

    #[test]
    fn validate_block_leaves_policy_alone() {
        use crate::{AllowancePolicy, LockMode};
        let mut b = block("x", &["Reddit.com"], vec![]);
        b.allowance = Some(AllowancePolicy::PerDay { secs: 0 });
        b.allowance_secs_per_day = 42;
        b.lock = LockMode::ChallengeBreaks;
        assert_eq!(validate_block(&mut b), Ok(()));
        assert_eq!(b.allowance, Some(AllowancePolicy::PerDay { secs: 0 }));
        assert_eq!(b.allowance_secs_per_day, 42);
        assert_eq!(b.lock, LockMode::ChallengeBreaks);
        assert_eq!(b.id, 1);
        assert_eq!(b.name, "x");
    }
}
