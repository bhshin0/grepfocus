use std::process::Command;

/// True when a StatusNotifier host (a visible tray) is registered on the
/// user bus. Stock GNOME ships no host, so our tray icon silently never
/// renders even though TrayIconBuilder::build() succeeds. Any failure counts
/// as "no tray" so the window stays closable. NB: must be the `call` verb —
/// `busctl get-property` silently ignores --timeout/--auto-start (25s
/// default method-call timeout, and it could dbus-activate the name).
pub fn status_notifier_host_present() -> bool {
    let out = Command::new("busctl")
        .args([
            "--user",
            "--timeout=2",
            "--auto-start=no",
            "call",
            "org.kde.StatusNotifierWatcher",
            "/StatusNotifierWatcher",
            "org.freedesktop.DBus.Properties",
            "Get",
            "ss",
            "org.kde.StatusNotifierWatcher",
            "IsStatusNotifierHostRegistered",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            parse_is_host_registered(&String::from_utf8_lossy(&o.stdout))
        }
        _ => false,
    }
}

/// Parses `v b true` (Properties.Get wraps the bool in a variant).
fn parse_is_host_registered(stdout: &str) -> bool {
    let mut it = stdout.split_whitespace();
    if it.clone().next() == Some("v") {
        it.next();
    }
    it.next() == Some("b") && it.next() == Some("true")
}

#[cfg(test)]
mod tests {
    use super::parse_is_host_registered;

    #[test]
    fn accepts_variant_wrapped_true() {
        assert!(parse_is_host_registered("v b true"));
        assert!(parse_is_host_registered("v b true\n"));
    }

    #[test]
    fn accepts_bare_true() {
        assert!(parse_is_host_registered("b true"));
    }

    #[test]
    fn rejects_everything_else() {
        assert!(!parse_is_host_registered("v b false"));
        assert!(!parse_is_host_registered("b false"));
        assert!(!parse_is_host_registered(""));
        assert!(!parse_is_host_registered("true"));
        assert!(!parse_is_host_registered("s \"x\""));
    }
}
