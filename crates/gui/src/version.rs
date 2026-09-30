//! Version comparison and the GUI/daemon skew decision.
//!
//! The one place versions are compared: the skew banner (here) and the
//! release check (`update.rs`) both go through `parse_version`/`compare`, on the
//! `semver` crate rather than a hand-rolled triple so prerelease ordering is
//! semver's. The daemon never compares versions; the installer script's
//! `sort -V` downgrade guard is the only other comparison and must work as
//! root without the GUI — releases are plain MAJOR.MINOR.PATCH so both agree.

use std::cmp::Ordering;

use grepfocus_core::InstallKind;
use semver::Version;

/// Trim, strip one leading `v`/`V`, then strict semver. `None` for anything
/// else (`1.2`, `1.2.3.4`, `a.b.c`, empty).
pub fn parse_version(s: &str) -> Option<Version> {
    let s = s.trim();
    let s = s
        .strip_prefix('v')
        .or_else(|| s.strip_prefix('V'))
        .unwrap_or(s);
    Version::parse(s).ok()
}

/// `None` when either side does not parse — the caller says nothing rather
/// than guessing.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(parse_version(a)?.cmp(&parse_version(b)?))
}

/// Strict `>`: an equal version is never "newer", so a release check on the
/// running version stays quiet. Used by the release check (`update.rs`).
pub fn newer_than(latest: &Version, current: &Version) -> bool {
    latest > current
}

/// Everything the skew decision looks at, gathered by `get_status`.
#[derive(Clone, Copy, Debug)]
pub struct Probe<'a> {
    /// `GUI_VERSION`.
    pub gui: &'a str,
    /// `health.daemon_version`, `None` (or empty) when the daemon predates
    /// version reporting.
    pub daemon: Option<&'a str>,
    pub install_kind: InstallKind,
    /// `$APPIMAGE` set by AppRun.
    pub appimage: bool,
    /// `/usr/bin/grepfocusd` exists (a package install owns the daemon).
    pub packaged_binary: bool,
    /// `/usr/local/bin/grepfocusd` exists (the AppImage installer or the dev
    /// scripts put it there).
    pub local_binary: bool,
}

/// What the GUI/daemon version skew calls for. `from` is the daemon's version
/// (`None` = it predates reporting), `to` this GUI's. Only `UpdateService`
/// comes with a button; every other variant is advice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpdateAdvice {
    UpToDate,
    /// AppImage over a `/usr/local/bin` daemon and nothing in `/usr/bin`:
    /// the bundled installer can re-run.
    UpdateService {
        from: Option<String>,
        to: String,
    },
    /// A package install owns the daemon.
    PackageManager {
        from: Option<String>,
        to: String,
    },
    /// Both a package and a local daemon exist; the installer refuses to run
    /// over a package install, so the user must pick one.
    BothInstalls {
        from: Option<String>,
        to: String,
    },
    /// Nothing this GUI can do itself.
    Manual {
        from: Option<String>,
        to: String,
    },
    /// The daemon is newer than this GUI — never an install offer.
    GuiOutdated {
        gui: String,
        daemon: String,
    },
}

/// The skew decision table (docs/plans/hardening-health-updates.md, WP6).
/// An unparseable version on either side is `UpToDate`: better silent than
/// an install offer built on a guess.
pub fn advise(p: Probe) -> UpdateAdvice {
    let to = p.gui.to_string();
    let daemon = p.daemon.filter(|d| !d.is_empty());
    let Some(daemon) = daemon else {
        // A pre-reporting daemon is older than any GUI that asks; the offer
        // still depends on who owns the binary.
        return if p.packaged_binary {
            UpdateAdvice::PackageManager { from: None, to }
        } else if p.appimage && p.local_binary {
            UpdateAdvice::UpdateService { from: None, to }
        } else {
            UpdateAdvice::Manual { from: None, to }
        };
    };
    let from = Some(daemon.to_string());
    match compare(p.gui, daemon) {
        None | Some(Ordering::Equal) => UpdateAdvice::UpToDate,
        Some(Ordering::Less) => UpdateAdvice::GuiOutdated {
            gui: to,
            daemon: daemon.to_string(),
        },
        Some(Ordering::Greater) => match p.install_kind {
            InstallKind::Package => UpdateAdvice::PackageManager { from, to },
            InstallKind::Local if p.packaged_binary => UpdateAdvice::BothInstalls { from, to },
            InstallKind::Local if p.appimage => UpdateAdvice::UpdateService { from, to },
            InstallKind::Local | InstallKind::Unknown => UpdateAdvice::Manual { from, to },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_plain_triple() {
        let v = parse_version("0.5.1").expect("parses");
        assert_eq!((v.major, v.minor, v.patch), (0, 5, 1));
        assert_eq!(parse_version(" 1.2.3 \n"), parse_version("1.2.3"));
    }

    #[test]
    fn parse_strips_v() {
        assert_eq!(parse_version("v0.6.0"), parse_version("0.6.0"));
        assert_eq!(parse_version("V0.6.0"), parse_version("0.6.0"));
        assert_eq!(parse_version("vv0.6.0"), None);
    }

    #[test]
    fn parse_rejects() {
        for bad in ["", "1.2", "1.2.3.4", "a.b.c"] {
            assert_eq!(parse_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn compare_is_numeric_not_lexical() {
        assert_eq!(compare("0.10.0", "0.9.9"), Some(Ordering::Greater));
        assert_eq!(compare("0.9.9", "0.10.0"), Some(Ordering::Less));
        assert_eq!(compare("1.0.0", "v1.0.0"), Some(Ordering::Equal));
        let latest = parse_version("0.10.0").unwrap();
        let current = parse_version("0.9.9").unwrap();
        assert!(newer_than(&latest, &current));
        assert!(!newer_than(&current, &latest));
        assert!(!newer_than(&latest, &latest));
    }

    #[test]
    fn compare_unparseable_is_none() {
        assert_eq!(compare("0.5", "0.5.1"), None);
        assert_eq!(compare("0.5.1", ""), None);
    }

    /// A reporting daemon at 0.5.1 under a 0.6.0 GUI; every field a row of
    /// the decision table can flip is set by the caller.
    fn newer_gui(
        install_kind: InstallKind,
        appimage: bool,
        packaged: bool,
        local: bool,
    ) -> Probe<'static> {
        Probe {
            gui: "0.6.0",
            daemon: Some("0.5.1"),
            install_kind,
            appimage,
            packaged_binary: packaged,
            local_binary: local,
        }
    }

    fn pre_reporting(appimage: bool, packaged: bool, local: bool) -> Probe<'static> {
        Probe {
            daemon: None,
            ..newer_gui(InstallKind::Unknown, appimage, packaged, local)
        }
    }

    fn to() -> String {
        "0.6.0".to_string()
    }

    fn from() -> Option<String> {
        Some("0.5.1".to_string())
    }

    #[test]
    fn advise_pre_reporting_with_package_binary_is_package_manager() {
        for appimage in [false, true] {
            for local in [false, true] {
                assert_eq!(
                    advise(pre_reporting(appimage, true, local)),
                    UpdateAdvice::PackageManager {
                        from: None,
                        to: to()
                    }
                );
            }
        }
    }

    #[test]
    fn advise_pre_reporting_appimage_over_local_is_update_service() {
        // The migration case: every AppImage install made before this release.
        assert_eq!(
            advise(pre_reporting(true, false, true)),
            UpdateAdvice::UpdateService {
                from: None,
                to: to()
            }
        );
    }

    #[test]
    fn advise_pre_reporting_non_appimage_over_local_is_manual() {
        assert_eq!(
            advise(pre_reporting(false, false, true)),
            UpdateAdvice::Manual {
                from: None,
                to: to()
            }
        );
    }

    #[test]
    fn advise_pre_reporting_without_any_binary_is_manual() {
        for appimage in [false, true] {
            assert_eq!(
                advise(pre_reporting(appimage, false, false)),
                UpdateAdvice::Manual {
                    from: None,
                    to: to()
                }
            );
        }
    }

    #[test]
    fn advise_unparseable_daemon_version_is_up_to_date() {
        let p = Probe {
            daemon: Some("0.5"),
            ..newer_gui(InstallKind::Local, true, false, true)
        };
        assert_eq!(advise(p), UpdateAdvice::UpToDate);
        let p = Probe {
            gui: "next",
            ..newer_gui(InstallKind::Local, true, false, true)
        };
        assert_eq!(advise(p), UpdateAdvice::UpToDate);
    }

    #[test]
    fn advise_equal_is_up_to_date() {
        let p = Probe {
            daemon: Some("v0.6.0"),
            ..newer_gui(InstallKind::Local, true, true, true)
        };
        assert_eq!(advise(p), UpdateAdvice::UpToDate);
    }

    #[test]
    fn advise_gui_newer_appimage_over_local_is_update_service() {
        // The only row with a button; whether /usr/local/bin still holds
        // the binary does not matter (a live daemon proves it did).
        for local in [false, true] {
            assert_eq!(
                advise(newer_gui(InstallKind::Local, true, false, local)),
                UpdateAdvice::UpdateService {
                    from: from(),
                    to: to()
                }
            );
        }
    }

    #[test]
    fn advise_gui_newer_package_kind_is_package_manager() {
        for appimage in [false, true] {
            for packaged in [false, true] {
                assert_eq!(
                    advise(newer_gui(InstallKind::Package, appimage, packaged, true)),
                    UpdateAdvice::PackageManager {
                        from: from(),
                        to: to()
                    }
                );
            }
        }
    }

    #[test]
    fn advise_gui_newer_local_kind_with_package_binary_is_both_installs() {
        for appimage in [false, true] {
            assert_eq!(
                advise(newer_gui(InstallKind::Local, appimage, true, true)),
                UpdateAdvice::BothInstalls {
                    from: from(),
                    to: to()
                }
            );
        }
    }

    #[test]
    fn advise_gui_newer_non_appimage_local_is_manual() {
        assert_eq!(
            advise(newer_gui(InstallKind::Local, false, false, true)),
            UpdateAdvice::Manual {
                from: from(),
                to: to()
            }
        );
    }

    #[test]
    fn advise_gui_newer_unknown_kind_is_manual() {
        for appimage in [false, true] {
            for packaged in [false, true] {
                assert_eq!(
                    advise(newer_gui(InstallKind::Unknown, appimage, packaged, true)),
                    UpdateAdvice::Manual {
                        from: from(),
                        to: to()
                    }
                );
            }
        }
    }

    #[test]
    fn advise_gui_older_is_gui_outdated() {
        let p = Probe {
            gui: "0.5.1",
            daemon: Some("0.6.0"),
            ..newer_gui(InstallKind::Local, true, false, true)
        };
        assert_eq!(
            advise(p),
            UpdateAdvice::GuiOutdated {
                gui: "0.5.1".to_string(),
                daemon: "0.6.0".to_string()
            }
        );
    }

    #[test]
    fn advise_daemon_newer_never_offers_install() {
        // Every combination of the install-offer inputs, including a
        // prerelease GUI below the daemon's release.
        for gui in ["0.5.1", "0.6.0-rc1"] {
            for kind in [
                InstallKind::Package,
                InstallKind::Local,
                InstallKind::Unknown,
            ] {
                for appimage in [false, true] {
                    for packaged in [false, true] {
                        for local in [false, true] {
                            let p = Probe {
                                gui,
                                daemon: Some("0.6.0"),
                                install_kind: kind,
                                appimage,
                                packaged_binary: packaged,
                                local_binary: local,
                            };
                            assert!(
                                matches!(advise(p), UpdateAdvice::GuiOutdated { .. }),
                                "{p:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn advise_empty_daemon_version_is_pre_reporting() {
        let p = Probe {
            daemon: Some(""),
            ..newer_gui(InstallKind::Local, true, false, true)
        };
        assert_eq!(
            advise(p),
            UpdateAdvice::UpdateService {
                from: None,
                to: to()
            }
        );
        assert_eq!(advise(p), advise(Probe { daemon: None, ..p }));
    }

    #[test]
    fn advice_wire_shape() {
        assert_eq!(
            serde_json::to_value(UpdateAdvice::UpToDate).unwrap(),
            json!({"kind": "up_to_date"})
        );
        assert_eq!(
            serde_json::to_value(UpdateAdvice::UpdateService {
                from: None,
                to: to()
            })
            .unwrap(),
            json!({"kind": "update_service", "from": null, "to": "0.6.0"})
        );
        assert_eq!(
            serde_json::to_value(UpdateAdvice::PackageManager {
                from: from(),
                to: to()
            })
            .unwrap(),
            json!({"kind": "package_manager", "from": "0.5.1", "to": "0.6.0"})
        );
        assert_eq!(
            serde_json::to_value(UpdateAdvice::BothInstalls {
                from: from(),
                to: to()
            })
            .unwrap(),
            json!({"kind": "both_installs", "from": "0.5.1", "to": "0.6.0"})
        );
        assert_eq!(
            serde_json::to_value(UpdateAdvice::Manual {
                from: from(),
                to: to()
            })
            .unwrap(),
            json!({"kind": "manual", "from": "0.5.1", "to": "0.6.0"})
        );
        assert_eq!(
            serde_json::to_value(UpdateAdvice::GuiOutdated {
                gui: "0.5.1".to_string(),
                daemon: "0.6.0".to_string()
            })
            .unwrap(),
            json!({"kind": "gui_outdated", "gui": "0.5.1", "daemon": "0.6.0"})
        );
    }
}
