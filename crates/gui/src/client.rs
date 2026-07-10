//! Tiny client that opens a Unix socket per call to talk to grepfocusd.
//!
//! Per-call connections keep the code simple and avoid lifecycle headaches
//! for a v0.1 GUI; the daemon handles each connection independently.

use grepfocus_core::{Request, Response};
use tokio::net::UnixStream;

const SOCK_PATH: &str = "/run/grepfocus/sock";

/// Actionable copy for the classic first-run connect failures; the raw error
/// is appended by the caller so debuggability survives the friendlier text.
fn connect_error_message(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind::{ConnectionRefused, NotFound, PermissionDenied};
    match kind {
        NotFound | ConnectionRefused => {
            "The GrepFocus daemon is not running.\n\
             Start it: sudo systemctl start grepfocusd\n\
             Not installed yet? From the repo: sudo ./packaging/install.sh"
        }
        PermissionDenied => {
            "Your user is not allowed to talk to the GrepFocus daemon.\n\
             Fix: sudo usermod -aG grepfocus $USER\n\
             then log out and back in — the new group needs a fresh login."
        }
        _ => "Could not reach the GrepFocus daemon.",
    }
}

pub async fn call(req: Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(SOCK_PATH).await.map_err(|e| {
        format!(
            "{}\n(connect {SOCK_PATH}: {e})",
            connect_error_message(e.kind())
        )
    })?;
    grepfocus_core::wire::write_json(&mut stream, &req)
        .await
        .map_err(|e| format!("write: {e}"))?;
    let resp: Response = grepfocus_core::wire::read_json(&mut stream)
        .await
        .map_err(|e| format!("read: {e}"))?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::connect_error_message;
    use std::io::ErrorKind;

    #[test]
    fn not_found_suggests_starting_the_daemon() {
        assert!(connect_error_message(ErrorKind::NotFound).contains("systemctl start grepfocusd"));
    }

    #[test]
    fn connection_refused_matches_not_found() {
        assert_eq!(
            connect_error_message(ErrorKind::ConnectionRefused),
            connect_error_message(ErrorKind::NotFound)
        );
    }

    #[test]
    fn permission_denied_suggests_group_and_relogin() {
        let msg = connect_error_message(ErrorKind::PermissionDenied);
        assert!(msg.contains("usermod -aG grepfocus"));
        assert!(msg.contains("log out"));
    }

    #[test]
    fn other_kinds_get_the_generic_fallback() {
        let msg = connect_error_message(ErrorKind::TimedOut);
        assert_eq!(msg, "Could not reach the GrepFocus daemon.");
        assert!(!msg.contains("sudo"));
    }
}
