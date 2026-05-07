//! Tiny client that opens a Unix socket per call to talk to frostbited.
//!
//! Per-call connections keep the code simple and avoid lifecycle headaches
//! for a v0.1 GUI; the daemon handles each connection independently.

use frostbite_core::{Request, Response};
use tokio::net::UnixStream;

const SOCK_PATH: &str = "/run/frostbite/sock";

pub async fn call(req: Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(SOCK_PATH)
        .await
        .map_err(|e| format!("connect {SOCK_PATH}: {e}"))?;
    frostbite_core::wire::write_json(&mut stream, &req)
        .await
        .map_err(|e| format!("write: {e}"))?;
    let resp: Response = frostbite_core::wire::read_json(&mut stream)
        .await
        .map_err(|e| format!("read: {e}"))?;
    Ok(resp)
}
