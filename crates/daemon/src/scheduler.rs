//! Watches for active-block expiration and lifts enforcement when the timer ends.

use std::sync::Arc;
use std::time::Duration;

use frostbite_core::now_unix;
use tracing::{error, info};

use crate::{hosts, state, Daemon};

const TICK: Duration = Duration::from_secs(1);

pub async fn run(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let now = now_unix();
        let expired = {
            let st = daemon.state.lock().await;
            matches!(&st.active, Some(a) if a.ends_at_unix <= now)
        };
        if !expired {
            continue;
        }
        info!("active block expired — lifting enforcement");
        if let Err(e) = hosts::clear_block() {
            error!(?e, "failed to clear hosts block on expiry");
        }
        let mut st = daemon.state.lock().await;
        st.active = None;
        if let Err(e) = state::save(&st, &daemon.key) {
            error!(?e, "failed to save state after expiry");
        }
    }
}
