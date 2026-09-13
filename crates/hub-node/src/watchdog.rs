//! Finality-progress watchdog.
//!
//! A validator that stops finalizing while connected to peers is wedged, not
//! idle: the known cause is falling behind epoch boundaries that peers have
//! pruned, where following ceremonies forward can no longer make progress.
//! The watchdog fails the process fast so supervision restarts it into the
//! boot-time rejoin, which re-engages peer state sync from a current floor.

use std::time::Duration;

use hub_jsonrpc::NodeState;

/// Exit code reported when the watchdog trips.
pub(crate) const EXIT_CODE: i32 = 83;

/// Decide whether the process should fail from observed progress.
///
/// `finalized_ever` gates arming: a node that has never finalized is still
/// joining, and initial synchronization may legitimately take longer than the
/// stall budget.
pub(crate) fn tripped(
    finalized_ever: bool,
    stalled_for: Duration,
    peers_connected: bool,
    budget: Duration,
) -> bool {
    finalized_ever && peers_connected && stalled_for >= budget
}

/// Run the watchdog until the process ends.
pub(crate) async fn run(state: NodeState, budget: Duration) {
    let mut last_count = state.finalized_count();
    let mut last_progress = tokio::time::Instant::now();
    let mut finalized_ever = last_count > 0;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let count = state.finalized_count();
        if count != last_count {
            last_count = count;
            last_progress = tokio::time::Instant::now();
            finalized_ever = true;
        }
        if tripped(
            finalized_ever,
            last_progress.elapsed(),
            state.peer_count() > 0,
            budget,
        ) {
            tracing::error!(
                stalled_seconds = last_progress.elapsed().as_secs(),
                peers = state.peer_count(),
                "finality stalled with peers connected; exiting for supervised rejoin"
            );
            std::process::exit(EXIT_CODE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arms_only_after_first_finalization() {
        let budget = Duration::from_secs(600);
        assert!(!tripped(false, Duration::from_secs(9_999), true, budget));
        assert!(tripped(true, Duration::from_secs(600), true, budget));
    }

    #[test]
    fn peerless_stalls_do_not_trip() {
        assert!(!tripped(
            true,
            Duration::from_secs(9_999),
            false,
            Duration::from_secs(600),
        ));
    }

    #[test]
    fn progress_within_budget_does_not_trip() {
        assert!(!tripped(
            true,
            Duration::from_secs(599),
            true,
            Duration::from_secs(600),
        ));
    }
}
