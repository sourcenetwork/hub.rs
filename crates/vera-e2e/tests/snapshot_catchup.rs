//! Recover and restart an empty replica through authenticated snapshot transfer.

#[path = "support/catchup.rs"]
mod catchup;

#[tokio::test]
async fn snapshot_replica_recovers_history_and_rejoins_consensus() {
    catchup::recover_replica(true, false, false).await;
}

#[tokio::test]
async fn snapshot_replica_recovers_from_pruned_peers() {
    catchup::recover_replica(true, false, true).await;
}
