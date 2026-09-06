//! Recover an empty replica by replaying retained history.

#[path = "support/catchup.rs"]
mod catchup;

#[tokio::test]
async fn cold_replica_replays_across_epochs() {
    catchup::recover_replica(false, false).await;
}
