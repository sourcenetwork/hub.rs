//! Resume snapshot startup after a process crash during durable history import.

#[path = "support/catchup.rs"]
mod catchup;

#[tokio::test]
async fn interrupted_snapshot_resumes_without_an_explicit_request() {
    catchup::recover_replica(true, true, false).await;
}
