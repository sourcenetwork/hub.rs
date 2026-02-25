//! Core chain e2e tests — BFT consensus, observability, cluster state.
//!
//! All tests use 4-node BFT clusters. This is a distributed system —
//! single-node tests don't exercise the interesting failure modes.
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use hub_e2e::cluster::TestCluster;
use hub_e2e::observe::ClusterAssertions;

/// Canonical integration test exercising all observability subsystems.
///
/// Starts a 4-node BFT cluster, attaches observability, waits for blocks,
/// and cross-validates data between LogTracker, RpcPoller, and ClusterState.
#[tokio::test]
async fn cluster_observability_canonical() {
    let n = 4;
    let chain_id = 7777;

    // 1. Build 4-node BFT cluster with random keys.
    let cluster = TestCluster::builder()
        .binary(hub_e2e::hubd_binary())
        .nodes(n)
        .chain_id(chain_id)
        .build()
        .await
        .expect("cluster should start");

    // 2. Wait for all 4 nodes to become healthy.
    cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("cluster should become healthy");

    // 3. Attach observability — spawns LogTracker per node + RpcPoller.
    let state = cluster.observe(Duration::from_millis(200));

    // 4. RPC poller should detect all 4 nodes as healthy.
    state
        .wait_for_healthy(n, Duration::from_secs(15))
        .await
        .expect("observer should see all nodes healthy");

    // 5. Wait for BFT consensus to finalize blocks.
    //    Height 6 gives the block index + RPC poller time to converge,
    //    so we can assert latest_block_height >= 4 below.
    state
        .wait_for_height(6, Duration::from_secs(30))
        .await
        .expect("should reach height 6");

    // 6. Chain ID must be consistent across all nodes (RPC poller).
    state
        .assert_chain_id(chain_id)
        .expect("chain_id should match across all nodes");

    // 7. All node snapshots should show consistent state.
    for i in 0..n {
        let snap = state.node(i);
        assert!(snap.is_healthy, "node{} should be healthy", i);
        assert_eq!(snap.chain_id, chain_id, "node{} snapshot chain_id", i);
        assert!(
            snap.effective_height() >= 6,
            "node{} effective height should be >= 6 (finalized={}, block={})",
            i,
            snap.finalized_count,
            snap.latest_block_height,
        );
        assert!(
            snap.current_view >= 6,
            "node{} consensus view should have advanced past 6",
            i,
        );
        assert!(
            snap.latest_block_height >= 4,
            "node{} latest_block_height should be >= 4 via IndexedStateProvider (got {})",
            i,
            snap.latest_block_height,
        );
    }

    // 8. LogTracker must be working — this test validates the observability framework.
    //    Give the log parser a moment to catch up with block production.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for i in 0..n {
        let log_height = state.node_logs(i).latest_height();
        assert!(
            log_height >= 2,
            "node{} log tracker should have seen at least 2 blocks (got {}). \
             Log parser regex may not match hub's output format.",
            i,
            log_height,
        );
    }

    // 9. Cross-validate: log tracker heights and RPC poller heights must agree.
    for i in 0..n {
        let log_height = state.node_logs(i).latest_height();
        let rpc_height = state.node(i).effective_height();
        let diff = rpc_height.abs_diff(log_height);
        assert!(
            diff <= 5,
            "node{} log height ({}) and RPC height ({}) diverged by {} blocks",
            i,
            log_height,
            rpc_height,
            diff,
        );
    }

    // 10. All healthy nodes should have converged block heights (BFT guarantee).
    state
        .assert_heights_converged(2)
        .expect("BFT nodes should have converged heights");

    // 11. Verify node metadata across all validators.
    for i in 0..n {
        let snap = state.node(i);
        assert!(
            snap.uptime_secs > 0 || snap.finalized_count >= 6,
            "node{} should show progress (uptime={}, finalized={})",
            i,
            snap.uptime_secs,
            snap.finalized_count,
        );
    }

    // 12. Verify test infrastructure: each node has log and data files.
    for i in 0..n {
        let node = cluster.node(i);
        assert!(
            node.log_dir.join("stderr.log").exists(),
            "node{} stderr.log should exist",
            i,
        );
        assert!(
            node.log_dir.join("stdout.log").exists(),
            "node{} stdout.log should exist",
            i,
        );
        assert!(
            node.data_dir.join("genesis.json").exists(),
            "node{} genesis.json should exist",
            i,
        );
        assert!(
            node.data_dir.join("validator.key").exists(),
            "node{} validator.key should exist",
            i,
        );
    }

    // 13. No errors should have been logged by any node.
    state
        .assert_no_errors()
        .expect("cluster should have no errors");
}
