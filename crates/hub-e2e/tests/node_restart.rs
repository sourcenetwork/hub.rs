//! Node restart e2e test — validates state persistence and consensus
//! recovery across process restarts.
//!
//! Lifecycle:
//!   1. Start 4-node cluster, submit EVM + BLS transactions
//!   2. Snapshot state, kill node 3
//!   3. Verify 3-node cluster continues (EVM tx while node is down)
//!   4. Restart node 3, wait for backfill completion
//!   5. Verify pre-kill state survived restart (QMDB persistence)
//!   6. Verify restarted node caught up on blocks produced while down
//!   7. Submit post-restart EVM + BLS txs, verify both paths work
//!   8. Submit tx THROUGH the restarted node (mempool/forwarding)
//!   9. Verify restarted node is in consensus (view advances, blocks produced)
//!  10. Final cluster health
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;

use hub_client::{ACP_ADDRESS, BlsSigner, EvmSigner, HubClient, TransactionReceipt};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_modules::acp::abi::IAcp;

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const TEST_POLICY_YAML: &str = "\
name: restart-test-policy
resources:
  - name: file
    relations:
      - name: owner
    permissions:
      - name: read
        expr: owner
";

const RECEIPT_INTERVAL: Duration = Duration::from_millis(150);
const RECEIPT_ATTEMPTS: u32 = 200;

fn create_policy_calldata() -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode()
}

async fn broadcast_evm_tx(
    cluster: &TestCluster,
    client: &HubClient,
    signer: &EvmSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let nonce = client
        .get_nonce(signer.address())
        .await
        .expect("get_nonce should work");
    let raw = signer
        .sign_tx(target, Bytes::from(calldata), nonce)
        .expect("EVM sign should succeed");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let r = raw.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move {
                let result = HubClient::new(url).send_raw_transaction(&r).await;
                (i, result)
            })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok((_node_idx, Ok(hash))) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the EVM tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_INTERVAL, RECEIPT_ATTEMPTS)
        .await
        .expect("EVM receipt should appear")
}

async fn broadcast_native_tx(
    cluster: &TestCluster,
    client: &HubClient,
    signer: &BlsSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let wire = signer
        .sign_native_tx(target, Bytes::from(calldata))
        .expect("BLS sign should succeed");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let w = wire.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move {
                let result = HubClient::new(url).send_native_tx(&w).await;
                (i, result)
            })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok((_node_idx, Ok(hash))) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the BLS tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_INTERVAL, RECEIPT_ATTEMPTS)
        .await
        .expect("BLS receipt should appear")
}

/// Send a single EVM tx directly to one node (not broadcast).
async fn send_evm_tx_to_node(
    client: &HubClient,
    signer: &EvmSigner,
    target: Address,
    calldata: Vec<u8>,
) -> TransactionReceipt {
    let nonce = client
        .get_nonce(signer.address())
        .await
        .expect("get_nonce should work");
    let raw = signer
        .sign_tx(target, Bytes::from(calldata), nonce)
        .expect("EVM sign should succeed");
    let tx_hash = client
        .send_raw_transaction(&raw)
        .await
        .expect("node should accept tx");
    client
        .wait_for_receipt(tx_hash, RECEIPT_INTERVAL, RECEIPT_ATTEMPTS)
        .await
        .expect("receipt should appear")
}

/// Poll until a condition holds, with a descriptive panic on timeout.
async fn poll_until(
    description: &str,
    timeout: Duration,
    interval: Duration,
    mut check: impl FnMut()
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>>,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(msg) = check().await {
            if tokio::time::Instant::now() >= deadline {
                panic!("timeout: {description} — {msg}");
            }
            tokio::time::sleep(interval).await;
        } else {
            return;
        }
    }
}

#[tokio::test]
async fn node_restart_preserves_state() {
    let chain_id = 9001;
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let mut cluster = TestCluster::builder()
        .binary(hub_e2e::resolve_binary().expect("resolve hubd binary"))
        .nodes(4)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Stress)
        .build()
        .await
        .expect("cluster should start");

    cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("cluster should become healthy");

    let mut state = cluster.observe(Duration::from_millis(200));
    state
        .wait_for_height(3, Duration::from_secs(60))
        .await
        .expect("should reach height 3");

    let client = HubClient::new(cluster.node(0).rpc_url());
    let evm_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");
    let bls_signer = BlsSigner::random(chain_id).expect("random BLS signer");
    let bls_did = bls_signer.did().to_owned();

    // ── 1. Submit EVM + BLS policies before kill ───────────────────

    let evm_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        create_policy_calldata(),
    )
    .await;
    assert_eq!(evm_receipt.status, 1, "EVM create_policy should succeed");

    let bls_receipt = broadcast_native_tx(
        &cluster,
        &client,
        &bls_signer,
        ACP_ADDRESS,
        create_policy_calldata(),
    )
    .await;
    assert_eq!(bls_receipt.status, 1, "BLS create_policy should succeed");

    let max_block = evm_receipt.block_number.max(bls_receipt.block_number);
    state
        .wait_for_height(max_block + 1, Duration::from_secs(60))
        .await
        .expect("cluster should advance past create_policy blocks");

    // ── 2. Snapshot state before kill ────────────────────────────

    let pre_kill_policies = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert!(
        pre_kill_policies.len() >= 2,
        "should have at least 2 policies before kill, got: {pre_kill_policies:?}"
    );

    let pre_kill_bls_nonce = client
        .get_native_nonce(&bls_did)
        .await
        .expect("get_native_nonce should work");
    assert_eq!(pre_kill_bls_nonce, 1, "BLS nonce should be 1 after one tx");

    let pre_kill_evm_nonce = client
        .get_nonce(evm_signer.address())
        .await
        .expect("get_nonce should work");

    let pre_kill_height = state
        .all_nodes()
        .iter()
        .filter(|s| s.is_healthy)
        .map(|s| s.effective_height())
        .max()
        .unwrap_or(0);

    // ── 3. Kill node 3 ──────────────────────────────────────────

    cluster.kill_node(3);

    state
        .wait_for_healthy(3, Duration::from_secs(10))
        .await
        .expect("3 nodes should remain healthy after kill");

    state
        .wait_for_height(pre_kill_height + 3, Duration::from_secs(30))
        .await
        .expect("cluster should continue producing blocks with 3 nodes");

    // Submit an EVM tx while node 3 is down — the restarted node must
    // catch up on this block during backfill.
    let while_down_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        create_policy_calldata(),
    )
    .await;
    assert_eq!(
        while_down_receipt.status, 1,
        "EVM tx while node down should succeed"
    );

    let while_down_evm_nonce = client
        .get_nonce(evm_signer.address())
        .await
        .expect("get_nonce after while-down tx");
    assert!(
        while_down_evm_nonce > pre_kill_evm_nonce,
        "EVM nonce should advance while node is down"
    );

    // ── 4. Restart node 3 ───────────────────────────────────────

    cluster
        .restart_node(3)
        .expect("restart_node should succeed");
    state.restart_node_logs(3);

    state
        .wait_for_healthy(4, Duration::from_secs(30))
        .await
        .expect("all 4 nodes should be healthy after restart");

    // ── 5. Verify pre-restart QMDB state survived ───────────────
    //
    // These queries hit QMDB directly (not BlockIndex), so they
    // work immediately even before backfill completes.

    let restarted_client = HubClient::new(cluster.node(3).rpc_url());

    let restarted_chain_id = restarted_client
        .chain_id()
        .await
        .expect("restarted node should respond to eth_chainId");
    assert_eq!(
        restarted_chain_id, chain_id,
        "restarted node chain ID should match"
    );

    let restarted_policies = restarted_client
        .get_policy_ids()
        .await
        .expect("restarted node get_policy_ids should succeed");
    for pid in &pre_kill_policies {
        assert!(
            restarted_policies.contains(pid),
            "restarted node should contain pre-kill policy {pid}"
        );
    }

    let restarted_bls_nonce = restarted_client
        .get_native_nonce(&bls_did)
        .await
        .expect("restarted node get_native_nonce should work");
    assert_eq!(
        restarted_bls_nonce, pre_kill_bls_nonce,
        "restarted node BLS nonce should match pre-kill value"
    );

    // ── 6. Wait for backfill completion and state convergence ────
    //
    // The FinalizedReporter replays blocks (skipping already-committed
    // ones) and updates QMDB. Wait for the restarted node to finish
    // backfilling and converge on all state indicators.

    state
        .wait_for_synced(4, Duration::from_secs(120))
        .await
        .expect("all 4 nodes should finish backfilling");

    // EVM nonce convergence: the restarted node must process the
    // tx submitted while it was down.
    let restarted_url = cluster.node(3).rpc_url();
    let addr = evm_signer.address();
    let target_nonce = while_down_evm_nonce;
    poll_until(
        "restarted node EVM nonce convergence",
        Duration::from_secs(120),
        Duration::from_millis(500),
        {
            let url = restarted_url.clone();
            move || {
                let url = url.clone();
                Box::pin(async move {
                    let nonce = HubClient::new(url).get_nonce(addr).await.unwrap_or(0);
                    if nonce >= target_nonce {
                        None
                    } else {
                        Some(format!("nonce {nonce}, need {target_nonce}"))
                    }
                })
            }
        },
    )
    .await;

    // The restarted node should now see the policy created while it was down.
    let converged_policies = restarted_client
        .get_policy_ids()
        .await
        .expect("restarted node get_policy_ids after convergence");
    assert!(
        converged_policies.len() > pre_kill_policies.len(),
        "restarted node should have more policies after catching up (pre-kill: {}, now: {})",
        pre_kill_policies.len(),
        converged_policies.len()
    );

    // ── 7. Post-restart EVM + BLS transactions ──────────────────
    //
    // Verify both tx paths work through the full cluster after restart.

    let post_evm_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        create_policy_calldata(),
    )
    .await;
    assert_eq!(
        post_evm_receipt.status, 1,
        "post-restart EVM tx should succeed"
    );

    let post_bls_receipt = broadcast_native_tx(
        &cluster,
        &client,
        &bls_signer,
        ACP_ADDRESS,
        create_policy_calldata(),
    )
    .await;
    assert_eq!(
        post_bls_receipt.status, 1,
        "post-restart BLS tx should succeed (native nonce recovery)"
    );

    let post_bls_nonce = client
        .get_native_nonce(&bls_did)
        .await
        .expect("get_native_nonce after post-restart BLS tx");
    assert_eq!(
        post_bls_nonce,
        pre_kill_bls_nonce + 1,
        "BLS nonce should increment after post-restart tx"
    );

    // ── 8. Submit tx THROUGH the restarted node ─────────────────
    //
    // Verifies the restarted node's mempool accepts txs and forwards
    // them to the leader for inclusion.

    let through_restarted_receipt = send_evm_tx_to_node(
        &restarted_client,
        &evm_signer,
        ACP_ADDRESS,
        create_policy_calldata(),
    )
    .await;
    assert_eq!(
        through_restarted_receipt.status, 1,
        "tx submitted through restarted node should succeed"
    );

    // ── 9. Consensus participation ──────────────────────────────
    //
    // Verify the restarted node is actively participating in consensus
    // by checking that its view advances and it finalizes new blocks.
    // We poll the restarted node's status directly rather than using
    // wait_for_height (which requires all nodes to converge).

    let status_before = restarted_client
        .node_status()
        .await
        .expect("restarted node should report status");
    let view_before = status_before.current_view;
    let finalized_before = status_before.finalized_count;

    let restarted_url2 = cluster.node(3).rpc_url();
    poll_until(
        "restarted node consensus participation",
        Duration::from_secs(60),
        Duration::from_millis(500),
        {
            let url = restarted_url2.clone();
            move || {
                let url = url.clone();
                Box::pin(async move {
                    let Ok(status) = HubClient::new(url).node_status().await else {
                        return Some("node unreachable".to_string());
                    };
                    if status.current_view > view_before
                        && status.finalized_count > finalized_before
                    {
                        None
                    } else {
                        Some(format!(
                            "view {} -> {}, finalized {} -> {}",
                            view_before,
                            status.current_view,
                            finalized_before,
                            status.finalized_count
                        ))
                    }
                })
            }
        },
    )
    .await;

    let status_after = restarted_client
        .node_status()
        .await
        .expect("restarted node status after consensus check");
    assert!(
        status_after.current_view > view_before,
        "restarted node view should advance ({} -> {})",
        view_before,
        status_after.current_view
    );
    assert!(
        status_after.finalized_count > finalized_before,
        "restarted node should finalize new blocks ({} -> {})",
        finalized_before,
        status_after.finalized_count
    );

    // ── 10. Final cluster health ────────────────────────────────

    state
        .assert_chain_id(chain_id)
        .expect("chain ID should be consistent across nodes");

    // All 4 nodes should be healthy and synced.
    let final_snaps = state.all_nodes();
    let healthy_count = final_snaps.iter().filter(|s| s.is_healthy).count();
    assert_eq!(healthy_count, 4, "all 4 nodes should be healthy at end");

    state
        .wait_for_synced(4, Duration::from_secs(30))
        .await
        .expect("all 4 nodes should be synced at end");

    // Verify final policy count is consistent across primary and restarted node.
    let primary_final_policies = client
        .get_policy_ids()
        .await
        .expect("primary final get_policy_ids");
    let restarted_final_policies = restarted_client
        .get_policy_ids()
        .await
        .expect("restarted final get_policy_ids");
    assert_eq!(
        primary_final_policies.len(),
        restarted_final_policies.len(),
        "policy count should match between primary ({}) and restarted ({})",
        primary_final_policies.len(),
        restarted_final_policies.len()
    );
}
