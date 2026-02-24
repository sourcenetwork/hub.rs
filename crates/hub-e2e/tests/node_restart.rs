//! Node restart e2e test — validates state persistence across process restarts.
//!
//! Starts a 4-node cluster, submits EVM + BLS transactions, kills a node,
//! verifies the remaining cluster continues, restarts the killed node, and
//! confirms it rejoins with all prior state intact.
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

#[tokio::test]
async fn node_restart_preserves_state() {
    let chain_id = 9001;
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let mut cluster = TestCluster::builder()
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

    // ── 1. Submit EVM + BLS policies (sequential to avoid nonce races) ──

    let evm_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let bls_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();

    let evm_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, evm_calldata).await;
    assert_eq!(evm_receipt.status, 1, "EVM create_policy should succeed");

    let bls_receipt =
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, bls_calldata).await;
    assert_eq!(bls_receipt.status, 1, "BLS create_policy should succeed");

    let max_block = evm_receipt.block_number.max(bls_receipt.block_number);

    state
        .wait_for_height(max_block + 1, Duration::from_secs(60))
        .await
        .expect("cluster should advance past create_policy blocks");

    // ── 2. Snapshot state before kill ────────────────────────────

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert!(
        policy_ids.len() >= 2,
        "should have at least 2 policies before kill, got: {policy_ids:?}"
    );

    let bls_nonce = client
        .get_native_nonce(&bls_did)
        .await
        .expect("get_native_nonce should work");
    assert_eq!(bls_nonce, 1, "BLS nonce should be 1 after one tx");

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

    // ── 4. Restart node 3 ───────────────────────────────────────

    cluster
        .restart_node(3)
        .expect("restart_node should succeed");
    state.restart_node_logs(3);

    state
        .wait_for_healthy(4, Duration::from_secs(30))
        .await
        .expect("all 4 nodes should be healthy after restart");

    // ── 5. Verify pre-restart state on restarted node ─────────────
    //
    // QMDB state is preserved across restarts (idempotent init_genesis
    // skips existing accounts). These queries hit QMDB directly, not
    // the in-memory BlockIndex, so they work immediately.

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
    for pid in &policy_ids {
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
        restarted_bls_nonce, 1,
        "restarted node BLS nonce should be 1"
    );

    // ── 6. Submit tx through cluster (verify full functionality) ─

    let post_restart_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let post_restart_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        post_restart_calldata,
    )
    .await;
    assert_eq!(
        post_restart_receipt.status, 1,
        "post-restart EVM tx should succeed"
    );

    // ── 7. Wait for restarted node to converge ─────────────────
    //
    // Poll the restarted node's EVM nonce until it matches the primary.
    // The FinalizedReporter replays blocks (skipping already-committed
    // ones) and updates QMDB. This can take time in debug builds.
    let primary_nonce = client
        .get_nonce(evm_signer.address())
        .await
        .expect("primary node should report EVM nonce");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    loop {
        let restarted_nonce = restarted_client
            .get_nonce(evm_signer.address())
            .await
            .unwrap_or(0);
        if restarted_nonce == primary_nonce {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "restarted node EVM nonce ({restarted_nonce}) should converge to primary ({primary_nonce})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── 8. Cluster health ────────────────────────────────────────

    state
        .assert_chain_id(chain_id)
        .expect("chain ID should be consistent across nodes");
}
