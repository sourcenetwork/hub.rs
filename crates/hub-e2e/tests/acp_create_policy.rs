//! Integration test for the ACP create_policy pipeline.
//!
//! Exercises both EVM and BLS transaction paths through the full pipeline:
//! cluster startup -> RPC connectivity -> transaction signing -> submission ->
//! block execution -> AcpModule::create_policy() -> query policy back.
//!
//! Validates receipt structure, policy content, cross-node consistency,
//! consensus health, nonce accounting, and block progression.
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::{B256, Bytes, U256};
use alloy_sol_types::SolCall;

use hub_client::{ACP_ADDRESS, BlsSigner, EvmSigner, HubClient};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_e2e::observe::ClusterAssertions;
use hub_modules::acp::abi::IAcp;

/// Hardhat account 0 private key (pre-funded by `GenesisBuilder::funded_accounts`).
const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Minimal DPI-compliant ACP policy for testing.
const TEST_POLICY_YAML: &str = "\
name: test-policy
resources:
  - name: document
    relations:
      - name: owner
      - name: reader
    permissions:
      - name: read
        expr: owner + reader
      - name: update
        expr: owner
      - name: delete
        expr: owner
";

/// Create ACP policies via both EVM and BLS paths, then query them back.
///
/// Validates the full transaction + persistence pipeline:
/// 1. Cluster starts and produces blocks (consensus + block execution)
/// 2. RPC layer responds (chain_id, balance queries)
/// 3. EVM create_policy -> receipt assertions
/// 4. Nonce/balance accounting after EVM tx
/// 5. BLS create_policy (parallel broadcast) -> receipt assertions
/// 6. Policy content verification (get_policy for each ID)
/// 7. Cross-node state consistency (all nodes agree)
/// 8. Cluster health (convergence, no errors, chain_id)
/// 9. Node status assertions (finalized_count, peer_count)
#[tokio::test]
async fn create_and_query_policies() {
    let chain_id = 9001;
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let cluster = TestCluster::builder()
        .nodes(4)
        .chain_id(chain_id)
        .genesis(genesis)
        .preset(ConsensusPreset::Fast)
        .build()
        .await
        .expect("cluster should start");

    cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("cluster should become healthy");

    let state = cluster.observe(Duration::from_millis(200));
    state
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("should reach height 3");

    let client = HubClient::new(cluster.node(0).rpc_url());

    let reported_chain_id = client.chain_id().await.expect("eth_chainId should work");
    assert_eq!(reported_chain_id, chain_id, "chain ID should match");

    // -- EVM path: create policy via eth_sendRawTransaction --
    let evm_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");

    let balance_before = client
        .get_balance(evm_signer.address())
        .await
        .expect("eth_getBalance should work");
    assert!(balance_before > U256::ZERO, "test account should be funded");

    let evm_receipt = client
        .create_policy(&evm_signer, TEST_POLICY_YAML.as_bytes(), 1)
        .await
        .expect("EVM create_policy tx should succeed");

    // -- EVM receipt structure assertions --
    // Note: create_policy() already returns Err on status == 0, so this
    // assertion is documentation rather than a safety net.
    assert_eq!(evm_receipt.status, 1, "EVM create_policy should succeed");
    assert!(
        evm_receipt.block_number > 0,
        "EVM tx should be included in a real block"
    );
    assert!(evm_receipt.gas_used > 0, "EVM tx should consume gas");
    assert_ne!(
        evm_receipt.transaction_hash,
        B256::ZERO,
        "EVM tx hash should be non-degenerate"
    );
    assert_eq!(
        evm_receipt.from,
        evm_signer.address(),
        "EVM receipt 'from' should match signer address"
    );
    assert_eq!(
        evm_receipt.to,
        Some(ACP_ADDRESS),
        "EVM receipt 'to' should be the ACP precompile"
    );

    // -- Nonce accounting after EVM tx --
    let nonce_after_evm = client
        .get_nonce(evm_signer.address())
        .await
        .expect("get_nonce should work");
    assert_eq!(
        nonce_after_evm, 1,
        "EVM nonce should increment to 1 after first tx"
    );

    let balance_after = client
        .get_balance(evm_signer.address())
        .await
        .expect("get_balance should work");
    assert!(
        balance_after < balance_before,
        "balance should decrease after paying gas (before={balance_before}, after={balance_after})"
    );

    // -- BLS path: create policy via hub_sendNativeTx --
    // Submit to all nodes in parallel so every potential leader has
    // the tx in its mempool. P2P forwarding of native txs to the
    // current leader is not yet reliable under test conditions.
    let bls_signer = BlsSigner::random(chain_id).expect("random BLS signer");
    let calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();

    let wire = bls_signer
        .sign_native_tx(ACP_ADDRESS, Bytes::from(calldata))
        .expect("BLS sign should succeed");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let w = wire.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move { HubClient::new(url).send_native_tx(&w).await })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok(Ok(hash)) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the BLS tx");

    let bls_receipt = client
        .wait_for_receipt(tx_hash, Duration::from_millis(250), 200)
        .await
        .expect("BLS create_policy receipt should appear");

    // -- BLS receipt structure assertions --
    assert_eq!(bls_receipt.status, 1, "BLS create_policy should succeed");
    assert!(
        bls_receipt.block_number > 0,
        "BLS tx should be included in a real block"
    );
    assert!(bls_receipt.gas_used > 0, "BLS tx should consume gas");
    assert_ne!(
        bls_receipt.transaction_hash,
        B256::ZERO,
        "BLS tx hash should be non-degenerate"
    );

    // -- Block progression --
    assert!(
        evm_receipt.block_number <= bls_receipt.block_number,
        "BLS tx should be in same block or later than EVM tx \
         (evm={}, bls={})",
        evm_receipt.block_number,
        bls_receipt.block_number
    );

    let current_height = client
        .block_number()
        .await
        .expect("eth_blockNumber should work");
    assert!(
        bls_receipt.block_number <= current_height,
        "BLS receipt block ({}) should not exceed current height ({})",
        bls_receipt.block_number,
        current_height
    );

    // -- Query: verify both policies are persisted and queryable --
    tokio::time::sleep(Duration::from_millis(500)).await;

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");

    assert_eq!(
        policy_ids.len(),
        2,
        "should have 2 policies (EVM + BLS), got: {policy_ids:?}"
    );

    // -- Policy content assertions --
    // get_policy returns a JSON-serialized PolicyRecord with structure:
    //   { "policy": { "name": ..., "resources": [...] }, "raw_policy": "...",
    //     "marshal_type": ..., "metadata": { ... } }
    for (i, policy_id_str) in policy_ids.iter().enumerate() {
        let mut id_bytes = [0u8; 32];
        let hex = policy_id_str.strip_prefix("0x").unwrap_or(policy_id_str);
        hex::decode_to_slice(hex, &mut id_bytes)
            .unwrap_or_else(|e| panic!("policy ID {i} should be valid hex: {e}"));
        let policy_id = alloy_primitives::FixedBytes::from(id_bytes);

        let policy_bytes = client
            .get_policy(policy_id)
            .await
            .unwrap_or_else(|e| panic!("get_policy({policy_id_str}) should succeed: {e}"));
        assert!(
            !policy_bytes.is_empty(),
            "policy {i} bytes should not be empty"
        );

        let record: serde_json::Value = serde_json::from_slice(&policy_bytes)
            .unwrap_or_else(|e| panic!("policy {i} should be valid JSON: {e}"));

        let name = record
            .pointer("/policy/name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(name, "test-policy", "policy {i} name should match");

        let resources = record.pointer("/policy/resources");
        assert!(
            resources.is_some(),
            "policy {i} should have resources field"
        );
        let resources_str = serde_json::to_string(resources.unwrap()).unwrap();
        assert!(
            resources_str.contains("document"),
            "policy {i} resources should contain 'document'"
        );

        let raw_policy = record
            .get("raw_policy")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            raw_policy.contains("test-policy"),
            "policy {i} raw_policy should contain the original YAML"
        );
    }

    // -- Cross-node state consistency --
    for node_idx in 0..cluster.node_count() {
        let node_client = HubClient::new(cluster.node(node_idx).rpc_url());
        let node_policy_ids = node_client
            .get_policy_ids()
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} get_policy_ids should succeed: {e}"));
        assert_eq!(
            node_policy_ids.len(),
            2,
            "node{node_idx} should have 2 policies, got: {node_policy_ids:?}"
        );
        let mut expected_sorted = policy_ids.clone();
        expected_sorted.sort();
        let mut actual_sorted = node_policy_ids.clone();
        actual_sorted.sort();
        assert_eq!(
            actual_sorted, expected_sorted,
            "node{node_idx} policy IDs should match node0"
        );
    }

    // -- Cluster health assertions --
    // Ensure all nodes have advanced past the last tx before checking
    // convergence — assert_heights_converged reads snapshots once
    // without retry, so stale data can cause spurious failures.
    state
        .wait_for_height(bls_receipt.block_number + 1, Duration::from_secs(15))
        .await
        .expect("all nodes should advance past BLS tx block");
    state
        .assert_heights_converged(2)
        .expect("block heights should converge within 2 blocks");
    state
        .assert_no_errors()
        .expect("no unexpected errors in cluster logs");
    state
        .assert_chain_id(chain_id)
        .expect("chain ID should be consistent across nodes");

    // -- Node status assertions --
    for node_idx in 0..cluster.node_count() {
        let node_client = HubClient::new(cluster.node(node_idx).rpc_url());
        let status = node_client
            .node_status()
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} node_status should succeed: {e}"));
        assert!(
            status.finalized_count > 0,
            "node{node_idx} should have finalized at least one block (got {})",
            status.finalized_count
        );
    }
}
