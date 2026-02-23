//! Canonical integration test — full module lifecycle.
//!
//! Exercises both EVM and BLS transaction paths through every module:
//! ACP (policy, object, relationship, access control),
//! Bulletin (namespace, collaborator, post),
//! and cross-path verification (BLS write + EVM query, EVM write + BLS query).
//!
//! One cluster startup, one comprehensive test.
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;

use hub_client::{
    ACP_ADDRESS, BULLETIN_ADDRESS, BlsSigner, EvmSigner, HubClient, TransactionReceipt,
};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_e2e::observe::ClusterAssertions;
use hub_modules::acp::abi::IAcp;
use hub_modules::bulletin::abi::IBulletin;

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

/// Receipt polling: 300ms interval, 200 attempts = 60s max.
const RECEIPT_INTERVAL: Duration = Duration::from_millis(300);
const RECEIPT_ATTEMPTS: u32 = 200;

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
}

/// Sign an EVM transaction and broadcast to all nodes in the cluster.
///
/// Simplex leader rotation means the tx may sit in a non-leader's mempool;
/// broadcasting to every node ensures the current leader has it.
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
        if let Ok((node_idx, result)) = fut.await {
            match result {
                Ok(hash) => {
                    eprintln!("[broadcast_evm] node{node_idx} accepted: {hash:?}");
                    tx_hash = Some(hash);
                }
                Err(e) => {
                    eprintln!("[broadcast_evm] node{node_idx} rejected: {e}");
                }
            }
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the EVM tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_INTERVAL, RECEIPT_ATTEMPTS)
        .await
        .expect("EVM receipt should appear")
}

/// Sign a native BLS transaction and broadcast to all nodes in the cluster.
///
/// P2P forwarding of native txs to the current leader is not yet reliable
/// under test conditions, so we submit to every node.
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
        if let Ok((node_idx, result)) = fut.await {
            match result {
                Ok(hash) => {
                    eprintln!("[broadcast_bls] node{node_idx} accepted: {hash:?}");
                    tx_hash = Some(hash);
                }
                Err(e) => {
                    eprintln!("[broadcast_bls] node{node_idx} rejected: {e}");
                }
            }
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the BLS tx");

    // Check block production during wait.
    let start_height = client.block_number().await.unwrap_or(0);
    eprintln!("[broadcast_bls] polling for receipt {tx_hash:?}, start_height={start_height}");

    for attempt in 0..RECEIPT_ATTEMPTS {
        if let Some(receipt) = client
            .get_transaction_receipt(tx_hash)
            .await
            .expect("receipt RPC should not error")
        {
            eprintln!("[broadcast_bls] receipt found at attempt {attempt}");
            return receipt;
        }
        if attempt % 20 == 0 && attempt > 0 {
            let height = client.block_number().await.unwrap_or(0);
            eprintln!("[broadcast_bls] attempt {attempt}/{RECEIPT_ATTEMPTS}, height={height}");
        }
        tokio::time::sleep(RECEIPT_INTERVAL).await;
    }

    let final_height = client.block_number().await.unwrap_or(0);
    panic!(
        "BLS receipt not found after {RECEIPT_ATTEMPTS} attempts. \
         tx_hash={tx_hash:?}, start_height={start_height}, final_height={final_height}"
    );
}

/// Full module lifecycle: ACP + Bulletin, EVM + BLS, writes + queries.
#[tokio::test]
async fn canonical_module_test() {
    // ── SETUP ─────────────────────────────────────────────────────

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

    let evm_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");
    let bls_signer = BlsSigner::random(chain_id).expect("random BLS signer");

    let evm_did = evm_signer.did();
    let bls_did = bls_signer.did().to_owned();

    // ── A: ACP Policy Creation ────────────────────────────────────

    // A1. EVM create_policy
    let balance_before = client
        .get_balance(evm_signer.address())
        .await
        .expect("eth_getBalance should work");
    assert!(balance_before > U256::ZERO, "test account should be funded");

    let evm_create_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let evm_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        evm_create_calldata,
    )
    .await;

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

    // A2. BLS create_policy (broadcast)
    let bls_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let bls_receipt =
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, bls_calldata).await;

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

    assert!(
        evm_receipt.block_number <= bls_receipt.block_number,
        "BLS tx should be in same block or later than EVM tx \
         (evm={}, bls={})",
        evm_receipt.block_number,
        bls_receipt.block_number
    );

    // A3. get_policy_ids → 2 policies
    state
        .wait_for_height(bls_receipt.block_number + 1, Duration::from_secs(15))
        .await
        .expect("cluster should advance past BLS create_policy block");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert_eq!(
        policy_ids.len(),
        2,
        "should have 2 policies (EVM + BLS), got: {policy_ids:?}"
    );

    let evm_policy_id = parse_policy_id(&policy_ids[0]);
    let _bls_policy_id = parse_policy_id(&policy_ids[1]);

    // A4. Policy content verification
    for (i, policy_id_str) in policy_ids.iter().enumerate() {
        let policy_id = parse_policy_id(policy_id_str);

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

    // ── B: ACP Object Registration ───────────────────────────────

    // B1. EVM register_object
    let b1_calldata = IAcp::registerObjectCall {
        policyId: evm_policy_id,
        objectId: "doc-evm".into(),
        resource: "document".into(),
    }
    .abi_encode();
    let b1_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, b1_calldata).await;
    assert_eq!(b1_receipt.status, 1, "EVM register_object should succeed");

    let (registered, _) = client
        .get_object_owner(evm_policy_id, "document", "doc-evm")
        .await
        .expect("get_object_owner should succeed");
    assert!(registered, "doc-evm should be registered");

    // B2. BLS register_object (cross-path: BLS writes to EVM-created policy)
    let b2_calldata = IAcp::registerObjectCall {
        policyId: evm_policy_id,
        objectId: "doc-bls".into(),
        resource: "document".into(),
    }
    .abi_encode();
    let b2_receipt =
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, b2_calldata).await;
    assert_eq!(b2_receipt.status, 1, "BLS register_object should succeed");

    let (registered, _) = client
        .get_object_owner(evm_policy_id, "document", "doc-bls")
        .await
        .expect("get_object_owner should succeed");
    assert!(registered, "doc-bls should be registered");

    // ── C: ACP Relationships + Access ────────────────────────────

    // C1. EVM set_relationship: grant bls_did "reader" on "doc-evm"
    let c1_calldata = IAcp::setRelationshipCall {
        policyId: evm_policy_id,
        resource: "document".into(),
        objectId: "doc-evm".into(),
        relation: "reader".into(),
        actor: bls_did.clone().into(),
    }
    .abi_encode();
    let c1_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, c1_calldata).await;
    assert_eq!(c1_receipt.status, 1, "EVM set_relationship should succeed");

    // C2. Verify relationship exists
    let has_rel = client
        .has_relationship(evm_policy_id, "document", "doc-evm", "reader", &bls_did)
        .await
        .expect("has_relationship should succeed");
    assert!(has_rel, "bls_did should have reader relationship");

    // C3. Verify access: bls_did can read but not update
    let can_read = client
        .verify_access_request(
            evm_policy_id,
            vec!["document".into()],
            vec!["doc-evm".into()],
            vec!["read".into()],
            &bls_did,
        )
        .await
        .expect("verify_access_request should succeed");
    assert!(can_read, "bls_did should have read access");

    let can_update = client
        .verify_access_request(
            evm_policy_id,
            vec!["document".into()],
            vec!["doc-evm".into()],
            vec!["update".into()],
            &bls_did,
        )
        .await
        .expect("verify_access_request should succeed");
    assert!(!can_update, "bls_did should NOT have update access");

    // C4. Owner retains full access
    let owner_can_read = client
        .verify_access_request(
            evm_policy_id,
            vec!["document".into()],
            vec!["doc-evm".into()],
            vec!["read".into()],
            &evm_did,
        )
        .await
        .expect("verify_access_request should succeed");
    assert!(owner_can_read, "owner (evm_did) should have read access");

    // ── D: ACP Delete + Access Revocation ────────────────────────

    // D1. BLS delete_relationship (cross-path: BLS revokes relationship on EVM object)
    let d1_calldata = IAcp::deleteRelationshipCall {
        policyId: evm_policy_id,
        resource: "document".into(),
        objectId: "doc-evm".into(),
        relation: "reader".into(),
        actor: bls_did.clone().into(),
    }
    .abi_encode();
    let d1_receipt =
        broadcast_native_tx(&cluster, &client, &bls_signer, ACP_ADDRESS, d1_calldata).await;
    assert_eq!(
        d1_receipt.status, 1,
        "BLS delete_relationship should succeed"
    );

    // D2. Relationship removed
    let has_rel = client
        .has_relationship(evm_policy_id, "document", "doc-evm", "reader", &bls_did)
        .await
        .expect("has_relationship should succeed");
    assert!(!has_rel, "bls_did reader relationship should be deleted");

    // D3. Access revoked for bls_did
    let can_read = client
        .verify_access_request(
            evm_policy_id,
            vec!["document".into()],
            vec!["doc-evm".into()],
            vec!["read".into()],
            &bls_did,
        )
        .await
        .expect("verify_access_request should succeed");
    assert!(
        !can_read,
        "bls_did should NOT have read access after revocation"
    );

    // D4. Owner still has access
    let owner_can_read = client
        .verify_access_request(
            evm_policy_id,
            vec!["document".into()],
            vec!["doc-evm".into()],
            vec!["read".into()],
            &evm_did,
        )
        .await
        .expect("verify_access_request should succeed");
    assert!(
        owner_can_read,
        "owner (evm_did) should still have read access"
    );

    // ── E: Bulletin Namespace + Post ─────────────────────────────

    // E1. EVM register_namespace
    let e1_calldata = IBulletin::registerNamespaceCall {
        namespace: "test-ns-evm".into(),
    }
    .abi_encode();
    let e1_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        BULLETIN_ADDRESS,
        e1_calldata,
    )
    .await;
    assert_eq!(
        e1_receipt.status, 1,
        "EVM register_namespace should succeed"
    );

    // E2. BLS register_namespace
    let e2_calldata = IBulletin::registerNamespaceCall {
        namespace: "test-ns-bls".into(),
    }
    .abi_encode();
    let e2_receipt = broadcast_native_tx(
        &cluster,
        &client,
        &bls_signer,
        BULLETIN_ADDRESS,
        e2_calldata,
    )
    .await;
    assert_eq!(
        e2_receipt.status, 1,
        "BLS register_namespace should succeed"
    );

    // E3. EVM add_collaborator (add EVM signer as collaborator to its own namespace)
    let e3_calldata = IBulletin::addCollaboratorCall {
        namespace: "test-ns-evm".into(),
        collaborator: evm_signer.address(),
    }
    .abi_encode();
    let e3_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        BULLETIN_ADDRESS,
        e3_calldata,
    )
    .await;
    assert_eq!(e3_receipt.status, 1, "EVM add_collaborator should succeed");

    // E4. EVM create_post
    let e4_calldata = IBulletin::createPostCall {
        namespace: "test-ns-evm".into(),
        payload: b"hello-evm".to_vec().into(),
        proof: b"proof".to_vec().into(),
        artifact: "art".into(),
    }
    .abi_encode();
    let e4_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        BULLETIN_ADDRESS,
        e4_calldata,
    )
    .await;
    assert_eq!(e4_receipt.status, 1, "EVM create_post should succeed");

    // E5. BLS create_post
    let e5_calldata = IBulletin::createPostCall {
        namespace: "test-ns-bls".into(),
        payload: b"hello-bls".to_vec().into(),
        proof: b"proof".to_vec().into(),
        artifact: "art".into(),
    }
    .abi_encode();
    let e5_receipt = broadcast_native_tx(
        &cluster,
        &client,
        &bls_signer,
        BULLETIN_ADDRESS,
        e5_calldata,
    )
    .await;
    assert_eq!(e5_receipt.status, 1, "BLS create_post should succeed");

    // E6. Query namespaces and posts
    let ns_evm = client
        .get_namespace("test-ns-evm")
        .await
        .expect("get_namespace(test-ns-evm) should succeed");
    assert!(!ns_evm.is_empty(), "EVM namespace should be non-empty");

    let ns_bls = client
        .get_namespace("test-ns-bls")
        .await
        .expect("get_namespace(test-ns-bls) should succeed");
    assert!(!ns_bls.is_empty(), "BLS namespace should be non-empty");

    let posts_evm = client
        .get_namespace_posts("test-ns-evm")
        .await
        .expect("get_namespace_posts(test-ns-evm) should succeed");
    assert!(!posts_evm.is_empty(), "EVM namespace should have posts");

    let posts_bls = client
        .get_namespace_posts("test-ns-bls")
        .await
        .expect("get_namespace_posts(test-ns-bls) should succeed");
    assert!(!posts_bls.is_empty(), "BLS namespace should have posts");

    // ── F: Cross-Node Consistency + Health ────────────────────────

    // F1. All nodes agree on policy IDs and namespace queries
    let last_block = e5_receipt.block_number;
    state
        .wait_for_height(last_block + 1, Duration::from_secs(15))
        .await
        .expect("all nodes should advance past last tx block");

    // Bulletin's ensure_policy creates an internal ACP policy on first
    // register_namespace, so we expect 3 total: 2 user + 1 bulletin.
    for node_idx in 0..cluster.node_count() {
        let node_client = HubClient::new(cluster.node(node_idx).rpc_url());
        let node_policy_ids = node_client
            .get_policy_ids()
            .await
            .unwrap_or_else(|e| panic!("node{node_idx} get_policy_ids should succeed: {e}"));
        assert_eq!(
            node_policy_ids.len(),
            3,
            "node{node_idx} should have 3 policies (2 user + 1 bulletin), got: {node_policy_ids:?}"
        );
        for user_pid in &policy_ids {
            assert!(
                node_policy_ids.contains(user_pid),
                "node{node_idx} should contain user policy {user_pid}"
            );
        }

        let node_ns_evm = node_client
            .get_namespace("test-ns-evm")
            .await
            .unwrap_or_else(|e| {
                panic!("node{node_idx} get_namespace(test-ns-evm) should succeed: {e}")
            });
        assert!(
            !node_ns_evm.is_empty(),
            "node{node_idx} EVM namespace should be non-empty"
        );

        let node_ns_bls = node_client
            .get_namespace("test-ns-bls")
            .await
            .unwrap_or_else(|e| {
                panic!("node{node_idx} get_namespace(test-ns-bls) should succeed: {e}")
            });
        assert!(
            !node_ns_bls.is_empty(),
            "node{node_idx} BLS namespace should be non-empty"
        );
    }

    // F2. Cluster health
    state
        .assert_heights_converged(2)
        .expect("block heights should converge within 2 blocks");
    state
        .assert_no_errors()
        .expect("no unexpected errors in cluster logs");
    state
        .assert_chain_id(chain_id)
        .expect("chain ID should be consistent across nodes");

    // F3. Node status
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
