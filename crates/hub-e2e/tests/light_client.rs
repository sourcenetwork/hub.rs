//! Light client verification end-to-end test.
//!
//! Exercises the full light client pipeline: gossip headers, light block
//! verification, module state proofs, and state change detection across
//! block boundaries.
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_sol_types::SolCall;

use hub_client::{ACP_ADDRESS, EvmSigner, HubClient, TransactionReceipt};
use hub_domain::{LightBlock, ModuleStateProof, verify_light_block, verify_module_state_proof};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_modules::acp::abi::IAcp;
use jsonrpsee::core::client::SubscriptionClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
";

const RECEIPT_INTERVAL: Duration = Duration::from_millis(150);
const RECEIPT_ATTEMPTS: u32 = 200;

fn parse_policy_id(hex_str: &str) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode_to_slice(hex, &mut bytes).expect("policy ID should be valid hex");
    FixedBytes::from(bytes)
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

#[tokio::test]
async fn light_client_proof_verification() {
    // ── Phase 1: Setup ───────────────────────────────────────────────
    let chain_id = 9003;
    let genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");

    let cluster = TestCluster::builder()
        .binary(hub_e2e::resolve_binary().expect("resolve hubd binary"))
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
    let evm_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");
    let evm_did = evm_signer.did();

    // ── Phase 2: Create ACP policy + register document ───────────────
    let create_calldata = IAcp::createPolicyCall {
        policy: TEST_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let create_receipt =
        broadcast_evm_tx(&cluster, &client, &evm_signer, ACP_ADDRESS, create_calldata).await;
    assert_eq!(create_receipt.status, 1, "create_policy should succeed");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    assert!(!policy_ids.is_empty(), "should have at least one policy");
    let policy_id = parse_policy_id(&policy_ids[0]);

    let register_calldata = IAcp::registerObjectCall {
        policyId: policy_id,
        objectId: "doc1".into(),
        resource: "document".into(),
    }
    .abi_encode();
    let register_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        register_calldata,
    )
    .await;
    assert_eq!(register_receipt.status, 1, "register_object should succeed");
    let h_register = register_receipt.block_number;

    // ── Phase 3: Subscribe to gossip headers ─────────────────────────
    let ws_client = WsClientBuilder::default()
        .build(&cluster.node(0).ws_url())
        .await
        .expect("WebSocket connection should succeed");

    let mut headers_sub = ws_client
        .subscribe::<serde_json::Value, _>(
            "eth_subscribe",
            rpc_params!["headers"],
            "eth_unsubscribe",
        )
        .await
        .expect("headers subscription should succeed");

    // Consume headers until we reach one at or past h_register.
    let header_1 = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let h = headers_sub
                .next()
                .await
                .expect("subscription should not close")
                .expect("header should deserialize");
            let height = h["height"].as_u64().expect("height should be u64");
            if height >= h_register {
                return h;
            }
        }
    })
    .await
    .expect("should receive header at or past h_register within timeout");

    let h1 = header_1["height"].as_u64().expect("height should be u64");
    assert!(
        !header_1["module_state_root"].is_null(),
        "module_state_root should be present"
    );
    let header_1_msr = header_1["module_state_root"]
        .as_str()
        .expect("module_state_root should be a string");

    // ── Phase 4: Verify light block at H₁ ────────────────────────────
    let light_block: LightBlock = client
        .rpc_call_typed("hub_getLightBlock", serde_json::json!([h1]))
        .await
        .expect("hub_getLightBlock should succeed");

    let (_state_root, module_state_root) =
        verify_light_block(&light_block).expect("light block should verify");

    let lb_msr_hex = format!("0x{}", hex::encode(module_state_root.as_slice()));
    assert_eq!(
        lb_msr_hex, header_1_msr,
        "light block module_state_root should match gossip header"
    );

    // ── Phase 5: Verify module state proof at H₁ ─────────────────────
    let policy_id_str = &policy_ids[0];
    let acp_key = format!("policy/objs/{policy_id_str}");
    let key_hex = format!("0x{}", hex::encode(acp_key.as_bytes()));

    let proof_1: ModuleStateProof = client
        .rpc_call_typed("hub_getStateProof", serde_json::json!(["acp", key_hex, h1]))
        .await
        .expect("hub_getStateProof should succeed");

    assert!(
        proof_1.value.is_some(),
        "policy record should exist (proof.value should be Some)"
    );
    verify_module_state_proof(module_state_root, &proof_1)
        .expect("module state proof should verify against module_state_root");

    // ── Phase 6: Mutate — add a reader relationship ──────────────────
    let set_rel_calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "reader".into(),
        actor: evm_did.clone(),
    }
    .abi_encode();
    let mutate_receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &evm_signer,
        ACP_ADDRESS,
        set_rel_calldata,
    )
    .await;
    assert_eq!(mutate_receipt.status, 1, "set_relationship should succeed");
    let h_mutate = mutate_receipt.block_number;

    // ── Phase 7: Detect state change by re-verifying old proof ─────
    //
    // A light client holds proof_1 (valid at h1). For each new gossip
    // header it verifies the light block, then checks whether proof_1
    // still verifies against that block's module_state_root. The first
    // block where verification fails is where the ACP tree changed.
    let invalidation_height = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let h = headers_sub
                .next()
                .await
                .expect("subscription should not close")
                .expect("header should deserialize");
            let height = h["height"].as_u64().expect("height should be u64");

            let lb: LightBlock = client
                .rpc_call_typed("hub_getLightBlock", serde_json::json!([height]))
                .await
                .expect("hub_getLightBlock should succeed");
            let (_, msr) = verify_light_block(&lb).expect("light block should verify");

            if verify_module_state_proof(msr, &proof_1).is_err() {
                return (height, msr);
            }
        }
    })
    .await
    .expect("old proof should eventually fail against a new block");

    let (h_invalidated, module_state_root_2) = invalidation_height;
    assert!(
        h_invalidated >= h_mutate,
        "proof should not invalidate before the mutation block \
         (invalidated at {h_invalidated}, mutation at {h_mutate})"
    );

    // ── Phase 8: Verify fresh proof at the invalidation height ───────
    let proof_2: ModuleStateProof = client
        .rpc_call_typed(
            "hub_getStateProof",
            serde_json::json!(["acp", key_hex, h_invalidated]),
        )
        .await
        .expect("hub_getStateProof at invalidation height should succeed");

    verify_module_state_proof(module_state_root_2, &proof_2)
        .expect("fresh proof should verify at invalidation height");

    assert_ne!(
        proof_2.module_root, proof_1.module_root,
        "ACP module root should differ after set_relationship"
    );
}
