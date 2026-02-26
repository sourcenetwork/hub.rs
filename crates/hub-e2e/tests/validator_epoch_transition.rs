//! Validator set epoch transition integration test.
//!
//! Verifies that validator set mutations (add/remove/status change) detected
//! by the FinalizedReporter flow through to the EpochManager, which registers
//! new epoch schemes for Simplex consensus.
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, FixedBytes};
use alloy_sol_types::{SolCall, SolEvent};

use hub_client::{
    ACP_ADDRESS, EvmSigner, HubClient, TransactionReceipt, VALIDATOR_REGISTRY_ADDRESS,
};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster, ValidatorConfig};
use hub_modules::acp::abi::IAcp;
use hub_modules::validator_registry::abi::IValidatorRegistry;
use hub_modules::validator_registry::types::ValidatorInfo;

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const RECEIPT_INTERVAL: Duration = Duration::from_millis(150);
const RECEIPT_ATTEMPTS: u32 = 200;

const REGISTRY_POLICY_YAML: &str = "\
name: validator-registry-policy
resources:
  - name: registry
    relations:
      - name: admin
    permissions:
      - name: manage
        expr: admin
";

fn test_validators() -> Vec<ValidatorConfig> {
    vec![
        ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "aa".repeat(32),
            p2p_address: "127.0.0.1:30300".to_string(),
        },
        ValidatorConfig {
            evm_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
            consensus_pubkey: "bb".repeat(32),
            p2p_address: "127.0.0.1:30301".to_string(),
        },
    ]
}

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
    let nonce = client.get_nonce(signer.address()).await.expect("get_nonce");
    let raw = signer
        .sign_tx(target, Bytes::from(calldata), nonce)
        .expect("sign_tx");

    let futs: Vec<_> = (0..cluster.node_count())
        .map(|i| {
            let r = raw.clone();
            let url = cluster.node(i).rpc_url();
            tokio::spawn(async move { HubClient::new(url).send_raw_transaction(&r).await })
        })
        .collect();
    let mut tx_hash = None;
    for fut in futs {
        if let Ok(Ok(hash)) = fut.await {
            tx_hash = Some(hash);
        }
    }
    let tx_hash = tx_hash.expect("at least one node should accept the tx");

    client
        .wait_for_receipt(tx_hash, RECEIPT_INTERVAL, RECEIPT_ATTEMPTS)
        .await
        .expect("receipt should appear")
}

async fn eth_call_raw(client: &HubClient, target: Address, calldata: Vec<u8>) -> Vec<u8> {
    client
        .eth_call(target, Bytes::from(calldata))
        .await
        .expect("eth_call should succeed")
        .to_vec()
}

async fn setup_acp_policy(cluster: &TestCluster, client: &HubClient, admin: &EvmSigner) {
    let calldata = IAcp::createPolicyCall {
        policy: REGISTRY_POLICY_YAML.as_bytes().to_vec().into(),
        marshalType: 1,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(cluster, client, admin, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "createPolicy should succeed");

    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should succeed");
    let policy_id = parse_policy_id(&policy_ids[0]);

    let calldata = IAcp::registerObjectCall {
        policyId: policy_id,
        objectId: "registry".to_string(),
        resource: "registry".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(cluster, client, admin, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "registerObject should succeed");

    let calldata = IAcp::setRelationshipCall {
        policyId: policy_id,
        resource: "registry".to_string(),
        objectId: "registry".to_string(),
        relation: "admin".to_string(),
        actor: admin.did(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(cluster, client, admin, ACP_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "setRelationship should succeed");

    let calldata = IValidatorRegistry::setPolicyCall {
        policyId: B256::from(policy_id.0),
    }
    .abi_encode();
    let receipt =
        broadcast_evm_tx(cluster, client, admin, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    assert_eq!(receipt.status, 1, "setPolicy should succeed");
}

#[tokio::test]
async fn validator_epoch_transition() {
    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9010;
    let validators = test_validators();
    let genesis = GenesisBuilder::devnet()
        .funded_accounts(3, "1000000000000000000000000")
        .validators(validators.clone());

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
    let admin_signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");

    // ── A: Verify genesis validators ──────────────────────────────

    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(all_validators.len(), 2, "should have 2 genesis validators");

    // ── B: Set up ACP policy for write access ─────────────────────

    setup_acp_policy(&cluster, &client, &admin_signer).await;

    // ── C: Add a new validator ────────────────────────────────────

    let new_validator_addr: Address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        .parse()
        .unwrap();
    let new_consensus_key = B256::repeat_byte(0xCC);

    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: new_validator_addr,
        consensusPubkey: new_consensus_key,
        p2pAddr: "127.0.0.1:30302".to_string(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "addValidator should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorAdded::SIGNATURE_HASH,
        "event should be ValidatorAdded"
    );

    // Verify the validator was added
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let all_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        all_validators.len(),
        3,
        "should have 3 validators after add"
    );

    // ── D: Verify epoch transition was detected ───────────────────

    // Allow a settling period for the finalization pipeline to process
    // the block and for the epoch manager consumer to handle the update.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let logs = tokio::fs::read_to_string(state.node_logs(0).log_path())
        .await
        .expect("should read node logs");

    assert!(
        logs.contains("validator set change detected"),
        "FinalizedReporter should detect ValidatorAdded event in block receipts"
    );
    assert!(
        logs.contains("entered epoch"),
        "EpochManager should register a new epoch after validator set change"
    );

    // ── E: Deactivate a validator → triggers another epoch ────────

    let calldata = IValidatorRegistry::setValidatorStatusCall {
        evmAddr: new_validator_addr,
        active: false,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "setValidatorStatus should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorStatusChanged::SIGNATURE_HASH,
        "event should be ValidatorStatusChanged"
    );

    // ── F: Remove the validator → triggers another epoch ──────────

    let calldata = IValidatorRegistry::removeValidatorCall {
        evmAddr: new_validator_addr,
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(
        &cluster,
        &client,
        &admin_signer,
        VALIDATOR_REGISTRY_ADDRESS,
        calldata,
    )
    .await;
    assert_eq!(receipt.status, 1, "removeValidator should succeed");
    assert_eq!(
        receipt.logs[0].topics[0],
        IValidatorRegistry::ValidatorRemoved::SIGNATURE_HASH,
        "event should be ValidatorRemoved"
    );

    // Verify back to 2 validators
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let final_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        final_validators.len(),
        2,
        "should be back to 2 validators after removal"
    );

    // ── G: Verify all three mutations were detected ───────────────

    tokio::time::sleep(Duration::from_secs(3)).await;

    let logs = tokio::fs::read_to_string(state.node_logs(0).log_path())
        .await
        .expect("should read node logs");

    // Count validator set change detections — should be at least 3
    // (add in C, status change in E, remove in F).
    let change_count = logs.matches("validator set change detected").count();
    assert!(
        change_count >= 3,
        "expected at least 3 validator set changes, got {change_count}"
    );

    // ── H: Cross-node consistency ─────────────────────────────────

    let client2 = HubClient::new(cluster.node(1).rpc_url());
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client2, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators from node 1");
    let node1_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        node1_validators.len(),
        final_validators.len(),
        "validator count should match across nodes"
    );
}
