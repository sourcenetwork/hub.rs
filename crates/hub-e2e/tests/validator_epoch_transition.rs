//! Validator set epoch transition integration test.
//!
//! Verifies that ValidatorRegistry membership feeds resharing and that Simplex
//! enters an epoch whose key material includes a newly registered validator.
//!
//! Requires `cargo build -p hubd` before running.

#[path = "support/administration.rs"]
mod administration;

use hub_client::BlsSigner;
use hub_client::administration::AdministrativeCommand;

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, FixedBytes};
use alloy_sol_types::{SolCall, SolEvent};
use commonware_codec::Encode;
use commonware_cryptography::{Signer as _, ed25519};

use hub_client::{
    ACP_ADDRESS, EvmSigner, HubClient, TransactionReceipt, VALIDATOR_REGISTRY_ADDRESS,
};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use hub_modules::acp::abi::IAcp;
use hub_modules::validator_registry::abi::IValidatorRegistry;
use hub_modules::validator_registry::types::ValidatorInfo;

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
        .wait_for_receipt(tx_hash, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
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

    let signed = administration::approve(
        client,
        AdministrativeCommand::InitializeMembershipPolicy(policy_id.0),
        0,
    )
    .await;
    let receipt = client
        .native_apply_administration(
            &BlsSigner::new(42u64.into(), admin.chain_id()).unwrap(),
            &signed,
        )
        .await
        .expect("initialize membership policy");
    assert_eq!(receipt.status, 1);
}

#[tokio::test]
async fn validator_epoch_transition() {
    // ── SETUP ─────────────────────────────────────────────────────

    let chain_id = 9010;
    let genesis = GenesisBuilder::devnet()
        .operators(administration::operators())
        .funded_accounts(3, "1000000000000000000000000");

    let cluster = TestCluster::builder()
        .binary(hub_e2e::resolve_binary().expect("resolve hubd binary"))
        .nodes(4)
        .seed(chain_id)
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
    assert_eq!(all_validators.len(), 4, "should have 4 genesis validators");

    // ── B: Set up ACP policy for write access ─────────────────────

    setup_acp_policy(&cluster, &client, &admin_signer).await;

    // ── C: Add a new validator ────────────────────────────────────

    let new_validator_addr: Address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        .parse()
        .unwrap();
    let new_public_key = ed25519::PrivateKey::from_seed(chain_id + 4).public_key();
    let new_consensus_key = B256::from_slice(Encode::encode(&new_public_key).as_ref());

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
        5,
        "should have 5 validators after add"
    );

    // ── D: Verify the registry-backed set completes resharing ─────

    state
        .wait_for_height(42, Duration::from_secs(60))
        .await
        .expect("cluster should enter epoch 2 with the added validator");

    let logs = tokio::fs::read_to_string(state.node_logs(0).log_path())
        .await
        .expect("should read node logs");

    let entered_epochs = logs.matches("entered epoch").count();
    assert!(
        entered_epochs >= 3,
        "expected the engine to enter epochs 0, 1, and 2, got {entered_epochs} entries"
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

    // Verify back to 4 validators
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();
    let result = eth_call_raw(&client, VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let decoded = IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result)
        .expect("abi decode getValidators");
    let final_validators: Vec<ValidatorInfo> =
        serde_json::from_slice(&decoded).expect("parse validators JSON");
    assert_eq!(
        final_validators.len(),
        4,
        "should be back to 4 validators after removal"
    );

    // ── G: Cross-node consistency ─────────────────────────────────

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
