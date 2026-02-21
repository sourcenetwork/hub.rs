//! Integration test for the ACP create_policy pipeline.
//!
//! Exercises both EVM and BLS transaction paths through the full pipeline:
//! cluster startup → RPC connectivity → transaction signing → submission →
//! block execution → AcpModule::create_policy().
//!
//! Currently `#[ignore]` because `AcpModule::create_policy()` is a `todo!()`
//! stub. The precompile panic crashes the node during block execution, so
//! receipt polling fails. Phase 9 implements the stub to make these pass.
//!
//! Run with: `cargo test -p hub-e2e -- --ignored`
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::U256;

use hub_client::{BlsSigner, EvmSigner, HubClient};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};

/// Hardhat account 0 private key (pre-funded by `GenesisBuilder::funded_accounts`).
const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Minimal DPI-compliant ACP policy for testing.
const TEST_POLICY_YAML: &str = "\
name: test-policy
resources:
  document:
    relations:
      owner:
        types:
          - actor
      reader:
        types:
          - actor
    permissions:
      read:
        expr: owner + reader
      update:
        expr: owner
      delete:
        expr: owner
";

/// EVM path: create an ACP policy via `eth_sendRawTransaction` to precompile 0x0810.
///
/// Pipeline stages:
/// 1. Cluster starts and produces blocks (consensus + block execution)
/// 2. RPC layer responds (chain_id, balance queries)
/// 3. EVM transaction hits AcpModule::create_policy() → todo!() panic
///
/// Stages 1-2 validate the infrastructure. Stage 3 fails at the module stub.
#[tokio::test]
#[ignore]
async fn evm_create_policy() {
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

    // -- Stage 2: RPC layer --
    let client = HubClient::new(cluster.node(0).rpc_url());

    let reported_chain_id = client.chain_id().await.expect("eth_chainId should work");
    assert_eq!(reported_chain_id, chain_id, "chain ID should match");

    let signer = EvmSigner::from_hex(HARDHAT_KEY_0, chain_id).expect("valid signer");

    let balance = client
        .get_balance(signer.address())
        .await
        .expect("eth_getBalance should work");
    assert!(balance > U256::ZERO, "test account should be funded");

    // -- Stage 3: ACP create_policy --
    // Hits AcpModule::create_policy() which is todo!().
    // The panic propagates through the precompile → REVM → executor,
    // crashing the node. Receipt polling will fail.
    let receipt = client
        .create_policy(&signer, TEST_POLICY_YAML.as_bytes(), 1)
        .await
        .expect("create_policy should succeed once module is implemented");

    assert_eq!(receipt.status, 1, "create_policy tx should succeed");

    // -- Stage 4: Query confirms state --
    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should work");
    assert!(!policy_ids.is_empty(), "should have at least one policy");
}

/// BLS path: create an ACP policy via `hub_sendNativeTx` to precompile 0x0810.
///
/// Same pipeline as the EVM test but uses BLS12-381 signing and the native
/// transaction format. Both paths converge at the same AcpModule::create_policy()
/// stub.
#[tokio::test]
#[ignore]
async fn bls_create_policy() {
    let chain_id = 9002;
    let genesis = GenesisBuilder::devnet();

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

    // -- Stage 2: RPC layer --
    let client = HubClient::new(cluster.node(0).rpc_url());

    let reported_chain_id = client.chain_id().await.expect("eth_chainId should work");
    assert_eq!(reported_chain_id, chain_id, "chain ID should match");

    let signer = BlsSigner::random(chain_id).expect("random BLS signer");

    // -- Stage 3: ACP create_policy via native BLS tx --
    // Hits the same AcpModule::create_policy() todo!() through the native
    // dispatch path (BLS verify → DID derivation → dispatch_to_module).
    let receipt = client
        .native_create_policy(&signer, TEST_POLICY_YAML.as_bytes(), 1)
        .await
        .expect("native_create_policy should succeed once module is implemented");

    assert_eq!(receipt.status, 1, "native create_policy tx should succeed");

    // -- Stage 4: Query confirms state --
    let policy_ids = client
        .get_policy_ids()
        .await
        .expect("get_policy_ids should work");
    assert!(!policy_ids.is_empty(), "should have at least one policy");
}
