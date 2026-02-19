//! EVM contract deployment and interaction tests.
//!
//! Deploys a minimal storage contract to a running hub cluster,
//! then exercises read (`eth_getStorageAt`) and write (`eth_sendRawTransaction`) paths.
//!
//! Requires `cargo build -p hubd` before running.

use std::time::Duration;

use alloy_primitives::U256;
use alloy_sol_types::SolCall;

use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_e2e::contracts;

// ABI definition for the test contract's set(uint256) function.
alloy_sol_types::sol! {
    function set(uint256 value) external;
}

/// Hand-assembled bytecode for a minimal storage contract.
///
/// Constructor: stores 42 in storage slot 0, returns runtime code.
///
/// Runtime supports two functions:
///   - get() [0x6d4ce63c] → returns uint256 from slot 0
///   - set(uint256) [0x60fe47b1] → stores uint256 to slot 0
fn storage_contract_bytecode() -> Vec<u8> {
    //
    // Runtime code (59 bytes = 0x3b):
    //   Function dispatcher matching get()/set(uint256) selectors,
    //   with a revert fallback for unknown selectors.
    //
    // Init code (17 bytes = 0x11):
    //   Stores 42 in slot 0, then CODECOPYs the runtime to memory and RETURNs it.
    //
    let hex = concat!(
        // --- Init code (17 bytes) ---
        "602a", // PUSH1 42
        "6000", // PUSH1 0 (slot)
        "55",   // SSTORE
        "603b", // PUSH1 59 (runtime length)
        "6011", // PUSH1 17 (runtime offset = init length)
        "6000", // PUSH1 0 (memory dest)
        "39",   // CODECOPY
        "603b", // PUSH1 59 (runtime length)
        "6000", // PUSH1 0 (memory offset)
        "f3",   // RETURN
        // --- Runtime code (59 bytes) ---
        // Function dispatcher
        "36",         // CALLDATASIZE
        "6004",       // PUSH1 4
        "11",         // GT  (calldatasize < 4 → revert)
        "6020",       // PUSH1 0x20 (→ revert JUMPDEST)
        "57",         // JUMPI
        "6000",       // PUSH1 0
        "35",         // CALLDATALOAD
        "60e0",       // PUSH1 224
        "1c",         // SHR (extract 4-byte selector)
        "80",         // DUP1
        "636d4ce63c", // PUSH4 get() selector
        "14",         // EQ
        "6026",       // PUSH1 0x26 (→ GET JUMPDEST)
        "57",         // JUMPI
        "6360fe47b1", // PUSH4 set(uint256) selector
        "14",         // EQ
        "6033",       // PUSH1 0x33 (→ SET JUMPDEST)
        "57",         // JUMPI
        // Revert fallback (runtime offset 0x20)
        "5b",   // JUMPDEST
        "6000", // PUSH1 0
        "6000", // PUSH1 0
        "fd",   // REVERT
        // GET handler (runtime offset 0x26)
        "5b",   // JUMPDEST
        "50",   // POP (selector)
        "6000", // PUSH1 0 (slot)
        "54",   // SLOAD
        "6000", // PUSH1 0 (mem offset)
        "52",   // MSTORE
        "6020", // PUSH1 32 (return size)
        "6000", // PUSH1 0 (mem offset)
        "f3",   // RETURN
        // SET handler (runtime offset 0x33)
        "5b",   // JUMPDEST
        "6004", // PUSH1 4 (skip selector)
        "35",   // CALLDATALOAD
        "6000", // PUSH1 0 (slot)
        "55",   // SSTORE
        "00",   // STOP
    );

    hex::decode(hex).expect("valid bytecode hex")
}

/// Deploy a contract, read its initial value, write a new value, read again.
///
/// Validates the full contract interaction pipeline:
/// 1. Transaction signing with funded test accounts
/// 2. Contract deployment (CREATE)
/// 3. Contract reads (`eth_getStorageAt`)
/// 4. Contract writes (`eth_sendRawTransaction`)
/// 5. Receipt polling / confirmation
#[tokio::test]
async fn deploy_and_interact() {
    let chain_id = 9001;
    let genesis = GenesisBuilder::devnet().funded_accounts(3, "1000000000000000000000000");

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

    let rpc_url = cluster.node(0).rpc_url();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let signer = contracts::test_signer(0);

    // 1. Deploy the storage contract (nonce 0).
    let receipt = contracts::deploy(
        &client,
        &rpc_url,
        &signer,
        chain_id,
        storage_contract_bytecode(),
        0,
    )
    .await
    .expect("contract should deploy");

    let contract_addr = receipt.contract_address;
    assert!(receipt.block_number > 0, "should be in a real block");

    // 2. Read initial value via eth_getStorageAt — constructor stored 42 in slot 0.
    let value = contracts::get_storage_at(&client, &rpc_url, contract_addr, U256::ZERO)
        .await
        .expect("eth_getStorageAt should succeed");
    assert_eq!(value, U256::from(42), "initial value should be 42");

    // 3. Write a new value via state-changing transaction (nonce 1).
    let calldata = setCall {
        value: U256::from(100),
    }
    .abi_encode();
    let write_receipt = contracts::send(
        &client,
        &rpc_url,
        &signer,
        chain_id,
        contract_addr,
        calldata,
        1,
    )
    .await
    .expect("set() transaction should succeed");

    let status = write_receipt
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("0x0");
    assert_eq!(status, "0x1", "set() transaction should succeed (status=1)");

    // 4. Read the updated value.
    let value = contracts::get_storage_at(&client, &rpc_url, contract_addr, U256::ZERO)
        .await
        .expect("second eth_getStorageAt should succeed");
    assert_eq!(value, U256::from(100), "value should be updated to 100");
}
