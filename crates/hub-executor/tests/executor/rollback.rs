use super::*;
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{TxKind, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use hub_executor::{
    ExecutionOutcome, HubExecutor, ModuleState,
    precompiles::{ACP_ADDRESS, VALIDATOR_REGISTRY_ADDRESS},
};
use hub_modules::{acp::abi::IAcp, validator_registry::abi::IValidatorRegistry};

fn policy(name: &str) -> Bytes {
    IAcp::createPolicyCall {
        policy: format!("name: {name}\nresources:\n  - name: file\n")
            .into_bytes()
            .into(),
        marshalType: 1,
    }
    .abi_encode()
    .into()
}

fn forwarding_code(target: Address, end: &[u8], is_static: bool) -> Bytes {
    // Copy calldata, call the target, and discard the success flag.
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f];
    if !is_static {
        code.push(0x5f);
    }
    code.push(0x73);
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[0x5a, if is_static { 0xfa } else { 0xf1 }, 0x50]);
    code.extend_from_slice(end);
    code.into()
}

fn embedded_call(data: &[u8], end: &[u8]) -> Bytes {
    let length = u16::try_from(data.len()).unwrap().to_be_bytes();
    // CODECOPY the appended input, then call ACP. This also works in initcode.
    let mut code = vec![
        0x61, length[0], length[1], 0x61, 0, 0, 0x5f, 0x39, 0x5f, 0x5f, 0x61, length[0], length[1],
        0x5f, 0x5f, 0x73,
    ];
    code.extend_from_slice(ACP_ADDRESS.as_slice());
    code.extend_from_slice(&[0x5a, 0xf1, 0x50]);
    code.extend_from_slice(end);
    let offset = u16::try_from(code.len()).unwrap().to_be_bytes();
    code[4..6].copy_from_slice(&offset);
    code.extend_from_slice(data);
    code.into()
}

fn install(state: &MockStateDb, address: Address, code: Bytes) {
    let code_hash = keccak256(&code);
    state.insert_code(code_hash, code);
    state.insert_account(
        address,
        MockAccount {
            code_hash,
            ..Default::default()
        },
    );
}

fn execute(state: &MockStateDb, to: TxKind, input: Bytes) -> (ExecutionOutcome, ModuleState) {
    let signer: PrivateKeySigner = "42".repeat(32).parse().unwrap();
    state.insert_account(
        signer.address(),
        MockAccount {
            balance: U256::from(10).pow(U256::from(18)),
            ..Default::default()
        },
    );
    let tx = TxLegacy {
        chain_id: Some(9001),
        gas_limit: 1_000_000,
        to,
        input,
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let wire = TxEnvelope::Legacy(tx.into_signed(signature))
        .encoded_2718()
        .into();
    let executor = HubExecutor::new(9001);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, modules) = executor
        .execute_with_modules(state, &context, &[wire], executor.snapshot().unwrap())
        .unwrap();
    executor.commit_snapshot(1, modules).unwrap();
    let modules = executor.modules().read().unwrap().clone();
    (outcome, modules)
}

#[rstest]
#[case(&[0x00], &[0x00], false, true, 1)]
#[case(&[0x00], &[0x5f, 0x5f, 0xfd], false, false, 0)]
#[case(&[0x5f, 0x5f, 0xfd], &[0x00], false, true, 0)]
#[case(&[0xfe], &[0x00], false, true, 0)]
#[case(&[0x00], &[0x00], true, true, 0)]
fn module_writes_follow_nested_call_outcomes(
    #[case] inner_end: &[u8],
    #[case] outer_end: &[u8],
    #[case] is_static: bool,
    #[case] success: bool,
    #[case] policies: usize,
) {
    let state = MockStateDb::new();
    let inner = Address::repeat_byte(0x11);
    let outer = Address::repeat_byte(0x22);
    install(
        &state,
        inner,
        forwarding_code(ACP_ADDRESS, inner_end, is_static),
    );
    install(&state, outer, forwarding_code(inner, outer_end, false));
    let (outcome, modules) = execute(&state, TxKind::Call(outer), policy("rollback"));
    assert_eq!(outcome.receipts.len(), 1);
    assert_eq!(outcome.receipts[0].success(), success);
    assert_eq!(modules.acp.query_policy_ids().unwrap().len(), policies);
    assert_eq!(outcome.receipts[0].logs().len(), policies);
}

#[rstest]
#[case(&[0x00], true)]
#[case(&[0x5f, 0x5f, 0xfd], false)]
fn creation_frames_restore_module_state(#[case] end: &[u8], #[case] success: bool) {
    let (outcome, modules) = execute(
        &MockStateDb::new(),
        TxKind::Create,
        embedded_call(&policy("constructor"), end),
    );
    assert_eq!(outcome.receipts[0].success(), success);
    assert_eq!(
        modules.acp.query_policy_ids().unwrap().len(),
        usize::from(success)
    );
}

#[test]
fn failed_child_preserves_prior_parent_writes() {
    let state = MockStateDb::new();
    let inner = Address::repeat_byte(0x11);
    let outer = Address::repeat_byte(0x22);
    install(
        &state,
        inner,
        embedded_call(&policy("discarded"), &[0x5f, 0x5f, 0xfd]),
    );
    let mut code = forwarding_code(ACP_ADDRESS, &[], false).to_vec();
    code.extend_from_slice(&forwarding_code(inner, &[0x00], false));
    install(&state, outer, code.into());
    let (outcome, modules) = execute(&state, TxKind::Call(outer), policy("kept"));
    assert!(outcome.receipts[0].success());
    let ids = modules.acp.query_policy_ids().unwrap();
    assert_eq!(ids.len(), 1);
    assert!(
        modules
            .acp
            .query_policy(&ids[0])
            .unwrap()
            .raw_policy
            .contains("kept")
    );
    assert_eq!(outcome.receipts[0].logs().len(), 1);
}

#[test]
fn post_execution_error_restores_successful_module_call() {
    // The beneficiary is loaded when execution has finished, to credit its fee.
    let state = MockStateDb {
        unreadable_account: Some(Address::ZERO),
        ..Default::default()
    };
    let (outcome, modules) = execute(&state, TxKind::Call(ACP_ADDRESS), policy("discarded"));
    assert!(outcome.receipts.is_empty());
    assert_eq!(outcome.executed_tx_indices, Some(vec![]));
    assert!(modules.acp.query_policy_ids().unwrap().is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn registry_static_calls_allow_only_queries(#[case] query: bool) {
    let state = MockStateDb::new();
    let outer = Address::repeat_byte(0x22);
    let mut code = forwarding_code(VALIDATOR_REGISTRY_ADDRESS, &[], true).to_vec();
    code.pop();
    let success = u8::try_from(code.len() + 6).unwrap();
    code.extend_from_slice(&[0x60, success, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x00]);
    install(&state, outer, code.into());
    let input = if query {
        IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode()
    } else {
        IValidatorRegistry::setPolicyCall {
            policyId: B256::repeat_byte(7),
        }
        .abi_encode()
    };
    let (outcome, _) = execute(&state, TxKind::Call(outer), input.into());
    assert_eq!(outcome.receipts[0].success(), query);
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.values().all(U256::is_zero))
    );
}
