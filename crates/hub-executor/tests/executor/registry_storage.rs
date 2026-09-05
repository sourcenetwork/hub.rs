use super::{rollback::execute_with_executor, *};
use alloy_primitives::{TxKind, keccak256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use hub_executor::{HubExecutor, ModuleState, precompiles::VALIDATOR_REGISTRY_ADDRESS};
use hub_modules::{
    acp::types::{Object, PolicyCmd, PolicyMarshalingType},
    validator_registry::abi::IValidatorRegistry,
};

fn authorized_state() -> (MockStateDb, HubExecutor) {
    let signer: PrivateKeySigner = "42".repeat(32).parse().unwrap();
    let did = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        &signer.credential().verifying_key().to_sec1_bytes(),
    )
    .unwrap()
    .parse::<identity::Did>()
    .unwrap();
    let mut modules = ModuleState::default();
    let policy = modules.acp.create_policy(&did,
        "name: membership\nresources:\n  - name: registry\n    relations:\n      - name: admin\n    permissions:\n      - name: manage\n        expr: admin\n",
        PolicyMarshalingType::ShortYaml,
    ).unwrap().policy.id;
    modules
        .acp
        .direct_policy_cmd(
            &did,
            &policy,
            PolicyCmd::RegisterObject(Object {
                resource: "registry".into(),
                id: "registry".into(),
            }),
        )
        .unwrap();
    modules
        .acp
        .direct_policy_cmd(
            &did,
            &policy,
            PolicyCmd::SetRelationship(acp::Relationship::new(
                "registry",
                "registry",
                "admin",
                acp::Subject::entity(did.clone()),
            )),
        )
        .unwrap();
    let state = MockStateDb::new();
    state.insert_account(
        VALIDATOR_REGISTRY_ADDRESS,
        MockAccount {
            storage: HashMap::from([(
                U256::ZERO,
                U256::from_be_slice(&hex::decode(policy).unwrap()),
            )]),
            ..Default::default()
        },
    );
    let executor = HubExecutor::new(9001);
    executor.set_base_modules(modules);
    (state, executor)
}

fn member_slot(address: Address) -> U256 {
    let mut data = [0; 64];
    data[12..32].copy_from_slice(address.as_slice());
    data[63] = 3;
    U256::from_be_bytes(keccak256(data).0)
}

#[rstest]
#[case(None)]
#[case(Some(false))]
#[case(Some(true))]
fn registry_write_storage_failure_cannot_commit_partial_member(#[case] during_write: Option<bool>) {
    let (mut state, executor) = authorized_state();
    let member = Address::repeat_byte(0x11);
    let slot = if during_write == Some(true) {
        member_slot(member).wrapping_add(U256::from(2))
    } else {
        U256::from(1)
    };
    state.unreadable_storage = during_write.map(|_| (VALIDATOR_REGISTRY_ADDRESS, slot));
    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: member,
        consensusPubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode();
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    if during_write.is_none() {
        assert_eq!(outcome.receipts.len(), 1);
        assert!(outcome.receipts[0].success());
        assert_eq!(
            outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage[&U256::from(1)],
            U256::from(1)
        );
        return;
    }
    assert!(
        outcome.receipts.iter().all(|receipt| !receipt.success()),
        "failed storage access returned success"
    );
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.is_empty()),
        "failed operation retained registry writes"
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn registry_queries_do_not_treat_storage_failure_as_absence(#[case] single_member: bool) {
    let (mut state, executor) = authorized_state();
    let member = Address::repeat_byte(0x11);
    let (slot, calldata) = if single_member {
        (
            member_slot(member),
            IValidatorRegistry::getValidatorCall { evmAddr: member }.abi_encode(),
        )
    } else {
        (
            U256::from(1),
            IValidatorRegistry::getValidatorsCall {}.abi_encode(),
        )
    };
    state.unreadable_storage = Some((VALIDATOR_REGISTRY_ADDRESS, slot));
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    assert!(outcome.receipts.iter().all(|receipt| !receipt.success()));
}

#[test]
fn registry_rejects_malformed_consensus_key() {
    let (state, executor) = authorized_state();
    let calldata = IValidatorRegistry::addValidatorCall {
        evmAddr: Address::repeat_byte(0x11),
        consensusPubkey: B256::repeat_byte(0xDD),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode();
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    assert_eq!(outcome.receipts.len(), 1);
    assert!(!outcome.receipts[0].success());
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.is_empty())
    );
}
