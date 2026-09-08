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
    authorized_actor(did)
}

fn authorized_actor(did: identity::Did) -> (MockStateDb, HubExecutor) {
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

fn native_member_call(sequence: u64, calldata: Vec<u8>) -> (Bytes, identity::Did) {
    use ark_ec::{AffineRepr as _, CurveGroup as _};
    use ark_serialize::CanonicalSerialize as _;
    let key = ark_bls12_381::Fr::from(7u64);
    let public = (ark_bls12_381::G1Affine::generator() * key).into_affine();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
    let mut request = hub_domain::NativeTx {
        chain_id: 9001,
        nonce: sequence,
        bls_pubkey: alloy_primitives::FixedBytes::from_slice(&encoded),
        target: VALIDATOR_REGISTRY_ADDRESS,
        calldata: calldata.into(),
        signature: Default::default(),
    };
    request.signature = alloy_primitives::FixedBytes::from_slice(
        &hub_crypto::bls::sign(&key, &request.signing_data()).unwrap(),
    );
    (
        request.encode_wire().into(),
        hub_crypto::bls::did_from_bls_pubkey(&public)
            .unwrap()
            .parse()
            .unwrap(),
    )
}

fn native_registration() -> Vec<u8> {
    IValidatorRegistry::addValidatorCall {
        evmAddr: Address::repeat_byte(0x11),
        consensusPubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode()
}

#[test]
fn native_membership_changes_share_proposal_storage_and_preserve_parent() {
    let (registration, actor) = native_member_call(0, native_registration());
    let (duplicate, _) = native_member_call(1, native_registration());
    let (deactivate, _) = native_member_call(
        2,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: false,
        }
        .abi_encode(),
    );
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let parent = executor.snapshot().unwrap();
    let (outcome, _) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration.clone(), duplicate, deactivate],
            parent.clone(),
        )
        .unwrap();
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|r| r.success())
            .collect::<Vec<_>>(),
        [true, false, true]
    );
    let slots = &outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage;
    assert_eq!(slots[&U256::from(1)], U256::from(1));
    assert_eq!(
        slots[&member_slot(Address::repeat_byte(0x11))].to_be_bytes::<32>()[20],
        0
    );
    assert_eq!(
        state.accounts.read().unwrap()[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .len(),
        1
    );
    let (sibling, _) = executor
        .execute_with_modules(&state, &context, &[registration], parent)
        .unwrap();
    assert!(sibling.receipts[0].success());
    assert_eq!(
        sibling.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage
            [&member_slot(Address::repeat_byte(0x11))]
            .to_be_bytes::<32>()[20],
        1
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn native_membership_storage_failure_aborts_the_proposal(#[case] building: bool) {
    let (registration, actor) = native_member_call(0, native_registration());
    let (mut state, executor) = authorized_actor(actor);
    state.unreadable_storage = Some((
        VALIDATOR_REGISTRY_ADDRESS,
        member_slot(Address::repeat_byte(0x11)).wrapping_add(U256::from(2)),
    ));
    let mut context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    context.is_verification = !building;
    let error = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration],
            executor.snapshot().unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        hub_executor::ExecutionError::TxExecution(_)
    ));
    assert_eq!(
        state.accounts.read().unwrap()[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .len(),
        1
    );
}

#[test]
fn native_membership_requires_the_configured_actor_permission() {
    let (registration, _) = native_member_call(0, native_registration());
    let (state, executor) = authorized_state();
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, _) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration],
            executor.snapshot().unwrap(),
        )
        .unwrap();
    assert!(!outcome.receipts[0].success());
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.is_empty())
    );
}

#[rstest]
#[case(U256::from(hub_domain::MAX_DKG_PARTICIPANTS.get()), false)]
#[case(U256::from(hub_domain::MAX_DKG_PARTICIPANTS.get() + 1), true)]
#[case(U256::from_limbs([0, 1, 0, 0]), true)]
#[case(U256::MAX, true)]
fn native_membership_bounds_the_full_stored_count(#[case] count: U256, #[case] corrupt: bool) {
    let (request, actor) = native_member_call(0, native_registration());
    let (state, executor) = authorized_actor(actor);
    state
        .accounts
        .write()
        .unwrap()
        .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
        .unwrap()
        .storage
        .insert(U256::from(1), count);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let result =
        executor.execute_with_modules(&state, &context, &[request], executor.snapshot().unwrap());
    if corrupt {
        assert!(matches!(
            result,
            Err(hub_executor::ExecutionError::TxExecution(_))
        ));
    } else {
        let (outcome, _) = result.unwrap();
        assert!(!outcome.receipts[0].success());
        assert!(
            outcome
                .changes
                .accounts
                .get(&VALIDATOR_REGISTRY_ADDRESS)
                .is_none_or(|a| a.storage.is_empty())
        );
    }
}

#[test]
fn native_membership_rejects_reusing_an_inactive_consensus_identity() {
    let (registration, actor) = native_member_call(0, native_registration());
    let (inactive, _) = native_member_call(
        1,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: false,
        }
        .abi_encode(),
    );
    let mut duplicate =
        IValidatorRegistry::addValidatorCall::abi_decode(&native_registration()).unwrap();
    duplicate.evmAddr = Address::repeat_byte(0x22);
    let (duplicate, _) = native_member_call(2, duplicate.abi_encode());
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, _) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration, inactive, duplicate],
            executor.snapshot().unwrap(),
        )
        .unwrap();
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|r| r.success())
            .collect::<Vec<_>>(),
        [true, true, false]
    );
    assert_eq!(
        outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS].storage[&U256::from(1)],
        U256::from(1)
    );
}

#[rstest]
#[case(2, U256::from_limbs([0, 1, 0, 0]))]
#[case(3, U256::from(33))]
#[case(3, U256::from_limbs([10, 1, 0, 0]))]
fn native_membership_rejects_truncated_record_fields(#[case] offset: u64, #[case] value: U256) {
    let (registration, actor) = native_member_call(0, native_registration());
    let (state, executor) = authorized_actor(actor);
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, parent) = executor
        .execute_with_modules(
            &state,
            &context,
            &[registration],
            executor.snapshot().unwrap(),
        )
        .unwrap();
    let mut accounts = state.accounts.write().unwrap();
    let storage = &mut accounts
        .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
        .unwrap()
        .storage;
    storage.extend(
        outcome.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS]
            .storage
            .clone(),
    );
    storage.insert(
        member_slot(Address::repeat_byte(0x11)).wrapping_add(U256::from(offset)),
        value,
    );
    drop(accounts);
    let (request, _) = native_member_call(
        1,
        IValidatorRegistry::setValidatorStatusCall {
            evmAddr: Address::repeat_byte(0x11),
            active: true,
        }
        .abi_encode(),
    );
    assert!(matches!(
        executor.execute_with_modules(&state, &context, &[request], parent),
        Err(hub_executor::ExecutionError::TxExecution(_))
    ));
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

#[rstest]
#[case(U256::ZERO, true)]
#[case(U256::from(1), false)]
#[case(U256::from_limbs([0, 1, 0, 0]), false)]
#[case(U256::MAX, false)]
fn registry_status_checks_the_full_member_index(#[case] index: U256, #[case] success: bool) {
    let (state, executor) = authorized_state();
    let member = Address::repeat_byte(0x11);
    let registration = IValidatorRegistry::addValidatorCall {
        evmAddr: member,
        consensusPubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap(),
        p2pAddr: "127.0.0.1:3000".into(),
    }
    .abi_encode();
    let (registered, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        registration.into(),
        executor.clone(),
    );
    assert_eq!(registered.receipts.len(), 1);
    assert!(registered.receipts[0].success());
    state
        .accounts
        .write()
        .unwrap()
        .get_mut(&VALIDATOR_REGISTRY_ADDRESS)
        .unwrap()
        .storage
        .extend(
            registered.changes.accounts[&VALIDATOR_REGISTRY_ADDRESS]
                .storage
                .clone(),
        );
    let calldata = IValidatorRegistry::setValidatorStatusByIndexCall {
        index,
        active: false,
    }
    .abi_encode();
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        calldata.into(),
        executor,
    );
    assert_eq!(outcome.receipts.len(), 1);
    assert_eq!(outcome.receipts[0].success(), success);
    let changes = outcome.changes.accounts.get(&VALIDATOR_REGISTRY_ADDRESS);
    if success {
        let packed = changes.unwrap().storage[&member_slot(member)].to_be_bytes::<32>();
        assert_eq!(packed[20], 0);
    } else {
        assert!(changes.is_none_or(|account| account.storage.is_empty()));
    }
}
