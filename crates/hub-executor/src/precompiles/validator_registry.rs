//! ValidatorRegistry precompile — EVM storage-backed validator management at `0x0813`.
//!
//! Unlike ACP/Bulletin/Hub which use InMemoryKvStore, ValidatorRegistry stores
//! state directly in EVM storage slots (Solidity-compatible layout). This means
//! the EVM state root already covers validator state — no separate module tree.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::SolCall;
use hub_modules::acp::AcpModule;
use hub_modules::acp::types::{AccessRequest, Actor, Object, Operation};
use hub_modules::types::{BlockExecCtx, TxExecCtx};
use hub_modules::validator_registry::abi::IValidatorRegistry;
use hub_modules::validator_registry::error::ValidatorRegistryError;
use hub_modules::validator_registry::types::ValidatorInfo;
use identity::Did;
use revm::context_interface::{ContextTr, JournalTr};
use revm::precompile::PrecompileError;

use super::{
    DispatchReturn, VALIDATOR_REGISTRY_ADDRESS, decode_error, did_from_signer, err_dispatch,
    event_log, json_bytes, ok_dispatch,
};

const WRITE_GAS: u64 = 50_000;
const READ_GAS: u64 = 10_000;

// ── Storage layout constants ───────────────────────────────────────────

const SLOT_POLICY_ID: U256 = U256::ZERO;
const SLOT_VALIDATOR_COUNT: U256 = U256::from_limbs([1, 0, 0, 0]);
const SLOT_VALIDATORS_ARRAY_BASE: U256 = U256::from_limbs([2, 0, 0, 0]);
const SLOT_VALIDATORS_MAPPING_BASE: U256 = U256::from_limbs([3, 0, 0, 0]);

fn mapping_slot(key: Address, base: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(&base.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

fn array_element_slot(base: U256, index: u64) -> U256 {
    let hash = keccak256(base.to_be_bytes::<32>());
    U256::from_be_bytes(hash.0).wrapping_add(U256::from(index))
}

fn pack_address_active(addr: Address, active: bool) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(addr.as_slice());
    bytes[20] = u8::from(active);
    U256::from_be_bytes(bytes)
}

fn unpack_address_active(val: U256) -> (Address, bool) {
    let bytes = val.to_be_bytes::<32>();
    let addr = Address::from_slice(&bytes[..20]);
    let active = bytes[20] != 0;
    (addr, active)
}

fn address_to_padded_u256(addr: Address) -> U256 {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr.as_slice());
    U256::from_be_bytes(buf)
}

fn u256_to_address(val: U256) -> Address {
    let bytes = val.to_be_bytes::<32>();
    Address::from_slice(&bytes[12..32])
}

// ── Journal helpers ────────────────────────────────────────────────────

fn journal_sload<CTX: ContextTr>(context: &mut CTX, slot: U256) -> U256 {
    context
        .journal_mut()
        .sload(VALIDATOR_REGISTRY_ADDRESS, slot)
        .map(|r| r.data)
        .unwrap_or_default()
}

fn journal_sstore<CTX: ContextTr>(context: &mut CTX, slot: U256, value: U256) {
    let _ = context
        .journal_mut()
        .sstore(VALIDATOR_REGISTRY_ADDRESS, slot, value);
}

// ── ACP access check ──────────────────────────────────────────────────

fn check_manage_access(
    acp: &AcpModule,
    policy_id: &str,
    caller_did: Did,
) -> Result<(), ValidatorRegistryError> {
    // Zero policy ID means unrestricted access (no ACP policy configured).
    if policy_id.chars().all(|c| c == '0') {
        return Ok(());
    }

    let access_request = AccessRequest {
        operations: vec![Operation {
            object: Object {
                resource: "registry".to_string(),
                id: "registry".to_string(),
            },
            permission: "manage".to_string(),
        }],
        actor: Actor(caller_did),
    };

    match acp.query_verify_access_request(policy_id, &access_request) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ValidatorRegistryError::Unauthorized(
            "ACP denied manage permission".to_string(),
        )),
        Err(e) => Err(ValidatorRegistryError::State(format!(
            "ACP check failed: {e}"
        ))),
    }
}

fn load_policy_id<CTX: ContextTr>(context: &mut CTX) -> String {
    let val = journal_sload(context, SLOT_POLICY_ID);
    hex::encode(val.to_be_bytes::<32>())
}

// ── Read helpers ───────────────────────────────────────────────────────

fn load_validator_raw<CTX: ContextTr>(
    context: &mut CTX,
    addr: Address,
) -> Option<(Address, [u8; 32], String, bool, u64)> {
    let entry_base = mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
    let packed = journal_sload(context, entry_base);
    if packed.is_zero() {
        return None;
    }
    let (evm_address, active) = unpack_address_active(packed);
    let consensus_bytes: [u8; 32] =
        journal_sload(context, entry_base.wrapping_add(U256::from(1))).to_be_bytes();
    let index = journal_sload(context, entry_base.wrapping_add(U256::from(2))).as_limbs()[0];
    let p2p_len =
        journal_sload(context, entry_base.wrapping_add(U256::from(3))).as_limbs()[0] as usize;
    let p2p_data: [u8; 32] =
        journal_sload(context, entry_base.wrapping_add(U256::from(4))).to_be_bytes();
    let p2p_address = String::from_utf8_lossy(&p2p_data[..p2p_len.min(32)]).to_string();

    Some((evm_address, consensus_bytes, p2p_address, active, index))
}

fn to_validator_info(raw: (Address, [u8; 32], String, bool, u64)) -> ValidatorInfo {
    ValidatorInfo {
        evm_address: format!("{:?}", raw.0),
        consensus_pubkey: hex::encode(raw.1),
        p2p_address: raw.2,
        active: raw.3,
        index: raw.4,
    }
}

fn load_all_validators<CTX: ContextTr>(context: &mut CTX) -> Vec<ValidatorInfo> {
    let count = journal_sload(context, SLOT_VALIDATOR_COUNT).as_limbs()[0];
    let mut validators = Vec::with_capacity(count as usize);
    for i in 0..count {
        let addr_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, i);
        let addr = u256_to_address(journal_sload(context, addr_slot));
        if let Some(raw) = load_validator_raw(context, addr) {
            validators.push(to_validator_info(raw));
        }
    }
    validators
}

// ── Write helpers ──────────────────────────────────────────────────────

fn store_validator_raw<CTX: ContextTr>(
    context: &mut CTX,
    addr: Address,
    consensus_pubkey: [u8; 32],
    p2p_address: &str,
    active: bool,
    index: u64,
) {
    let entry_base = mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
    journal_sstore(context, entry_base, pack_address_active(addr, active));
    journal_sstore(
        context,
        entry_base.wrapping_add(U256::from(1)),
        U256::from_be_bytes(consensus_pubkey),
    );
    journal_sstore(
        context,
        entry_base.wrapping_add(U256::from(2)),
        U256::from(index),
    );
    let p2p_bytes = p2p_address.as_bytes();
    journal_sstore(
        context,
        entry_base.wrapping_add(U256::from(3)),
        U256::from(p2p_bytes.len()),
    );
    let mut padded = [0u8; 32];
    let copy_len = p2p_bytes.len().min(32);
    padded[..copy_len].copy_from_slice(&p2p_bytes[..copy_len]);
    journal_sstore(
        context,
        entry_base.wrapping_add(U256::from(4)),
        U256::from_be_bytes(padded),
    );
}

fn clear_validator<CTX: ContextTr>(context: &mut CTX, addr: Address) {
    let entry_base = mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
    for offset in 0..5u64 {
        journal_sstore(
            context,
            entry_base.wrapping_add(U256::from(offset)),
            U256::ZERO,
        );
    }
}

// ── Dispatch entry point ───────────────────────────────────────────────

pub(super) fn dispatch_with_journal<CTX: ContextTr>(
    context: &mut CTX,
    acp: &AcpModule,
    _block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    if input.len() < 4 {
        return Err(PrecompileError::Other(
            "input too short for selector".into(),
        ));
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");

    match selector {
        IValidatorRegistry::addValidatorCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IValidatorRegistry::addValidatorCall::abi_decode(input).map_err(decode_error)?;

            let policy_id = load_policy_id(context);
            let caller_did = match did_from_signer(&tx_ctx.signer) {
                Ok(d) => d,
                Err(_) => {
                    return Ok(err_dispatch(ValidatorRegistryError::Unauthorized(
                        "invalid signer DID".to_string(),
                    )));
                }
            };
            if let Err(e) = check_manage_access(acp, &policy_id, caller_did) {
                return Ok(err_dispatch(e));
            }
            if call.consensusPubkey == B256::ZERO {
                return Ok(err_dispatch(ValidatorRegistryError::InvalidPublicKey));
            }
            if load_validator_raw(context, call.evmAddr).is_some() {
                return Ok(err_dispatch(
                    ValidatorRegistryError::ValidatorAlreadyExists(format!("{:?}", call.evmAddr)),
                ));
            }

            let count = journal_sload(context, SLOT_VALIDATOR_COUNT).as_limbs()[0];
            store_validator_raw(
                context,
                call.evmAddr,
                call.consensusPubkey.0,
                &call.p2pAddr,
                true,
                count,
            );

            let addr_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, count);
            journal_sstore(context, addr_slot, address_to_padded_u256(call.evmAddr));
            journal_sstore(context, SLOT_VALIDATOR_COUNT, U256::from(count + 1));

            let event = IValidatorRegistry::ValidatorAdded {
                evmAddr: call.evmAddr,
                consensusPubkey: call.consensusPubkey,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(VALIDATOR_REGISTRY_ADDRESS, &event)],
            ))
        }

        IValidatorRegistry::removeValidatorCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IValidatorRegistry::removeValidatorCall::abi_decode(input).map_err(decode_error)?;

            let policy_id = load_policy_id(context);
            let caller_did = match did_from_signer(&tx_ctx.signer) {
                Ok(d) => d,
                Err(_) => {
                    return Ok(err_dispatch(ValidatorRegistryError::Unauthorized(
                        "invalid signer DID".to_string(),
                    )));
                }
            };
            if let Err(e) = check_manage_access(acp, &policy_id, caller_did) {
                return Ok(err_dispatch(e));
            }

            let (_, _, _, _, val_index) = match load_validator_raw(context, call.evmAddr) {
                Some(v) => v,
                None => {
                    return Ok(err_dispatch(ValidatorRegistryError::ValidatorNotFound(
                        format!("{:?}", call.evmAddr),
                    )));
                }
            };

            let count = journal_sload(context, SLOT_VALIDATOR_COUNT).as_limbs()[0];
            let last_index = count - 1;

            if val_index != last_index {
                let last_addr_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, last_index);
                let last_addr_val = journal_sload(context, last_addr_slot);
                let last_addr = u256_to_address(last_addr_val);

                let removed_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, val_index);
                journal_sstore(context, removed_slot, last_addr_val);

                if let Some((la, lc, lp, ls, _)) = load_validator_raw(context, last_addr) {
                    store_validator_raw(context, la, lc, &lp, ls, val_index);
                }
                journal_sstore(context, last_addr_slot, U256::ZERO);
            } else {
                let removed_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, val_index);
                journal_sstore(context, removed_slot, U256::ZERO);
            }

            clear_validator(context, call.evmAddr);
            journal_sstore(context, SLOT_VALIDATOR_COUNT, U256::from(last_index));

            let event = IValidatorRegistry::ValidatorRemoved {
                evmAddr: call.evmAddr,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(VALIDATOR_REGISTRY_ADDRESS, &event)],
            ))
        }

        IValidatorRegistry::setValidatorStatusCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IValidatorRegistry::setValidatorStatusCall::abi_decode(input)
                .map_err(decode_error)?;

            let policy_id = load_policy_id(context);
            let caller_did = match did_from_signer(&tx_ctx.signer) {
                Ok(d) => d,
                Err(_) => {
                    return Ok(err_dispatch(ValidatorRegistryError::Unauthorized(
                        "invalid signer DID".to_string(),
                    )));
                }
            };
            if let Err(e) = check_manage_access(acp, &policy_id, caller_did) {
                return Ok(err_dispatch(e));
            }

            let (addr, consensus, p2p, _, index) = match load_validator_raw(context, call.evmAddr) {
                Some(v) => v,
                None => {
                    return Ok(err_dispatch(ValidatorRegistryError::ValidatorNotFound(
                        format!("{:?}", call.evmAddr),
                    )));
                }
            };
            store_validator_raw(context, addr, consensus, &p2p, call.active, index);

            let event = IValidatorRegistry::ValidatorStatusChanged {
                evmAddr: call.evmAddr,
                active: call.active,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(VALIDATOR_REGISTRY_ADDRESS, &event)],
            ))
        }

        IValidatorRegistry::updateP2PAddressCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IValidatorRegistry::updateP2PAddressCall::abi_decode(input)
                .map_err(decode_error)?;

            let caller_addr = evm_address_from_signer(&tx_ctx.signer);
            let (addr, consensus, _, active, index) = match load_validator_raw(context, caller_addr)
            {
                Some(v) => v,
                None => {
                    return Ok(err_dispatch(ValidatorRegistryError::Unauthorized(
                        "caller is not a registered validator".to_string(),
                    )));
                }
            };
            store_validator_raw(context, addr, consensus, &call.p2pAddr, active, index);

            let event = IValidatorRegistry::ValidatorUpdated {
                evmAddr: caller_addr,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(VALIDATOR_REGISTRY_ADDRESS, &event)],
            ))
        }

        IValidatorRegistry::getValidatorsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let validators = load_all_validators(context);
            let ret =
                IValidatorRegistry::getValidatorsCall::abi_encode_returns(&json_bytes(&validators));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IValidatorRegistry::getValidatorCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IValidatorRegistry::getValidatorCall::abi_decode(input).map_err(decode_error)?;
            let validator = load_validator_raw(context, call.evmAddr).map(to_validator_info);
            let ret =
                IValidatorRegistry::getValidatorCall::abi_encode_returns(&json_bytes(&validator));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IValidatorRegistry::getActiveValidatorCountCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let validators = load_all_validators(context);
            let active_count = validators.iter().filter(|v| v.active).count();
            let ret = IValidatorRegistry::getActiveValidatorCountCall::abi_encode_returns(
                &U256::from(active_count),
            );
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        _ => Err(PrecompileError::Other(
            format!(
                "unknown ValidatorRegistry selector: 0x{}",
                hex::encode(selector)
            )
            .into(),
        )),
    }
}

fn evm_address_from_signer(signer: &str) -> Address {
    if signer.starts_with("0x") || signer.starts_with("0X") {
        signer.parse().unwrap_or(Address::ZERO)
    } else if signer.starts_with("did:key:") {
        hub_crypto::secp256k1::evm_address_from_did(signer).unwrap_or(Address::ZERO)
    } else {
        Address::ZERO
    }
}

/// Compute the storage entries needed to bootstrap validators at genesis.
#[allow(dead_code)]
pub(crate) fn genesis_storage_entries(
    validators: &[GenesiValidator],
    policy_id_hash: B256,
) -> Vec<(U256, U256)> {
    let mut entries = Vec::new();

    entries.push((SLOT_POLICY_ID, U256::from_be_bytes(policy_id_hash.0)));
    entries.push((SLOT_VALIDATOR_COUNT, U256::from(validators.len())));

    for (i, v) in validators.iter().enumerate() {
        let addr_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, i as u64);
        entries.push((addr_slot, address_to_padded_u256(v.evm_address)));

        let entry_base = mapping_slot(v.evm_address, SLOT_VALIDATORS_MAPPING_BASE);
        entries.push((entry_base, pack_address_active(v.evm_address, true)));
        entries.push((
            entry_base.wrapping_add(U256::from(1)),
            U256::from_be_bytes(v.consensus_pubkey),
        ));
        entries.push((entry_base.wrapping_add(U256::from(2)), U256::from(i)));
        let p2p_bytes = v.p2p_address.as_bytes();
        entries.push((
            entry_base.wrapping_add(U256::from(3)),
            U256::from(p2p_bytes.len()),
        ));
        let mut padded = [0u8; 32];
        let copy_len = p2p_bytes.len().min(32);
        padded[..copy_len].copy_from_slice(&p2p_bytes[..copy_len]);
        entries.push((
            entry_base.wrapping_add(U256::from(4)),
            U256::from_be_bytes(padded),
        ));
    }

    entries
}

/// Genesis-time validator descriptor (uses native types, not serializable strings).
#[allow(dead_code)]
pub(crate) struct GenesiValidator {
    pub evm_address: Address,
    pub consensus_pubkey: [u8; 32],
    pub p2p_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_slot_is_deterministic() {
        let addr = Address::repeat_byte(0x01);
        let s1 = mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
        let s2 = mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
        assert_eq!(s1, s2);
    }

    #[test]
    fn different_addresses_different_slots() {
        let a = mapping_slot(Address::repeat_byte(0x01), SLOT_VALIDATORS_MAPPING_BASE);
        let b = mapping_slot(Address::repeat_byte(0x02), SLOT_VALIDATORS_MAPPING_BASE);
        assert_ne!(a, b);
    }

    #[test]
    fn array_element_slot_increments() {
        let s0 = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, 0);
        let s1 = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, 1);
        assert_eq!(s1, s0.wrapping_add(U256::from(1)));
    }

    #[test]
    fn pack_unpack_address_active() {
        let addr = Address::repeat_byte(0xAB);
        let packed = pack_address_active(addr, true);
        let (unpacked_addr, unpacked_active) = unpack_address_active(packed);
        assert_eq!(unpacked_addr, addr);
        assert!(unpacked_active);

        let packed_inactive = pack_address_active(addr, false);
        let (_, active) = unpack_address_active(packed_inactive);
        assert!(!active);
    }

    #[test]
    fn genesis_storage_entries_roundtrip() {
        let validators = vec![GenesiValidator {
            evm_address: Address::repeat_byte(0x01),
            consensus_pubkey: [0xAA; 32],
            p2p_address: "127.0.0.1:30300".to_string(),
        }];
        let policy_id = B256::repeat_byte(0xFF);
        let entries = genesis_storage_entries(&validators, policy_id);

        assert!(entries.len() > 2);
        assert_eq!(entries[0].0, SLOT_POLICY_ID);
        assert_eq!(entries[1].0, SLOT_VALIDATOR_COUNT);
        assert_eq!(entries[1].1, U256::from(1));
    }

    #[test]
    fn evm_address_from_signer_hex() {
        let addr = evm_address_from_signer("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_ne!(addr, Address::ZERO);
    }

    #[test]
    fn evm_address_from_signer_did() {
        let addr = evm_address_from_signer("did:key:z6MkTest");
        assert_eq!(addr, Address::ZERO);
    }
}
