//! Validator set change detection after block finalization.

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, SolEvent};
use hub_executor::{ExecutionReceipt, SimulateRequest, simulate_call};
use hub_modules::module_state::ModuleState;
use hub_modules::validator_registry::abi::IValidatorRegistry;
use hub_modules::validator_registry::types::ValidatorInfo;
use hub_traits::StateDbRead;
use tracing::warn;

/// Notification that the on-chain validator set changed.
#[derive(Clone, Debug)]
pub struct ValidatorSetUpdate {
    /// Block height at which the change was finalized.
    pub height: u64,
    /// The full validator set as of this block.
    pub validators: Vec<ValidatorInfo>,
}

fn is_mutation_event(topic0: &B256) -> bool {
    *topic0 == IValidatorRegistry::ValidatorAdded::SIGNATURE_HASH
        || *topic0 == IValidatorRegistry::ValidatorRemoved::SIGNATURE_HASH
        || *topic0 == IValidatorRegistry::ValidatorStatusChanged::SIGNATURE_HASH
}

/// Check whether any receipt contains a ValidatorRegistry mutation event.
pub fn has_validator_events(receipts: &[ExecutionReceipt], registry_address: Address) -> bool {
    for receipt in receipts {
        for log in receipt.logs() {
            if log.address == registry_address
                && let Some(topic0) = log.data.topics().first()
                && is_mutation_event(topic0)
            {
                return true;
            }
        }
    }
    false
}

/// Read the current validator set from on-chain state via `getValidators()`.
pub fn read_validator_set<S: StateDbRead>(
    state: &S,
    chain_id: u64,
    gas_limit: u64,
    modules: Option<&ModuleState>,
) -> Option<Vec<ValidatorInfo>> {
    let calldata = IValidatorRegistry::getValidatorsCall {}.abi_encode();

    let request = SimulateRequest {
        from: Address::ZERO,
        to: Some(hub_executor::VALIDATOR_REGISTRY_ADDRESS),
        value: U256::ZERO,
        data: Bytes::from(calldata),
        gas: None,
    };

    match simulate_call(state, chain_id, &request, gas_limit, modules) {
        Ok(result) if result.success => {
            let json_bytes =
                IValidatorRegistry::getValidatorsCall::abi_decode_returns(&result.output).ok()?;
            serde_json::from_slice::<Vec<ValidatorInfo>>(&json_bytes).ok()
        }
        Ok(result) => {
            warn!(
                output = %String::from_utf8_lossy(&result.output),
                "getValidators() reverted"
            );
            None
        }
        Err(err) => {
            warn!(?err, "getValidators() simulation failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Log, LogData};
    use hub_executor::ExecutionReceipt;

    use super::*;

    fn registry_addr() -> Address {
        hub_executor::VALIDATOR_REGISTRY_ADDRESS
    }

    fn receipt_with_event(address: Address, topic0: B256) -> ExecutionReceipt {
        let log = Log {
            address,
            data: LogData::new_unchecked(vec![topic0], alloy_primitives::Bytes::new()),
        };
        ExecutionReceipt::new(B256::ZERO, true, 21_000, 21_000, vec![log], None)
    }

    #[test]
    fn detects_validator_added() {
        let receipt = receipt_with_event(
            registry_addr(),
            IValidatorRegistry::ValidatorAdded::SIGNATURE_HASH,
        );
        assert!(has_validator_events(&[receipt], registry_addr()));
    }

    #[test]
    fn detects_validator_removed() {
        let receipt = receipt_with_event(
            registry_addr(),
            IValidatorRegistry::ValidatorRemoved::SIGNATURE_HASH,
        );
        assert!(has_validator_events(&[receipt], registry_addr()));
    }

    #[test]
    fn detects_validator_status_changed() {
        let receipt = receipt_with_event(
            registry_addr(),
            IValidatorRegistry::ValidatorStatusChanged::SIGNATURE_HASH,
        );
        assert!(has_validator_events(&[receipt], registry_addr()));
    }

    #[test]
    fn ignores_non_mutation_event() {
        let receipt = receipt_with_event(
            registry_addr(),
            IValidatorRegistry::ValidatorUpdated::SIGNATURE_HASH,
        );
        assert!(!has_validator_events(&[receipt], registry_addr()));
    }

    #[test]
    fn ignores_event_from_wrong_address() {
        let receipt = receipt_with_event(
            Address::repeat_byte(0xff),
            IValidatorRegistry::ValidatorAdded::SIGNATURE_HASH,
        );
        assert!(!has_validator_events(&[receipt], registry_addr()));
    }

    #[test]
    fn no_events_in_empty_receipts() {
        assert!(!has_validator_events(&[], registry_addr()));
    }

    #[test]
    fn detects_event_among_multiple_receipts() {
        let normal = ExecutionReceipt::new(B256::ZERO, true, 21_000, 21_000, vec![], None);
        let mutation = receipt_with_event(
            registry_addr(),
            IValidatorRegistry::ValidatorRemoved::SIGNATURE_HASH,
        );
        assert!(has_validator_events(&[normal, mutation], registry_addr()));
    }
}
