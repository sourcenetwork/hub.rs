//! Stateless EVM simulation for `eth_call` and `eth_estimateGas`.

use alloy_primitives::{Address, Bytes, U256};
use hub_traits::StateDbRead;
use revm::{
    Context, ExecuteEvm, Journal, MainBuilder,
    context::block::BlockEnv,
    context::result::{ExecutionResult, Output},
    database::State,
    primitives::{TxKind, hardfork::SpecId},
};

use crate::{ExecutionError, StateDbAdapter, precompiles::HubPrecompiles};

/// Input for a simulation call (no signature, no RLP).
#[derive(Debug)]
pub struct SimulateRequest {
    /// Sender address.
    pub from: Address,
    /// Recipient address (`None` for contract creation).
    pub to: Option<Address>,
    /// Value to transfer.
    pub value: U256,
    /// Calldata.
    pub data: Bytes,
    /// Gas limit override.
    pub gas: Option<u64>,
}

/// Output from a simulation call.
#[derive(Debug)]
pub struct SimulateResult {
    /// Return data (or revert reason).
    pub output: Bytes,
    /// Gas consumed.
    pub gas_used: u64,
    /// Whether execution succeeded.
    pub success: bool,
}

const BASE_TX_GAS: u64 = 21_000;

/// Execute a read-only EVM call against the given state.
///
/// Builds a full REVM context with `HubPrecompiles` so that `eth_call` to
/// precompile addresses (ACP queries, etc.) works correctly.
pub fn simulate_call<S: StateDbRead>(
    state: &S,
    chain_id: u64,
    request: &SimulateRequest,
    block_gas_limit: u64,
) -> Result<SimulateResult, ExecutionError> {
    let adapter = StateDbAdapter::new(state.clone());
    let db = State::builder().with_database_ref(adapter).build();

    type Db<S> = State<revm::database::WrapDatabaseRef<StateDbAdapter<S>>>;

    let gas_limit = request.gas.unwrap_or(block_gas_limit);

    let tx_kind = request.to.map_or(TxKind::Create, TxKind::Call);

    let ctx: Context<BlockEnv, _, _, Db<S>, Journal<Db<S>>, ()> = Context::new(db, SpecId::CANCUN);
    let ctx = ctx
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.disable_nonce_check = true;
        })
        .modify_block_chained(|blk: &mut BlockEnv| {
            blk.gas_limit = block_gas_limit;
        });

    let tx_env = revm::context::TxEnv::builder()
        .caller(request.from)
        .kind(tx_kind)
        .value(request.value)
        .data(request.data.clone())
        .gas_limit(gas_limit)
        .gas_price(0u128)
        .nonce(0)
        .build()
        .map_err(|e| ExecutionError::TxExecution(format!("{e:?}")))?;

    let mut evm = ctx
        .build_mainnet()
        .with_precompiles(HubPrecompiles::new(SpecId::CANCUN));

    let result_and_state = evm
        .transact(tx_env)
        .map_err(|e| ExecutionError::TxExecution(format!("{e:?}")))?;

    match result_and_state.result {
        ExecutionResult::Success {
            output, gas_used, ..
        } => {
            let bytes = match output {
                Output::Call(b) => b,
                Output::Create(b, _) => b,
            };
            Ok(SimulateResult {
                output: bytes,
                gas_used,
                success: true,
            })
        }
        ExecutionResult::Revert { output, gas_used } => Ok(SimulateResult {
            output,
            gas_used,
            success: false,
        }),
        ExecutionResult::Halt { reason, gas_used } => Ok(SimulateResult {
            output: Bytes::from(format!("{reason:?}").into_bytes()),
            gas_used,
            success: false,
        }),
    }
}

/// Estimate the minimum gas required for a transaction via binary search.
pub fn estimate_gas<S: StateDbRead>(
    state: &S,
    chain_id: u64,
    request: &SimulateRequest,
    block_gas_limit: u64,
) -> Result<u64, ExecutionError> {
    let cap = request.gas.unwrap_or(block_gas_limit);

    // First check: does it succeed at the cap at all?
    let mut req_at_cap = SimulateRequest {
        from: request.from,
        to: request.to,
        value: request.value,
        data: request.data.clone(),
        gas: Some(cap),
    };
    let result = simulate_call(state, chain_id, &req_at_cap, block_gas_limit)?;
    if !result.success {
        return Err(ExecutionError::TxExecution(
            "execution reverted at gas cap".to_string(),
        ));
    }

    let mut lo = BASE_TX_GAS;
    let mut hi = cap;

    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        req_at_cap.gas = Some(mid);
        let result = simulate_call(state, chain_id, &req_at_cap, block_gas_limit)?;
        if result.success && !is_out_of_gas(&result) {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    Ok(hi)
}

fn is_out_of_gas(result: &SimulateResult) -> bool {
    if result.success {
        return false;
    }
    let msg = String::from_utf8_lossy(&result.output);
    msg.contains("OutOfGas")
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, KECCAK256_EMPTY};
    use hub_traits::StateDbError;

    use super::*;

    #[derive(Clone, Debug)]
    struct MockState;

    impl StateDbRead for MockState {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            Ok(0)
        }
        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::from(1_000_000_000_000_000_000u128))
        }
        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(KECCAK256_EMPTY)
        }
        async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
            Ok(Bytes::new())
        }
        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
    }

    #[test]
    fn simulate_simple_transfer() {
        let state = MockState;
        let request = SimulateRequest {
            from: Address::ZERO,
            to: Some(Address::repeat_byte(1)),
            value: U256::ZERO,
            data: Bytes::new(),
            gas: None,
        };

        let result = simulate_call(&state, 1, &request, 30_000_000).unwrap();
        assert!(result.success);
        assert!(result.gas_used >= BASE_TX_GAS);
    }

    #[test]
    fn estimate_simple_transfer() {
        let state = MockState;
        let request = SimulateRequest {
            from: Address::ZERO,
            to: Some(Address::repeat_byte(1)),
            value: U256::ZERO,
            data: Bytes::new(),
            gas: None,
        };

        let gas = estimate_gas(&state, 1, &request, 30_000_000).unwrap();
        assert!(gas >= BASE_TX_GAS);
    }

    #[test]
    fn simulate_with_explicit_gas() {
        let state = MockState;
        let request = SimulateRequest {
            from: Address::ZERO,
            to: Some(Address::repeat_byte(1)),
            value: U256::ZERO,
            data: Bytes::new(),
            gas: Some(100_000),
        };

        let result = simulate_call(&state, 1, &request, 30_000_000).unwrap();
        assert!(result.success);
    }
}
