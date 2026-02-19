//! HubExecutor — EVM executor with hub precompiles (ACP, Bulletin, Hub).

use crate::{
    BlockContext, BlockExecutor, ExecutionConfig, ExecutionError, ExecutionOutcome,
    ExecutionReceipt, StateDbAdapter, build_receipt, decode_tx_env, extract_changes,
};
use alloy_primitives::{B256, Bytes, U256, keccak256};
use hub_traits::StateDb;
use revm::{
    Context, ExecuteEvm, Journal, MainBuilder, context::block::BlockEnv,
    context_interface::ContextSetters, database::State,
};
use tracing::warn;

use crate::precompiles::HubPrecompiles;

/// Block executor with hub precompiles (ACP, Bulletin, Hub).
#[derive(Clone, Debug)]
pub struct HubExecutor {
    config: ExecutionConfig,
}

impl HubExecutor {
    /// Create a new hub executor.
    pub const fn new(chain_id: u64) -> Self {
        Self {
            config: ExecutionConfig::new(chain_id),
        }
    }

    /// Create a new hub executor with full configuration.
    pub const fn with_config(config: ExecutionConfig) -> Self {
        Self { config }
    }

    /// Get the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get the execution configuration.
    pub const fn config(&self) -> &ExecutionConfig {
        &self.config
    }
}

impl<S: StateDb> BlockExecutor<S> for HubExecutor {
    type Tx = Bytes;

    fn execute(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Self::Tx],
    ) -> Result<ExecutionOutcome, ExecutionError> {
        let adapter = StateDbAdapter::new(state.clone());
        let db = State::builder().with_database_ref(adapter).build();

        type Db<S> = State<revm::database::WrapDatabaseRef<StateDbAdapter<S>>>;
        let ctx: Context<BlockEnv, _, _, Db<S>, Journal<Db<S>>, ()> =
            Context::new(db, self.config.spec_id);
        let ctx = ctx
            .modify_cfg_chained(|cfg| {
                cfg.chain_id = self.config.chain_id;
            })
            .modify_block_chained(|blk: &mut BlockEnv| {
                blk.number = U256::from(context.header.number);
                blk.timestamp = U256::from(context.header.timestamp);
                blk.beneficiary = context.header.beneficiary;
                blk.gas_limit = context.header.gas_limit;
                blk.basefee = context.header.base_fee_per_gas.unwrap_or_default();
                blk.prevrandao = Some(context.prevrandao);
            });

        let mut evm = ctx
            .build_mainnet()
            .with_precompiles(HubPrecompiles::new(self.config.spec_id));

        let mut outcome = ExecutionOutcome::new();
        let mut cumulative_gas = 0u64;
        let building = !context.is_verification;
        let mut executed_indices: Vec<usize> = Vec::new();

        for (i, tx_bytes) in txs.iter().enumerate() {
            let tx_hash = keccak256(tx_bytes);

            let tx_env = match decode_tx_env(tx_bytes, self.config.chain_id) {
                Ok(env) => env,
                Err(e) if building => {
                    warn!(%tx_hash, ?e, "skipping tx: decode error");
                    continue;
                }
                Err(e) => return Err(e),
            };
            evm.set_tx(tx_env);

            let result_and_state = match evm.replay() {
                Ok(r) => r,
                Err(e) if building => {
                    warn!(%tx_hash, ?e, "skipping tx: execution error");
                    continue;
                }
                Err(e) => {
                    return Err(ExecutionError::TxExecution(format!("{e:?}")));
                }
            };

            executed_indices.push(i);

            let gas_used = result_and_state.result.gas_used();
            cumulative_gas = cumulative_gas.saturating_add(gas_used);

            let receipt =
                build_receipt(&result_and_state.result, tx_hash, gas_used, cumulative_gas);
            outcome.receipts.push(receipt);

            let changes = extract_changes(result_and_state.state);
            outcome.changes.merge(changes);
        }

        if building {
            outcome.executed_tx_indices = Some(executed_indices);
        }

        outcome.gas_used = cumulative_gas;
        outcome.ibc_root = B256::ZERO;

        Ok(outcome)
    }

    fn validate_header(&self, header: &alloy_consensus::Header) -> Result<(), ExecutionError> {
        if header.gas_limit < self.config.gas_limit_bounds.min {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} below minimum {}",
                header.gas_limit, self.config.gas_limit_bounds.min
            )));
        }
        if header.gas_limit > self.config.gas_limit_bounds.max {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} above maximum {}",
                header.gas_limit, self.config.gas_limit_bounds.max
            )));
        }
        Ok(())
    }

    fn mark_height_verified(&self, _height: u64) {}

    fn cached_receipts(&self, _height: u64) -> Option<(Vec<ExecutionReceipt>, u64)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY};
    use hub_qmdb::ChangeSet;
    use hub_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct MockStateDb;

    impl StateDbRead for MockStateDb {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            Ok(0)
        }
        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
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

    impl StateDbWrite for MockStateDb {
        async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        fn merge_changes(&self, _older: ChangeSet, newer: ChangeSet) -> ChangeSet {
            newer
        }
    }

    impl StateDb for MockStateDb {
        async fn state_root(&self) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
    }

    fn test_executor() -> HubExecutor {
        HubExecutor::new(9001)
    }

    #[test]
    fn hub_executor_new() {
        let executor = test_executor();
        assert_eq!(executor.chain_id(), 9001);
    }

    #[test]
    fn hub_executor_execute_empty_block() {
        use alloy_consensus::Header;

        let executor = test_executor();
        let state = MockStateDb;
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        let context = BlockContext::new(header, B256::ZERO, B256::ZERO);
        let txs: Vec<Bytes> = vec![];
        let outcome = executor.execute(&state, &context, &txs).unwrap();
        assert_eq!(outcome.gas_used, 0);
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.ibc_root, B256::ZERO);
    }

    #[test]
    fn hub_executor_validate_header() {
        let executor = test_executor();
        let mut header = alloy_consensus::Header::default();
        header.gas_limit = 30_000_000;
        assert!(
            <HubExecutor as BlockExecutor<MockStateDb>>::validate_header(&executor, &header)
                .is_ok()
        );
    }
}
