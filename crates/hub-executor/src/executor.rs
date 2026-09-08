//! HubExecutor — EVM executor with hub precompiles (ACP, Bulletin, Hub)
//! and native BLS transaction support.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, RwLock};

use crate::{
    BlockContext, BlockExecutor, ExecutionConfig, ExecutionError, ExecutionOutcome,
    ExecutionReceipt, ModuleSnapshot, StateDbAdapter, build_receipt, decode_evm_tx,
    extract_changes,
};
use alloy_primitives::{B256, Bytes, U256, keccak256};
use hub_crypto::bls;
use hub_domain::NativeTx;
use hub_modules::acp::AcpModule;
use hub_modules::bulletin::BulletinModule;
use hub_modules::hub::HubModule;
use hub_modules::module_state::{ModuleState, SharedModuleState, state_root_from_jmt};
use hub_modules::native_account::NativeNonceStore;
use hub_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};
use hub_state::ModuleStateTree;
use hub_traits::StateDb;
use revm::{
    Context, ExecuteCommitEvm, InspectEvm, Journal, MainBuilder,
    context::{block::BlockEnv, result::ExecutionResult},
    context_interface::{ContextTr, JournalTr},
    database::State,
    precompile::PrecompileError,
};
use tracing::warn;

use crate::precompiles::{
    ACP_ADDRESS, BULLETIN_ADDRESS, HUB_ADDRESS, HubPrecompiles, VALIDATOR_REGISTRY_ADDRESS,
    dispatch_to_module,
};

/// Gas budget for native BLS transactions dispatched to modules.
const NATIVE_TX_GAS_LIMIT: u64 = 1_000_000;

mod recovery;

/// Per-module JMT-backed state trees: [acp, bulletin, hub, nonces].
pub type ModuleTrees = [Arc<Mutex<ModuleStateTree>>; 4];

/// Block executor with hub precompiles (ACP, Bulletin, Hub).
///
/// Processes both EVM transactions (secp256k1) and native BLS transactions
/// (BLS12-381) in block order. The first byte of each transaction determines
/// the path: `0x45` → native BLS, anything else → REVM.
///
/// Shared module state serves committed queries. Consensus execution supplies
/// an explicit parent snapshot and receives its post-execution state.
#[derive(Clone, Debug)]
pub struct HubExecutor {
    config: ExecutionConfig,
    modules: SharedModuleState,
    module_trees: Option<ModuleTrees>,
    commit_lock: Arc<Mutex<()>>,
    #[cfg(feature = "fault-injection")]
    crash_marker: Option<std::path::PathBuf>,
}

impl HubExecutor {
    /// Configure a one-shot process crash marker for persistence tests.
    #[cfg(feature = "fault-injection")]
    #[must_use]
    pub fn with_crash_marker(mut self, path: std::path::PathBuf) -> Self {
        self.crash_marker = Some(path);
        self
    }

    /// Abort at a selected module boundary in fault-injection builds.
    #[cfg(feature = "fault-injection")]
    pub fn after_module_commit(&self, height: u64, index: usize) {
        if let Some(marker) = &self.crash_marker {
            crate::faults::after_module_commit(marker, height, index);
        }
    }
    /// Create a new hub executor.
    pub fn new(chain_id: u64) -> Self {
        Self {
            config: ExecutionConfig::new(chain_id),
            modules: Arc::new(RwLock::new(ModuleState::default())),
            module_trees: None,
            commit_lock: Arc::default(),
            #[cfg(feature = "fault-injection")]
            crash_marker: None,
        }
    }

    /// Create a new hub executor with full configuration.
    pub fn with_config(config: ExecutionConfig) -> Self {
        Self {
            config,
            modules: Arc::new(RwLock::new(ModuleState::default())),
            module_trees: None,
            commit_lock: Arc::default(),
            #[cfg(feature = "fault-injection")]
            crash_marker: None,
        }
    }

    /// Attach JMT-backed module state trees for authenticated state roots.
    #[must_use]
    pub fn with_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.module_trees = Some(trees);
        self
    }

    /// Bind administrative execution to the deployment genesis record.
    #[must_use]
    pub const fn with_genesis_id(mut self, genesis_id: [u8; 32]) -> Self {
        self.config.genesis_id = genesis_id;
        self
    }

    /// Get the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get the execution configuration.
    pub const fn config(&self) -> &ExecutionConfig {
        &self.config
    }

    /// Get the shared module state.
    pub const fn modules(&self) -> &SharedModuleState {
        &self.modules
    }

    /// Get the JMT-backed module state trees, if attached.
    pub const fn module_trees(&self) -> Option<&ModuleTrees> {
        self.module_trees.as_ref()
    }

    /// Install module state loaded at startup or selected by finalization.
    pub fn set_base_modules(&self, modules: ModuleState) {
        *self.modules.write().unwrap() = modules;
    }

    /// Capture module values and tree views from the same committed revision.
    pub fn snapshot(&self) -> Result<ModuleSnapshot, ExecutionError> {
        let _guard = self.commit_lock.lock().unwrap();
        let trees = self
            .module_trees
            .as_ref()
            .map(|trees| {
                let snapshots = trees
                    .iter()
                    .map(|tree| tree.lock().unwrap().snapshot())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
                Ok::<_, ExecutionError>(snapshots.try_into().expect("four module trees"))
            })
            .transpose()?;
        Ok(ModuleSnapshot {
            modules: self.modules.read().unwrap().clone(),
            trees,
        })
    }

    /// Persist selected tree updates before replacing the shared module values.
    pub fn commit_snapshot(
        &self,
        height: u64,
        snapshot: ModuleSnapshot,
    ) -> Result<(), ExecutionError> {
        let _guard = self.commit_lock.lock().unwrap();
        match (&self.module_trees, &snapshot.trees) {
            (Some(trees), Some(snapshots)) => {
                #[cfg(feature = "fault-injection")]
                let changed = trees.iter().zip(snapshots).any(|(tree, snapshot)| {
                    tree.lock().unwrap().root().expect("read module root") != snapshot.root()
                });
                for (index, (tree, snapshot)) in trees.iter().zip(snapshots).enumerate() {
                    tree.lock()
                        .unwrap()
                        .commit_prepared(height, snapshot)
                        .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
                    #[cfg(feature = "fault-injection")]
                    if changed && let Some(marker) = &self.crash_marker {
                        crate::faults::after_module_commit(marker, height, index);
                    }
                    #[cfg(not(feature = "fault-injection"))]
                    let _ = index;
                }
            }
            (None, None) => {}
            _ => {
                return Err(ExecutionError::ModuleTree(
                    "module snapshot has incompatible trees".into(),
                ));
            }
        }
        self.set_base_modules(snapshot.modules);
        Ok(())
    }

    /// Execute a native BLS transaction: verify signature, derive DID, dispatch to module.
    #[allow(clippy::too_many_arguments)]
    fn execute_native_tx<CTX: ContextTr>(
        &self,
        tx_bytes: &[u8],
        block_ctx: &BlockExecCtx,
        acp: &mut AcpModule,
        bulletin: &mut BulletinModule,
        hub: &mut HubModule,
        nonce_store: &mut NativeNonceStore,
        journal: &mut CTX,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;

        if native_tx.chain_id != self.config.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: native_tx.chain_id,
            });
        }

        let pubkey = bls::deserialize_pubkey(native_tx.bls_pubkey.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("pubkey: {e}")))?;

        let signing_data = native_tx.signing_data();
        bls::verify(&pubkey, &signing_data, native_tx.signature.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("signature: {e}")))?;

        let signer_did = bls::did_from_bls_pubkey(&pubkey)
            .map_err(|e| ExecutionError::BlsVerification(format!("DID: {e}")))?;

        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != HUB_ADDRESS
            && native_tx.target != VALIDATOR_REGISTRY_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }

        nonce_store
            .check_and_increment(&signer_did, native_tx.nonce)
            .map_err(|e| match e {
                hub_modules::native_account::NonceError::Mismatch { did, expected, got } => {
                    ExecutionError::NonceMismatch { did, expected, got }
                }
                hub_modules::native_account::NonceError::Overflow(did) => {
                    ExecutionError::InvalidTx(format!("nonce overflow for {did}"))
                }
            })?;

        let tx_hash = native_tx.tx_id().0;
        let tx_ctx = TxExecCtx {
            sequence: native_tx.nonce,
            tx_hash: tx_hash.to_vec(),
            signer: signer_did,
        };

        let before = (acp.clone(), bulletin.clone(), hub.clone());
        let checkpoint = journal.journal_mut().checkpoint();
        let dispatch_result = catch_unwind(AssertUnwindSafe(|| {
            if native_tx.target == VALIDATOR_REGISTRY_ADDRESS {
                journal
                    .journal_mut()
                    .load_account(VALIDATOR_REGISTRY_ADDRESS)
                    .map_err(|error| {
                        PrecompileError::Fatal(format!("membership account read failed: {error:?}"))
                    })?;
                journal
                    .journal_mut()
                    .touch_account(VALIDATOR_REGISTRY_ADDRESS);
                return crate::precompiles::validator_registry::dispatch_with_journal(
                    journal,
                    acp,
                    hub,
                    block_ctx,
                    &tx_ctx,
                    &native_tx.calldata,
                    NATIVE_TX_GAS_LIMIT,
                );
            }
            dispatch_to_module(
                acp,
                bulletin,
                hub,
                native_tx.target,
                &native_tx.calldata,
                block_ctx,
                &tx_ctx,
                NATIVE_TX_GAS_LIMIT,
            )
            .expect("target validated above")
        }));

        if !matches!(&dispatch_result, Ok(Ok(result)) if !result.precompile.reverted) {
            (*acp, *bulletin, *hub) = before;
            journal.journal_mut().checkpoint_revert(checkpoint);
        } else {
            journal.journal_mut().checkpoint_commit();
        }

        let failed_receipt = || {
            ExecutionReceipt::new(
                tx_hash,
                false,
                NATIVE_TX_GAS_LIMIT,
                0, // cumulative gas set by caller
                vec![],
                None,
            )
        };

        match dispatch_result {
            Ok(Ok(result)) => {
                let logs = if result.precompile.reverted {
                    vec![]
                } else {
                    result.logs
                };
                Ok(ExecutionReceipt::new(
                    tx_hash,
                    !result.precompile.reverted,
                    result.precompile.gas_used,
                    0, // cumulative gas set by caller
                    logs,
                    None,
                ))
            }
            Ok(Err(PrecompileError::Fatal(message))) => Err(ExecutionError::TxExecution(message)),
            Ok(Err(_)) => Ok(failed_receipt()),
            Err(_) => {
                warn!(%tx_hash, "native tx module panicked");
                Ok(failed_receipt())
            }
        }
    }

    /// Run end-of-block hooks for modules that need per-block maintenance.
    fn run_end_block_hooks(modules: &mut ModuleState, block_ctx: &BlockExecCtx) {
        if let Err(e) = modules.acp.end_blocker(block_ctx) {
            warn!(?e, "ACP end_blocker failed");
        }

        if let Err(e) = modules.hub.check_and_update_expired_tokens(block_ctx) {
            warn!(?e, "Hub expired token sweep failed");
        }
    }
}

impl HubExecutor {
    /// Execute against an owned parent snapshot without replacing query state.
    pub fn execute_with_modules<S: StateDb>(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Bytes],
        parent: ModuleSnapshot,
    ) -> Result<(ExecutionOutcome, ModuleSnapshot), ExecutionError> {
        let ModuleSnapshot {
            modules: base_modules,
            trees: mut snapshots,
        } = parent;
        let mut modules = base_modules.clone();

        let block_ctx = BlockExecCtx {
            genesis_id: self.config.genesis_id,
            deployment_id: self.config.chain_id,
            timestamp: Timestamp {
                seconds: context.header.timestamp,
                block_height: context.header.number,
            },
        };

        let mut outcome = ExecutionOutcome::new();
        let mut cumulative_gas = 0u64;
        let building = !context.is_verification;
        let mut executed_indices: Vec<usize> = Vec::new();

        let adapter = StateDbAdapter::new(state.clone());
        let db = State::builder().with_database_ref(adapter).build();

        type Db<S> = State<revm::database::WrapDatabaseRef<StateDbAdapter<S>>>;
        let ctx: Context<BlockEnv, _, _, Db<S>, Journal<Db<S>>, ()> =
            Context::new(db, self.config.spec_id);
        let mut ctx = ctx
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

        for (i, tx_bytes) in txs.iter().enumerate() {
            if tx_bytes.is_empty() || !NativeTx::is_native_tx(tx_bytes[0]) {
                continue;
            }

            let receipt = match self.execute_native_tx(
                tx_bytes,
                &block_ctx,
                &mut modules.acp,
                &mut modules.bulletin,
                &mut modules.hub,
                &mut modules.nonces,
                &mut ctx,
            ) {
                Ok(r) => r,
                Err(error @ ExecutionError::TxExecution(_)) => return Err(error),
                Err(e) if building => {
                    let tx_hash = keccak256(tx_bytes);
                    warn!(%tx_hash, ?e, "skipping native tx");
                    continue;
                }
                Err(e) => return Err(e),
            };

            let journaled = ctx.journal_mut().finalize();
            outcome.changes.merge(extract_changes(&journaled));
            // Native module storage is retained even when its account has no balance or code.
            for (address, account) in journaled {
                if account.is_touched() {
                    let storage = account
                        .storage
                        .into_iter()
                        .map(|(slot, value)| (slot, value.into()))
                        .collect();
                    ctx.journal_mut()
                        .db_mut()
                        .cache
                        .accounts
                        .get_mut(&address)
                        .expect("journaled account was loaded into the proposal cache")
                        .change(account.info, storage);
                }
            }

            executed_indices.push(i);
            let gas_used = receipt.gas_used;
            cumulative_gas = cumulative_gas.saturating_add(gas_used);

            let mut receipt = receipt;
            receipt.receipt.cumulative_gas_used = cumulative_gas;
            outcome.receipts.push(receipt);
        }

        let precompiles = HubPrecompiles::with_modules(
            self.config.spec_id,
            modules.acp.clone(),
            modules.bulletin.clone(),
            modules.hub.clone(),
        )
        .with_genesis_id(self.config.genesis_id);
        let mut evm = ctx
            .build_mainnet_with_inspector(precompiles.inspector())
            .with_precompiles(precompiles);

        for (i, tx_bytes) in txs.iter().enumerate() {
            if !tx_bytes.is_empty() && NativeTx::is_native_tx(tx_bytes[0]) {
                continue;
            }

            let tx_hash = keccak256(tx_bytes);

            let (tx_env, signer_did) = match decode_evm_tx(tx_bytes, self.config.chain_id) {
                Ok(r) => r,
                Err(ExecutionError::TxDecode(msg)) if building => {
                    warn!(%tx_hash, msg, "skipping tx: decode error");
                    continue;
                }
                Err(e) => return Err(e),
            };

            evm.precompiles.set_tx_hash(tx_hash);
            evm.precompiles.set_signer_did(signer_did);

            evm.precompiles.begin_transaction();
            let execution = evm.inspect_tx(tx_env);
            evm.precompiles
                .finish_transaction(execution.as_ref().is_ok_and(|r| r.result.is_success()));
            let result_and_state = match execution {
                Ok(r) => r,
                Err(e) if building => {
                    warn!(%tx_hash, ?e, "skipping tx: execution error");
                    continue;
                }
                Err(e) => {
                    return Err(ExecutionError::TxExecution(format!("{e:?}")));
                }
            };

            match &result_and_state.result {
                ExecutionResult::Revert { output, .. } => {
                    let reason = String::from_utf8_lossy(output);
                    warn!(%tx_hash, %reason, "EVM tx reverted");
                }
                ExecutionResult::Halt { reason, .. } => {
                    warn!(%tx_hash, ?reason, "EVM tx halted");
                }
                ExecutionResult::Success { .. } => {}
            }

            executed_indices.push(i);

            let gas_used = result_and_state.result.gas_used();
            cumulative_gas = cumulative_gas.saturating_add(gas_used);

            let receipt =
                build_receipt(&result_and_state.result, tx_hash, gas_used, cumulative_gas);
            outcome.receipts.push(receipt);

            let changes = extract_changes(&result_and_state.state);
            // Advance the proposal cache without writing canonical state.
            evm.commit(result_and_state.state);
            outcome.changes.merge(changes);
        }

        let (acp, bulletin, hub) = evm.precompiles.take_modules();
        modules.acp = acp;
        modules.bulletin = bulletin;
        modules.hub = hub;

        Self::run_end_block_hooks(&mut modules, &block_ctx);

        if building {
            outcome.executed_tx_indices = Some(executed_indices);
        }

        outcome.gas_used = cumulative_gas;
        outcome.module_state_root = if context.receipt_only {
            B256::ZERO
        } else if let Some(ref trees) = self.module_trees {
            let stores = [
                modules.acp.store(),
                modules.bulletin.store(),
                modules.hub.store(),
                modules.nonces.store(),
            ];
            let changes = modules.diff_from(&base_modules);

            let parents = snapshots
                .as_mut()
                .ok_or_else(|| ExecutionError::ModuleTree("missing parent tree views".into()))?;
            for (i, (tree_lock, mut dirty)) in trees.iter().zip(changes).enumerate() {
                if i == 0 {
                    crate::relation_index::index_relationships(&parents[i], stores[i], &mut dirty)?;
                }
                parents[i] = tree_lock
                    .lock()
                    .unwrap()
                    .prepare(&parents[i], dirty)
                    .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
            }
            let jmt_roots = std::array::from_fn(|i| parents[i].root().0);
            state_root_from_jmt(&jmt_roots)
        } else {
            // Fallback for tests without JMT trees. Production code always
            // provides module_trees, so this path should never run in prod.
            modules.state_root()
        };

        Ok((
            outcome,
            ModuleSnapshot {
                modules,
                trees: snapshots,
            },
        ))
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
        let modules = self.snapshot()?;
        self.execute_with_modules(state, context, txs, modules)
            .map(|(outcome, _)| outcome)
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
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, FixedBytes, KECCAK256_EMPTY};
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

    fn test_block_ctx() -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1_700_000_000,
                block_height: 1,
            },
        }
    }

    fn test_journal()
    -> Context<BlockEnv, revm::context::TxEnv, revm::context::CfgEnv, revm::database::EmptyDB> {
        Context::new(
            revm::database::EmptyDB::default(),
            revm::primitives::hardfork::SpecId::default(),
        )
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
        assert_ne!(outcome.module_state_root, B256::ZERO);
    }

    #[test]
    fn hub_executor_validate_header() {
        let executor = test_executor();
        let header = alloy_consensus::Header {
            gas_limit: 30_000_000,
            ..Default::default()
        };
        assert!(
            <HubExecutor as BlockExecutor<MockStateDb>>::validate_header(&executor, &header)
                .is_ok()
        );
    }

    #[test]
    fn native_tx_decode_error() {
        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        // 0x45 followed by garbage
        let bad_bytes = [0x45, 0xFF, 0xFF];
        let result = executor.execute_native_tx(
            &bad_bytes,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(result, Err(ExecutionError::TxDecode(_))));
    }

    #[test]
    fn native_tx_wrong_chain_id() {
        let tx = NativeTx {
            chain_id: 999,
            nonce: 0,
            bls_pubkey: FixedBytes::from([0xAA; 48]),
            target: ACP_ADDRESS,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0xBB; 96]),
        };
        let wire = tx.encode_wire();

        let executor = test_executor(); // chain_id = 9001
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        match result {
            Err(ExecutionError::ChainIdMismatch { expected, got }) => {
                assert_eq!(expected, 9001);
                assert_eq!(got, 999);
            }
            other => panic!("expected ChainIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn native_tx_invalid_bls_sig() {
        let tx = NativeTx {
            chain_id: 9001,
            nonce: 0,
            bls_pubkey: FixedBytes::from([0xFF; 48]), // not a valid G1 point
            target: ACP_ADDRESS,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0xBB; 96]),
        };
        let wire = tx.encode_wire();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(result, Err(ExecutionError::BlsVerification(_))));
    }

    #[test]
    fn native_tx_unknown_target() {
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();

        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let bad_target = Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
        ]);

        let mut tx = NativeTx {
            chain_id: 9001,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: bad_target,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]), // placeholder
        };

        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);

        let wire = tx.encode_wire();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(
            result,
            Err(ExecutionError::UnknownNativeTarget(_))
        ));
        assert!(
            nonces.store().is_empty(),
            "invalid target must not consume a nonce"
        );
    }

    #[test]
    fn native_tx_building_mode_skips_invalid() {
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
        // Building mode (is_verification = false)
        let context = BlockContext::new(header, B256::ZERO, B256::ZERO);

        // Malformed native tx: 0x45 + garbage
        let bad_native = Bytes::from(vec![0x45, 0xFF, 0xFF]);
        let txs = vec![bad_native];

        let outcome = executor.execute(&state, &context, &txs).unwrap();
        // Invalid tx should be skipped
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.gas_used, 0);
        assert_eq!(outcome.executed_tx_indices, Some(vec![]));
    }

    #[test]
    fn empty_block_runs_end_hooks() {
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

        // Should not panic — end-block hooks are no-ops
        let outcome = executor.execute(&state, &context, &txs).unwrap();
        assert_eq!(outcome.gas_used, 0);
    }

    #[test]
    fn native_tx_dispatches_to_module() {
        use alloy_sol_types::SolCall;
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;
        use hub_modules::acp::abi::IAcp;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();

        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let calldata = IAcp::getParamsCall {}.abi_encode();

        let mut tx = NativeTx {
            chain_id: 9001,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: ACP_ADDRESS,
            calldata: Bytes::from(calldata),
            signature: FixedBytes::from([0x00; 96]),
        };

        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);

        let wire = tx.encode_wire();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        // Passes BLS verification and nonce check, dispatches to module query_params
        let receipt = executor
            .execute_native_tx(
                &wire,
                &block_ctx,
                &mut acp,
                &mut bulletin,
                &mut hub,
                &mut nonces,
                &mut test_journal(),
            )
            .unwrap();
        assert!(receipt.success(), "getParams query should succeed");
    }

    /// Build a signed native tx targeting ACP with a given nonce and keypair.
    fn signed_native_tx(sk: &ark_bls12_381::Fr, pk_bytes: &[u8], nonce: u64) -> Vec<u8> {
        let mut tx = NativeTx {
            chain_id: 9001,
            nonce,
            bls_pubkey: FixedBytes::from_slice(pk_bytes),
            target: ACP_ADDRESS,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        tx.encode_wire()
    }

    fn test_bls_keypair() -> (ark_bls12_381::Fr, Vec<u8>) {
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        (sk, pk_bytes)
    }

    #[test]
    fn native_decisions_bind_authenticated_sequence_and_revision() {
        use alloy_sol_types::SolCall;
        use hub_modules::acp::{
            abi::IAcp,
            decision::DecisionRequest,
            types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
        };
        let (sk, pk_bytes) = test_bls_keypair();
        let pubkey = bls::deserialize_pubkey(&pk_bytes).unwrap();
        let creator = bls::did_from_bls_pubkey(&pubkey).unwrap();
        let actor = creator.parse().unwrap();
        let mut acp = AcpModule::new();
        let policy = acp.create_policy(&actor, "name: decisions\nresources:\n  - name: file\n    permissions:\n      - name: read\n", PolicyMarshalingType::ShortYaml).unwrap().policy.id;
        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        acp.direct_policy_cmd(&actor, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
        let request = AccessRequest {
            actor: Actor(actor),
            operations: vec![Operation {
                object,
                permission: "read".into(),
            }],
        };
        let call = IAcp::checkAccessCall {
            policyId: FixedBytes::from_slice(&hex::decode(&policy).unwrap()),
            resources: vec!["file".into()],
            objectIds: vec!["report".into()],
            permissions: vec!["read".into()],
            actor: creator.clone(),
        };
        let executor = test_executor();
        let block = test_block_ctx();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();
        for sequence in 0..2 {
            let mut tx = NativeTx {
                chain_id: 9001,
                nonce: sequence,
                bls_pubkey: FixedBytes::from_slice(&pk_bytes),
                target: ACP_ADDRESS,
                calldata: call.abi_encode().into(),
                signature: FixedBytes::ZERO,
            };
            tx.signature = FixedBytes::from_slice(&bls::sign(&sk, &tx.signing_data()).unwrap());
            let result = executor
                .execute_native_tx(
                    &tx.encode_wire(),
                    &block,
                    &mut acp,
                    &mut bulletin,
                    &mut hub,
                    &mut nonces,
                    &mut test_journal(),
                )
                .unwrap();
            assert!(result.success());
            let expected = DecisionRequest {
                deployment_id: block.deployment_id,
                policy_id: policy.clone(),
                creator: creator.clone(),
                creator_sequence: sequence,
                request: request.clone(),
            };
            let decision = acp
                .query_access_decision(&expected.id().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(decision.creator_acc_sequence, sequence);
            assert_eq!(decision.creation_time, block.timestamp);
            assert_eq!(decision.issued_height, block.timestamp.block_height);
        }
    }

    #[test]
    fn native_tx_nonce_mismatch_rejected() {
        let (sk, pk_bytes) = test_bls_keypair();
        let wire = signed_native_tx(&sk, &pk_bytes, 5); // expected 0

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        match result {
            Err(ExecutionError::NonceMismatch { expected, got, .. }) => {
                assert_eq!(expected, 0);
                assert_eq!(got, 5);
            }
            other => panic!("expected NonceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn native_tx_sequential_nonces_accepted() {
        let (sk, pk_bytes) = test_bls_keypair();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        // nonce 0 passes nonce check; empty calldata fails ABI decode → failed receipt
        let wire_0 = signed_native_tx(&sk, &pk_bytes, 0);
        let result_0 = executor.execute_native_tx(
            &wire_0,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(result_0.is_ok(), "nonce 0 should pass: {result_0:?}");

        // nonce 1 also passes nonce check
        let wire_1 = signed_native_tx(&sk, &pk_bytes, 1);
        let result_1 = executor.execute_native_tx(
            &wire_1,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(result_1.is_ok(), "nonce 1 should pass: {result_1:?}");

        // Replay of nonce 0 should fail
        let wire_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let result_replay = executor.execute_native_tx(
            &wire_replay,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(
            result_replay,
            Err(ExecutionError::NonceMismatch { .. })
        ));
    }

    #[test]
    fn native_tx_replay_rejected_after_success() {
        let (sk, pk_bytes) = test_bls_keypair();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut hub = HubModule::new();
        let mut nonces = NativeNonceStore::default();

        // First: nonce 0 passes nonce check (empty calldata → failed receipt, but nonce consumed)
        let wire = signed_native_tx(&sk, &pk_bytes, 0);
        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(result.is_ok());

        // Replay: nonce 0 again should fail with NonceMismatch
        let wire_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let result = executor.execute_native_tx(
            &wire_replay,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut hub,
            &mut nonces,
            &mut test_journal(),
        );
        match result {
            Err(ExecutionError::NonceMismatch { expected, got, .. }) => {
                assert_eq!(expected, 1);
                assert_eq!(got, 0);
            }
            other => panic!("expected NonceMismatch, got {other:?}"),
        }
    }
}
