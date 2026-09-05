//! The glue stateful application.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use commonware_consensus::marshal::ancestry::Ancestry;
use commonware_consensus::types::Round;
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::{Application, Input, Proposed, db::DatabaseSet};
use futures::StreamExt as _;
use hub_backend::{Ctx, HubMerkleized, HubStateSet, HubSyncTargets, HubUnmerkleized};
use hub_consensus::{Mempool as _, TxId, components::InMemoryMempool};
use hub_domain::{Block, BlockId, ConsensusContext, PublicKey};
use hub_executor::{BlockContext, ExecutionReceipt, HubExecutor, ModuleSnapshot};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::{AppError, ConsensusScheme, FinalizedSink, ReshareInput, execute_block, sync_targets};

const MAX_CLOCK_DRIFT_SECS: u64 = 15;
const MAX_PENDING_ANCESTORS: usize = 64;

struct PendingExecution {
    height: u64,
    modules: ModuleSnapshot,
    receipts: Vec<ExecutionReceipt>,
}

/// VRF randomness recovered by consensus while it unlocks each proposal round.
///
/// Simplex keeps the unlocking certificate outside the application context, so
/// the node's elector records its canonical threshold seed here before asking
/// the application to build or verify the round's block.
#[derive(Clone, Debug, Default)]
pub struct VrfSeedCache(Arc<RwLock<HashMap<Round, B256>>>);

impl VrfSeedCache {
    /// Record the 32-byte EVM randomness derived from a round's unlocking VRF seed.
    pub fn insert(&self, round: Round, prevrandao: B256) {
        self.0
            .write()
            .expect("VRF seed cache lock poisoned")
            .insert(round, prevrandao);
    }

    /// Return the randomness that must be committed by a block in `round`.
    #[must_use]
    pub fn get(&self, round: Round) -> Option<B256> {
        self.0
            .read()
            .expect("VRF seed cache lock poisoned")
            .get(&round)
            .copied()
    }
}

/// Hub block production and verification on top of glue-managed state.
#[derive(Clone)]
pub struct StatefulHubApp<S: FinalizedSink> {
    executor: HubExecutor,
    genesis: Block,
    mempool: InMemoryMempool,
    sink: S,
    max_txs: usize,
    gas_limit: u64,
    participant_addresses: Arc<Vec<(PublicKey, Address)>>,
    vrf_seeds: VrfSeedCache,
    pending: Arc<Mutex<HashMap<BlockId, PendingExecution>>>,
}

impl<S: FinalizedSink> std::fmt::Debug for StatefulHubApp<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatefulHubApp")
            .field("max_txs", &self.max_txs)
            .field("gas_limit", &self.gas_limit)
            .finish_non_exhaustive()
    }
}

impl<S: FinalizedSink> StatefulHubApp<S> {
    /// Create the application around an executor and the genesis block.
    pub fn new(
        executor: HubExecutor,
        genesis: Block,
        mempool: InMemoryMempool,
        sink: S,
        max_txs: usize,
        gas_limit: u64,
    ) -> Self {
        let modules = executor.snapshot().expect("read initial module snapshot");
        let pending = HashMap::from([(
            genesis.id(),
            PendingExecution {
                height: genesis.height,
                modules,
                receipts: Vec::new(),
            },
        )]);
        Self {
            executor,
            genesis,
            mempool,
            sink,
            max_txs,
            gas_limit,
            participant_addresses: Arc::new(Vec::new()),
            vrf_seeds: VrfSeedCache::default(),
            pending: Arc::new(Mutex::new(pending)),
        }
    }

    /// Map consensus leaders to the EVM address credited as block beneficiary.
    #[must_use]
    pub fn with_participant_addresses(mut self, addrs: Vec<(PublicKey, Address)>) -> Self {
        self.participant_addresses = Arc::new(addrs);
        self
    }

    /// Shared cache populated by the node's VRF-aware consensus elector.
    #[must_use]
    pub fn vrf_seed_cache(&self) -> VrfSeedCache {
        self.vrf_seeds.clone()
    }

    fn round_prevrandao(&self, round: Round) -> Option<B256> {
        if round.view().get() <= 1 {
            Some(B256::ZERO)
        } else {
            self.vrf_seeds.get(round)
        }
    }

    fn beneficiary_for(&self, leader: &PublicKey) -> Address {
        self.participant_addresses
            .iter()
            .find(|(pk, _)| pk == leader)
            .map_or(Address::ZERO, |(_, addr)| *addr)
    }

    fn block_context(
        &self,
        height: u64,
        timestamp: u64,
        prevrandao: B256,
        leader: &PublicKey,
    ) -> BlockContext {
        let header = Header {
            number: height,
            timestamp,
            gas_limit: self.gas_limit,
            beneficiary: self.beneficiary_for(leader),
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        BlockContext::new(header, B256::ZERO, prevrandao)
    }

    fn modules_for(&self, parent: BlockId) -> ModuleSnapshot {
        self.pending
            .lock()
            .get(&parent)
            .map(|execution| execution.modules.clone())
            .unwrap_or_else(|| {
                self.executor
                    .snapshot()
                    .expect("read committed module snapshot")
            })
    }

    async fn re_execute(
        &self,
        block: &Block,
        batches: HubUnmerkleized,
    ) -> Result<HubMerkleized, AppError> {
        let modules = self.modules_for(block.parent);
        let context = self
            .block_context(
                block.height,
                block.timestamp,
                block.prevrandao,
                &block.context.leader,
            )
            .with_verification()
            .with_expected_module_state_root(block.module_state_root);
        let executed =
            execute_block(&self.executor, batches, &context, &block.txs, modules).await?;
        if executed.state_root != block.state_root {
            return Err(AppError::RootMismatch("state root"));
        }
        if executed.outcome.module_state_root != block.module_state_root {
            return Err(AppError::RootMismatch("module state root"));
        }
        if executed.db_targets != block.db_targets {
            return Err(AppError::RootMismatch("db targets"));
        }
        self.cache_execution(block, executed.modules, executed.outcome.receipts);
        Ok(executed.merkleized)
    }

    fn cache_execution(
        &self,
        block: &Block,
        modules: ModuleSnapshot,
        receipts: Vec<ExecutionReceipt>,
    ) {
        self.pending.lock().insert(
            block.id(),
            PendingExecution {
                height: block.height,
                modules,
                receipts,
            },
        );
    }

    fn pending_tx_ids(blocks: &[Arc<Block>]) -> BTreeSet<TxId> {
        blocks
            .iter()
            .flat_map(|block| block.txs.iter().map(hub_domain::Tx::id))
            .collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

impl<S: FinalizedSink> Application<Ctx> for StatefulHubApp<S> {
    type SigningScheme = ConsensusScheme;
    type Context = ConsensusContext;
    type Block = Block;
    type Databases = HubStateSet;
    type Captured = (ModuleSnapshot, Vec<ExecutionReceipt>);
    type Provider = InMemoryMempool;
    type Input = ReshareInput;

    fn sync_targets(block: &Self::Block) -> HubSyncTargets {
        sync_targets(&block.db_targets)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (Ctx, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: HubUnmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, Ctx>> {
        let start = Instant::now();
        let consensus_context = context.1;
        let parent = ancestry.next().await?;
        let mut pending = vec![parent.clone()];
        while pending.len() < MAX_PENDING_ANCESTORS {
            match ancestry.next().await {
                Some(block) => pending.push(block),
                None => break,
            }
        }
        let excluded = Self::pending_tx_ids(&pending);
        let txs = input.provider.build(self.max_txs, &excluded);

        let modules = self.modules_for(parent.id());
        let height = parent.height + 1;
        let timestamp = now_secs().max(parent.timestamp);
        let prevrandao = match self.round_prevrandao(consensus_context.round) {
            Some(seed) => seed,
            None => {
                warn!(round = ?consensus_context.round, "missing parent VRF seed");
                return None;
            }
        };
        let block_context =
            self.block_context(height, timestamp, prevrandao, &consensus_context.leader);
        let exec_start = Instant::now();
        let executed =
            match execute_block(&self.executor, batches, &block_context, &txs, modules).await {
                Ok(executed) => executed,
                Err(e) => {
                    warn!(height, txs = txs.len(), error = %e, "propose: execution failed");
                    return None;
                }
            };
        let exec_ms = exec_start.elapsed().as_millis();
        let txs = match &executed.outcome.executed_tx_indices {
            Some(indices) => indices.iter().map(|&i| txs[i].clone()).collect(),
            None => txs,
        };
        let block = Block {
            context: consensus_context,
            parent: parent.id(),
            height,
            timestamp,
            prevrandao,
            state_root: executed.state_root,
            module_state_root: executed.outcome.module_state_root,
            txs,
            payload: input.upstream.payload,
            db_targets: executed.db_targets,
        };
        self.cache_execution(&block, executed.modules, executed.outcome.receipts);
        info!(
            block_digest = ?block.digest(),
            height,
            txs = block.txs.len(),
            snapshot_ms = 0u128,
            exec_ms,
            root_ms = 0u128,
            total_ms = start.elapsed().as_millis(),
            "built block"
        );
        self.sink.proposed(&block);
        Some(Proposed {
            block,
            merkleized: executed.merkleized,
        })
    }

    async fn verify(
        &mut self,
        context: (Ctx, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: HubUnmerkleized,
    ) -> Option<HubMerkleized> {
        let start = Instant::now();
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        let digest = block.digest();
        if block.context != context.1 {
            warn!(?digest, "block consensus context mismatch");
            return None;
        }
        let expected_prevrandao = match self.round_prevrandao(context.1.round) {
            Some(seed) => seed,
            None => {
                warn!(round = ?context.1.round, "missing parent VRF seed");
                return None;
            }
        };
        if block.prevrandao != expected_prevrandao {
            warn!(
                ?digest,
                expected = ?expected_prevrandao,
                actual = ?block.prevrandao,
                "block prevrandao does not match parent VRF seed"
            );
            return None;
        }
        if block.timestamp < parent.timestamp {
            warn!(
                ?digest,
                block_ts = block.timestamp,
                parent_ts = parent.timestamp,
                "block timestamp before parent"
            );
            return None;
        }
        if block.timestamp > now_secs() + MAX_CLOCK_DRIFT_SECS {
            warn!(
                ?digest,
                block_ts = block.timestamp,
                "block timestamp too far in future"
            );
            return None;
        }
        match self.re_execute(&block, batches).await {
            Ok(merkleized) => {
                info!(
                    ?digest,
                    height = block.height,
                    txs = block.txs.len(),
                    snapshot_ms = 0u128,
                    exec_ms = start.elapsed().as_millis(),
                    root_ms = 0u128,
                    total_ms = start.elapsed().as_millis(),
                    "verified block"
                );
                Some(merkleized)
            }
            Err(e) => {
                warn!(?digest, height = block.height, error = %e, "verification failed");
                None
            }
        }
    }

    async fn apply(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        batches: HubUnmerkleized,
    ) -> Option<HubMerkleized> {
        match self.re_execute(block, batches).await {
            Ok(merkleized) => Some(merkleized),
            Err(e) => {
                warn!(height = block.height, error = %e, "apply failed");
                None
            }
        }
    }

    async fn capture(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        _batches: &HubMerkleized,
        _readers: <HubStateSet as DatabaseSet<Ctx>>::Readers,
    ) -> Self::Captured {
        let pending = self.pending.lock();
        let execution = pending
            .get(&block.id())
            .expect("finalized block must have its execution result");
        (execution.modules.clone(), execution.receipts.clone())
    }

    async fn finalized(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        _readers: <HubStateSet as DatabaseSet<Ctx>>::Readers,
    ) {
        let ids: Vec<TxId> = block.txs.iter().map(hub_domain::Tx::id).collect();
        self.mempool.prune(&ids);
        let (modules, receipts) = captured;
        self.executor
            .commit_snapshot(block.height, modules)
            .expect("persist finalized modules");
        self.sink.finalized(block, receipts).await;
        self.pending
            .lock()
            .retain(|_, execution| execution.height >= block.height);
    }
}
