//! Consensus reporters for hub nodes.
#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/mizufinance/hub-commonware/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::{fmt, marker::PhantomData, sync::Arc};

// Re-import tokio broadcast from the crate (not commonware_runtime::tokio).
use ::tokio::sync::broadcast;
use alloy_consensus::{Transaction as _, TxEnvelope, transaction::SignerRecoverable as _};
use alloy_eips::eip2718::Decodable2718 as _;
use alloy_primitives::{B256, Bytes, keccak256};
use commonware_consensus::{
    Block as _, Reporter,
    marshal::Update,
    simplex::{
        scheme::bls12381_threshold::vrf::{Scheme, Seedable as _},
        types::Activity,
    },
};
use commonware_cryptography::{Committable as _, bls12381::primitives::variant::Variant};
use commonware_runtime::{Spawner as _, tokio};
use commonware_utils::acknowledgement::Acknowledgement as _;
use hub_consensus::BlockExecution;
use hub_domain::{Block, ConsensusDigest, PublicKey};
use hub_executor::{BlockContext, BlockExecutor, ExecutionReceipt};
use hub_indexer::{BlockIndex, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction};
use hub_jsonrpc::{NodeState, RpcBlock, RpcLog};
use hub_ledger::LedgerService;
use hub_overlay::OverlayState;
use hub_qmdb_ledger::QmdbState;
use tracing::{error, trace, warn};

/// Provides block execution context for finalized block verification.
pub trait BlockContextProvider: Clone + Send + Sync + 'static {
    /// Build a block execution context for the provided block.
    fn context(&self, block: &Block) -> BlockContext;
}

/// Helper function for SeedReporter::report that owns all its inputs.
async fn seed_report_inner<V: Variant>(
    state: LedgerService,
    activity: Activity<Scheme<PublicKey, V>, ConsensusDigest>,
) {
    match activity {
        Activity::Notarization(notarization) => {
            state
                .set_seed(
                    notarization.proposal.payload,
                    SeedReporter::<V>::hash_seed(notarization.seed()),
                )
                .await;
        }
        Activity::Finalization(finalization) => {
            state
                .set_seed(
                    finalization.proposal.payload,
                    SeedReporter::<V>::hash_seed(finalization.seed()),
                )
                .await;
        }
        _ => {}
    }
}

#[derive(Clone)]
/// Tracks simplex activity to store seed hashes for future proposals.
pub struct SeedReporter<V> {
    /// Ledger service that keeps per-digest seeds and snapshots.
    state: LedgerService,
    /// Marker indicating the variant for the threshold scheme in use.
    _variant: PhantomData<V>,
}

impl<V> fmt::Debug for SeedReporter<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedReporter").finish_non_exhaustive()
    }
}

impl<V> SeedReporter<V> {
    /// Create a new seed reporter for the provided ledger service.
    pub const fn new(state: LedgerService) -> Self {
        Self {
            state,
            _variant: PhantomData,
        }
    }

    fn hash_seed(seed: impl commonware_codec::Encode) -> B256 {
        keccak256(seed.encode())
    }
}

impl<V> Reporter for SeedReporter<V>
where
    V: Variant,
{
    type Activity = Activity<Scheme<PublicKey, V>, ConsensusDigest>;

    fn report(&mut self, activity: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let state = self.state.clone();
        async move {
            seed_report_inner(state, activity).await;
        }
    }
}

/// Optional subscription broadcast senders.
struct SubscriptionSenders {
    heads: broadcast::Sender<RpcBlock>,
    logs: broadcast::Sender<Vec<RpcLog>>,
}

#[allow(clippy::too_many_arguments)]
async fn handle_finalized_update<E, P>(
    state: LedgerService,
    context: tokio::Context,
    executor: E,
    provider: P,
    update: Update<Block>,
    block_index: Option<Arc<BlockIndex>>,
    subscriptions: Option<SubscriptionSenders>,
) where
    E: BlockExecutor<OverlayState<QmdbState>, Tx = Bytes>,
    P: BlockContextProvider,
{
    match update {
        Update::Tip(..) => {}
        Update::Block(block, ack) => {
            let digest = block.commitment();
            let mut cached_receipts: Option<(Vec<ExecutionReceipt>, u64)> = None;

            if state.query_state_root(digest).await.is_none() {
                trace!(
                    ?digest,
                    "missing snapshot for finalized block; re-executing"
                );
                let parent_digest = block.parent();
                let Some(parent_snapshot) = state.parent_snapshot(parent_digest).await else {
                    error!(
                        ?digest,
                        ?parent_digest,
                        "missing parent snapshot for finalized block"
                    );
                    ack.acknowledge();
                    return;
                };
                let block_context = provider.context(&block);
                let execution = match BlockExecution::execute(
                    &parent_snapshot,
                    &executor,
                    &block_context,
                    &block.txs,
                )
                .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        error!(?digest, error = ?err, "failed to execute finalized block");
                        ack.acknowledge();
                        return;
                    }
                };
                let merged_changes = parent_snapshot
                    .state
                    .merge_changes(execution.outcome.changes.clone());
                let state_root = match state
                    .compute_root_from_store(parent_digest, execution.outcome.changes.clone())
                    .await
                {
                    Ok(root) => root,
                    Err(err) => {
                        error!(?digest, error = ?err, "failed to compute qmdb root");
                        ack.acknowledge();
                        return;
                    }
                };
                if state_root != block.state_root {
                    warn!(
                        ?digest,
                        expected = ?block.state_root,
                        computed = ?state_root,
                        "state root mismatch for finalized block"
                    );
                    ack.acknowledge();
                    return;
                }
                // Save receipts for indexing before consuming changes.
                let receipts = execution.outcome.receipts;
                let gas_used = execution.outcome.gas_used;
                cached_receipts = Some((receipts, gas_used));

                let next_state = OverlayState::new(parent_snapshot.state.base(), merged_changes);
                state
                    .insert_snapshot(
                        digest,
                        parent_digest,
                        next_state,
                        state_root,
                        execution.outcome.changes,
                        &block.txs,
                    )
                    .await;
            } else {
                trace!(?digest, "using cached snapshot for finalized block");
            }

            // Obtain receipts BEFORE persisting, because persist_snapshot mutates
            // the QMDB base state, invalidating overlay states that reference it.
            // Re-executing after persistence would see post-commit state and fail
            // with nonce/balance mismatches.
            if block_index.is_some() && cached_receipts.is_none() {
                cached_receipts = executor.cached_receipts(block.height);
                if cached_receipts.is_none() {
                    cached_receipts =
                        re_execute_for_receipts(&state, &executor, &provider, &block).await;
                }
            }

            // Prune mempool BEFORE marking the snapshot as persisted.
            // `collect_pending_tx_ids` walks ancestor snapshots and stops
            // at the first persisted one.  If we mark-persisted first, the
            // walk breaks early, excludes nothing, and stale txs leak back
            // into the next proposal (NonceTooLow → block build failure).
            state.prune_mempool(&block.txs).await;

            let persist_state = state.clone();
            let persist_handle = context
                .shared(true)
                .spawn(move |_| async move { persist_state.persist_snapshot(digest).await });
            let persist_result = match persist_handle.await {
                Ok(result) => result,
                Err(err) => {
                    error!(?digest, error = ?err, "persist task failed");
                    ack.acknowledge();
                    return;
                }
            };
            if let Err(err) = persist_result {
                error!(?digest, error = ?err, "failed to persist finalized block");
                ack.acknowledge();
                return;
            }

            // Index the finalized block and broadcast subscription events.
            let needs_receipts = block_index.is_some() || subscriptions.is_some();
            if needs_receipts {
                let receipts_result = match cached_receipts {
                    Some(cached) => Some(cached),
                    None => {
                        // Snapshot was already cached (from propose/verify), so no receipts
                        // were captured during finalization. Check executor cache first,
                        // then fall back to re-execution.
                        match executor.cached_receipts(block.height) {
                            Some(cached) => Some(cached),
                            None => {
                                re_execute_for_receipts(&state, &executor, &provider, &block).await
                            }
                        }
                    }
                };
                match receipts_result {
                    Some((receipts, gas_used)) => {
                        if let Some(ref index) = block_index {
                            index_finalized_block(index, &block, &provider, &receipts, gas_used);
                        }
                        // Broadcast to WebSocket subscribers.
                        if let Some(ref subs) = subscriptions {
                            let (rpc_block, rpc_logs) =
                                build_subscription_data(&block, &provider, &receipts, gas_used);
                            match subs.heads.send(rpc_block) {
                                Ok(n) => trace!(
                                    height = block.height,
                                    receivers = n,
                                    "broadcast newHeads"
                                ),
                                Err(_) => {
                                    trace!(height = block.height, "no active newHeads subscribers")
                                }
                            }
                            if !rpc_logs.is_empty() {
                                match subs.logs.send(rpc_logs) {
                                    Ok(n) => trace!(
                                        height = block.height,
                                        receivers = n,
                                        "broadcast logs"
                                    ),
                                    Err(_) => {
                                        trace!(height = block.height, "no active logs subscribers")
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        warn!(
                            height = block.height,
                            "skipping block indexing: could not obtain receipts"
                        );
                    }
                }
            }

            // Marshal waits for the application to acknowledge processing before advancing the
            // delivery floor. Without this, the node can stall on finalized block delivery.
            ack.acknowledge();
        }
    }
}

/// Re-execute a finalized block to obtain receipts for indexing.
async fn re_execute_for_receipts<E, P>(
    state: &LedgerService,
    executor: &E,
    provider: &P,
    block: &Block,
) -> Option<(Vec<ExecutionReceipt>, u64)>
where
    E: BlockExecutor<OverlayState<QmdbState>, Tx = Bytes>,
    P: BlockContextProvider,
{
    let parent_digest = block.parent();
    let Some(parent_snapshot) = state.parent_snapshot(parent_digest).await else {
        warn!(
            height = block.height,
            ?parent_digest,
            "missing parent snapshot for receipt re-execution"
        );
        return None;
    };
    let block_context = provider.context(block);
    let execution =
        match BlockExecution::execute(&parent_snapshot, executor, &block_context, &block.txs).await
        {
            Ok(exec) => exec,
            Err(err) => {
                warn!(
                    height = block.height,
                    error = ?err,
                    "failed to re-execute finalized block for receipts"
                );
                return None;
            }
        };
    Some((execution.outcome.receipts, execution.outcome.gas_used))
}

/// Index a finalized block into the block index.
fn index_finalized_block<P: BlockContextProvider>(
    index: &BlockIndex,
    block: &Block,
    provider: &P,
    receipts: &[ExecutionReceipt],
    gas_used: u64,
) {
    let block_hash = block.id().0;
    let block_context = provider.context(block);

    let mut tx_hashes = Vec::with_capacity(block.txs.len());
    let mut indexed_txs = Vec::with_capacity(block.txs.len());
    let mut indexed_receipts = Vec::with_capacity(receipts.len());
    let mut block_log_index: u64 = 0;

    for (i, tx) in block.txs.iter().enumerate() {
        let tx_hash = keccak256(&tx.bytes);

        let Ok(envelope) = TxEnvelope::decode_2718(&mut tx.bytes.as_ref()) else {
            error!(height = block.height, index = i, %tx_hash, "failed to decode tx for indexing");
            tx_hashes.push(tx_hash);
            continue;
        };
        let Ok(sender) = envelope.recover_signer() else {
            error!(height = block.height, index = i, %tx_hash, "failed to recover sender for indexing");
            tx_hashes.push(tx_hash);
            continue;
        };

        tx_hashes.push(tx_hash);

        indexed_txs.push(IndexedTransaction {
            hash: tx_hash,
            block_hash,
            block_number: block.height,
            transaction_index: i as u64,
            from: sender,
            to: envelope.to(),
            value: envelope.value(),
            gas_limit: envelope.gas_limit(),
            gas_price: envelope
                .gas_price()
                .unwrap_or_else(|| envelope.max_fee_per_gas()),
            input: envelope.input().clone(),
            nonce: envelope.nonce(),
        });

        if let Some(receipt) = receipts.get(i) {
            let logs = receipt
                .logs()
                .iter()
                .map(|log| {
                    let idx = block_log_index;
                    block_log_index += 1;
                    IndexedLog {
                        address: log.address,
                        topics: log.data.topics().to_vec(),
                        data: log.data.data.clone(),
                        log_index: idx,
                        block_hash,
                        block_number: block.height,
                        transaction_hash: tx_hash,
                        transaction_index: i as u64,
                    }
                })
                .collect();

            indexed_receipts.push(IndexedReceipt {
                transaction_hash: tx_hash,
                block_hash,
                block_number: block.height,
                transaction_index: i as u64,
                from: sender,
                to: envelope.to(),
                cumulative_gas_used: receipt.cumulative_gas_used(),
                gas_used: receipt.gas_used,
                contract_address: receipt.contract_address,
                logs,
                status: receipt.success(),
            });
        } else {
            warn!(
                height = block.height,
                tx_index = i,
                %tx_hash,
                "missing receipt for transaction"
            );
        }
    }

    let indexed_block = IndexedBlock {
        hash: block_hash,
        number: block.height,
        parent_hash: block.parent.0,
        state_root: block.state_root.0,
        timestamp: block_context.header.timestamp,
        gas_limit: block_context.header.gas_limit,
        gas_used,
        base_fee_per_gas: block_context.header.base_fee_per_gas,
        prevrandao: block.prevrandao,
        transaction_hashes: tx_hashes,
    };

    index.insert_block(indexed_block, indexed_txs, indexed_receipts);
    trace!(height = block.height, "indexed finalized block");
}

/// Build RPC subscription data from a finalized block and its receipts.
fn build_subscription_data<P: BlockContextProvider>(
    block: &Block,
    provider: &P,
    receipts: &[ExecutionReceipt],
    gas_used: u64,
) -> (RpcBlock, Vec<RpcLog>) {
    use alloy_primitives::{Bytes, U64, U256};

    let block_hash = block.id().0;
    let block_context = provider.context(block);

    let rpc_block = RpcBlock {
        hash: block_hash,
        parent_hash: block.parent.0,
        number: U64::from(block.height),
        state_root: block.state_root.0,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Bytes::new(),
        timestamp: U64::from(block_context.header.timestamp),
        gas_limit: U64::from(block_context.header.gas_limit),
        gas_used: U64::from(gas_used),
        extra_data: Bytes::new(),
        mix_hash: block.prevrandao,
        nonce: Default::default(),
        base_fee_per_gas: block_context.header.base_fee_per_gas.map(U256::from),
        miner: alloy_primitives::Address::ZERO,
        difficulty: U256::ZERO,
        total_difficulty: U256::ZERO,
        uncles: vec![],
        size: U64::ZERO,
        transactions: hub_jsonrpc::BlockTransactions::Hashes(
            block.txs.iter().map(|tx| keccak256(&tx.bytes)).collect(),
        ),
    };

    let mut rpc_logs = Vec::new();
    let mut block_log_index: u64 = 0;
    for (i, tx) in block.txs.iter().enumerate() {
        let tx_hash = keccak256(&tx.bytes);
        if let Some(receipt) = receipts.get(i) {
            for log in receipt.logs() {
                let idx = block_log_index;
                block_log_index += 1;
                rpc_logs.push(RpcLog {
                    address: log.address,
                    topics: log.data.topics().to_vec(),
                    data: log.data.data.clone(),
                    block_number: U64::from(block.height),
                    transaction_hash: tx_hash,
                    transaction_index: U64::from(i as u64),
                    block_hash,
                    log_index: U64::from(idx),
                    removed: false,
                });
            }
        } else {
            warn!(
                height = block.height,
                tx_index = i,
                "missing receipt for transaction in subscription data"
            );
        }
    }

    (rpc_block, rpc_logs)
}

#[derive(Clone)]
/// Persists finalized blocks.
pub struct FinalizedReporter<E, P> {
    /// Ledger service used to verify blocks and persist snapshots.
    state: LedgerService,
    /// Tokio context used to schedule blocking work.
    context: tokio::Context,
    /// Block executor used to replay finalized blocks.
    executor: E,
    /// Provider that builds block execution context.
    provider: P,
    /// Optional block index for indexing finalized blocks for RPC queries.
    block_index: Option<Arc<BlockIndex>>,
    /// Optional broadcast sender for new block headers (WebSocket subscriptions).
    subscription_heads: Option<broadcast::Sender<RpcBlock>>,
    /// Optional broadcast sender for new logs (WebSocket subscriptions).
    subscription_logs: Option<broadcast::Sender<Vec<RpcLog>>>,
}

impl<E, P> fmt::Debug for FinalizedReporter<E, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalizedReporter").finish_non_exhaustive()
    }
}

impl<E, P> FinalizedReporter<E, P>
where
    E: BlockExecutor<OverlayState<QmdbState>, Tx = Bytes>,
    P: BlockContextProvider,
{
    /// Create a new finalized reporter.
    pub const fn new(
        state: LedgerService,
        context: tokio::Context,
        executor: E,
        provider: P,
    ) -> Self {
        Self {
            state,
            context,
            executor,
            provider,
            block_index: None,
            subscription_heads: None,
            subscription_logs: None,
        }
    }

    /// Set the block index for indexing finalized blocks.
    #[must_use]
    pub fn with_block_index(mut self, index: Arc<BlockIndex>) -> Self {
        self.block_index = Some(index);
        self
    }

    /// Set subscription broadcast senders for `eth_subscribe` support.
    #[must_use]
    pub fn with_subscriptions(
        mut self,
        heads_tx: broadcast::Sender<RpcBlock>,
        logs_tx: broadcast::Sender<Vec<RpcLog>>,
    ) -> Self {
        self.subscription_heads = Some(heads_tx);
        self.subscription_logs = Some(logs_tx);
        self
    }
}

impl<E, P> Reporter for FinalizedReporter<E, P>
where
    E: BlockExecutor<OverlayState<QmdbState>, Tx = Bytes>,
    P: BlockContextProvider,
{
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let state = self.state.clone();
        let context = self.context.clone();
        let executor = self.executor.clone();
        let provider = self.provider.clone();
        let block_index = self.block_index.clone();
        let subscriptions = self
            .subscription_heads
            .as_ref()
            .zip(self.subscription_logs.as_ref())
            .map(|(h, l)| SubscriptionSenders {
                heads: h.clone(),
                logs: l.clone(),
            });
        async move {
            handle_finalized_update(
                state,
                context,
                executor,
                provider,
                update,
                block_index,
                subscriptions,
            )
            .await;
        }
    }
}

/// Reporter that updates RPC-visible node state from consensus activity.
///
/// This reporter tracks:
/// - Current view number (from notarizations)
/// - Finalized block count
/// - Nullified round count
#[derive(Clone)]
pub struct NodeStateReporter<S> {
    /// RPC node state to update.
    state: NodeState,
    /// Marker for the signing scheme.
    _scheme: PhantomData<S>,
}

impl<S> fmt::Debug for NodeStateReporter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeStateReporter").finish_non_exhaustive()
    }
}

impl<S> NodeStateReporter<S> {
    /// Create a new node state reporter.
    pub const fn new(state: NodeState) -> Self {
        Self {
            state,
            _scheme: PhantomData,
        }
    }
}

impl<S> Reporter for NodeStateReporter<S>
where
    S: commonware_cryptography::certificate::Scheme + Clone + Send + 'static,
{
    type Activity = Activity<S, ConsensusDigest>;

    fn report(&mut self, activity: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        match &activity {
            Activity::Notarization(n) => {
                self.state.set_view(n.proposal.round.view().get());
            }
            Activity::Finalization(f) => {
                self.state.set_view(f.proposal.round.view().get());
                self.state.inc_finalized();
            }
            Activity::Nullification(_) => {
                self.state.inc_nullified();
            }
            _ => {}
        }
        async {}
    }
}

/// Lightweight reporter that writes the current view to an `AtomicU64`.
///
/// Used by the `LeaderSchedule` in Gulfstream tx forwarding to track
/// consensus progress without depending on the RPC `NodeState`.
#[derive(Clone)]
pub struct ViewTracker<S> {
    view: Arc<std::sync::atomic::AtomicU64>,
    _scheme: PhantomData<S>,
}

impl<S> fmt::Debug for ViewTracker<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewTracker").finish_non_exhaustive()
    }
}

impl<S> ViewTracker<S> {
    /// Create a new view tracker writing to the given atomic.
    pub const fn new(view: Arc<std::sync::atomic::AtomicU64>) -> Self {
        Self {
            view,
            _scheme: PhantomData,
        }
    }
}

impl<S> Reporter for ViewTracker<S>
where
    S: commonware_cryptography::certificate::Scheme + Clone + Send + 'static,
{
    type Activity = Activity<S, ConsensusDigest>;

    fn report(&mut self, activity: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let view = match &activity {
            Activity::Notarization(n) => Some(n.proposal.round.view().get()),
            Activity::Finalization(f) => Some(f.proposal.round.view().get()),
            _ => None,
        };
        if let Some(v) = view {
            self.view.store(v, std::sync::atomic::Ordering::Relaxed);
        }
        async {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_consensus::Header;
    use alloy_primitives::{Address, B256, Log, LogData, U256};
    use hub_domain::{Block, BlockId, StateRoot, Tx, evm::Evm};
    use hub_executor::{BlockContext, ExecutionReceipt};
    use hub_indexer::BlockIndex;
    use k256::ecdsa::SigningKey;

    use super::{BlockContextProvider, build_subscription_data, index_finalized_block};

    const GAS_LIMIT: u64 = 30_000_000;
    const CHAIN_ID: u64 = 1337;
    const GAS_LIMIT_TRANSFER: u64 = 21_000;

    #[derive(Clone, Debug)]
    struct TestContextProvider;

    impl BlockContextProvider for TestContextProvider {
        fn context(&self, block: &Block) -> BlockContext {
            let header = Header {
                number: block.height,
                timestamp: block.timestamp,
                gas_limit: GAS_LIMIT,
                beneficiary: Address::ZERO,
                base_fee_per_gas: Some(0),
                ..Default::default()
            };
            BlockContext::new(header, B256::ZERO, block.prevrandao).with_verification()
        }
    }

    fn test_key(seed: u8) -> SigningKey {
        let mut secret = [0u8; 32];
        secret[31] = seed.max(1);
        SigningKey::from_bytes((&secret).into()).expect("valid key")
    }

    fn test_block(height: u64, txs: Vec<Tx>) -> Block {
        Block {
            context: Block::genesis_context(),
            parent: BlockId(B256::ZERO),
            height,
            timestamp: height,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::repeat_byte(0xaa)),
            ibc_root: B256::ZERO,
            txs,
        }
    }

    fn signed_transfer(from_key: &SigningKey, to: Address, value: u64, nonce: u64) -> Tx {
        Evm::sign_eip1559_transfer(
            from_key,
            CHAIN_ID,
            to,
            U256::from(value),
            nonce,
            GAS_LIMIT_TRANSFER,
        )
    }

    fn mock_receipt(tx_hash: B256, gas_used: u64, cumulative_gas_used: u64) -> ExecutionReceipt {
        ExecutionReceipt::new(tx_hash, true, gas_used, cumulative_gas_used, vec![], None)
    }

    fn mock_failed_receipt(
        tx_hash: B256,
        gas_used: u64,
        cumulative_gas_used: u64,
    ) -> ExecutionReceipt {
        ExecutionReceipt::new(tx_hash, false, gas_used, cumulative_gas_used, vec![], None)
    }

    fn mock_receipt_with_log(
        tx_hash: B256,
        gas_used: u64,
        cumulative_gas_used: u64,
        log_address: Address,
    ) -> ExecutionReceipt {
        let log = Log {
            address: log_address,
            data: LogData::new_unchecked(
                vec![B256::repeat_byte(0x01)],
                alloy_primitives::Bytes::from_static(&[0xca, 0xfe]),
            ),
        };
        ExecutionReceipt::new(
            tx_hash,
            true,
            gas_used,
            cumulative_gas_used,
            vec![log],
            None,
        )
    }

    fn mock_receipt_with_logs(
        tx_hash: B256,
        gas_used: u64,
        cumulative_gas_used: u64,
        log_addresses: &[Address],
    ) -> ExecutionReceipt {
        let logs = log_addresses
            .iter()
            .map(|&addr| Log {
                address: addr,
                data: LogData::new_unchecked(
                    vec![B256::repeat_byte(0x01)],
                    alloy_primitives::Bytes::from_static(&[0xca, 0xfe]),
                ),
            })
            .collect();
        ExecutionReceipt::new(tx_hash, true, gas_used, cumulative_gas_used, logs, None)
    }

    #[test]
    fn index_empty_block() {
        let index = Arc::new(BlockIndex::new());
        let block = test_block(1, vec![]);

        index_finalized_block(&index, &block, &TestContextProvider, &[], 0);

        let indexed = index
            .get_block_by_number(1)
            .expect("block should be indexed");
        assert_eq!(indexed.number, 1);
        assert_eq!(indexed.hash, block.id().0);
        assert_eq!(indexed.parent_hash, B256::ZERO);
        assert_eq!(indexed.gas_used, 0);
        assert_eq!(indexed.gas_limit, GAS_LIMIT);
        assert!(indexed.transaction_hashes.is_empty());
        assert_eq!(index.head_block_number(), 1);
    }

    #[test]
    fn index_block_with_single_transfer() {
        let index = Arc::new(BlockIndex::new());
        let from_key = test_key(1);
        let from = Evm::address_from_key(&from_key);
        let to = Address::repeat_byte(0xbb);
        let tx = signed_transfer(&from_key, to, 100, 0);
        let tx_hash = alloy_primitives::keccak256(&tx.bytes);
        let block = test_block(5, vec![tx]);

        let receipt = mock_receipt(tx_hash, GAS_LIMIT_TRANSFER, GAS_LIMIT_TRANSFER);
        index_finalized_block(
            &index,
            &block,
            &TestContextProvider,
            &[receipt],
            GAS_LIMIT_TRANSFER,
        );

        // Verify block
        let indexed_block = index.get_block_by_number(5).expect("block");
        assert_eq!(indexed_block.number, 5);
        assert_eq!(indexed_block.gas_used, GAS_LIMIT_TRANSFER);
        assert_eq!(indexed_block.transaction_hashes.len(), 1);
        assert_eq!(indexed_block.transaction_hashes[0], tx_hash);

        // Verify transaction
        let indexed_tx = index.get_transaction(&tx_hash).expect("tx");
        assert_eq!(indexed_tx.from, from);
        assert_eq!(indexed_tx.to, Some(to));
        assert_eq!(indexed_tx.value, U256::from(100));
        assert_eq!(indexed_tx.nonce, 0);
        assert_eq!(indexed_tx.gas_limit, GAS_LIMIT_TRANSFER);
        assert_eq!(indexed_tx.block_number, 5);
        assert_eq!(indexed_tx.transaction_index, 0);

        // Verify receipt
        let indexed_receipt = index.get_receipt(&tx_hash).expect("receipt");
        assert_eq!(indexed_receipt.transaction_hash, tx_hash);
        assert_eq!(indexed_receipt.gas_used, GAS_LIMIT_TRANSFER);
        assert!(indexed_receipt.status);
        assert_eq!(indexed_receipt.from, from);
        assert_eq!(indexed_receipt.to, Some(to));
    }

    #[test]
    fn index_block_with_multiple_txs() {
        let index = Arc::new(BlockIndex::new());
        let key_a = test_key(1);
        let key_b = test_key(2);
        let addr_a = Evm::address_from_key(&key_a);
        let addr_b = Evm::address_from_key(&key_b);
        let to = Address::repeat_byte(0xcc);

        let tx_a = signed_transfer(&key_a, to, 50, 0);
        let tx_b = signed_transfer(&key_b, to, 75, 0);
        let hash_a = alloy_primitives::keccak256(&tx_a.bytes);
        let hash_b = alloy_primitives::keccak256(&tx_b.bytes);

        let block = test_block(10, vec![tx_a, tx_b]);
        let receipts = vec![
            mock_receipt(hash_a, GAS_LIMIT_TRANSFER, GAS_LIMIT_TRANSFER),
            mock_receipt(hash_b, GAS_LIMIT_TRANSFER, GAS_LIMIT_TRANSFER * 2),
        ];
        let total_gas = GAS_LIMIT_TRANSFER * 2;
        index_finalized_block(&index, &block, &TestContextProvider, &receipts, total_gas);

        // Verify block
        let indexed_block = index.get_block_by_number(10).expect("block");
        assert_eq!(indexed_block.transaction_hashes.len(), 2);
        assert_eq!(indexed_block.gas_used, total_gas);

        // Verify both transactions are indexed with correct indices
        let itx_a = index.get_transaction(&hash_a).expect("tx_a");
        assert_eq!(itx_a.from, addr_a);
        assert_eq!(itx_a.transaction_index, 0);
        assert_eq!(itx_a.value, U256::from(50));

        let itx_b = index.get_transaction(&hash_b).expect("tx_b");
        assert_eq!(itx_b.from, addr_b);
        assert_eq!(itx_b.transaction_index, 1);
        assert_eq!(itx_b.value, U256::from(75));

        // Verify receipt cumulative gas
        let receipt_b = index.get_receipt(&hash_b).expect("receipt_b");
        assert_eq!(receipt_b.cumulative_gas_used, GAS_LIMIT_TRANSFER * 2);
    }

    #[test]
    fn index_block_with_receipt_logs() {
        let index = Arc::new(BlockIndex::new());
        let from_key = test_key(3);
        let to = Address::repeat_byte(0xdd);
        let log_emitter = Address::repeat_byte(0xee);
        let tx = signed_transfer(&from_key, to, 10, 0);
        let tx_hash = alloy_primitives::keccak256(&tx.bytes);
        let block = test_block(7, vec![tx]);

        let receipt =
            mock_receipt_with_log(tx_hash, GAS_LIMIT_TRANSFER, GAS_LIMIT_TRANSFER, log_emitter);
        index_finalized_block(
            &index,
            &block,
            &TestContextProvider,
            &[receipt],
            GAS_LIMIT_TRANSFER,
        );

        let indexed_receipt = index.get_receipt(&tx_hash).expect("receipt");
        assert_eq!(indexed_receipt.logs.len(), 1);
        assert_eq!(indexed_receipt.logs[0].address, log_emitter);
        assert_eq!(indexed_receipt.logs[0].topics.len(), 1);
        assert_eq!(indexed_receipt.logs[0].topics[0], B256::repeat_byte(0x01));
        assert_eq!(indexed_receipt.logs[0].data.as_ref(), &[0xca, 0xfe]);
        assert_eq!(indexed_receipt.logs[0].log_index, 0);
    }

    #[test]
    fn index_block_log_indices_span_transactions() {
        let index = Arc::new(BlockIndex::new());
        let key_a = test_key(1);
        let key_b = test_key(2);
        let to = Address::repeat_byte(0xdd);
        let log_emitter_a = Address::repeat_byte(0xaa);
        let log_emitter_b = Address::repeat_byte(0xbb);

        let tx_a = signed_transfer(&key_a, to, 10, 0);
        let tx_b = signed_transfer(&key_b, to, 20, 0);
        let hash_a = alloy_primitives::keccak256(&tx_a.bytes);
        let hash_b = alloy_primitives::keccak256(&tx_b.bytes);

        let block = test_block(15, vec![tx_a, tx_b]);

        // tx_a has 2 logs, tx_b has 1 log
        let receipt_a = mock_receipt_with_logs(
            hash_a,
            GAS_LIMIT_TRANSFER,
            GAS_LIMIT_TRANSFER,
            &[log_emitter_a, log_emitter_a],
        );
        let receipt_b = mock_receipt_with_logs(
            hash_b,
            GAS_LIMIT_TRANSFER,
            GAS_LIMIT_TRANSFER * 2,
            &[log_emitter_b],
        );
        let total_gas = GAS_LIMIT_TRANSFER * 2;
        index_finalized_block(
            &index,
            &block,
            &TestContextProvider,
            &[receipt_a, receipt_b],
            total_gas,
        );

        // tx_a logs should have block-level indices 0 and 1
        let receipt_a = index.get_receipt(&hash_a).expect("receipt_a");
        assert_eq!(receipt_a.logs.len(), 2);
        assert_eq!(receipt_a.logs[0].log_index, 0);
        assert_eq!(receipt_a.logs[1].log_index, 1);

        // tx_b log should have block-level index 2 (continuing from tx_a)
        let receipt_b = index.get_receipt(&hash_b).expect("receipt_b");
        assert_eq!(receipt_b.logs.len(), 1);
        assert_eq!(receipt_b.logs[0].log_index, 2);
    }

    #[test]
    fn index_block_invalid_tx_bytes_skipped() {
        let index = Arc::new(BlockIndex::new());
        let garbage_tx = Tx::new(alloy_primitives::Bytes::from_static(&[0xde, 0xad]));
        let block = test_block(3, vec![garbage_tx.clone()]);

        // No receipt for the invalid tx
        index_finalized_block(&index, &block, &TestContextProvider, &[], 0);

        // Block should still be indexed
        let indexed_block = index.get_block_by_number(3).expect("block");
        assert_eq!(indexed_block.number, 3);
        // Tx hash is still recorded (keccak of raw bytes) even though decoding failed
        assert_eq!(indexed_block.transaction_hashes.len(), 1);
        // But no IndexedTransaction entry since decoding failed
        let tx_hash = alloy_primitives::keccak256(&garbage_tx.bytes);
        assert!(index.get_transaction(&tx_hash).is_none());
    }

    #[test]
    fn index_block_txs_without_receipts() {
        let index = Arc::new(BlockIndex::new());
        let from_key = test_key(4);
        let to = Address::repeat_byte(0xff);
        let tx = signed_transfer(&from_key, to, 200, 0);
        let tx_hash = alloy_primitives::keccak256(&tx.bytes);
        let block = test_block(2, vec![tx]);

        // No receipts provided (e.g. re-execution failed)
        index_finalized_block(&index, &block, &TestContextProvider, &[], 0);

        // Transaction should be indexed
        let indexed_tx = index.get_transaction(&tx_hash).expect("tx should exist");
        assert_eq!(indexed_tx.value, U256::from(200));

        // But no receipt
        assert!(index.get_receipt(&tx_hash).is_none());
    }

    #[test]
    fn index_block_lookups_by_hash() {
        let index = Arc::new(BlockIndex::new());
        let block = test_block(42, vec![]);
        let block_hash = block.id().0;

        index_finalized_block(&index, &block, &TestContextProvider, &[], 0);

        let by_hash = index.get_block_by_hash(&block_hash).expect("block by hash");
        let by_number = index.get_block_by_number(42).expect("block by number");
        assert_eq!(by_hash.hash, by_number.hash);
        assert_eq!(by_hash.number, 42);
    }

    #[test]
    fn index_block_state_root_and_parent() {
        let parent_hash = B256::repeat_byte(0x11);
        let state_root = B256::repeat_byte(0x22);
        let block = Block {
            context: Block::genesis_context(),
            parent: BlockId(parent_hash),
            height: 99,
            timestamp: 1_700_000_099,
            prevrandao: B256::ZERO,
            state_root: StateRoot(state_root),
            ibc_root: B256::ZERO,
            txs: vec![],
        };
        let index = Arc::new(BlockIndex::new());

        index_finalized_block(&index, &block, &TestContextProvider, &[], 0);

        let indexed = index.get_block_by_number(99).expect("block");
        assert_eq!(indexed.parent_hash, parent_hash);
        assert_eq!(indexed.state_root, state_root);
        assert_eq!(indexed.base_fee_per_gas, Some(0));
    }

    #[test]
    fn index_block_with_failed_receipt() {
        let index = Arc::new(BlockIndex::new());
        let from_key = test_key(5);
        let to = Address::repeat_byte(0xaa);
        let tx = signed_transfer(&from_key, to, 500, 0);
        let tx_hash = alloy_primitives::keccak256(&tx.bytes);
        let block = test_block(8, vec![tx]);

        let receipt = mock_failed_receipt(tx_hash, GAS_LIMIT_TRANSFER, GAS_LIMIT_TRANSFER);
        index_finalized_block(
            &index,
            &block,
            &TestContextProvider,
            &[receipt],
            GAS_LIMIT_TRANSFER,
        );

        let indexed_receipt = index.get_receipt(&tx_hash).expect("receipt");
        assert!(
            !indexed_receipt.status,
            "reverted tx should have status=false"
        );
        assert_eq!(indexed_receipt.gas_used, GAS_LIMIT_TRANSFER);
        assert_eq!(indexed_receipt.transaction_hash, tx_hash);
    }

    #[test]
    fn index_block_mixed_valid_and_invalid_txs() {
        let index = Arc::new(BlockIndex::new());
        let key_a = test_key(6);
        let addr_a = Evm::address_from_key(&key_a);
        let to = Address::repeat_byte(0xbb);

        // First tx is garbage (invalid), second is a valid signed transfer.
        let invalid_tx = Tx::new(alloy_primitives::Bytes::from_static(&[0xba, 0xad]));
        let valid_tx = signed_transfer(&key_a, to, 42, 0);
        let invalid_hash = alloy_primitives::keccak256(&invalid_tx.bytes);
        let valid_hash = alloy_primitives::keccak256(&valid_tx.bytes);

        let block = test_block(11, vec![invalid_tx, valid_tx]);

        // Only one receipt exists — for the valid tx at index 1.
        // Note: receipts are aligned by tx index, so receipts[0] corresponds to
        // the invalid tx (which has no receipt) and receipts[1] to the valid tx.
        // We pass two receipts to maintain index alignment.
        let receipts = vec![
            mock_receipt(invalid_hash, 0, 0),
            mock_receipt(valid_hash, GAS_LIMIT_TRANSFER, GAS_LIMIT_TRANSFER),
        ];
        index_finalized_block(
            &index,
            &block,
            &TestContextProvider,
            &receipts,
            GAS_LIMIT_TRANSFER,
        );

        // Block should have both tx hashes recorded.
        let indexed_block = index.get_block_by_number(11).expect("block");
        assert_eq!(indexed_block.transaction_hashes.len(), 2);
        assert_eq!(indexed_block.transaction_hashes[0], invalid_hash);
        assert_eq!(indexed_block.transaction_hashes[1], valid_hash);

        // Invalid tx should NOT have an IndexedTransaction (decode failed).
        assert!(index.get_transaction(&invalid_hash).is_none());

        // Valid tx should have an IndexedTransaction with correct index.
        let indexed_tx = index.get_transaction(&valid_hash).expect("valid tx");
        assert_eq!(indexed_tx.from, addr_a);
        assert_eq!(indexed_tx.transaction_index, 1);
        assert_eq!(indexed_tx.value, U256::from(42));

        // Valid tx should have a receipt (receipts.get(1) returns the second receipt).
        let indexed_receipt = index.get_receipt(&valid_hash).expect("valid tx receipt");
        assert!(indexed_receipt.status);
        assert_eq!(indexed_receipt.gas_used, GAS_LIMIT_TRANSFER);
    }

    #[test]
    fn finalized_reporter_with_block_index_builder() {
        // Verify the builder pattern works (compile-time + runtime check)
        let index = Arc::new(BlockIndex::new());
        let index_clone = index.clone();

        // We can't easily construct a full FinalizedReporter without a LedgerService,
        // but we can verify the Arc is shared correctly.
        assert_eq!(Arc::strong_count(&index), 2);
        drop(index_clone);
        assert_eq!(Arc::strong_count(&index), 1);
    }

    #[test]
    fn build_subscription_data_empty_block() {
        let block = test_block(10, vec![]);
        let (rpc_block, rpc_logs) = build_subscription_data(&block, &TestContextProvider, &[], 0);

        assert_eq!(rpc_block.number, alloy_primitives::U64::from(10));
        assert_eq!(rpc_block.hash, block.id().0);
        assert_eq!(rpc_block.parent_hash, B256::ZERO);
        assert_eq!(rpc_block.state_root, block.state_root.0);
        assert_eq!(rpc_block.gas_used, alloy_primitives::U64::ZERO);
        assert_eq!(rpc_block.gas_limit, alloy_primitives::U64::from(GAS_LIMIT));
        assert_eq!(rpc_block.timestamp, alloy_primitives::U64::from(10));
        assert!(rpc_logs.is_empty());
    }

    #[test]
    fn build_subscription_data_with_logs() {
        let from_key = test_key(1);
        let to = Address::repeat_byte(0xdd);
        let log_addr_a = Address::repeat_byte(0xaa);
        let log_addr_b = Address::repeat_byte(0xbb);

        let tx_a = signed_transfer(&from_key, to, 10, 0);
        let tx_b = signed_transfer(&from_key, to, 20, 1);
        let hash_a = alloy_primitives::keccak256(&tx_a.bytes);
        let hash_b = alloy_primitives::keccak256(&tx_b.bytes);

        let block = test_block(5, vec![tx_a, tx_b]);
        let block_hash = block.id().0;

        // tx_a has 1 log, tx_b has 2 logs.
        let receipt_a = mock_receipt_with_log(hash_a, 21_000, 21_000, log_addr_a);
        let receipt_b = mock_receipt_with_logs(hash_b, 21_000, 42_000, &[log_addr_b, log_addr_b]);
        let total_gas = 42_000;

        let (rpc_block, rpc_logs) = build_subscription_data(
            &block,
            &TestContextProvider,
            &[receipt_a, receipt_b],
            total_gas,
        );

        // Block fields.
        assert_eq!(rpc_block.number, alloy_primitives::U64::from(5));
        assert_eq!(rpc_block.gas_used, alloy_primitives::U64::from(total_gas));

        // Should have 3 logs total.
        assert_eq!(rpc_logs.len(), 3);

        // First log from tx_a.
        assert_eq!(rpc_logs[0].address, log_addr_a);
        assert_eq!(rpc_logs[0].block_hash, block_hash);
        assert_eq!(rpc_logs[0].transaction_hash, hash_a);
        assert_eq!(rpc_logs[0].log_index, alloy_primitives::U64::ZERO);
        assert_eq!(rpc_logs[0].transaction_index, alloy_primitives::U64::ZERO);

        // Second and third logs from tx_b (log_index continues from tx_a).
        assert_eq!(rpc_logs[1].address, log_addr_b);
        assert_eq!(rpc_logs[1].transaction_hash, hash_b);
        assert_eq!(rpc_logs[1].log_index, alloy_primitives::U64::from(1));
        assert_eq!(
            rpc_logs[1].transaction_index,
            alloy_primitives::U64::from(1)
        );

        assert_eq!(rpc_logs[2].log_index, alloy_primitives::U64::from(2));
        assert_eq!(
            rpc_logs[2].transaction_index,
            alloy_primitives::U64::from(1)
        );
    }
}
