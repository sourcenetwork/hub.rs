//! Node-side handling of proposals and finalized blocks: indexing,
//! subscriptions, gossip headers, node status, and mempool recheck.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use commonware_codec::Encode as _;
use commonware_cryptography::Digestible as _;
use hub_app::FinalizedSink;
use hub_consensus::components::InMemoryMempool;
use hub_domain::{Block, GossipHeader};
use hub_executor::{ExecutionReceipt, HubExecutor};
use hub_indexer::{BlockIndex, LightBlockIndex, StoredFinalization};
use hub_jsonrpc::{NodeState, RpcBlock, RpcLog};
use tokio::sync::broadcast;
use tracing::trace;

use hub_backend::HubStateSet;

use crate::{
    CommittedState, FinalizedHistory,
    finalize::{index_finalized_block, subscription_data},
    history::restore_epoch,
    tx_gossip::{SharedValidator, recheck},
};

/// Encoded finalization artifacts fetched from marshal after a block commits.
#[derive(Clone, Debug)]
pub struct FinalizationArtifacts {
    /// Epoch whose public material verifies the certificate.
    pub epoch: u64,
    /// Canonical full finalization bytes served to light clients.
    pub finalization: Vec<u8>,
    /// Canonical recovered certificate bytes gossiped with the header.
    pub certificate: Vec<u8>,
}

/// Async lookup for the finalization marshal persisted at a block height.
pub type FinalizationLookup = Arc<
    dyn Fn(u64) -> Pin<Box<dyn Future<Output = Option<FinalizationArtifacts>> + Send>>
        + Send
        + Sync,
>;

/// Everything the node does with a finalized block once its state is readable.
#[derive(Clone)]
pub struct NodeSink {
    history: Arc<FinalizedHistory>,
    failures: tokio::sync::mpsc::Sender<anyhow::Error>,
    index: Arc<BlockIndex>,
    light_index: Arc<LightBlockIndex>,
    heads: broadcast::Sender<RpcBlock>,
    logs: broadcast::Sender<Vec<RpcLog>>,
    headers: broadcast::Sender<GossipHeader>,
    node_state: NodeState,
    finalization_lookup: FinalizationLookup,
    chain_id: u64,
    publisher_index: u32,
    gas_limit: u64,
    executor: HubExecutor,
    mempool: InMemoryMempool,
    validator: SharedValidator,
    state: Arc<OnceLock<HubStateSet>>,
}

impl std::fmt::Debug for NodeSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSink").finish_non_exhaustive()
    }
}

/// Inputs to [`NodeSink::new`].
pub struct SinkParts {
    /// Durable execution history used to restore the query indexes.
    pub history: Arc<FinalizedHistory>,
    /// Fatal failures from asynchronous finalization persistence.
    pub failures: tokio::sync::mpsc::Sender<anyhow::Error>,
    /// Block, transaction, and receipt index served over RPC.
    pub index: Arc<BlockIndex>,
    /// Public consensus artifacts served to light clients.
    pub light_index: Arc<LightBlockIndex>,
    /// `newHeads` subscribers.
    pub heads: broadcast::Sender<RpcBlock>,
    /// `logs` subscribers.
    pub logs: broadcast::Sender<Vec<RpcLog>>,
    /// `headers` subscribers.
    pub headers: broadcast::Sender<GossipHeader>,
    /// Node status counters.
    pub node_state: NodeState,
    /// Retrieves marshal's canonical finalization for a committed height.
    pub finalization_lookup: FinalizationLookup,
    /// Chain id stamped on gossip headers.
    pub chain_id: u64,
    /// This node's index in the validator set.
    pub publisher_index: u32,
    /// Block gas limit for indexed headers.
    pub gas_limit: u64,
    /// Executor whose module state is read for native nonces.
    pub executor: HubExecutor,
    /// Mempool to recheck after each finalized block.
    pub mempool: InMemoryMempool,
    /// Validator to reset after each finalized block.
    pub validator: SharedValidator,
}

impl std::fmt::Debug for SinkParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkParts").finish_non_exhaustive()
    }
}

impl NodeSink {
    /// Build the sink from its parts.
    pub fn new(parts: SinkParts) -> Self {
        Self {
            history: parts.history,
            failures: parts.failures,
            index: parts.index,
            light_index: parts.light_index,
            heads: parts.heads,
            logs: parts.logs,
            headers: parts.headers,
            node_state: parts.node_state,
            finalization_lookup: parts.finalization_lookup,
            chain_id: parts.chain_id,
            publisher_index: parts.publisher_index,
            gas_limit: parts.gas_limit,
            executor: parts.executor,
            mempool: parts.mempool,
            validator: parts.validator,
            state: Arc::new(OnceLock::new()),
        }
    }

    /// Attach the committed database set once the stateful actor has opened it.
    pub fn attach_state(&self, set: HubStateSet) {
        let _ = self.state.set(set);
    }
}

impl FinalizedSink for NodeSink {
    fn proposed(&self, _block: &Block) {
        self.node_state.inc_proposed();
    }

    async fn finalized(&self, block: &Block, receipts: Vec<ExecutionReceipt>) {
        let history = self.history.clone();
        let persisted = block.clone();
        let gas_limit = self.gas_limit;
        let receipts = ::tokio::task::spawn_blocking(move || {
            history.append(&persisted, &receipts, gas_limit)?;
            Ok::<_, anyhow::Error>(receipts)
        })
        .await
        .expect("finalized history writer stopped")
        .expect("persist finalized execution before publication");
        self.node_state.inc_finalized();
        self.node_state.set_view(block.context.round.view().get());
        self.node_state.set_backfilling(false);

        let gas_used = receipts.iter().map(|r| r.gas_used).sum();
        index_finalized_block(&self.index, block, self.gas_limit, &receipts, gas_used);
        self.node_state.notify_proof_progress();
        let (rpc_block, rpc_logs) = subscription_data(block, self.gas_limit, &receipts, gas_used);
        if self.heads.send(rpc_block).is_err() {
            trace!(height = block.height, "no newHeads subscribers");
        }
        if !rpc_logs.is_empty() && self.logs.send(rpc_logs).is_err() {
            trace!(height = block.height, "no logs subscribers");
        }
        restore_epoch(&self.light_index, block);
        // Marshal invokes reporters while processing this finalization, so it
        // cannot answer its own mailbox until the callback returns. Finish the
        // lookup, indexing, and header publication in a detached task.
        let mut header = GossipHeader::from_block(block, self.chain_id, self.publisher_index);
        let height = block.height;
        let digest = block.digest().0;
        let block_bytes = block.encode().to_vec();
        let lookup = self.finalization_lookup.clone();
        let light_index = self.light_index.clone();
        let headers = self.headers.clone();
        let history = self.history.clone();
        let failures = self.failures.clone();
        let node_state = self.node_state.clone();
        ::tokio::spawn(async move {
            let artifacts = lookup(height).await;
            if let Err(error) = history.store_finalization(height, artifacts.as_ref()) {
                let _ = failures.try_send(error);
                return;
            }
            if let Some(artifacts) = artifacts {
                header.set_signature(&artifacts.certificate);
                light_index.insert_finalization(
                    digest,
                    StoredFinalization {
                        epoch: artifacts.epoch,
                        bytes: artifacts.finalization,
                        block: block_bytes,
                    },
                );
                if headers.send(header).is_err() {
                    trace!(height, "no headers subscribers");
                }
            } else {
                trace!(height, "no direct finalization certificate in marshal");
            }
            node_state.notify_proof_progress();
        });

        let Some(set) = self.state.get() else {
            return;
        };
        let nonces = self
            .executor
            .modules()
            .read()
            .map(|m| m.nonces.clone())
            .unwrap_or_default();
        recheck(
            &self.mempool,
            &self.validator,
            CommittedState::new(set.clone()),
            nonces,
        )
        .await;
    }
}
