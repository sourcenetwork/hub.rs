//! Node-side handling of proposals and finalized blocks: indexing,
//! subscriptions, gossip headers, node status, and mempool recheck.

use std::sync::{Arc, OnceLock};

use commonware_cryptography::{Signer as _, ed25519};
use hub_app::FinalizedSink;
use hub_consensus::components::InMemoryMempool;
use hub_domain::{Block, GossipHeader};
use hub_executor::{ExecutionReceipt, HubExecutor};
use hub_indexer::BlockIndex;
use hub_jsonrpc::{NodeState, RpcBlock, RpcLog};
use tokio::sync::broadcast;
use tracing::trace;

use hub_backend::HubStateSet;

use crate::{
    CommittedState,
    finalize::{index_finalized_block, subscription_data},
    tx_gossip::{SharedValidator, recheck},
};

/// Ed25519 namespace for gossip header signatures.
const GOSSIP_NAMESPACE: &[u8] = b"sourcehub/headers/v1";

/// Everything the node does with a finalized block once its state is readable.
#[derive(Clone)]
pub struct NodeSink {
    index: Arc<BlockIndex>,
    heads: broadcast::Sender<RpcBlock>,
    logs: broadcast::Sender<Vec<RpcLog>>,
    headers: broadcast::Sender<GossipHeader>,
    node_state: NodeState,
    signing_key: ed25519::PrivateKey,
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
    /// Block, transaction, and receipt index served over RPC.
    pub index: Arc<BlockIndex>,
    /// `newHeads` subscribers.
    pub heads: broadcast::Sender<RpcBlock>,
    /// `logs` subscribers.
    pub logs: broadcast::Sender<Vec<RpcLog>>,
    /// `headers` subscribers.
    pub headers: broadcast::Sender<GossipHeader>,
    /// Node status counters.
    pub node_state: NodeState,
    /// Key that signs gossip headers.
    pub signing_key: ed25519::PrivateKey,
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
            index: parts.index,
            heads: parts.heads,
            logs: parts.logs,
            headers: parts.headers,
            node_state: parts.node_state,
            signing_key: parts.signing_key,
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
        self.node_state.inc_finalized();
        self.node_state.set_view(block.context.round.view().get());
        self.node_state.set_backfilling(false);

        let gas_used = receipts.iter().map(|r| r.gas_used).sum();
        index_finalized_block(&self.index, block, self.gas_limit, &receipts, gas_used);
        let (rpc_block, rpc_logs) = subscription_data(block, self.gas_limit, &receipts, gas_used);
        if self.heads.send(rpc_block).is_err() {
            trace!(height = block.height, "no newHeads subscribers");
        }
        if !rpc_logs.is_empty() && self.logs.send(rpc_logs).is_err() {
            trace!(height = block.height, "no logs subscribers");
        }
        let mut header = GossipHeader::from_block(block, self.chain_id, self.publisher_index);
        let signature = self
            .signing_key
            .sign(GOSSIP_NAMESPACE, &header.signing_data());
        header.set_signature(signature.as_ref());
        if self.headers.send(header).is_err() {
            trace!(height = block.height, "no headers subscribers");
        }

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
