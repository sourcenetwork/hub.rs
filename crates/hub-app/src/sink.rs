//! Delivery of block events to the rest of the node.

use std::future::Future;

use hub_domain::Block;
use hub_executor::ExecutionReceipt;

/// Receives proposals and finalized blocks with their receipts.
pub trait FinalizedSink: Clone + Send + Sync + 'static {
    /// Called after this node built a proposal.
    fn proposed(&self, _block: &Block) {}

    /// Called once a finalized block's batches are applied and readable.
    fn finalized(
        &self,
        block: &Block,
        receipts: Vec<ExecutionReceipt>,
    ) -> impl Future<Output = ()> + Send;
}

/// Sink that drops every event.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSink;

impl FinalizedSink for NoopSink {
    async fn finalized(&self, _block: &Block, _receipts: Vec<ExecutionReceipt>) {}
}
