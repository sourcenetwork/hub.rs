//! Delivery of finalized blocks to the rest of the node.

use hub_domain::Block;
use hub_executor::ExecutionReceipt;

/// Receives every finalized block with its receipts, once state is readable.
pub trait FinalizedSink: Clone + Send + Sync + 'static {
    /// Called after the block's batches are applied.
    fn finalized(&self, block: &Block, receipts: Vec<ExecutionReceipt>);
}

/// Sink that drops finalized blocks.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSink;

impl FinalizedSink for NoopSink {
    fn finalized(&self, _block: &Block, _receipts: Vec<ExecutionReceipt>) {}
}
