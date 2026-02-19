//! Core execution traits.

use alloy_consensus::Header;
use hub_traits::StateDb;

use crate::{BlockContext, ExecutionError, ExecutionOutcome};

/// Executes transactions against a state database.
///
/// Abstracts the EVM execution layer to allow different backends.
pub trait BlockExecutor<S: StateDb>: Clone + Send + Sync + 'static {
    /// Transaction type accepted for execution.
    type Tx: Clone + Send + Sync + 'static;

    /// Execute a batch of transactions against the given state.
    ///
    /// Returns the execution outcome containing state changes and receipts.
    fn execute(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Self::Tx],
    ) -> Result<ExecutionOutcome, ExecutionError>;

    /// Validate a block header.
    fn validate_header(&self, header: &Header) -> Result<(), ExecutionError>;

    /// Notify the executor that a block at `height` has been verified.
    ///
    /// Called when the consensus layer confirms a block without re-execution
    /// (e.g. the "already verified" fast path). Executors that maintain
    /// height-ordered state can use this to advance their verified-height
    /// tracking and unblock subsequent heights.
    fn mark_height_verified(&self, _height: u64) {}

    /// Retrieve cached receipts for a block at `height`.
    ///
    /// Executors that cache receipts during verification return them here
    /// to avoid re-execution in the finalized block reporter. The entry
    /// is removed from the cache on retrieval.
    fn cached_receipts(&self, _height: u64) -> Option<(Vec<crate::ExecutionReceipt>, u64)> {
        None
    }
}
