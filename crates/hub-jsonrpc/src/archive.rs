//! Bounded point reads from durable execution history.

use crate::{NodeState, RpcError};
use hub_indexer::{BlockIndex, IndexQuery};
use std::sync::Arc;

/// Reconstruct the index entries for one retained revision.
pub type IndexLookup =
    Arc<dyn Fn(IndexQuery) -> Result<Option<Arc<BlockIndex>>, String> + Send + Sync>;

/// Archive point reader sharing the node-wide blocking-history admission limit.
#[derive(Clone)]
pub struct ArchiveReader {
    state: NodeState,
    lookup: IndexLookup,
}

impl std::fmt::Debug for ArchiveReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveReader").finish_non_exhaustive()
    }
}

impl ArchiveReader {
    /// Use the same node state as the RPC server to share its admission budget.
    pub const fn new(state: NodeState, lookup: IndexLookup) -> Self {
        Self { state, lookup }
    }

    /// Read one revision without populating the global memory index.
    pub async fn read(&self, query: IndexQuery) -> Result<Option<Arc<BlockIndex>>, RpcError> {
        let permit = self
            .state
            .light_lookup_permit()
            .map_err(|_| RpcError::HistoryBusy)?;
        let lookup = self.lookup.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup(query).map_err(RpcError::StateError)
        })
        .await
        .map_err(|error| RpcError::Internal(error.to_string()))?
    }
}
