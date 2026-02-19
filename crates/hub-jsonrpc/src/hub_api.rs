//! Hub-specific JSON-RPC API implementation.

use std::sync::Arc;

use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::state::{NodeState, NodeStatus};

/// Hub-specific JSON-RPC API trait.
///
/// Provides methods specific to hub node operations.
#[rpc(server, namespace = "hub")]
pub trait HubApi {
    /// Returns the current node status including consensus information.
    #[method(name = "nodeStatus")]
    async fn node_status(&self) -> RpcResult<NodeStatus>;
}

/// Implementation of the hub RPC API.
#[derive(Debug)]
pub struct HubApiImpl {
    state: Arc<NodeState>,
}

impl HubApiImpl {
    /// Create a new hub API implementation.
    #[must_use]
    pub const fn new(state: Arc<NodeState>) -> Self {
        Self { state }
    }
}

#[jsonrpsee::core::async_trait]
impl HubApiServer for HubApiImpl {
    async fn node_status(&self) -> RpcResult<NodeStatus> {
        Ok(self.state.status())
    }
}
