//! HTTP and JSON-RPC server implementation.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use jsonrpsee::server::{Server, ServerHandle};
use tokio::sync::broadcast;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{error, info};

use hub_executor::{ModuleTrees, SharedModuleState};
use hub_indexer::{BlockIndex, LightBlockIndex};

use hub_domain::GossipHeader;

use crate::{
    config::{CorsConfig, RpcServerConfig},
    eth::{
        EthApiImpl, EthApiServer, NetApiImpl, NetApiServer, TxSubmitCallback, Web3ApiImpl,
        Web3ApiServer,
    },
    eth_subscribe::{EthSubscriptionApiImpl, EthSubscriptionApiServer},
    hub_api::{HubApiImpl, HubApiServer},
    state::NodeState,
    state_provider::{NoopStateProvider, StateProvider},
    types::{RpcBlock, RpcLog},
};

/// Error type for RPC server operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Failed to bind server.
    #[error("failed to bind server: {0}")]
    Bind(std::io::Error),
    /// Failed to build server.
    #[error("failed to build server: {0}")]
    Build(String),
    /// Failed to register RPC methods.
    #[error("failed to register RPC methods: {0}")]
    RegisterMethod(#[from] jsonrpsee::core::RegisterMethodError),
}

/// Build a CORS layer from configuration.
fn build_cors_layer(config: &CorsConfig) -> CorsLayer {
    if config.allowed_origins.is_empty() {
        return CorsLayer::new();
    }

    let mut layer = CorsLayer::new();

    if config.allowed_origins.len() == 1 && config.allowed_origins[0] == "*" {
        layer = layer.allow_origin(Any);
    } else {
        let origins: Vec<_> = config
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        layer = layer.allow_origin(AllowOrigin::list(origins));
    }

    if config.allowed_methods.iter().any(|m| m == "*") {
        layer = layer.allow_methods(Any);
    } else {
        let methods: Vec<_> = config
            .allowed_methods
            .iter()
            .filter_map(|m| m.parse().ok())
            .collect();
        layer = layer.allow_methods(methods);
    }

    if config.allowed_headers.iter().any(|h| h == "*") {
        layer = layer.allow_headers(Any);
    } else {
        let headers: Vec<_> = config
            .allowed_headers
            .iter()
            .filter_map(|h| h.parse().ok())
            .collect();
        layer = layer.allow_headers(headers);
    }

    layer.max_age(Duration::from_secs(config.max_age))
}

/// RPC server for exposing node status via HTTP and Ethereum JSON-RPC.
pub struct RpcServer<S: StateProvider = NoopStateProvider> {
    state: NodeState,
    addr: SocketAddr,
    chain_id: u64,
    tx_submit: Option<TxSubmitCallback>,
    state_provider: S,
    cors_config: CorsConfig,
    max_connections: u32,
    subscription_heads: Option<broadcast::Sender<RpcBlock>>,
    subscription_logs: Option<broadcast::Sender<Vec<RpcLog>>>,
    subscription_headers: Option<broadcast::Sender<GossipHeader>>,
    extra_modules: Vec<jsonrpsee::RpcModule<()>>,
    hub_index: Option<Arc<BlockIndex>>,
    hub_modules: Option<SharedModuleState>,
    hub_module_trees: Option<ModuleTrees>,
    hub_light_block_index: Option<Arc<LightBlockIndex>>,
}

impl<S: StateProvider> std::fmt::Debug for RpcServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServer")
            .field("state", &self.state)
            .field("addr", &self.addr)
            .field("chain_id", &self.chain_id)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("subscriptions", &self.subscription_heads.is_some())
            .finish()
    }
}

impl RpcServer<NoopStateProvider> {
    /// Create a new RPC server with default (noop) state provider.
    pub fn new(state: NodeState, addr: SocketAddr) -> Self {
        Self {
            state,
            addr,
            chain_id: 1,
            tx_submit: None,
            state_provider: NoopStateProvider,
            cors_config: CorsConfig::default(),
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            hub_index: None,
            hub_modules: None,
            hub_module_trees: None,
            hub_light_block_index: None,
        }
    }

    /// Create a new RPC server with chain ID.
    pub fn with_chain_id(state: NodeState, addr: SocketAddr, chain_id: u64) -> Self {
        Self {
            state,
            addr,
            chain_id,
            tx_submit: None,
            state_provider: NoopStateProvider,
            cors_config: CorsConfig::default(),
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            hub_index: None,
            hub_modules: None,
            hub_module_trees: None,
            hub_light_block_index: None,
        }
    }
}

impl<S: StateProvider + Clone + 'static> RpcServer<S> {
    /// Create a new RPC server with a custom state provider.
    pub fn with_state_provider(
        state: NodeState,
        addr: SocketAddr,
        chain_id: u64,
        state_provider: S,
    ) -> Self {
        Self {
            state,
            addr,
            chain_id,
            tx_submit: None,
            state_provider,
            cors_config: CorsConfig::default(),
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            hub_index: None,
            hub_modules: None,
            hub_module_trees: None,
            hub_light_block_index: None,
        }
    }

    /// Set the transaction submission callback.
    #[must_use]
    pub fn with_tx_submit(mut self, tx_submit: TxSubmitCallback) -> Self {
        self.tx_submit = Some(tx_submit);
        self
    }

    /// Set CORS configuration.
    #[must_use]
    pub fn with_cors(mut self, cors_config: CorsConfig) -> Self {
        self.cors_config = cors_config;
        self
    }

    /// Set maximum concurrent connections.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
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

    /// Enable gossip header subscriptions via `eth_subscribe("headers")`.
    #[must_use]
    pub fn with_headers_subscription(
        mut self,
        headers_tx: broadcast::Sender<GossipHeader>,
    ) -> Self {
        self.subscription_headers = Some(headers_tx);
        self
    }

    /// Merge an additional JSON-RPC module into the server.
    #[must_use]
    pub fn with_extra_module(mut self, module: jsonrpsee::RpcModule<()>) -> Self {
        self.extra_modules.push(module);
        self
    }

    /// Set the block index and shared module state for hub API receipt/nonce queries.
    #[must_use]
    pub fn with_hub_index_and_modules(
        mut self,
        index: Arc<BlockIndex>,
        modules: SharedModuleState,
    ) -> Self {
        self.hub_index = Some(index);
        self.hub_modules = Some(modules);
        self
    }

    /// Set JMT-backed module state trees for proof generation.
    #[must_use]
    pub fn with_hub_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.hub_module_trees = Some(trees);
        self
    }

    /// Set the light block index for `hub_getLightBlock` queries.
    #[must_use]
    pub fn with_hub_light_block_index(mut self, index: Arc<LightBlockIndex>) -> Self {
        self.hub_light_block_index = Some(index);
        self
    }

    /// Create from configuration.
    pub fn from_config(state: NodeState, config: RpcServerConfig, state_provider: S) -> Self {
        Self {
            state,
            addr: config.http_addr,
            chain_id: config.chain_id,
            tx_submit: None,
            state_provider,
            cors_config: config.cors,
            max_connections: config.max_connections,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            hub_index: None,
            hub_modules: None,
            hub_module_trees: None,
            hub_light_block_index: None,
        }
    }

    /// Start the RPC server.
    ///
    /// This spawns background tasks for both HTTP and JSON-RPC servers and returns immediately.
    pub fn start(self) -> RpcServerHandle {
        let addr = self.addr;
        let node_state = Arc::new(self.state);
        let node_state_for_jsonrpc = Arc::clone(&node_state);
        let chain_id = self.chain_id;
        let tx_submit = self.tx_submit;
        let cors_layer = build_cors_layer(&self.cors_config);
        let max_connections = self.max_connections;
        let state_provider = self.state_provider;
        let subscription_heads = self.subscription_heads;
        let subscription_logs = self.subscription_logs;
        let subscription_headers = self.subscription_headers;
        let hub_index = self.hub_index;
        let hub_modules = self.hub_modules;
        let hub_module_trees = self.hub_module_trees;
        let hub_light_block_index = self.hub_light_block_index;

        // Signal from the JSON-RPC task to the HTTP task indicating whether it
        // successfully bound the port. The HTTP status server waits for this
        // before attempting to bind, so there is no race condition.
        let (jsonrpc_ready_tx, jsonrpc_ready_rx) = tokio::sync::oneshot::channel::<bool>();

        // JSON-RPC server serves eth_*, hub_*, net_*, web3_* methods over both
        // HTTP and WebSocket. It binds first and signals readiness to the HTTP task.
        let extra_modules = self.extra_modules;

        let jsonrpc_handle = tokio::spawn(async move {
            let server = match Server::builder()
                .max_connections(max_connections)
                .build(addr)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "Failed to build JSON-RPC server");
                    let _ = jsonrpc_ready_tx.send(false);
                    return None;
                }
            };

            let eth_api = {
                let api = tx_submit.as_ref().map_or_else(
                    || EthApiImpl::new(chain_id, state_provider.clone()),
                    |submit| {
                        EthApiImpl::with_tx_submit(chain_id, state_provider.clone(), submit.clone())
                    },
                );
                api.with_node_state((*node_state_for_jsonrpc).clone())
            };
            let net_api = NetApiImpl::new(chain_id);
            let web3_api = Web3ApiImpl::new();
            let hub_api = {
                let mut api = HubApiImpl::new(node_state_for_jsonrpc, tx_submit);
                if let (Some(idx), Some(mods)) = (hub_index, hub_modules) {
                    api = api.with_index_and_modules(idx, mods);
                }
                if let Some(trees) = hub_module_trees {
                    api = api.with_module_trees(trees);
                }
                if let Some(lbi) = hub_light_block_index {
                    api = api.with_light_block_index(lbi);
                }
                api
            };

            let mut module = jsonrpsee::RpcModule::new(());
            if let Err(e) = module.merge(eth_api.into_rpc()) {
                error!(error = %e, "Failed to merge eth API");
                let _ = jsonrpc_ready_tx.send(false);
                return None;
            }
            if let Err(e) = module.merge(net_api.into_rpc()) {
                error!(error = %e, "Failed to merge net API");
                let _ = jsonrpc_ready_tx.send(false);
                return None;
            }
            if let Err(e) = module.merge(web3_api.into_rpc()) {
                error!(error = %e, "Failed to merge web3 API");
                let _ = jsonrpc_ready_tx.send(false);
                return None;
            }
            if let Err(e) = module.merge(hub_api.into_rpc()) {
                error!(error = %e, "Failed to merge hub API");
                let _ = jsonrpc_ready_tx.send(false);
                return None;
            }
            if let (Some(heads_tx), Some(logs_tx)) = (subscription_heads, subscription_logs) {
                let mut sub_api = EthSubscriptionApiImpl::new(heads_tx, logs_tx);
                if let Some(headers_tx) = subscription_headers {
                    sub_api = sub_api.with_headers(headers_tx);
                }
                if let Err(e) = module.merge(sub_api.into_rpc()) {
                    error!(error = %e, "Failed to merge subscription API");
                    let _ = jsonrpc_ready_tx.send(false);
                    return None;
                }
            }
            for extra in extra_modules {
                if let Err(e) = module.merge(extra) {
                    error!(error = %e, "Failed to merge extra API module");
                    let _ = jsonrpc_ready_tx.send(false);
                    return None;
                }
            }

            info!(addr = %addr, "JSON-RPC server started");
            let _ = jsonrpc_ready_tx.send(true);

            let handle = server.start(module);
            handle.stopped().await;
            Some(())
        });

        // HTTP status server provides /status and /health endpoints.
        // Waits for the JSON-RPC server to signal readiness before attempting
        // to bind. If the JSON-RPC server already holds the port, the HTTP
        // server will not start (this is expected).
        let http_handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/status", get(status_handler))
                .route("/health", get(health_handler))
                .layer(cors_layer)
                .layer(ConcurrencyLimitLayer::new(max_connections as usize))
                .with_state(node_state);

            // Wait for JSON-RPC server to finish binding before we try.
            let jsonrpc_bound = jsonrpc_ready_rx.await.unwrap_or(false);
            if !jsonrpc_bound {
                error!(addr = %addr, "JSON-RPC server failed to start; HTTP status server will attempt to bind independently");
            }

            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    if jsonrpc_bound {
                        // Expected: JSON-RPC already holds the port.
                        info!(addr = %addr, "HTTP status server not started (JSON-RPC has the port)");
                    } else {
                        // Unexpected: both servers failed to bind.
                        error!(error = %e, addr = %addr, "HTTP status server failed to bind");
                    }
                    return;
                }
            };

            info!(addr = %addr, "HTTP status server started");

            if let Err(e) = axum::serve(listener, app).await {
                error!(error = %e, "HTTP server error");
            }
        });

        RpcServerHandle {
            http_handle,
            jsonrpc_handle,
        }
    }
}

/// Handle for managing the RPC server lifecycle.
pub struct RpcServerHandle {
    http_handle: tokio::task::JoinHandle<()>,
    jsonrpc_handle: tokio::task::JoinHandle<Option<()>>,
}

impl std::fmt::Debug for RpcServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServerHandle").finish_non_exhaustive()
    }
}

impl RpcServerHandle {
    /// Wait for both servers to complete.
    pub async fn stopped(self) {
        let _ = tokio::join!(self.http_handle, self.jsonrpc_handle);
    }

    /// Abort both servers.
    pub fn abort(self) {
        self.http_handle.abort();
        self.jsonrpc_handle.abort();
    }
}

async fn status_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let status = state.status();
    (StatusCode::OK, axum::Json(status))
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Standalone JSON-RPC server without HTTP status endpoints.
pub struct JsonRpcServer<S: StateProvider = NoopStateProvider> {
    addr: SocketAddr,
    chain_id: u64,
    tx_submit: Option<TxSubmitCallback>,
    state_provider: S,
    node_state: Option<Arc<NodeState>>,
    max_connections: u32,
    subscription_heads: Option<broadcast::Sender<RpcBlock>>,
    subscription_logs: Option<broadcast::Sender<Vec<RpcLog>>>,
    subscription_headers: Option<broadcast::Sender<GossipHeader>>,
    extra_modules: Vec<jsonrpsee::RpcModule<()>>,
    hub_index: Option<Arc<BlockIndex>>,
    hub_modules: Option<SharedModuleState>,
    hub_module_trees: Option<ModuleTrees>,
    hub_light_block_index: Option<Arc<LightBlockIndex>>,
}

impl<S: StateProvider> std::fmt::Debug for JsonRpcServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRpcServer")
            .field("addr", &self.addr)
            .field("chain_id", &self.chain_id)
            .field("tx_submit", &self.tx_submit.is_some())
            .finish()
    }
}

impl JsonRpcServer<NoopStateProvider> {
    /// Create a new JSON-RPC server with default (noop) state provider.
    pub fn new(addr: SocketAddr, chain_id: u64) -> Self {
        Self {
            addr,
            chain_id,
            tx_submit: None,
            state_provider: NoopStateProvider,
            node_state: None,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            hub_index: None,
            hub_modules: None,
            hub_module_trees: None,
            hub_light_block_index: None,
        }
    }
}

impl<S: StateProvider + Clone + 'static> JsonRpcServer<S> {
    /// Create a new JSON-RPC server with a custom state provider.
    pub fn with_state_provider(addr: SocketAddr, chain_id: u64, state_provider: S) -> Self {
        Self {
            addr,
            chain_id,
            tx_submit: None,
            state_provider,
            node_state: None,
            max_connections: 100,
            subscription_heads: None,
            subscription_logs: None,
            subscription_headers: None,
            extra_modules: Vec::new(),
            hub_index: None,
            hub_modules: None,
            hub_module_trees: None,
            hub_light_block_index: None,
        }
    }

    /// Set the node state for hub API support.
    #[must_use]
    pub fn with_node_state(mut self, node_state: Arc<NodeState>) -> Self {
        self.node_state = Some(node_state);
        self
    }

    /// Set the transaction submission callback.
    #[must_use]
    pub fn with_tx_submit(mut self, tx_submit: TxSubmitCallback) -> Self {
        self.tx_submit = Some(tx_submit);
        self
    }

    /// Set maximum concurrent connections.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
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

    /// Enable gossip header subscriptions via `eth_subscribe("headers")`.
    #[must_use]
    pub fn with_headers_subscription(
        mut self,
        headers_tx: broadcast::Sender<GossipHeader>,
    ) -> Self {
        self.subscription_headers = Some(headers_tx);
        self
    }

    /// Merge an additional JSON-RPC module into the server.
    #[must_use]
    pub fn with_extra_module(mut self, module: jsonrpsee::RpcModule<()>) -> Self {
        self.extra_modules.push(module);
        self
    }

    /// Set the block index and shared module state for hub API receipt/nonce queries.
    #[must_use]
    pub fn with_hub_index_and_modules(
        mut self,
        index: Arc<BlockIndex>,
        modules: SharedModuleState,
    ) -> Self {
        self.hub_index = Some(index);
        self.hub_modules = Some(modules);
        self
    }

    /// Set JMT-backed module state trees for proof generation.
    #[must_use]
    pub fn with_hub_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.hub_module_trees = Some(trees);
        self
    }

    /// Set the light block index for `hub_getLightBlock` queries.
    #[must_use]
    pub fn with_hub_light_block_index(mut self, index: Arc<LightBlockIndex>) -> Self {
        self.hub_light_block_index = Some(index);
        self
    }

    /// Start the JSON-RPC server.
    ///
    /// Returns the server handle and the actual bound address (useful when binding to port 0).
    pub async fn start(self) -> Result<(ServerHandle, SocketAddr), ServerError> {
        let server = Server::builder()
            .max_connections(self.max_connections)
            .build(self.addr)
            .await
            .map_err(|e| ServerError::Build(e.to_string()))?;

        let local_addr = server
            .local_addr()
            .map_err(|e| ServerError::Build(e.to_string()))?;

        let eth_api = {
            let api = self.tx_submit.as_ref().map_or_else(
                || EthApiImpl::new(self.chain_id, self.state_provider.clone()),
                |submit| {
                    EthApiImpl::with_tx_submit(
                        self.chain_id,
                        self.state_provider.clone(),
                        submit.clone(),
                    )
                },
            );
            if let Some(ref ns) = self.node_state {
                api.with_node_state((**ns).clone())
            } else {
                api
            }
        };
        let net_api = NetApiImpl::new(self.chain_id);
        let web3_api = Web3ApiImpl::new();

        let mut module = jsonrpsee::RpcModule::new(());
        module.merge(eth_api.into_rpc())?;
        module.merge(net_api.into_rpc())?;
        module.merge(web3_api.into_rpc())?;
        if let Some(node_state) = self.node_state {
            let hub_api = {
                let mut api = HubApiImpl::new(node_state, self.tx_submit);
                if let (Some(idx), Some(mods)) = (self.hub_index, self.hub_modules) {
                    api = api.with_index_and_modules(idx, mods);
                }
                if let Some(trees) = self.hub_module_trees {
                    api = api.with_module_trees(trees);
                }
                if let Some(lbi) = self.hub_light_block_index {
                    api = api.with_light_block_index(lbi);
                }
                api
            };
            module.merge(hub_api.into_rpc())?;
        }
        if let (Some(heads_tx), Some(logs_tx)) = (self.subscription_heads, self.subscription_logs) {
            let mut sub_api = EthSubscriptionApiImpl::new(heads_tx, logs_tx);
            if let Some(headers_tx) = self.subscription_headers {
                sub_api = sub_api.with_headers(headers_tx);
            }
            module.merge(sub_api.into_rpc())?;
        }
        for extra in self.extra_modules {
            module.merge(extra)?;
        }

        info!(addr = %local_addr, "Starting JSON-RPC server");

        Ok((server.start(module), local_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_layer_empty_origins() {
        let config = CorsConfig::none();
        let _layer = build_cors_layer(&config);
    }

    #[test]
    fn cors_layer_specific_origins() {
        let config = CorsConfig {
            allowed_origins: vec!["http://localhost:3000".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            max_age: 3600,
        };
        let _layer = build_cors_layer(&config);
    }

    #[test]
    fn cors_layer_wildcard() {
        let config = CorsConfig::permissive();
        let _layer = build_cors_layer(&config);
    }
}
