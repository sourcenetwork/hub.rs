//! Transport provider trait for building node transport.

use commonware_runtime::tokio;
use hub_config::NodeConfig;

/// Provides transport for a node.
///
/// Implementations create the transport layer (simulated or production P2P)
/// that the node uses for consensus communication.
pub trait TransportProvider: Send + Sync + 'static {
    /// The transport type this provider creates.
    type Transport: Send + Sync + 'static;

    /// Error type for transport creation failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Build transport for a node.
    fn build_transport(
        &mut self,
        context: &tokio::Context,
        config: &NodeConfig,
    ) -> impl std::future::Future<Output = Result<Self::Transport, Self::Error>> + Send;
}
