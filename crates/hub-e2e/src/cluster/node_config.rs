//! Node configuration builder for e2e test clusters.

use std::time::Duration;

pub use hub_runner::ConsensusParams;

/// Preset consensus timing configurations.
#[derive(Clone, Copy, Debug, Default)]
pub enum ConsensusPreset {
    /// Fast consensus for testing (100ms/200ms/500ms).
    #[default]
    Fast,
    /// Normal consensus timing (500ms/1s/2s).
    Normal,
    /// Stress testing timing (2s/5s/10s).
    Stress,
}

impl ConsensusPreset {
    /// Convert preset to concrete timing parameters.
    pub const fn params(self) -> ConsensusParams {
        match self {
            Self::Fast => ConsensusParams {
                leader_timeout: Duration::from_millis(100),
                notarization_timeout: Duration::from_millis(200),
                nullify_retry: Duration::from_millis(500),
            },
            Self::Normal => ConsensusParams {
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1),
                nullify_retry: Duration::from_secs(2),
            },
            Self::Stress => ConsensusParams {
                leader_timeout: Duration::from_secs(2),
                notarization_timeout: Duration::from_secs(5),
                nullify_retry: Duration::from_secs(10),
            },
        }
    }
}

/// Builder for per-node configuration.
#[derive(Debug)]
pub struct NodeConfigBuilder {
    chain_id: u64,
    preset: ConsensusPreset,
    consensus_override: Option<ConsensusParams>,
}

impl Default for NodeConfigBuilder {
    fn default() -> Self {
        Self {
            chain_id: 9001,
            preset: ConsensusPreset::Fast,
            consensus_override: None,
        }
    }
}

impl NodeConfigBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the chain ID.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set the consensus preset.
    #[must_use]
    pub const fn preset(mut self, preset: ConsensusPreset) -> Self {
        self.preset = preset;
        self
    }

    /// Override individual consensus parameters (takes precedence over preset).
    #[must_use]
    pub const fn consensus_params(mut self, params: ConsensusParams) -> Self {
        self.consensus_override = Some(params);
        self
    }

    /// Resolve the consensus parameters (override > preset).
    pub fn consensus(&self) -> ConsensusParams {
        self.consensus_override
            .clone()
            .unwrap_or_else(|| self.preset.params())
    }

    /// Build a hub `NodeConfig` for a specific node directory and ports.
    pub fn build_node_config(
        &self,
        data_dir: std::path::PathBuf,
        p2p_port: u16,
        rpc_port: u16,
    ) -> hub_config::NodeConfig {
        hub_config::NodeConfig {
            chain_id: self.chain_id,
            data_dir,
            network: hub_config::NetworkConfig {
                listen_addr: format!("0.0.0.0:{}", p2p_port),
                dialable_addr: None,
                bootstrap_peers: Vec::new(),
            },
            rpc: hub_config::RpcConfig {
                http_addr: format!("0.0.0.0:{}", rpc_port),
                ws_addr: format!("0.0.0.0:{}", rpc_port),
            },
            ..Default::default()
        }
    }

    /// Get the configured chain ID.
    pub const fn get_chain_id(&self) -> u64 {
        self.chain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_preset_timing() {
        let params = ConsensusPreset::Fast.params();
        assert_eq!(params.leader_timeout, Duration::from_millis(100));
        assert_eq!(params.notarization_timeout, Duration::from_millis(200));
        assert_eq!(params.nullify_retry, Duration::from_millis(500));
    }

    #[test]
    fn normal_preset_timing() {
        let params = ConsensusPreset::Normal.params();
        assert_eq!(params.leader_timeout, Duration::from_millis(500));
        assert_eq!(params.notarization_timeout, Duration::from_secs(1));
        assert_eq!(params.nullify_retry, Duration::from_secs(2));
    }

    #[test]
    fn stress_preset_timing() {
        let params = ConsensusPreset::Stress.params();
        assert_eq!(params.leader_timeout, Duration::from_secs(2));
        assert_eq!(params.notarization_timeout, Duration::from_secs(5));
        assert_eq!(params.nullify_retry, Duration::from_secs(10));
    }

    #[test]
    fn override_takes_precedence() {
        let custom = ConsensusParams {
            leader_timeout: Duration::from_millis(42),
            notarization_timeout: Duration::from_millis(84),
            nullify_retry: Duration::from_millis(168),
        };
        let builder = NodeConfigBuilder::new()
            .preset(ConsensusPreset::Fast)
            .consensus_params(custom);

        let resolved = builder.consensus();
        assert_eq!(resolved.leader_timeout, Duration::from_millis(42));
    }

    #[test]
    fn default_builder_values() {
        let builder = NodeConfigBuilder::new();
        assert_eq!(builder.get_chain_id(), 9001);
    }
}
