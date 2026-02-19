//! Top-level node configuration.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{ConfigError, ConsensusConfig, ExecutionConfig, NetworkConfig, RpcConfig};

/// Default chain ID for local development.
pub const DEFAULT_CHAIN_ID: u64 = 1;

/// Default data directory.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/hubd";

/// Complete node configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    /// Chain ID for the network.
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// Data directory for persistent storage.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Consensus configuration.
    #[serde(default)]
    pub consensus: ConsensusConfig,

    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Execution configuration.
    #[serde(default)]
    pub execution: ExecutionConfig,

    /// RPC configuration.
    #[serde(default)]
    pub rpc: RpcConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            consensus: ConsensusConfig::default(),
            network: NetworkConfig::default(),
            execution: ExecutionConfig::default(),
            rpc: RpcConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Load configuration from a file path, auto-detecting format by extension.
    ///
    /// If the path is `None`, returns the default configuration.
    /// Supported extensions: `.json` for JSON, all others default to TOML.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        path.map_or_else(
            || Ok(Self::default()),
            |p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("toml");
                match ext {
                    "json" => Self::from_json_file(p),
                    _ => Self::from_toml_file(p),
                }
            },
        )
    }

    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.into(),
            source: e,
        })?;
        Self::from_toml(&contents)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Load configuration from a JSON file.
    pub fn from_json_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.into(),
            source: e,
        })?;
        Self::from_json(&contents)
    }

    /// Parse configuration from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serialize configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Serialize configuration to a JSON string.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Get or create the validator private key from `{data_dir}/validator.key`.
    pub fn validator_key(
        &self,
    ) -> Result<commonware_cryptography::ed25519::PrivateKey, ConfigError> {
        let key_path = self
            .consensus
            .validator_key
            .clone()
            .unwrap_or_else(|| self.data_dir.join("validator.key"));

        // Try to load existing key
        match std::fs::read(&key_path) {
            Ok(key_bytes) => {
                if key_bytes.len() != 32 {
                    return Err(ConfigError::InvalidKeyLength(key_bytes.len()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&key_bytes);
                Ok(commonware_cryptography::ed25519::PrivateKey::from(
                    ed25519_consensus::SigningKey::from(seed),
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Generate new key
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

                // Ensure parent directory exists
                if let Some(parent) = key_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| ConfigError::CreateDir {
                        path: parent.to_path_buf(),
                        source: e,
                    })?;
                }

                // Write key to disk
                std::fs::write(&key_path, seed).map_err(|e| ConfigError::Write {
                    path: key_path.clone(),
                    source: e,
                })?;

                Ok(commonware_cryptography::ed25519::PrivateKey::from(
                    ed25519_consensus::SigningKey::from(seed),
                ))
            }
            Err(e) => Err(ConfigError::Read {
                path: key_path,
                source: e,
            }),
        }
    }

    /// Get the validator public key.
    pub fn validator_public_key(
        &self,
    ) -> Result<commonware_cryptography::ed25519::PublicKey, ConfigError> {
        use commonware_cryptography::Signer as _;
        Ok(self.validator_key()?.public_key())
    }
}

const fn default_chain_id() -> u64 {
    DEFAULT_CHAIN_ID
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = NodeConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = NodeConfig::from_toml(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_json_roundtrip() {
        let config = NodeConfig::default();
        let json_str = config.to_json().unwrap();
        let parsed = NodeConfig::from_json(&json_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_load_none_returns_default() {
        let config = NodeConfig::load(None).unwrap();
        assert_eq!(config, NodeConfig::default());
    }

    #[test]
    fn test_load_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let expected = NodeConfig {
            chain_id: 42,
            ..Default::default()
        };
        std::fs::write(&path, expected.to_toml().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 42);
    }

    #[test]
    fn test_load_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let expected = NodeConfig {
            chain_id: 99,
            ..Default::default()
        };
        std::fs::write(&path, expected.to_json().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 99);
    }

    #[test]
    fn test_load_unknown_extension_defaults_to_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.conf");
        let expected = NodeConfig {
            chain_id: 77,
            ..Default::default()
        };
        std::fs::write(&path, expected.to_toml().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 77);
    }

    #[test]
    fn test_load_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.toml");
        assert!(NodeConfig::load(Some(&path)).is_err());
    }
}
