//! Hub genesis configuration.

use std::{path::Path, str::FromStr};

use alloy_evm::revm::primitives::{Address, U256};
use hub_domain::BootstrapConfig;
use serde::{Deserialize, Serialize};

/// Hub-extended genesis configuration.
///
/// Extends Kora's base genesis with hub-specific fields:
/// - `native_mint`: NativeMint precompile configuration
/// - `chain_name`: Human-readable chain identifier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HubGenesis {
    /// Chain ID.
    pub chain_id: u64,
    /// Chain name (e.g., "hub-devnet").
    #[serde(default = "default_chain_name")]
    pub chain_name: String,
    /// Genesis timestamp.
    #[serde(default = "default_timestamp")]
    pub timestamp: u64,
    /// Initial account allocations.
    pub allocations: Vec<GenesisAllocation>,
    /// NativeMint precompile configuration.
    #[serde(default)]
    pub native_mint: NativeMintConfig,
}

fn default_chain_name() -> String {
    "hubd".to_string()
}

const fn default_timestamp() -> u64 {
    0
}

/// A single genesis allocation entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Account address (hex with 0x prefix).
    pub address: String,
    /// Account balance (decimal string).
    pub balance: String,
}

/// Configuration for the NativeMint precompile.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeMintConfig {
    /// Admin address for the NativeMint precompile.
    #[serde(default)]
    pub admin: Option<String>,
    /// Initial whitelisted minter addresses.
    #[serde(default)]
    pub minters: Vec<String>,
    /// Native token denom name.
    #[serde(default = "default_denom")]
    pub denom: String,
}

fn default_denom() -> String {
    "abrl".to_string()
}

/// Errors from genesis loading.
#[derive(Debug)]
pub enum HubGenesisError {
    /// IO error reading the genesis file.
    Io(std::io::Error),
    /// JSON parsing error.
    Json(serde_json::Error),
    /// Error parsing address or balance values.
    Parse(String),
}

impl std::fmt::Display for HubGenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {}", e),
            Self::Json(e) => write!(f, "json error: {}", e),
            Self::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for HubGenesisError {}

impl From<std::io::Error> for HubGenesisError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for HubGenesisError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl HubGenesis {
    /// Load genesis from a JSON file.
    pub fn load(path: &Path) -> Result<Self, HubGenesisError> {
        let content = std::fs::read_to_string(path)?;
        let genesis: Self = serde_json::from_str(&content)?;
        Ok(genesis)
    }

    /// Convert to Kora's BootstrapConfig.
    pub fn to_bootstrap_config(&self) -> Result<BootstrapConfig, HubGenesisError> {
        let mut genesis_alloc = Vec::with_capacity(self.allocations.len());
        for alloc in &self.allocations {
            let address = Address::from_str(&alloc.address)
                .map_err(|e| HubGenesisError::Parse(format!("invalid address: {}", e)))?;
            let balance = U256::from_str(&alloc.balance)
                .map_err(|e| HubGenesisError::Parse(format!("invalid balance: {}", e)))?;
            genesis_alloc.push((address, balance));
        }

        Ok(BootstrapConfig::new(genesis_alloc, Vec::new()))
    }

    /// Create a default devnet genesis (chain_id=9001, test allocations).
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            chain_id: 9001,
            chain_name: "hub-devnet".to_string(),
            timestamp: 0,
            allocations: vec![
                GenesisAllocation {
                    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                    balance: "1000000000000000000000".to_string(), // 1000 ETH
                },
                GenesisAllocation {
                    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
                    balance: "1000000000000000000000".to_string(),
                },
            ],
            native_mint: NativeMintConfig {
                admin: Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()),
                minters: vec!["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()],
                denom: "abrl".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_genesis_roundtrip() {
        let genesis = HubGenesis::devnet();
        let json = serde_json::to_string_pretty(&genesis).unwrap();
        let parsed: HubGenesis = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, 9001);
        assert_eq!(parsed.allocations.len(), 2);
        assert_eq!(parsed.native_mint.denom, "abrl");
    }

    #[test]
    fn devnet_to_bootstrap_config() {
        let genesis = HubGenesis::devnet();
        let bootstrap = genesis.to_bootstrap_config().unwrap();
        assert_eq!(bootstrap.genesis_alloc.len(), 2);
        assert!(bootstrap.bootstrap_txs.is_empty());
    }

    #[test]
    fn genesis_load_from_file() {
        let genesis = HubGenesis::devnet();
        let json = serde_json::to_string_pretty(&genesis).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        std::fs::write(&path, &json).unwrap();

        let loaded = HubGenesis::load(&path).unwrap();
        assert_eq!(loaded.chain_id, genesis.chain_id);
        assert_eq!(loaded.chain_name, genesis.chain_name);
    }

    #[test]
    fn genesis_parse_error_on_invalid_address() {
        let genesis = HubGenesis {
            chain_id: 1,
            chain_name: "test".to_string(),
            timestamp: 0,
            allocations: vec![GenesisAllocation {
                address: "not-an-address".to_string(),
                balance: "100".to_string(),
            }],
            native_mint: NativeMintConfig::default(),
        };
        let err = genesis.to_bootstrap_config().unwrap_err();
        assert!(err.to_string().contains("invalid address"));
    }
}
