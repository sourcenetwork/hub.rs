//! Hub genesis configuration.

use std::{collections::HashSet, path::Path, str::FromStr};

use alloy_evm::revm::primitives::{Address, U256, keccak256};
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
    /// Genesis validators for the ValidatorRegistry precompile.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Arbitrary contract bytecode to deploy at genesis.
    #[serde(default)]
    pub contracts: Vec<GenesisContract>,
    /// Pre-set storage slot values at genesis.
    #[serde(default)]
    pub extra_storage: Vec<GenesisStorage>,
    /// Epoch length for consensus (number of views per epoch).
    /// `None` means a single infinite epoch (`u64::MAX`).
    #[serde(default)]
    pub epoch_length: Option<u64>,
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

/// A genesis validator entry for the ValidatorRegistry precompile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// EVM address (hex with 0x prefix).
    pub evm_address: String,
    /// Ed25519 consensus public key (hex string, 64 chars).
    pub consensus_pubkey: String,
    /// P2P network address (e.g., "127.0.0.1:30300").
    pub p2p_address: String,
}

/// Arbitrary contract bytecode to deploy at genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisContract {
    /// Contract address (hex with 0x prefix).
    pub address: String,
    /// Contract bytecode (hex with 0x prefix).
    pub bytecode: String,
}

/// Pre-set storage slot at genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisStorage {
    /// Account address (hex with 0x prefix).
    pub address: String,
    /// Storage slot (hex with 0x prefix).
    pub slot: String,
    /// Storage value (hex with 0x prefix).
    pub value: String,
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

        let (mut genesis_storage, mut genesis_code) = if self.validators.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let entries = validator_storage_entries(&self.validators)?;
            let storage = vec![(VALIDATOR_REGISTRY_ADDRESS, entries)];
            let code = vec![(
                VALIDATOR_REGISTRY_ADDRESS,
                PRECOMPILE_SENTINEL_BYTECODE.to_vec(),
            )];
            (storage, code)
        };

        for contract in &self.contracts {
            let address = Address::from_str(&contract.address)
                .map_err(|e| HubGenesisError::Parse(format!("invalid contract address: {}", e)))?;
            let bytecode_hex = contract
                .bytecode
                .strip_prefix("0x")
                .unwrap_or(&contract.bytecode);
            let bytecode = hex::decode(bytecode_hex)
                .map_err(|e| HubGenesisError::Parse(format!("invalid contract bytecode: {}", e)))?;
            genesis_code.push((address, bytecode));
        }

        for entry in &self.extra_storage {
            let address = Address::from_str(&entry.address)
                .map_err(|e| HubGenesisError::Parse(format!("invalid storage address: {}", e)))?;
            let slot = U256::from_str(&entry.slot)
                .map_err(|e| HubGenesisError::Parse(format!("invalid storage slot: {}", e)))?;
            let value = U256::from_str(&entry.value)
                .map_err(|e| HubGenesisError::Parse(format!("invalid storage value: {}", e)))?;

            if let Some(existing) = genesis_storage.iter_mut().find(|(a, _)| *a == address) {
                existing.1.push((slot, value));
            } else {
                genesis_storage.push((address, vec![(slot, value)]));
            }
        }

        let participant_addresses: Vec<Address> = self
            .validators
            .iter()
            .map(|v| {
                Address::from_str(&v.evm_address)
                    .expect("validator address already validated above")
            })
            .collect();

        Ok(BootstrapConfig {
            genesis_alloc,
            genesis_storage,
            genesis_code,
            bootstrap_txs: Vec::new(),
            participant_addresses,
        })
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
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_length: None,
        }
    }
}

// ── ValidatorRegistry storage layout ──────────────────────────────────
//
// Must match the layout in hub-executor/src/precompiles/validator_registry.rs.

const VALIDATOR_REGISTRY_ADDRESS: Address = {
    let mut bytes = [0u8; 20];
    bytes[18] = 0x08;
    bytes[19] = 0x13;
    Address::new(bytes)
};

/// EVM `INVALID` opcode — causes revert on direct calls. Same as Tempo.
const PRECOMPILE_SENTINEL_BYTECODE: &[u8] = &[0xfe];

const MAX_P2P_ADDRESS_LEN: usize = 32;

const SLOT_POLICY_ID: U256 = U256::ZERO;
const SLOT_VALIDATOR_COUNT: U256 = U256::from_limbs([1, 0, 0, 0]);
const SLOT_VALIDATORS_ARRAY_BASE: U256 = U256::from_limbs([2, 0, 0, 0]);
const SLOT_VALIDATORS_MAPPING_BASE: U256 = U256::from_limbs([3, 0, 0, 0]);

fn vr_mapping_slot(key: Address, base: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(&base.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

fn vr_array_element_slot(base: U256, index: u64) -> U256 {
    let hash = keccak256(base.to_be_bytes::<32>());
    U256::from_be_bytes(hash.0).wrapping_add(U256::from(index))
}

fn vr_pack_address_active(addr: Address, active: bool) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(addr.as_slice());
    bytes[20] = u8::from(active);
    U256::from_be_bytes(bytes)
}

fn vr_address_to_padded_u256(addr: Address) -> U256 {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr.as_slice());
    U256::from_be_bytes(buf)
}

fn validate_genesis_p2p_address(addr: &str) -> Result<(), HubGenesisError> {
    if addr.is_empty() {
        return Err(HubGenesisError::Parse(
            "validator p2p address is empty".into(),
        ));
    }
    if addr.len() > MAX_P2P_ADDRESS_LEN {
        return Err(HubGenesisError::Parse(format!(
            "validator p2p address exceeds {MAX_P2P_ADDRESS_LEN} bytes: {addr}"
        )));
    }
    addr.parse::<std::net::SocketAddr>().map_err(|e| {
        HubGenesisError::Parse(format!("invalid validator p2p address '{addr}': {e}"))
    })?;
    Ok(())
}

fn validator_storage_entries(
    validators: &[ValidatorConfig],
) -> Result<Vec<(U256, U256)>, HubGenesisError> {
    let mut seen = HashSet::new();
    for v in validators {
        let addr = Address::from_str(&v.evm_address)
            .map_err(|e| HubGenesisError::Parse(format!("invalid validator address: {e}")))?;
        if !seen.insert(addr) {
            return Err(HubGenesisError::Parse(format!(
                "duplicate validator address: {addr}"
            )));
        }
    }

    let mut entries = Vec::new();

    entries.push((SLOT_POLICY_ID, U256::ZERO));
    entries.push((SLOT_VALIDATOR_COUNT, U256::from(validators.len())));

    for (i, v) in validators.iter().enumerate() {
        let addr = Address::from_str(&v.evm_address)
            .map_err(|e| HubGenesisError::Parse(format!("invalid validator address: {e}")))?;
        if addr == Address::ZERO {
            return Err(HubGenesisError::Parse(
                "validator address cannot be zero".into(),
            ));
        }
        let consensus_bytes = hex::decode(&v.consensus_pubkey)
            .map_err(|e| HubGenesisError::Parse(format!("invalid consensus pubkey: {e}")))?;
        if consensus_bytes.len() != 32 {
            return Err(HubGenesisError::Parse(format!(
                "consensus pubkey must be 32 bytes, got {}",
                consensus_bytes.len()
            )));
        }
        let mut consensus: [u8; 32] = [0u8; 32];
        consensus.copy_from_slice(&consensus_bytes);
        if consensus == [0u8; 32] {
            return Err(HubGenesisError::Parse(
                "consensus pubkey cannot be all zeros".into(),
            ));
        }
        validate_genesis_p2p_address(&v.p2p_address)?;

        let addr_slot = vr_array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, i as u64);
        entries.push((addr_slot, vr_address_to_padded_u256(addr)));

        let entry_base = vr_mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
        entries.push((entry_base, vr_pack_address_active(addr, true)));
        entries.push((
            entry_base.wrapping_add(U256::from(1)),
            U256::from_be_bytes(consensus),
        ));
        entries.push((entry_base.wrapping_add(U256::from(2)), U256::from(i)));
        let p2p_bytes = v.p2p_address.as_bytes();
        entries.push((
            entry_base.wrapping_add(U256::from(3)),
            U256::from(p2p_bytes.len()),
        ));
        let mut padded = [0u8; 32];
        padded[..p2p_bytes.len()].copy_from_slice(p2p_bytes);
        entries.push((
            entry_base.wrapping_add(U256::from(4)),
            U256::from_be_bytes(padded),
        ));
    }

    Ok(entries)
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
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_length: None,
        };
        let err = genesis.to_bootstrap_config().unwrap_err();
        assert!(err.to_string().contains("invalid address"));
    }

    fn genesis_with_validators(validators: Vec<ValidatorConfig>) -> HubGenesis {
        HubGenesis {
            chain_id: 1,
            chain_name: "test".to_string(),
            timestamp: 0,
            allocations: Vec::new(),
            native_mint: NativeMintConfig::default(),
            validators,
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_length: None,
        }
    }

    #[test]
    fn genesis_rejects_duplicate_validators() {
        let genesis = genesis_with_validators(vec![
            ValidatorConfig {
                evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: "aa".repeat(32),
                p2p_address: "127.0.0.1:30300".to_string(),
            },
            ValidatorConfig {
                evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                consensus_pubkey: "bb".repeat(32),
                p2p_address: "127.0.0.1:30301".to_string(),
            },
        ]);
        let err = genesis.to_bootstrap_config().unwrap_err();
        assert!(err.to_string().contains("duplicate validator address"));
    }

    #[test]
    fn genesis_rejects_invalid_p2p_address() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "aa".repeat(32),
            p2p_address: "not-a-socket-addr".to_string(),
        }]);
        let err = genesis.to_bootstrap_config().unwrap_err();
        assert!(err.to_string().contains("invalid validator p2p address"));
    }

    #[test]
    fn genesis_rejects_zero_consensus_key() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "00".repeat(32),
            p2p_address: "127.0.0.1:30300".to_string(),
        }]);
        let err = genesis.to_bootstrap_config().unwrap_err();
        assert!(
            err.to_string()
                .contains("consensus pubkey cannot be all zeros")
        );
    }

    #[test]
    fn genesis_sets_precompile_bytecode() {
        let genesis = genesis_with_validators(vec![ValidatorConfig {
            evm_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            consensus_pubkey: "aa".repeat(32),
            p2p_address: "127.0.0.1:30300".to_string(),
        }]);
        let bootstrap = genesis.to_bootstrap_config().unwrap();
        assert_eq!(bootstrap.genesis_code.len(), 1);
        assert_eq!(bootstrap.genesis_code[0].0, VALIDATOR_REGISTRY_ADDRESS);
        assert_eq!(bootstrap.genesis_code[0].1, PRECOMPILE_SENTINEL_BYTECODE);
    }
}
