//! Genesis configuration builder for e2e test clusters.

use std::path::Path;

use hub_genesis::{GenesisAllocation, HubGenesis, NativeMintConfig, ValidatorConfig};

/// Builder for test genesis configurations.
#[derive(Debug)]
pub struct GenesisBuilder {
    chain_id: u64,
    chain_name: String,
    allocations: Vec<GenesisAllocation>,
    native_mint: NativeMintConfig,
    validators: Vec<ValidatorConfig>,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            chain_id: 9001,
            chain_name: "hub-test".to_string(),
            allocations: Vec::new(),
            native_mint: NativeMintConfig::default(),
            validators: Vec::new(),
        }
    }
}

impl GenesisBuilder {
    /// Create a new genesis builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder pre-configured for devnet (matches `HubGenesis::devnet()`).
    pub fn devnet() -> Self {
        let devnet = HubGenesis::devnet();
        Self {
            chain_id: devnet.chain_id,
            chain_name: devnet.chain_name,
            allocations: devnet.allocations,
            native_mint: devnet.native_mint,
            validators: devnet.validators,
        }
    }

    /// Set the chain ID.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set the chain name.
    #[must_use]
    pub fn chain_name(mut self, name: impl Into<String>) -> Self {
        self.chain_name = name.into();
        self
    }

    /// Add a single allocation.
    #[must_use]
    pub fn allocation(mut self, address: &str, balance: &str) -> Self {
        self.allocations.push(GenesisAllocation {
            address: address.to_string(),
            balance: balance.to_string(),
        });
        self
    }

    /// Add pre-funded test accounts (up to 10).
    ///
    /// Uses well-known deterministic addresses derived from the mnemonic
    /// "test test test test test test test test test test test junk".
    #[must_use]
    pub fn funded_accounts(mut self, count: usize, balance: &str) -> Self {
        const TEST_ADDRESSES: [&str; 10] = [
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
            "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
            "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
            "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
            "0x14dC79964da2C08daa4968306Dba23d250591E0A",
            "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
            "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
        ];

        for addr in TEST_ADDRESSES.iter().take(count) {
            self.allocations.push(GenesisAllocation {
                address: (*addr).to_string(),
                balance: balance.to_string(),
            });
        }
        self
    }

    /// Configure the NativeMint precompile.
    #[must_use]
    pub fn native_mint(mut self, config: NativeMintConfig) -> Self {
        self.native_mint = config;
        self
    }

    /// Set genesis validators for the ValidatorRegistry precompile.
    #[must_use]
    pub fn validators(mut self, configs: Vec<ValidatorConfig>) -> Self {
        self.validators = configs;
        self
    }

    /// Build the genesis configuration.
    pub fn build(self) -> HubGenesis {
        HubGenesis {
            chain_id: self.chain_id,
            chain_name: self.chain_name,
            timestamp: 0,
            allocations: self.allocations,
            native_mint: self.native_mint,
            validators: self.validators,
        }
    }

    /// Build and write genesis.json to a directory.
    pub fn build_and_write(&self, dir: &Path) -> eyre::Result<HubGenesis> {
        let genesis = HubGenesis {
            chain_id: self.chain_id,
            chain_name: self.chain_name.clone(),
            timestamp: 0,
            allocations: self.allocations.clone(),
            native_mint: self.native_mint.clone(),
            validators: self.validators.clone(),
        };

        let json = serde_json::to_string_pretty(&genesis)?;
        std::fs::write(dir.join("genesis.json"), json)?;
        Ok(genesis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_genesis() {
        let genesis = GenesisBuilder::devnet().build();
        assert_eq!(genesis.chain_id, 9001);
        assert_eq!(genesis.allocations.len(), 2);
        assert_eq!(genesis.native_mint.denom, "abrl");
    }

    #[test]
    fn custom_genesis() {
        let genesis = GenesisBuilder::new()
            .chain_id(1337)
            .allocation(
                "0xdead000000000000000000000000000000000000",
                "1000000000000000000000",
            )
            .build();

        assert_eq!(genesis.chain_id, 1337);
        assert_eq!(genesis.allocations.len(), 1);
    }

    #[test]
    fn funded_accounts_genesis() {
        let genesis = GenesisBuilder::new()
            .funded_accounts(3, "1000000000000000000000")
            .build();

        assert_eq!(genesis.allocations.len(), 3);
        assert!(genesis.allocations[0].address.starts_with("0xf39F"));
    }

    #[test]
    fn write_genesis_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = GenesisBuilder::devnet()
            .build_and_write(dir.path())
            .unwrap();

        assert!(dir.path().join("genesis.json").exists());
        assert_eq!(genesis.chain_id, 9001);
    }
}
