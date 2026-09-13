//! EVM genesis state produced from a [`HubGenesis`](crate::HubGenesis).

use alloy_evm::revm::primitives::{Address, U256};

/// Accounts, storage, and code to install at genesis, plus the validator
/// addresses that receive block rewards.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenesisState {
    /// Initial balances.
    pub genesis_alloc: Vec<(Address, U256)>,
    /// Storage slots per address.
    pub genesis_storage: Vec<(Address, Vec<(U256, U256)>)>,
    /// Bytecode per address.
    pub genesis_code: Vec<(Address, Vec<u8>)>,
    /// EVM addresses of the genesis validators, in genesis order.
    pub participant_addresses: Vec<Address>,
}
