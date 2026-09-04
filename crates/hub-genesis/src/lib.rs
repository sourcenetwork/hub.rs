//! Extended genesis configuration for hub.
//!
//! Produces the EVM [`GenesisState`] with hub-specific fields
//! (native mint configuration, validators, chain metadata).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod config;
mod state;
pub use config::{
    GenesisAllocation, GenesisContract, GenesisStorage, HubGenesis, HubGenesisError,
    NativeMintConfig, ValidatorConfig,
};
pub use state::GenesisState;
