//! Extended genesis configuration for hub.
//!
//! Produces the EVM [`GenesisState`] with hub-specific fields
//! (native mint configuration, validators, chain metadata).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(test, allow(unused_crate_dependencies))]

mod config;
mod state;
pub use config::{
    GenesisAllocation, GenesisContract, GenesisStorage, NativeMintConfig, ValidatorConfig,
    VeraGenesis, VeraGenesisError,
};
pub use state::GenesisState;
