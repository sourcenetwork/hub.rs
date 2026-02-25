//! Extended genesis configuration for hub.
//!
//! Produces Kora's [`BootstrapConfig`] with hub-specific fields
//! (native mint configuration, chain metadata).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod config;
pub use config::{
    GenesisAllocation, GenesisContract, GenesisStorage, HubGenesis, HubGenesisError,
    NativeMintConfig, ValidatorConfig,
};
