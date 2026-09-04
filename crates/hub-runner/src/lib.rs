//! Node runner assembly for hub validators.
//!
//! Contains `HubRunner` (HubExecutor with hub precompiles).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![allow(clippy::manual_async_fn)]

mod app;
pub use app::RevmApplication;

mod error;
pub use error::RunnerError;

mod scheme;
pub use scheme::{Ed25519Scheme, generate_ed25519_schemes, generate_for_validator};

mod scheme_provider;
pub use scheme_provider::EpochSchemeProvider;

mod epoch_manager;
pub use epoch_manager::EpochManager;

mod runner;
pub use runner::{ConsensusParams, HubRunner};

mod tx_forward;
pub use tx_forward::{LeaderSchedule, TxForwarder};
