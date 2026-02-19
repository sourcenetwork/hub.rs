//! Node runner assembly for hub validators.
//!
//! Contains both the generic `ProductionRunner` (base REVM executor) and
//! `HubRunner` (HubExecutor with hub precompiles).

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![allow(clippy::manual_async_fn)]

mod app;
pub use app::RevmApplication;

mod error;
pub use error::RunnerError;

mod production_runner;
pub use production_runner::ProductionRunner;

mod scheme;
pub use scheme::{ThresholdScheme, generate_for_validator, generate_threshold_schemes};

mod runner;
pub use runner::{ConsensusParams, HubRunner};

mod tx_forward;
pub use tx_forward::{LeaderSchedule, TxForwarder};
