//! Contract deployment and interaction utilities for e2e tests.
//!
//! Provides transaction signing with funded Hardhat test accounts,
//! contract deployment, storage reads, and state-changing calls.
//!
//! All transaction functions accept an explicit nonce — callers are
//! responsible for tracking nonces across sequential sends.

pub mod caller;
pub mod deployer;
pub mod rpc;
pub mod signer;

pub use caller::send;
pub use deployer::{DeployReceipt, deploy};
pub use rpc::{get_balance, get_storage_at};
pub use signer::{test_address, test_signer};
