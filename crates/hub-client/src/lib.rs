//! Rust client library for hub (EVM + BLS transaction paths).
//!
//! Provides [`HubClient`] for interacting with a hub node via JSON-RPC.
//! Includes typed query methods for each precompile module (ACP, Bulletin, Hub)
//! and standard Ethereum RPC wrappers.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod bls_signer;
mod client;
mod document_acp;
mod error;
mod native_tx;
mod query;
mod signer;
mod tx;
mod types;

pub use bls_signer::BlsSigner;
pub use client::{ACP_ADDRESS, BULLETIN_ADDRESS, HUB_ADDRESS, HubClient};
pub use document_acp::HubDocumentACP;
pub use error::ClientError;
pub use signer::EvmSigner;
pub use types::{Log, NativeReceipt, NodeStatus, TransactionReceipt};
