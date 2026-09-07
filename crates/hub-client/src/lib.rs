//! Rust client library for hub (EVM + BLS transaction paths).
//!
//! Provides [`HubClient`] for interacting with a hub node via JSON-RPC.
//! Includes typed query methods for each precompile module (ACP, Bulletin, Hub)
//! and standard Ethereum RPC wrappers.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Operator approval types, signing and submission.
pub mod administration;
mod bearer;
mod bls_signer;
mod client;
mod document_acp;
mod error;
mod native_tx;
mod permission;
mod query;
mod receipt;
mod record;
pub use hub_domain::{ExecutionReceipt, ReceiptResponse, ReceiptResponseError};
pub use hub_permission::{
    AccessRequest, Actor, ModuleId, Object, Operation, PERMISSION_LIMITS, PermissionLimits,
    PermissionProof, PermissionRead, PermissionResponse, RECORD_PROOF_BYTES, ReadLimits,
    RecordProof, RecordResponse, verify_permission_proof,
};
mod signer;
mod subject;
mod tx;
mod types;

pub use bearer::{create_bearer_token, create_scoped_bearer_token};
pub use bls_signer::BlsSigner;
pub use client::{
    ACP_ADDRESS, BULLETIN_ADDRESS, HUB_ADDRESS, HubClient, VALIDATOR_REGISTRY_ADDRESS,
    parse_policy_id,
};
pub use document_acp::HubDocumentACP;
pub use error::ClientError;
pub use hub_crypto::jwt::DelegationScope;
pub use signer::EvmSigner;
pub use subject::RelationshipSubject;
pub use types::{Log, NativeReceipt, NodeStatus, TransactionReceipt};
