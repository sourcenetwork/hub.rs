//! Rust client library for hub (EVM + BLS transaction paths).
//!
//! Provides [`HubClient`] for interacting with a hub node via JSON-RPC.
//! Includes typed query methods for each precompile module (ACP, Bulletin, Hub)
//! and standard Ethereum RPC wrappers.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Operator approval types, signing and submission.
pub mod administration;
/// Certified ownership-amendment history.
pub mod amendments;
mod bearer;
mod bls_signer;
/// Certified bulletin records and bounded listings.
pub mod bulletin;
mod client;
mod document_acp;
mod error;
mod native_tx;
/// Signed threshold-service node commands and certified records.
pub mod nodes;
mod permission;
/// Certified native policy discovery.
pub mod policies;
mod query;
mod receipt;
mod record;
/// Certified registration commitment discovery.
pub mod registrations;
/// Threshold-service ring commands and certified state.
pub mod rings;
/// Encrypted documents and signing derivations.
pub mod threshold_objects;
pub use hub_domain::{ExecutionReceipt, ReceiptResponse, ReceiptResponseError};
pub use hub_permission::{
    AccessRequest, Actor, ModuleId, Object, Operation, PERMISSION_LIMITS, PermissionLimits,
    PermissionProof, PermissionRead, PermissionResponse, PrefixProof, PrefixResponse,
    RECORD_PROOF_BYTES, ReadLimits, RecordProof, RecordResponse, object_owner_prefix,
    verify_permission_proof,
};
mod signer;
mod subject;
mod tx;
mod types;
mod worker;
pub use worker::NativeWorker;

pub use bearer::{
    create_bearer_token, create_operation_token, create_relay_token, create_scoped_bearer_token,
};
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
