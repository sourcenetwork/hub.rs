//! ACP module error types.

use thiserror::Error;

/// Errors produced by the ACP module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum AcpError {
    #[error("policy not found: {id}")]
    PolicyNotFound { id: String },

    #[error("invalid policy YAML: {reason}")]
    InvalidPolicy { reason: String },

    #[error("access denied for policy {policy_id}")]
    AccessDenied { policy_id: String },

    #[error("invalid access request: {reason}")]
    InvalidAccessRequest { reason: String },

    #[error("object not registered: {resource}/{object_id}")]
    ObjectNotRegistered { resource: String, object_id: String },

    #[error("commitment not found: {id}")]
    CommitmentNotFound { id: u64 },

    #[error("invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("invalid bearer token: {reason}")]
    InvalidBearerToken { reason: String },

    #[error("invalid JWS payload: {reason}")]
    InvalidJws { reason: String },

    #[error("state error: {0}")]
    State(String),

    #[error("replay detected: signed policy command already processed")]
    ReplayDetected,
}
